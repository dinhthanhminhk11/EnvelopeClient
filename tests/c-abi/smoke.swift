// Swift side of the C ABI smoke test (tools/c-abi-smoke.sh): what `import DoodleArtCore` gives the iOS package. Byte
// strings go in as (UnsafePointer<UInt8>?, Int), replies come back as DoodleArtBuf(ptr: UnsafeMutablePointer<UInt8>?,
// len: Int), statuses and DOODLEART_* macros are Int32. Vectors and expectations come through the bridging header the
// script generates (vectors.h, expect.h).
import Darwin
import DoodleArtCore

var checks = 0
var failures = 0

func check(_ condition: Bool, _ message: String, line: Int = #line) {
    checks += 1
    if !condition {
        failures += 1
        print("FAIL smoke.swift:\(line): \(message)")
    }
}

/// Calls `body` with the (pointer, count) pair of `bytes`, as the package passes Data / [UInt8].
func withPair<R>(_ bytes: [UInt8], _ body: (UnsafePointer<UInt8>?, Int) -> R) -> R {
    bytes.withUnsafeBufferPointer { body($0.baseAddress, $0.count) }
}

typealias Pair = (UnsafePointer<UInt8>?, Int)

/// Calls `body` with the pairs of every byte string, all valid for the call.
func withPairs<R>(_ values: [[UInt8]], _ body: ([Pair]) -> R) -> R {
    var pairs: [Pair] = []
    func nest(_ index: Int) -> R {
        if index == values.count {
            return body(pairs)
        }
        return values[index].withUnsafeBufferPointer { buffer in
            pairs.append((buffer.baseAddress, buffer.count))
            return nest(index + 1)
        }
    }
    return nest(0)
}

/// Copies a reply out and releases it (the caller's side of the ownership rule).
func take(_ buf: DoodleArtBuf) -> [UInt8] {
    guard let pointer = buf.ptr, buf.len > 0 else { fatalError("NULL reply") }
    let bytes = Array(UnsafeBufferPointer(start: pointer, count: buf.len))
    doodleart_buf_free(buf)
    return bytes
}

func status(_ reply: [UInt8]) -> Int32 { Int32(reply[0]) }

/// The frame after the status byte.
func fields(_ reply: [UInt8]) -> [[UInt8]] {
    var out: [[UInt8]] = []
    var index = 1
    while index + 4 <= reply.count {
        let length = reply[index..<index + 4].reduce(0) { $0 << 8 | Int($1) }
        index += 4
        guard index + length <= reply.count else { return [] }
        out.append(Array(reply[index..<index + length]))
        index += length
    }
    return index == reply.count ? out : []
}

func u64(_ bytes: [UInt8]) -> UInt64 { bytes.reduce(0) { $0 << 8 | UInt64($1) } }

func hex(_ text: String) -> [UInt8] {
    var bytes: [UInt8] = []
    var high: UInt8?
    for scalar in text.unicodeScalars {
        let nibble = UInt8(String(scalar), radix: 16)!
        if let first = high {
            bytes.append(first << 4 | nibble)
            high = nil
        } else {
            high = nibble
        }
    }
    return bytes
}

func utf8(_ text: String) -> [UInt8] { Array(text.utf8) }

// init: the JNI fields, then abiVersion and projectId.
let initFields = fields(take(doodleart_init()))
check(initFields.count == 5, "init fields \(initFields.count)")
if initFields.count == 5 {
    check(initFields[0] == utf8(EXPECT_BUILD_TYPE), "buildType")
    check(u64(initFields[3]) == UInt64(DOODLEART_ABI_VERSION), "abiVersion")
    check(initFields[4] == utf8(EXPECT_PROJECT_ID), "projectId")
}

// deviceKeyId, iosDeviceHash, DAAS1 and the registration message vectors.
let keyId = withPair(hex(V_SPKI_HEX)) { doodleart_device_key_id($0, $1) }
check(take(keyId) == [0] + utf8(V_DEVICE_KEY_ID), "deviceKeyId")
let deviceHash = withPair(hex(V_IOS_SECRET_HEX)) { doodleart_ios_device_hash($0, $1) }
check(take(deviceHash) == [0] + utf8(V_IOS_HASH), "iosDeviceHash")
check(status(take(doodleart_ios_device_hash(nil, 32))) == DOODLEART_STATUS_INVALID_ARGUMENT, "NULL with a length")
let daas1 = take(withPair(hex(V_DAAS1_MESSAGE_HEX)) { doodleart_session_assert_hash($0, $1) })
check(daas1 == [0] + hex(V_DAAS1_HASH_HEX), "DAAS1")

let registerArguments = [V_REG_0, V_REG_1, V_REG_2, V_REG_3].map(utf8)
let register = withPairs(registerArguments) { p in
    doodleart_register_message(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1, p[3].0, p[3].1)
}
check(fields(take(register)) == [hex(V_REG_MESSAGE_HEX), hex(V_REG_HASH_HEX)], "register message")

// DAPI1: requestId, requestHash text and its 32 raw bytes for generateAssertion.
let dapi1 = [V_DAPI1_0, V_DAPI1_1, V_DAPI1_2, V_DAPI1_3].map(utf8)
let integrity = withPairs(dapi1 + [hex(V_DAPI1_4)]) { p in
    doodleart_integrity_hash(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1, p[3].0, p[3].1, p[4].0, p[4].1)
}
let integrityFields = fields(take(integrity))
check(integrityFields == [dapi1[2], utf8(V_DAPI1_5), hex(V_DAPI1_6)], "DAPI1")

// A handshake: DAAS1 by handle equals DAAS1 of its signatureMessage; abort, then the handle is gone.
let beginArguments = ["8b0e5d1c-3f7a-4c2e-9a61-2d4b7c9e1f30", V_DEVICE_KEY_ID, "2.0.0"].map(utf8)
let begin = withPairs(beginArguments) { p in doodleart_handshake_begin(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1) }
let beginFields = fields(take(begin))
check(beginFields.count == 3, "handshake_begin")
if beginFields.count == 3 {
    let handshake = Int64(bitPattern: u64(beginFields[0]))
    let byHandle = take(doodleart_handshake_assert_hash(handshake))
    let byMessage = take(withPair(beginFields[1]) { doodleart_session_assert_hash($0, $1) })
    check(byHandle.count == 33 && byHandle == byMessage, "DAAS1 by handle")
    check(doodleart_handshake_abort(handshake) == DOODLEART_STATUS_OK, "abort")
    check(doodleart_handshake_abort(handshake) == DOODLEART_STATUS_UNKNOWN_HANDLE, "second abort")
}

// Ownership: {NULL, 0} is ignored; every reply is released exactly once (copy it out, then free it in one place, as
// take() does: a second release may hit another reply at the same address).
doodleart_buf_free(DoodleArtBuf(ptr: nil, len: 0))
let reply = doodleart_init()
doodleart_buf_free(reply)
check(status(take(doodleart_risk_scan())) == DOODLEART_STATUS_OK, "risk scan")

#if DOODLEART_DEBUG_HOOKS
check(doodleart_debug_clock_advance_ms(0) == DOODLEART_STATUS_OK, "debug clock advance 0")
check(doodleart_debug_clock_advance_ms(-1) == DOODLEART_STATUS_INVALID_ARGUMENT, "debug clock advance -1")
#endif

print("c-abi smoke (Swift, \(EXPECT_BUILD_TYPE)): \(checks) checks, \(failures) failures")
exit(failures == 0 ? 0 : 1)
