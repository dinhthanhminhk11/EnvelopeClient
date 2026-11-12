//
//  CoreBridge.swift
//  doodleart-core Swift sample
//
//  Swift side of the C ABI of doodleart-core (doodleart-core/include/doodleart_core.h). Every reply is copied into a
//  Data and released right away, so no DoodleArtBuf outlives the call that returned it. Without the module (a build
//  configuration that does not link the core) `isLinked` is false and every call throws: the app keeps the plain API.
//

import Foundation

#if canImport(DoodleArtCore)
    import DoodleArtCore
#endif

/// A refused call of the core: `status` is a DOODLEART_STATUS_* value. SERVER_REJECTED and UNSEALED_RESPONSE carry the
/// HTTP status and the unauthenticated `meta.code` of the answer (decimal text, "" when none).
struct CoreError: Error, CustomStringConvertible {
    let status: UInt8
    let httpStatus: Int?
    let code: String?
    let serverTime: UInt64?

    var description: String {
        "core status \(status)" + (httpStatus.map { " http \($0)" } ?? "") + (code.map { " code \($0)" } ?? "")
    }

    var metaCode: Int? {
        code.flatMap(Int.init)
    }
}

enum CoreStatus {
    static let ok: UInt8 = 0
    static let invalidArgument: UInt8 = 1
    static let unknownHandle: UInt8 = 2
    static let handshakeState: UInt8 = 3
    static let badServerResponse: UInt8 = 4
    static let badServerSignature: UInt8 = 5
    static let serverRejected: UInt8 = 6
    static let decryptFailed: UInt8 = 7
    static let replayedResponse: UInt8 = 8
    static let seqExhausted: UInt8 = 9
    static let sessionExpired: UInt8 = 10
    static let internalError: UInt8 = 13
    static let unsealedResponse: UInt8 = 14
}

/// What `doodleart_session_seal` returns: the headers and the body of one sealed request.
struct CoreSealedRequest {
    let seq: Int64
    let ts: UInt64
    let sid: String
    let appVersion: String
    /// `X-Tx-Tag` of a bodyless request (no body, no Content-Type); nil when `body` is sent.
    let tag: String?
    let body: Data
}

struct CoreHandshake {
    let handle: Int64
    /// The exact bytes the device key signs.
    let signatureMessage: Data
    let riskFlagsCSV: String
}

struct CoreSession {
    let handle: Int64
    let sid: String
    /// `{ session_ttl_seconds, idle_ttl_seconds, min_app_version, trust, user_id, is_anonymous }`.
    let info: Data
}

enum CoreBridge {}

// MARK: - Public Functions

extension CoreBridge {
    static var isLinked: Bool {
        #if canImport(DoodleArtCore)
            return true
        #else
            return false
        #endif
    }

    /// `frame(buildType, crateVersion, kidsCsv, u64(abiVersion), projectId)` as text, for logs.
    static func buildInfo() -> String? {
        #if canImport(DoodleArtCore)
            guard let fields = try? framed(call { doodleart_init() }), fields.count >= 5 else { return nil }
            let text = { (data: Data) in String(decoding: data, as: UTF8.self) }
            return "\(text(fields[0])) \(text(fields[1])) kids=\(text(fields[2])) abi=\(u64(fields[3])) project=\(text(fields[4]))"
        #else
            return nil
        #endif
    }

    static func deviceKeyID(spki: Data) throws -> String {
        #if canImport(DoodleArtCore)
            let reply = try raw(withInputs([spki]) { p in call { doodleart_device_key_id(p[0].0, p[0].1) } })
            return String(decoding: reply, as: UTF8.self)
        #else
            throw notLinked
        #endif
    }

    /// The registration message the device key signs and its SHA-256 (the App Attest clientDataHash).
    static func registerMessage(nonce: String, deviceID: String, keyID: String, platform: String) throws -> (message: Data, clientDataHash: Data) {
        #if canImport(DoodleArtCore)
            let inputs = [Data(nonce.utf8), Data(deviceID.utf8), Data(keyID.utf8), Data(platform.utf8)]
            let fields = try framed(withInputs(inputs) { p in
                call { doodleart_register_message(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1, p[3].0, p[3].1) }
            })
            guard fields.count >= 2 else { throw CoreError(status: CoreStatus.internalError, httpStatus: nil, code: nil, serverTime: nil) }
            return (fields[0], fields[1])
        #else
            throw notLinked
        #endif
    }

    /// Blocking (the core runs its risk scan): never call on the main thread.
    static func handshakeBegin(deviceID: String, keyID: String, appVersion: String) throws -> CoreHandshake {
        #if canImport(DoodleArtCore)
            let inputs = [Data(deviceID.utf8), Data(keyID.utf8), Data(appVersion.utf8)]
            let fields = try framed(withInputs(inputs) { p in
                call { doodleart_handshake_begin(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1) }
            })
            guard fields.count >= 3 else { throw CoreError(status: CoreStatus.internalError, httpStatus: nil, code: nil, serverTime: nil) }
            return CoreHandshake(handle: Int64(bitPattern: u64(fields[0])), signatureMessage: fields[1],
                                 riskFlagsCSV: String(decoding: fields[2], as: UTF8.self))
        #else
            throw notLinked
        #endif
    }

    /// DAAS1 clientDataHash of the handshake's own signature message (App Attest assertion of session/start).
    static func handshakeAssertHash(_ handshake: Int64) throws -> Data {
        #if canImport(DoodleArtCore)
            return try raw(call { doodleart_handshake_assert_hash(handshake) })
        #else
            throw notLinked
        #endif
    }

    static func handshakeBody(_ handshake: Int64, signature: Data) throws -> Data {
        #if canImport(DoodleArtCore)
            return try raw(withInputs([signature]) { p in call { doodleart_handshake_body(handshake, p[0].0, p[0].1) } })
        #else
            throw notLinked
        #endif
    }

    /// Consumes the handshake whatever the outcome. `serverTime` is the X-Server-Time header in ms (0 when absent).
    static func handshakeFinish(_ handshake: Int64, httpStatus: Int, serverTime: Int64, body: Data) throws -> CoreSession {
        #if canImport(DoodleArtCore)
            let fields = try framed(withInputs([body]) { p in
                call { doodleart_handshake_finish(handshake, Int32(clamping: httpStatus), serverTime, p[0].0, p[0].1) }
            })
            guard fields.count >= 3 else { throw CoreError(status: CoreStatus.internalError, httpStatus: nil, code: nil, serverTime: nil) }
            return CoreSession(handle: Int64(bitPattern: u64(fields[0])), sid: String(decoding: fields[1], as: UTF8.self), info: fields[2])
        #else
            throw notLinked
        #endif
    }

    static func handshakeAbort(_ handshake: Int64) {
        #if canImport(DoodleArtCore)
            _ = doodleart_handshake_abort(handshake)
        #endif
    }

    /// `pathWithQuery`: the request target exactly as sent (percent-encoded path, "?" and query).
    static func seal(session: Int64, method: String, pathWithQuery: String, body: Data?) throws -> CoreSealedRequest {
        #if canImport(DoodleArtCore)
            let fields = try framed(withInputs([Data(method.utf8), Data(pathWithQuery.utf8), body]) { p in
                call { doodleart_session_seal(session, p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1) }
            })
            guard fields.count >= 6 else { throw CoreError(status: CoreStatus.internalError, httpStatus: nil, code: nil, serverTime: nil) }
            let tag = String(decoding: fields[4], as: UTF8.self)
            return CoreSealedRequest(seq: Int64(bitPattern: u64(fields[0])), ts: u64(fields[1]), sid: String(decoding: fields[2], as: UTF8.self),
                                     appVersion: String(decoding: fields[3], as: UTF8.self), tag: tag.isEmpty ? nil : tag, body: fields[5])
        #else
            throw notLinked
        #endif
    }

    /// The plaintext `{meta, data}` of a sealed answer (gzip already decoded), or a CoreError: UNSEALED_RESPONSE for an
    /// answer that is not sealed (never data), DECRYPT_FAILED / REPLAYED_RESPONSE for one not to be trusted.
    static func response(session: Int64, seq: Int64, httpStatus: Int, contentType: String?, contentEncoding: String?, body: Data) throws -> Data {
        #if canImport(DoodleArtCore)
            let inputs = [contentType.map { Data($0.utf8) }, contentEncoding.map { Data($0.utf8) }, body]
            return try raw(withInputs(inputs) { p in
                call { doodleart_session_response(session, seq, Int32(clamping: httpStatus), p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1) }
            })
        #else
            throw notLinked
        #endif
    }

    static func abandon(session: Int64, seq: Int64) {
        #if canImport(DoodleArtCore)
            _ = doodleart_session_abandon(session, seq)
        #endif
    }

    static func close(session: Int64) {
        #if canImport(DoodleArtCore)
            _ = doodleart_session_close(session)
        #endif
    }

    /// `frame(riskFlagsCsv, detailsCsv)` of the core's own scan, for logs. Blocking.
    static func riskScan() -> (flags: String, details: String)? {
        #if canImport(DoodleArtCore)
            guard let fields = try? framed(call { doodleart_risk_scan() }), fields.count >= 2 else { return nil }
            return (String(decoding: fields[0], as: UTF8.self), String(decoding: fields[1], as: UTF8.self))
        #else
            return nil
        #endif
    }
}

// MARK: - Private Functions

extension CoreBridge {
    private struct Reply {
        let status: UInt8
        let payload: Data
    }

    private static var notLinked: CoreError {
        CoreError(status: CoreStatus.internalError, httpStatus: nil, code: nil, serverTime: nil)
    }

    #if canImport(DoodleArtCore)
        /// Copies the reply and releases it exactly once. A NULL reply counts as INTERNAL (header rule).
        private static func call(_ body: () -> DoodleArtBuf) -> Reply {
            let buf = body()
            defer { doodleart_buf_free(buf) }
            guard let pointer = buf.ptr, buf.len > 0 else { return Reply(status: CoreStatus.internalError, payload: Data()) }
            let bytes = Data(bytes: pointer, count: buf.len)
            return Reply(status: bytes[bytes.startIndex], payload: bytes.dropFirst())
        }
    #endif

    /// Copies each input into its own buffer for the call: (NULL, 0) for nil (absent), a live (ptr, len) otherwise.
    private static func withInputs<R>(_ inputs: [Data?], _ body: ([(UnsafePointer<UInt8>?, Int)]) -> R) -> R {
        var buffers: [UnsafeMutableBufferPointer<UInt8>] = []
        defer { buffers.forEach { $0.deallocate() } }
        let pairs: [(UnsafePointer<UInt8>?, Int)] = inputs.map { input in
            guard let input else { return (nil, 0) }
            let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: max(input.count, 1))
            _ = buffer.initialize(from: input)
            buffers.append(buffer)
            return (buffer.baseAddress.map { UnsafePointer($0) }, input.count)
        }
        return body(pairs)
    }

    private static func raw(_ reply: Reply) throws -> Data {
        guard reply.status == CoreStatus.ok else { throw error(of: reply) }
        return Data(reply.payload)
    }

    private static func framed(_ reply: Reply) throws -> [Data] {
        let payload = try raw(reply)
        guard let fields = unframe(payload) else {
            throw CoreError(status: CoreStatus.internalError, httpStatus: nil, code: nil, serverTime: nil)
        }
        return fields
    }

    private static func error(of reply: Reply) -> CoreError {
        let fields = unframe(Data(reply.payload)) ?? []
        switch reply.status {
        case CoreStatus.serverRejected where fields.count >= 3:
            let serverTime = u64(fields[2])
            return CoreError(status: reply.status, httpStatus: Int(u64(fields[0])), code: String(decoding: fields[1], as: UTF8.self),
                             serverTime: serverTime == 0 ? nil : serverTime)
        case CoreStatus.unsealedResponse where fields.count >= 2:
            return CoreError(status: reply.status, httpStatus: Int(u64(fields[0])), code: String(decoding: fields[1], as: UTF8.self), serverTime: nil)
        default:
            return CoreError(status: reply.status, httpStatus: nil, code: nil, serverTime: nil)
        }
    }

    /// frame(f1, f2, ...) = u32be(len(f1)) || f1 || ...
    private static func unframe(_ data: Data) -> [Data]? {
        let bytes = [UInt8](data)
        var fields: [Data] = []
        var index = 0
        while index < bytes.count {
            guard bytes.count - index >= 4 else { return nil }
            let length = bytes[index ..< index + 4].reduce(0) { $0 << 8 | Int($1) }
            index += 4
            guard bytes.count - index >= length else { return nil }
            fields.append(Data(bytes[index ..< index + length]))
            index += length
        }
        return fields
    }

    private static func u64(_ field: Data) -> UInt64 {
        field.reduce(0) { $0 << 8 | UInt64($1) }
    }
}
