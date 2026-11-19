package com.cem.doodleart.security

import java.io.ByteArrayOutputStream

/** Status bytes of the core (src/error.rs). 0 is success. */
object CoreStatus {
    const val OK = 0
    const val INVALID_ARGUMENT = 1
    const val UNKNOWN_HANDLE = 2
    const val HANDSHAKE_STATE = 3
    const val BAD_SERVER_RESPONSE = 4
    const val BAD_SERVER_SIGNATURE = 5
    const val SERVER_REJECTED = 6
    const val DECRYPT_FAILED = 7
    const val REPLAYED_RESPONSE = 8
    const val SEQ_EXHAUSTED = 9
    const val SESSION_EXPIRED = 10
    const val LIMIT_REACHED = 11
    const val RNG = 12
    const val INTERNAL = 13
    const val UNSEALED_RESPONSE = 14
}

/**
 * A call the core refused. [status] is a [CoreStatus] value. `SERVER_REJECTED` and `UNSEALED_RESPONSE` also carry the
 * HTTP status and the unauthenticated `meta.code` of the server answer (decimal text, "" when there was none).
 */
class CoreException(
    val status: Int,
    val httpStatus: Int? = null,
    val code: String? = null,
    val serverTime: Long? = null,
) : Exception(buildString {
    append("core status ").append(status)
    httpStatus?.let { append(" http ").append(it) }
    code?.takeIf { it.isNotEmpty() }?.let { append(" code ").append(it) }
}) {
    /** `meta.code` as a number, null when absent. */
    val metaCode: Int? get() = code?.toIntOrNull()
}

/** `nativeInit`: build type of the library, crate version and the server key ids it embeds. */
data class CoreInfo(val buildType: String, val version: String, val kids: List<String>)

/** A handshake in progress: sign [signatureMessage] with the device key, then call [CoreBridge.handshakeBody]. */
class CoreHandshake(val handle: Long, val signatureMessage: ByteArray, val riskFlags: List<String>)

/** An open session. [info] is the server's JSON (`session_ttl_seconds`, `idle_ttl_seconds`, `trust`, ...). */
class CoreSession(val handle: Long, val sid: String, val info: ByteArray)

/** Headers and body of one sealed request. Exactly one of [tag] (bodyless request) and [body] is set. */
class SealedRequest(
    val seq: Long,
    val ts: Long,
    val sid: String,
    val appVersion: String,
    val tag: String?,
    val body: ByteArray,
)

/** What the device key signs at registration, and its SHA-256 (the attestation / Play Integrity request hash). */
class RegisterMessage(val message: ByteArray, val clientDataHash: ByteArray)

/** Integrity hash of one request (`DAPI1`): the request id used and the base64url hash. */
data class IntegrityHash(val requestId: String, val requestHash: String)

/** Result of the core's own risk scan. [details] is empty in release libraries. */
data class RiskReport(val flags: List<String>, val details: List<String>)

/** One entry of `SensorManager.getSensorList(Sensor.TYPE_ALL)`, input of [CoreBridge.deviceSignals]. */
data class SensorInfo(val type: Int, val vendor: String, val name: String)

/**
 * Typed Kotlin API over [NativeCore]. Every function throws [CoreException] when the core refuses the call, or when
 * the library is not loaded (`INTERNAL`). All functions are thread-safe; [handshakeBegin] and [riskScan] are blocking
 * (they scan the process), so never call them on the main thread.
 */
object CoreBridge {
    val isAvailable: Boolean get() = NativeCore.isLoaded

    /** Remembers the APK path (fallback of the APK signature check) and reports the library's build. */
    fun init(apkPath: String?): CoreInfo {
        val fields = framed(call { NativeCore.nativeInit(apkPath?.utf8()) }, 3)
        return CoreInfo(
            buildType = fields[0].text(),
            version = fields[1].text(),
            kids = fields[2].text().split(',').filter(String::isNotEmpty),
        )
    }

    /** base64url(SHA-256(spki)) of an EC P-256 SubjectPublicKeyInfo (91 bytes, `PublicKey.getEncoded()`). */
    fun deviceKeyId(spki: ByteArray): String = raw(call { NativeCore.deviceKeyId(spki) }).text()

    /**
     * The registration message for `POST .../devices/register`. [nonce] is the challenge text from
     * `POST .../auth/challenge`; [deviceId] a lowercase UUID; [platform] `"android"`.
     */
    fun registerMessage(nonce: String, deviceId: String, keyId: String, platform: String): RegisterMessage {
        val fields = framed(
            call { NativeCore.registerMessage(nonce.utf8(), deviceId.utf8(), keyId.utf8(), platform.utf8()) },
            2,
        )
        return RegisterMessage(fields[0], fields[1])
    }

    /** Starts a handshake (runs the risk scan, creates an ephemeral X25519 key). Blocking. */
    fun handshakeBegin(
        deviceId: String,
        keyId: String,
        appVersion: String,
        extraRiskFlags: List<String> = emptyList(),
    ): CoreHandshake {
        val extra = extraRiskFlags.takeIf { it.isNotEmpty() }?.joinToString(",")?.utf8()
        val fields = framed(
            call { NativeCore.handshakeBegin(deviceId.utf8(), keyId.utf8(), appVersion.utf8(), extra) },
            3,
        )
        return CoreHandshake(
            handle = fields[0].u64(),
            signatureMessage = fields[1],
            riskFlags = fields[2].text().split(',').filter(String::isNotEmpty),
        )
    }

    /** JSON body of `POST .../session/start`. [signature] is the DER ECDSA signature of the signature message. */
    fun handshakeBody(handshake: Long, signature: ByteArray): ByteArray =
        raw(call { NativeCore.handshakeBody(handshake, signature) })

    /**
     * Verifies the server answer of `session/start` and opens the session. Consumes the handshake whatever the
     * outcome. [serverTime] is the `X-Server-Time` header in ms, 0 when absent.
     */
    fun handshakeFinish(handshake: Long, httpStatus: Int, serverTime: Long, body: ByteArray): CoreSession {
        val fields = framed(call { NativeCore.handshakeFinish(handshake, httpStatus, serverTime, body) }, 3)
        return CoreSession(handle = fields[0].u64(), sid = fields[1].text(), info = fields[2])
    }

    /** Drops a handshake whose request failed before any answer. */
    fun handshakeAbort(handshake: Long) {
        if (isAvailable) NativeCore.handshakeAbort(handshake)
    }

    /** Seals one request. [pathWithQuery] is the request target exactly as sent (encoded path, `?`, query). */
    fun seal(session: Long, method: String, pathWithQuery: String, body: ByteArray?): SealedRequest {
        val fields = framed(
            call { NativeCore.sessionSeal(session, method.utf8(), pathWithQuery.utf8(), body?.takeIf { it.isNotEmpty() }) },
            6,
        )
        return SealedRequest(
            seq = fields[0].u64(),
            ts = fields[1].u64(),
            sid = fields[2].text(),
            appVersion = fields[3].text(),
            tag = fields[4].text().takeIf(String::isNotEmpty),
            body = fields[5],
        )
    }

    /**
     * The plaintext of the answer to a sealed request (gzip already decoded). An answer that is not sealed throws
     * `UNSEALED_RESPONSE` (never data); one that does not open throws `DECRYPT_FAILED` / `REPLAYED_RESPONSE`.
     */
    fun response(
        session: Long,
        seq: Long,
        httpStatus: Int,
        contentType: String?,
        contentEncoding: String?,
        body: ByteArray,
    ): ByteArray = raw(call {
        NativeCore.sessionResponse(session, seq, httpStatus, contentType?.utf8(), contentEncoding?.utf8(), body)
    })

    /** Forgets a seq whose answer will never be read (transport error). */
    fun abandon(session: Long, seq: Long) {
        if (isAvailable) NativeCore.sessionAbandon(session, seq)
    }

    /** Wipes the session keys. */
    fun close(session: Long) {
        if (isAvailable) NativeCore.sessionClose(session)
    }

    /** `DAPI1` hash of a request. A null [requestId] makes the core generate a UUID v4; a null [sid] means "". */
    fun integrityHash(
        method: String,
        pathWithQuery: String,
        requestId: String? = null,
        sid: String? = null,
        body: ByteArray? = null,
    ): IntegrityHash {
        val fields = framed(
            call { NativeCore.integrityHash(method.utf8(), pathWithQuery.utf8(), requestId?.utf8(), sid?.utf8(), body) },
            2,
        )
        return IntegrityHash(fields[0].text(), fields[1].text())
    }

    /**
     * The `deviceSignals` JSON of the registration. [drmStatus] is the reason the Widevine id could not be read
     * (`unsupported`, `not_provisioned`, `error`) when [drmId] is null. See [DeviceSignalsCollector].
     */
    fun deviceSignals(androidId: String?, drmId: ByteArray?, drmStatus: String?, sensors: List<SensorInfo>): String {
        val encodedSensors = frame(sensors.flatMap { listOf(it.type.toBigEndian(), it.vendor.utf8(), it.name.utf8()) })
        return raw(call {
            NativeCore.deviceSignals(androidId?.utf8(), drmId, drmStatus?.utf8(), encodedSensors)
        }).text()
    }

    /** Frida / hook / root / emulator / debugger / re-signed APK flags of this process. Blocking. */
    fun riskScan(extraRiskFlags: List<String> = emptyList()): RiskReport {
        val extra = extraRiskFlags.takeIf { it.isNotEmpty() }?.joinToString(",")?.utf8()
        val fields = framed(call { NativeCore.riskScan(extra) }, 2)
        val csv = { field: ByteArray -> field.text().split(',').filter(String::isNotEmpty) }
        return RiskReport(flags = csv(fields[0]), details = csv(fields[1]))
    }

    // Reply decoding

    private class Reply(val status: Int, val payload: ByteArray)

    private fun call(native: () -> ByteArray?): Reply {
        if (!isAvailable) return Reply(CoreStatus.INTERNAL, ByteArray(0))
        val bytes = native() ?: return Reply(CoreStatus.INTERNAL, ByteArray(0))
        if (bytes.isEmpty()) return Reply(CoreStatus.INTERNAL, ByteArray(0))
        return Reply(bytes[0].toInt() and 0xff, bytes.copyOfRange(1, bytes.size))
    }

    private fun raw(reply: Reply): ByteArray {
        if (reply.status != CoreStatus.OK) throw error(reply)
        return reply.payload
    }

    private fun framed(reply: Reply, minFields: Int): List<ByteArray> {
        val fields = unframe(raw(reply))
        if (fields == null || fields.size < minFields) throw CoreException(CoreStatus.INTERNAL)
        return fields
    }

    private fun error(reply: Reply): CoreException {
        val fields = unframe(reply.payload).orEmpty()
        return when {
            reply.status == CoreStatus.SERVER_REJECTED && fields.size >= 3 -> CoreException(
                status = reply.status,
                httpStatus = fields[0].u64().toInt(),
                code = fields[1].text(),
                serverTime = fields[2].u64().takeIf { it != 0L },
            )

            reply.status == CoreStatus.UNSEALED_RESPONSE && fields.size >= 2 -> CoreException(
                status = reply.status,
                httpStatus = fields[0].u64().toInt(),
                code = fields[1].text(),
            )

            else -> CoreException(reply.status)
        }
    }

    /** `frame(f1, f2, ...)` = `u32be(len(f1)) || f1 || ...` */
    internal fun frame(fields: List<ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        for (field in fields) {
            out.write(field.size.toBigEndian())
            out.write(field)
        }
        return out.toByteArray()
    }

    /** Inverse of [frame]; null when the lengths do not add up exactly. */
    internal fun unframe(data: ByteArray): List<ByteArray>? {
        val fields = ArrayList<ByteArray>()
        var index = 0
        while (index < data.size) {
            if (data.size - index < 4) return null
            var length = 0L
            repeat(4) { length = (length shl 8) or (data[index + it].toLong() and 0xff) }
            index += 4
            if (data.size - index < length) return null
            fields += data.copyOfRange(index, index + length.toInt())
            index += length.toInt()
        }
        return fields
    }

    private fun ByteArray.u64(): Long = fold(0L) { acc, byte -> (acc shl 8) or (byte.toLong() and 0xff) }

    private fun ByteArray.text(): String = toString(Charsets.UTF_8)

    private fun String.utf8(): ByteArray = toByteArray(Charsets.UTF_8)

    private fun Int.toBigEndian(): ByteArray =
        byteArrayOf((this ushr 24).toByte(), (this ushr 16).toByte(), (this ushr 8).toByte(), toByte())
}
