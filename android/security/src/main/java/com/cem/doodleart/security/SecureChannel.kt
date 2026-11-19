package com.cem.doodleart.security

import android.content.Context
import android.os.Build
import android.os.SystemClock
import android.util.Base64
import android.util.Log
import org.json.JSONObject
import java.net.URI
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Platform attestation hooks (for example Play Integrity). The default sends none; a server that requires attestation
 * then gives the session a lower trust.
 */
interface IntegrityProvider {
    /** `attestation` of the registration. [requestHash] is SHA-256 of the registration message. */
    fun registrationToken(requestHash: ByteArray): String? = null

    /** `X-Integrity-Token` of `session/start`. [signatureMessage] is what the device key signed. */
    fun handshakeToken(signatureMessage: ByteArray): String? = null

    companion object {
        val NONE: IntegrityProvider = object : IntegrityProvider {}
    }
}

sealed class SecureChannelException(message: String) : Exception(message) {
    /** No session can be opened or used right now (server without the secure routes, unknown server key, ...). */
    class Unavailable(reason: String) : SecureChannelException(reason)

    /** An answer that must not be trusted (tampered, replayed): neither data nor a reason to fall back. */
    class Untrusted(reason: String) : SecureChannelException(reason)

    /** The server requires a newer app (426). Show the update screen. */
    class UpgradeRequired(val minVersion: String?, val storeUrl: String?) :
        SecureChannelException("upgrade required (minimum ${minVersion ?: "?"})")

    /** The server is under maintenance (503). Show the maintenance screen and retry later. */
    class Maintenance(val text: String?, val until: String?) :
        SecureChannelException("maintenance" + (text?.let { ": $it" } ?: ""))
}

/**
 * The secure session on top of the core: registers the device key once, opens a session (`POST <prefix>/session/start`),
 * then seals every request and opens every answer. Kotlin port of swift/Sources/SecureChannel.swift.
 *
 * [send] is blocking and thread-safe: call it from a background thread. Concurrent requests share one session; only
 * one handshake runs at a time.
 */
class SecureChannel(
    context: Context,
    private val transport: SecureTransport = UrlConnectionTransport(),
    private val integrity: IntegrityProvider = IntegrityProvider.NONE,
    /** Adds the `device_signals` object (hashes from [DeviceSignalsCollector]) to the registration body. */
    private val includeDeviceSignals: Boolean = false,
    /** Prefix of the protocol routes (handshake included), relative to the server origin. */
    private val apiPrefix: String = "api/v2",
) {
    private val appContext = context.applicationContext
    private val identity = DeviceIdentity(appContext)

    private val lock = Any()
    private val openLock = ReentrantLock()
    private var session: OpenSession? = null
    private var pausedUntil = 0L

    /** Requests sealed and not yet answered, per core session handle. */
    private val inFlight = HashMap<Long, Int>()

    /** Dropped sessions, closed in the core only once their last request is answered. */
    private val retired = HashSet<Long>()

    private class OpenSession(val core: CoreSession, val idleTtlMs: Long, val trust: String, @Volatile var lastUsed: Long) {
        val isIdle: Boolean get() = SystemClock.elapsedRealtime() - lastUsed > idleTtlMs - IDLE_MARGIN_MS
    }

    /** Trust the server gave the open session (`trusted`, `limited`, ...), null without a session. */
    val trust: String? get() = synchronized(lock) { session?.trust }

    /**
     * Seals [plain], sends it and opens the answer. Returns the HTTP answer with the plaintext body (`{meta, data}` of
     * the route); the status is the route's own (403, 409... are sealed too).
     */
    fun send(plain: HttpRequest): HttpResponse {
        synchronized(lock) {
            if (SystemClock.elapsedRealtime() < pausedUntil) {
                throw SecureChannelException.Unavailable("paused after an earlier failure")
            }
        }
        try {
            return sendSealed(plain, retry = true)
        } catch (error: SecureChannelException.Unavailable) {
            pause(error.message.orEmpty())
            throw error
        } catch (error: CoreException) {
            pause(error.message.orEmpty())
            throw SecureChannelException.Unavailable(error.message.orEmpty())
        }
    }

    /** Forgets the session (after a login, a logout, an account switch): the next request opens a new one. */
    fun reset() {
        synchronized(lock) {
            session?.let { retire(it.core.handle) }
            session = null
        }
    }

    // Sealed requests

    private fun sendSealed(plain: HttpRequest, retry: Boolean): HttpResponse {
        val target = requestTarget(plain.url) ?: throw SecureChannelException.Unavailable("no request target")
        if (isSessionEnd(target)) return endSession(plain, target)
        val current = currentSession(plain)
        val handle = current.core.handle
        begin(handle)
        try {
            val sealed = try {
                seal(plain, target, current)
            } catch (error: CoreException) {
                if (error.status !in SESSION_GONE) throw error
                drop(current)
                if (!retry) throw SecureChannelException.Unavailable(error.message.orEmpty())
                return sendSealed(plain, retry = false)
            }
            val response = exchange(plain, sealed, current)
            val plaintext = try {
                openAnswer(response, sealed.seq, current)
            } catch (error: CoreException) {
                if (error.status != CoreStatus.UNSEALED_RESPONSE) {
                    throw SecureChannelException.Untrusted(error.message.orEmpty())
                }
                // Refused before the route ran: only the code decides what to do, never the body.
                when (error.metaCode) {
                    CODE_SESSION_UNKNOWN, CODE_REPLAY_REFUSED -> {
                        drop(current)
                        if (!retry) throw SecureChannelException.Unavailable(error.message.orEmpty())
                        return sendSealed(plain, retry = false)
                    }

                    else -> throw SecureChannelException.Unavailable(error.message.orEmpty())
                }
            }
            touch(current)
            gateError(response.status, plaintext, minVersionHeader = null)?.let { throw it }
            return response.copy(body = plaintext)
        } finally {
            end(handle)
        }
    }

    /**
     * `POST .../session/end` never opens a session only to end it. Without a live session, or when the server has
     * forgotten it, the answer is built here. After a successful end the session is dropped.
     */
    private fun endSession(plain: HttpRequest, target: String): HttpResponse {
        val current = synchronized(lock) {
            val live = session
            if (live != null && live.isIdle) drop(live)
            live?.takeUnless { it.isIdle }
        } ?: return sessionEnded("No session to end")
        val handle = current.core.handle
        begin(handle)
        try {
            val sealed = try {
                seal(plain, target, current)
            } catch (error: CoreException) {
                if (error.status !in SESSION_GONE) throw error
                drop(current)
                return sessionEnded("Session already ended")
            }
            val response = exchange(plain, sealed, current)
            val plaintext = try {
                openAnswer(response, sealed.seq, current)
            } catch (error: CoreException) {
                if (error.status != CoreStatus.UNSEALED_RESPONSE) {
                    throw SecureChannelException.Untrusted(error.message.orEmpty())
                }
                return when (error.metaCode) {
                    CODE_SESSION_UNKNOWN -> {
                        drop(current)
                        sessionEnded("Session already ended")
                    }

                    CODE_REPLAY_REFUSED -> {
                        drop(current)
                        sessionEnded("Session dropped on this device")
                    }

                    else -> throw SecureChannelException.Unavailable(error.message.orEmpty())
                }
            }
            if (response.status == 200) drop(current) else touch(current)
            return response.copy(body = plaintext)
        } finally {
            end(handle)
        }
    }

    /** Sends a sealed request; a transport error forgets its seq in the core. */
    private fun exchange(plain: HttpRequest, sealed: SealedRequest, current: OpenSession): HttpResponse =
        try {
            transport.execute(sealedRequest(plain, sealed))
        } catch (error: Exception) {
            CoreBridge.abandon(current.core.handle, sealed.seq)
            throw error
        }

    private fun seal(plain: HttpRequest, target: String, current: OpenSession): SealedRequest =
        CoreBridge.seal(current.core.handle, plain.method.uppercase(Locale.ROOT), target, plain.body)

    /** [plain] with the session headers and the sealed body (or the tag of a bodyless request). */
    private fun sealedRequest(plain: HttpRequest, sealed: SealedRequest): HttpRequest {
        val headers = plain.headers.filterKeys { name -> SEALED_STRIPPED_HEADERS.none { it.equals(name, ignoreCase = true) } }
            .toMutableMap()
        headers["X-Tx-Session"] = sealed.sid
        headers["X-Tx-Seq"] = sealed.seq.toString()
        headers["X-Tx-Ts"] = sealed.ts.toString()
        headers["X-App-Version"] = sealed.appVersion
        val tag = sealed.tag
        return if (tag != null) {
            headers["X-Tx-Tag"] = tag
            plain.copy(headers = headers, body = null)
        } else {
            headers["Content-Type"] = SEALED_CONTENT_TYPE
            plain.copy(headers = headers, body = sealed.body)
        }
    }

    private fun openAnswer(response: HttpResponse, seq: Long, current: OpenSession): ByteArray =
        CoreBridge.response(
            session = current.core.handle,
            seq = seq,
            httpStatus = response.status,
            contentType = response.header("Content-Type"),
            contentEncoding = response.header("X-Tx-Encoding"),
            body = response.body,
        )

    private fun isSessionEnd(target: String): Boolean {
        val path = target.substringBefore('?')
        return path.endsWith("/$apiPrefix/session/end") || path.endsWith("/api/v1/session/end")
    }

    // Session bookkeeping

    private fun currentSession(plain: HttpRequest): OpenSession {
        synchronized(lock) {
            session?.let {
                if (!it.isIdle) return it
                drop(it)
            }
        }
        openLock.withLock {
            synchronized(lock) {
                // Another thread may have opened one while this one waited.
                session?.let { if (!it.isIdle) return it }
                if (SystemClock.elapsedRealtime() < pausedUntil) {
                    throw SecureChannelException.Unavailable("paused after an earlier failure")
                }
            }
            val opened = open(plain)
            synchronized(lock) { session = opened }
            return opened
        }
    }

    private fun drop(dropped: OpenSession) {
        synchronized(lock) {
            if (session?.core?.handle == dropped.core.handle) session = null
            retire(dropped.core.handle)
        }
    }

    /** Closes a dropped session in the core now, or after its last running request. */
    private fun retire(handle: Long) {
        synchronized(lock) {
            if ((inFlight[handle] ?: 0) == 0) {
                CoreBridge.close(handle)
            } else {
                retired.add(handle)
            }
        }
    }

    private fun begin(handle: Long) {
        synchronized(lock) {
            inFlight[handle] = (inFlight[handle] ?: 0) + 1
        }
    }

    private fun end(handle: Long) {
        synchronized(lock) {
            val left = (inFlight[handle] ?: 1) - 1
            if (left > 0) {
                inFlight[handle] = left
            } else {
                inFlight.remove(handle)
                if (retired.remove(handle)) CoreBridge.close(handle)
            }
        }
    }

    private fun touch(used: OpenSession) {
        used.lastUsed = SystemClock.elapsedRealtime()
    }

    private fun pause(reason: String) {
        synchronized(lock) { pausedUntil = SystemClock.elapsedRealtime() + PAUSE_MS }
        Log.w(TAG, "secure channel unavailable ($reason): paused for ${PAUSE_MS / 60_000} min")
    }

    // Opening a session

    private fun open(plain: HttpRequest): OpenSession {
        val origin = origin(plain.url) ?: throw SecureChannelException.Unavailable("no server origin")
        val context = RequestContext(origin, baseHeaders(plain.headers))
        val appVersion = plain.header("X-App-Version").orEmpty()
        for (attempt in 0 until 2) {
            val deviceId: String
            val key: DeviceKey
            try {
                deviceId = identity.deviceId()
                key = identity.key()
            } catch (error: Exception) {
                throw SecureChannelException.Unavailable("device identity: ${error.message}")
            }
            val keyId = CoreBridge.deviceKeyId(key.spki)
            if (identity.registeredKeyId != keyId) {
                val registered = register(deviceId, key, keyId, appVersion, context)
                // A new device id and key were made (device conflict): register them.
                if (!registered && attempt == 0) continue
            }
            try {
                return handshake(deviceId, key, keyId, appVersion, context)
            } catch (error: CoreException) {
                if (error.status != CoreStatus.SERVER_REJECTED) throw error
                when (error.metaCode) {
                    CODE_DEVICE_KEY_UNKNOWN -> {
                        if (attempt != 0) throw SecureChannelException.Unavailable("handshake refused: ${error.message}")
                        // The server does not know this key (account deleted, database reset): register again.
                        identity.resetRegistration()
                        continue
                    }

                    // Clock fixed from X-Server-Time, or a client key already used: one more handshake, fresh key.
                    CODE_CLOCK_SKEW, CODE_REPLAY_REFUSED -> return handshake(deviceId, key, keyId, appVersion, context)

                    else -> throw SecureChannelException.Unavailable("handshake refused: ${error.message}")
                }
            }
        }
        throw SecureChannelException.Unavailable("no session after a new registration")
    }

    /** `auth/challenge` then `devices/register`. False after a conflict that made a new device identity. */
    private fun register(deviceId: String, key: DeviceKey, keyId: String, appVersion: String, context: RequestContext): Boolean {
        for (round in 1..2) {
            val challenge = context.postJson("$apiPrefix/auth/challenge", JSONObject())
            val nonce = challenge.data?.optString("nonce").orEmpty()
            if (challenge.status != 200 || nonce.isEmpty()) {
                throw SecureChannelException.Unavailable("challenge answered ${challenge.status} ${challenge.code ?: ""}")
            }
            val message = CoreBridge.registerMessage(nonce, deviceId, keyId, PLATFORM)
            val signature = try {
                key.sign(message.message)
            } catch (error: Exception) {
                throw SecureChannelException.Unavailable("device key cannot sign: ${error.message}")
            }
            val body = JSONObject()
                .put("nonce", nonce)
                .put("device", deviceInfo(deviceId, appVersion))
                .put("device_public_key", base64Url(key.spki))
                .put("signature", base64Url(signature))
            integrity.registrationToken(message.clientDataHash)?.let { body.put("attestation", it) }
            if (includeDeviceSignals) {
                runCatching { JSONObject(DeviceSignalsCollector.collect(appContext)) }
                    .onSuccess { body.put("device_signals", it) }
            }
            val reply = context.postJson("$apiPrefix/devices/register", body)
            when {
                reply.status == 200 -> {
                    identity.markRegistered(keyId)
                    Log.i(TAG, "device registered, trust ${reply.data?.optString("trust") ?: "?"}, device ${deviceId.take(8)}")
                    return true
                }

                // Nonce expired or already used: a new challenge.
                reply.status == 400 && reply.code == CODE_NONCE_INVALID -> continue

                // This device id or key belongs to another row: start over with a new identity.
                reply.status == 409 && reply.code == CODE_DEVICE_CONFLICT -> {
                    identity.startOver()
                    return false
                }

                else -> throw SecureChannelException.Unavailable("register answered ${reply.status} ${reply.code ?: ""}")
            }
        }
        throw SecureChannelException.Unavailable("register: no valid challenge")
    }

    private fun handshake(deviceId: String, key: DeviceKey, keyId: String, appVersion: String, context: RequestContext): OpenSession {
        val begun = CoreBridge.handshakeBegin(deviceId, keyId, appVersion)
        try {
            val signature = try {
                key.sign(begun.signatureMessage)
            } catch (error: Exception) {
                throw SecureChannelException.Unavailable("device key cannot sign: ${error.message}")
            }
            val body = CoreBridge.handshakeBody(begun.handle, signature)
            val headers = mutableMapOf("Content-Type" to "application/json")
            integrity.handshakeToken(begun.signatureMessage)?.let { headers["X-Integrity-Token"] = it }
            val response = context.send("$apiPrefix/session/start", body, headers)
            gateError(response.status, response.body, response.header("X-Min-App-Version"))?.let { throw it }
            val serverTime = response.header("X-Server-Time")?.toLongOrNull() ?: 0L
            val core = CoreBridge.handshakeFinish(begun.handle, response.status, serverTime, response.body)
            val info = runCatching { JSONObject(core.info.toString(Charsets.UTF_8)) }.getOrNull()
            val idleSeconds = info?.optLong("idle_ttl_seconds", DEFAULT_IDLE_SECONDS) ?: DEFAULT_IDLE_SECONDS
            val trust = info?.optString("trust", "?") ?: "?"
            Log.i(TAG, "session open, trust $trust, device ${deviceId.take(8)}, risk flags ${begun.riskFlags}")
            return OpenSession(core, idleSeconds * 1000, trust, SystemClock.elapsedRealtime())
        } catch (error: Throwable) {
            // Already consumed when finish ran; otherwise drop the pending handshake and its ephemeral key.
            CoreBridge.handshakeAbort(begun.handle)
            throw error
        }
    }

    // Helpers

    private class JsonReply(val status: Int, val code: Int?, val data: JSONObject?)

    /** The plain JSON exchanges of the registration and the handshake (no session exists yet). */
    private inner class RequestContext(val origin: String, val headers: Map<String, String>) {
        fun send(path: String, body: ByteArray, extra: Map<String, String>): HttpResponse =
            transport.execute(HttpRequest("$origin/$path", "POST", headers + extra, body))

        fun postJson(path: String, json: JSONObject): JsonReply {
            val response = send(path, json.toString().toByteArray(), mapOf("Content-Type" to "application/json"))
            val envelope = parseJson(response.body)
            return JsonReply(response.status, envelope?.metaCode(), envelope?.optJSONObject("data"))
        }
    }

    /** The version gate (426) and the maintenance switch (503). */
    private fun gateError(status: Int, body: ByteArray, minVersionHeader: String?): SecureChannelException? {
        if (status != 426 && status != 503) return null
        val envelope = parseJson(body)
        val code = envelope?.metaCode()
        val data = envelope?.optJSONObject("data")
        return when {
            status == 426 && code == CODE_UPGRADE_REQUIRED -> SecureChannelException.UpgradeRequired(
                minVersion = data?.stringOrNull("min_app_version") ?: minVersionHeader,
                storeUrl = data?.stringOrNull("store_url"),
            )

            status == 503 && code == CODE_MAINTENANCE -> SecureChannelException.Maintenance(
                text = data?.stringOrNull("message"),
                until = data?.stringOrNull("until"),
            )

            else -> null
        }
    }

    /** `device` of the registration body. */
    private fun deviceInfo(deviceId: String, appVersion: String): JSONObject = JSONObject().apply {
        put("device_id", deviceId)
        put("platform", PLATFORM)
        put("app_version", appVersion)
        put("os_version", Build.VERSION.RELEASE.orEmpty())
        put("device_model", Build.MODEL.orEmpty())
        put("locale", Locale.getDefault().toString().take(16))
        put("timezone", TimeZone.getDefault().id)
        buildNumber()?.let { put("build_number", it) }
    }

    private fun buildNumber(): String? = runCatching {
        val info = appContext.packageManager.getPackageInfo(appContext.packageName, 0)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) info.longVersionCode.toString()
        else @Suppress("DEPRECATION") info.versionCode.toString()
    }.getOrNull()

    /** The session/end answer built on this device: the same `{meta, data}` as a successful end. */
    private fun sessionEnded(message: String): HttpResponse {
        val body = JSONObject()
            .put("meta", JSONObject().put("code", 200).put("message", message))
            .put("data", JSONObject())
        return HttpResponse(200, mapOf("Content-Type" to "application/json"), body.toString().toByteArray())
    }

    private companion object {
        const val TAG = "SecureChannel"
        const val PLATFORM = "android"
        const val SEALED_CONTENT_TYPE = "application/vnd.doodle.sealed"

        /** After `Unavailable`, the channel is not used for this long (no handshake storm). */
        const val PAUSE_MS = 10 * 60 * 1000L

        /** A session idle longer than idle TTL minus this margin is renewed before use. */
        const val IDLE_MARGIN_MS = 60 * 1000L
        const val DEFAULT_IDLE_SECONDS = 2 * 3600L

        // meta.code values of the reference server.
        const val CODE_NONCE_INVALID = 40001003
        const val CODE_CLOCK_SKEW = 40001004
        const val CODE_DEVICE_KEY_UNKNOWN = 40101009
        const val CODE_SESSION_UNKNOWN = 40101010
        const val CODE_DEVICE_CONFLICT = 40901003
        const val CODE_REPLAY_REFUSED = 40901004
        const val CODE_UPGRADE_REQUIRED = 42601001
        const val CODE_MAINTENANCE = 50317001

        /** Core statuses of a seal meaning the session is over on this device. */
        val SESSION_GONE = setOf(CoreStatus.SESSION_EXPIRED, CoreStatus.SEQ_EXHAUSTED, CoreStatus.UNKNOWN_HANDLE)

        /** Headers of the plain request the sealed one never carries (the session authenticates it). */
        val SEALED_STRIPPED_HEADERS = listOf(
            "Authorization", "If-None-Match", "If-Modified-Since", "Content-Type", "Content-Length",
            "X-App-Version", "X-Tx-Session", "X-Tx-Seq", "X-Tx-Ts", "X-Tx-Tag",
        )

        /** Headers of one request only, not copied to the registration and handshake requests. */
        val PER_REQUEST_HEADERS = listOf("Authorization", "If-None-Match", "If-Modified-Since", "Content-Type", "Content-Length")

        /** The raw request target the server authenticates: encoded path, then `?` and the query as sent. */
        fun requestTarget(url: String): String? = runCatching {
            val uri = URI(url)
            val path = uri.rawPath?.takeIf { it.isNotEmpty() } ?: "/"
            path + (uri.rawQuery?.let { "?$it" } ?: "")
        }.getOrNull()

        fun origin(url: String): String? = runCatching {
            val uri = URI(url)
            if (uri.scheme == null || uri.rawAuthority == null) null else "${uri.scheme}://${uri.rawAuthority}"
        }.getOrNull()

        fun baseHeaders(headers: Map<String, String>): Map<String, String> =
            headers.filterKeys { name -> PER_REQUEST_HEADERS.none { it.equals(name, ignoreCase = true) } }

        fun base64Url(bytes: ByteArray): String =
            Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

        fun parseJson(body: ByteArray): JSONObject? = runCatching { JSONObject(body.toString(Charsets.UTF_8)) }.getOrNull()

        fun JSONObject.metaCode(): Int? = optJSONObject("meta")?.takeIf { it.has("code") }?.optInt("code")

        fun JSONObject.stringOrNull(name: String): String? = if (has(name) && !isNull(name)) optString(name) else null
    }
}
