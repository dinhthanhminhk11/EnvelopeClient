package com.cem.doodleart.security

/**
 * The raw JNI surface of the Rust core (src/jni.rs).
 *
 * `JNI_OnLoad` binds these natives with `RegisterNatives`, so the class name, the method names and the parameter
 * types must match src/jni.rs exactly: `cargo test` reads this file and fails on any difference.
 *
 * Every `ByteArray` reply is `status (1 byte) || payload`. Use [CoreBridge] for typed calls; this object is only the
 * binding.
 */
object NativeCore {
    const val LIBRARY = "doodleart_core"

    /** True once the library is loaded and its natives are registered. False keeps the app on its plain API. */
    @JvmStatic
    val isLoaded: Boolean = try {
        System.loadLibrary(LIBRARY)
        true
    } catch (_: UnsatisfiedLinkError) {
        false
    }

    @JvmStatic external fun nativeInit(apkPath: ByteArray?): ByteArray?

    @JvmStatic external fun deviceKeyId(spki: ByteArray?): ByteArray?

    @JvmStatic external fun handshakeBegin(
        deviceId: ByteArray?,
        deviceKeyId: ByteArray?,
        appVersion: ByteArray?,
        extraRiskFlags: ByteArray?,
    ): ByteArray?

    @JvmStatic external fun handshakeBody(handshake: Long, deviceSignature: ByteArray?): ByteArray?

    @JvmStatic external fun handshakeFinish(handshake: Long, httpStatus: Int, serverTime: Long, body: ByteArray?): ByteArray?

    @JvmStatic external fun handshakeAbort(handshake: Long): Int

    @JvmStatic external fun sessionSeal(
        session: Long,
        method: ByteArray?,
        pathWithQuery: ByteArray?,
        body: ByteArray?,
    ): ByteArray?

    @JvmStatic external fun sessionOpen(
        session: Long,
        seq: Long,
        httpStatus: Int,
        contentEncoding: ByteArray?,
        sealed: ByteArray?,
    ): ByteArray?

    @JvmStatic external fun sessionResponse(
        session: Long,
        seq: Long,
        httpStatus: Int,
        contentType: ByteArray?,
        contentEncoding: ByteArray?,
        body: ByteArray?,
    ): ByteArray?

    @JvmStatic external fun sessionAbandon(session: Long, seq: Long): Int

    @JvmStatic external fun sessionClose(session: Long): Int

    @JvmStatic external fun integrityHash(
        method: ByteArray?,
        pathWithQuery: ByteArray?,
        requestId: ByteArray?,
        sid: ByteArray?,
        body: ByteArray?,
    ): ByteArray?

    @JvmStatic external fun deviceSignals(
        androidId: ByteArray?,
        drmId: ByteArray?,
        drmStatus: ByteArray?,
        sensors: ByteArray?,
    ): ByteArray?

    @JvmStatic external fun riskScan(extraRiskFlags: ByteArray?): ByteArray?

    @JvmStatic external fun registerMessage(
        nonce: ByteArray?,
        deviceId: ByteArray?,
        deviceKeyId: ByteArray?,
        platform: ByteArray?,
    ): ByteArray?
}
