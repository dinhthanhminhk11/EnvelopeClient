package com.cem.doodleart.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.UUID

/**
 * Runs the Kotlin bridge against the host build of the core (target/debug, built by the Gradle task
 * buildRustHostCore). Loading the library registers every native of NativeCore, so a name or signature mismatch with
 * src/jni.rs fails here before any APK is built.
 */
class CoreBridgeHostTest {
    @Before
    fun requireLibrary() {
        assumeTrue("host library not built (cargo build --lib)", NativeCore.isLoaded)
    }

    @Test
    fun initReportsTheEmbeddedServerKeys() {
        val info = CoreBridge.init(apkPath = null)
        assertEquals("debug", info.buildType)
        assertTrue(info.version.isNotEmpty())
        assertTrue("no server key id", info.kids.isNotEmpty())
    }

    @Test
    fun deviceKeyIdIsBase64UrlOfTheSpkiDigest() {
        val spki = newKey().public.encoded
        assertEquals(91, spki.size)
        assertEquals(b64url(sha256(spki)), CoreBridge.deviceKeyId(spki))
    }

    @Test
    fun malformedSpkiIsRefused() {
        val error = runCatching { CoreBridge.deviceKeyId(ByteArray(10)) }.exceptionOrNull()
        assertEquals(CoreStatus.INVALID_ARGUMENT, (error as CoreException).status)
    }

    @Test
    fun registerMessageCarriesItsOwnHash() {
        val spki = newKey().public.encoded
        val message = CoreBridge.registerMessage(nonce(), deviceId(), CoreBridge.deviceKeyId(spki), "android")
        assertArrayEquals(sha256(message.message), message.clientDataHash)
    }

    @Test
    fun handshakeBodyIsProducedOnceAndAbortForgetsTheHandshake() {
        val key = newKey()
        val keyId = CoreBridge.deviceKeyId(key.public.encoded)
        val handshake = CoreBridge.handshakeBegin(deviceId(), keyId, "1.0.0")
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(key.private)
            update(handshake.signatureMessage)
            sign()
        }
        val body = CoreBridge.handshakeBody(handshake.handle, signature).toString(Charsets.UTF_8)
        assertTrue(body, body.startsWith("{") && body.contains(keyId))

        val again = runCatching { CoreBridge.handshakeBody(handshake.handle, signature) }.exceptionOrNull()
        assertEquals(CoreStatus.HANDSHAKE_STATE, (again as CoreException).status)

        CoreBridge.handshakeAbort(handshake.handle)
        val gone = runCatching { CoreBridge.handshakeFinish(handshake.handle, 200, 0, ByteArray(0)) }.exceptionOrNull()
        assertEquals(CoreStatus.UNKNOWN_HANDLE, (gone as CoreException).status)
    }

    @Test
    fun unknownSessionIsRefused() {
        val error = runCatching { CoreBridge.seal(123_456_789L, "GET", "/api/v2/me", null) }.exceptionOrNull()
        assertEquals(CoreStatus.UNKNOWN_HANDLE, (error as CoreException).status)
    }

    @Test
    fun integrityHashGeneratesARequestId() {
        val hash = CoreBridge.integrityHash("POST", "/api/v2/items?page=1", body = "{}".toByteArray())
        assertNotNull(UUID.fromString(hash.requestId))
        assertEquals(43, hash.requestHash.length)
        val same = CoreBridge.integrityHash("POST", "/api/v2/items?page=1", hash.requestId, body = "{}".toByteArray())
        assertEquals(hash, same)
    }

    @Test
    fun deviceSignalsAreHashesOnly() {
        val json = CoreBridge.deviceSignals(
            androidId = "9774d56d682e549c",
            drmId = null,
            drmStatus = "unsupported",
            sensors = listOf(SensorInfo(1, "Vendor", "Accelerometer")),
        )
        assertTrue(json, json.contains("\"androidIdHash\"") && json.contains("\"drmStatus\":\"unsupported\""))
        assertTrue(json, !json.contains("9774d56d682e549c"))
    }

    @Test
    fun riskScanMergesTheAppsOwnFlags() {
        val report = CoreBridge.riskScan(listOf("debugger", "not_a_flag"))
        assertTrue(report.flags.toString(), "debugger" in report.flags)
        assertTrue(report.flags.toString(), "not_a_flag" !in report.flags)
    }

    @Test
    fun frameRoundTrips() {
        val fields = listOf(byteArrayOf(), "abc".toByteArray(), ByteArray(300) { it.toByte() })
        val decoded = CoreBridge.unframe(CoreBridge.frame(fields))!!
        assertEquals(fields.size, decoded.size)
        fields.zip(decoded).forEach { (expected, actual) -> assertArrayEquals(expected, actual) }
    }

    private fun newKey(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun nonce(): String = b64url(ByteArray(24).also(SecureRandom()::nextBytes))

    private fun deviceId(): String = UUID.randomUUID().toString()

    private fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    private fun b64url(data: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(data)
}
