package com.cem.doodleart.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Locale
import java.util.UUID

/** The device key: its SubjectPublicKeyInfo (91 bytes) and an ECDSA P-256 / SHA-256 signer (DER signatures). */
class DeviceKey(val spki: ByteArray, private val privateKey: PrivateKey) {
    fun sign(message: ByteArray): ByteArray = Signature.getInstance("SHA256withECDSA").run {
        initSign(privateKey)
        update(message)
        sign()
    }
}

/**
 * The long-term credential of the secure session: `device_id` (lowercase UUID, kept in the app's preferences) and an
 * EC P-256 key in the Android Keystore that never leaves the device. The id only names the device; the key's
 * signature is the proof.
 */
class DeviceIdentity(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** The lowercase UUID the server stores and every signed message carries. */
    @Synchronized
    fun deviceId(): String {
        prefs.getString(KEY_DEVICE_ID, null)?.let { return it.lowercase(Locale.ROOT) }
        val created = UUID.randomUUID().toString().lowercase(Locale.ROOT)
        check(prefs.edit().putString(KEY_DEVICE_ID, created).commit()) { "device id not stored" }
        return created
    }

    /** The Keystore key, created on first use (a new key also forgets the registration). */
    @Synchronized
    fun key(): DeviceKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val entry = keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
        if (entry != null) {
            return DeviceKey(entry.certificate.publicKey.encoded, entry.privateKey)
        }
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        generator.initialize(
            KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build(),
        )
        val pair = generator.generateKeyPair()
        resetRegistration()
        return DeviceKey(pair.public.encoded, pair.private)
    }

    /** The device key id the server confirmed at registration, null before. */
    val registeredKeyId: String? get() = prefs.getString(KEY_REGISTERED_KEY_ID, null)

    fun markRegistered(keyId: String) {
        prefs.edit().putString(KEY_REGISTERED_KEY_ID, keyId).apply()
    }

    /** Forgets the registration (device unknown to the server): the next session registers again. */
    fun resetRegistration() {
        prefs.edit().remove(KEY_REGISTERED_KEY_ID).apply()
    }

    /** A new device id and a new key (the server bound this id or key to another device). */
    @Synchronized
    fun startOver() {
        runCatching { KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.deleteEntry(KEY_ALIAS) }
        prefs.edit().remove(KEY_DEVICE_ID).remove(KEY_REGISTERED_KEY_ID).commit()
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val PREFS = "envelope.secure_identity"
        const val KEY_ALIAS = "envelope.device_key"
        const val KEY_DEVICE_ID = "device_id"
        const val KEY_REGISTERED_KEY_ID = "registered_key_id"
    }
}
