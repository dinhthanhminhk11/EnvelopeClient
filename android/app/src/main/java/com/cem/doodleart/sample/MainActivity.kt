package com.cem.doodleart.sample

import android.app.Activity
import android.os.Bundle
import android.util.Base64
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import com.cem.doodleart.security.CoreBridge
import com.cem.doodleart.security.CoreException
import com.cem.doodleart.security.DeviceIdentity
import com.cem.doodleart.security.DeviceSignalsCollector
import com.cem.doodleart.security.HttpRequest
import com.cem.doodleart.security.SecureChannel
import java.security.SecureRandom
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Demo of the core on a device:
 * - "Run local checks" exercises every call that needs no server (init, device key, registration message, handshake
 *   body, integrity hash, risk scan, device signals).
 * - "Send sealed request" goes through [SecureChannel] (register, handshake, seal, open) against a real server.
 */
class MainActivity : Activity() {
    private val worker: ExecutorService = Executors.newSingleThreadExecutor()
    private lateinit var output: TextView
    private lateinit var channel: SecureChannel

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        output = findViewById(R.id.output)
        channel = SecureChannel(this)
        val serverUrl = findViewById<EditText>(R.id.serverUrl)
        val requestPath = findViewById<EditText>(R.id.requestPath)

        findViewById<Button>(R.id.runLocal).setOnClickListener { runInBackground(::localChecks) }
        findViewById<Button>(R.id.sendRequest).setOnClickListener {
            val url = serverUrl.text.toString().trimEnd('/') + "/" + requestPath.text.toString().trimStart('/')
            runInBackground { log -> sealedRequest(url, log) }
        }

        output.text = if (CoreBridge.isAvailable) {
            val info = CoreBridge.init(applicationInfo.sourceDir)
            "core ${info.version} (${info.buildType}), server keys ${info.kids}\n"
        } else {
            "libdoodleart_core.so is not loaded\n"
        }
    }

    override fun onDestroy() {
        worker.shutdownNow()
        super.onDestroy()
    }

    private fun localChecks(log: (String) -> Unit) {
        val identity = DeviceIdentity(this)
        val deviceId = identity.deviceId()
        val key = identity.key()
        val keyId = CoreBridge.deviceKeyId(key.spki)
        log("device id      $deviceId")
        log("device key id  $keyId")

        // The server sends this nonce from POST .../auth/challenge; a random one shows the shape.
        val nonce = Base64.encodeToString(
            ByteArray(24).also(SecureRandom()::nextBytes),
            Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP,
        )
        val registration = CoreBridge.registerMessage(nonce, deviceId, keyId, "android")
        val registrationSignature = key.sign(registration.message)
        log("register msg   ${registration.message.size} bytes, signature ${registrationSignature.size} bytes")

        val handshake = CoreBridge.handshakeBegin(deviceId, keyId, BuildInfo.versionName(this))
        try {
            val body = CoreBridge.handshakeBody(handshake.handle, key.sign(handshake.signatureMessage))
            log("session/start  ${body.toString(Charsets.UTF_8).take(160)}...")
        } finally {
            CoreBridge.handshakeAbort(handshake.handle)
        }

        val hash = CoreBridge.integrityHash("POST", "/api/v2/example?page=1", body = "{}".toByteArray())
        log("integrity      ${hash.requestId} ${hash.requestHash}")

        val risk = CoreBridge.riskScan()
        log("risk flags     ${risk.flags.ifEmpty { listOf("none") }} ${risk.details}")

        log("device signals ${DeviceSignalsCollector.collect(this)}")
    }

    private fun sealedRequest(url: String, log: (String) -> Unit) {
        log("GET $url")
        val request = HttpRequest(
            url = url,
            headers = mapOf(
                "Accept" to "application/json",
                "X-Platform" to "android",
                "X-App-Version" to BuildInfo.versionName(this),
            ),
        )
        val response = channel.send(request)
        log("-> ${response.status}, session trust ${channel.trust}")
        log(response.body.toString(Charsets.UTF_8).take(2000))
    }

    private fun runInBackground(task: ((String) -> Unit) -> Unit) {
        output.append("\n")
        val log = { line: String -> runOnUiThread { output.append(line + "\n") } }
        worker.execute {
            try {
                task(log)
            } catch (error: CoreException) {
                log("core error: ${error.message}")
            } catch (error: Exception) {
                log("${error.javaClass.simpleName}: ${error.message}")
            }
        }
    }
}

private object BuildInfo {
    fun versionName(activity: Activity): String =
        activity.packageManager.getPackageInfo(activity.packageName, 0).versionName ?: "1.0.0"
}
