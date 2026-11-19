package com.cem.doodleart.security

import android.annotation.SuppressLint
import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorManager
import android.media.MediaDrm
import android.media.NotProvisionedException
import android.media.UnsupportedSchemeException
import android.os.Build
import android.provider.Settings
import java.util.UUID

/**
 * Reads what only Java can read reliably (ANDROID_ID, the Widevine device id, the sensor list) and lets the core turn
 * it into the `deviceSignals` JSON: hashes only, the raw values never leave this call. The core adds the hardware
 * values it reads itself (manufacturer, model, ABI, CPU count, RAM, /data size).
 */
object DeviceSignalsCollector {
    private val WIDEVINE: UUID = UUID.fromString("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed")

    /** Blocking (MediaDrm can take a moment): call it off the main thread. */
    fun collect(context: Context): String {
        val (drmId, drmStatus) = widevineId()
        return CoreBridge.deviceSignals(androidId(context), drmId, drmStatus, sensors(context))
    }

    @SuppressLint("HardwareIds")
    private fun androidId(context: Context): String? =
        runCatching { Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID) }.getOrNull()

    /** (id, null) when read, (null, reason) otherwise. */
    private fun widevineId(): Pair<ByteArray?, String?> {
        var drm: MediaDrm? = null
        return try {
            drm = MediaDrm(WIDEVINE)
            drm.getPropertyByteArray(MediaDrm.PROPERTY_DEVICE_UNIQUE_ID) to null
        } catch (_: UnsupportedSchemeException) {
            null to "unsupported"
        } catch (_: NotProvisionedException) {
            null to "not_provisioned"
        } catch (_: Exception) {
            null to "error"
        } finally {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) drm?.close() else @Suppress("DEPRECATION") drm?.release()
        }
    }

    private fun sensors(context: Context): List<SensorInfo> {
        val manager = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager ?: return emptyList()
        return manager.getSensorList(Sensor.TYPE_ALL).map { SensorInfo(it.type, it.vendor.orEmpty(), it.name.orEmpty()) }
    }
}
