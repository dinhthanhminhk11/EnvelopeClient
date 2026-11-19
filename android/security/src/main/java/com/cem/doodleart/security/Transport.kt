package com.cem.doodleart.security

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.TreeMap

/** One plain HTTP request as the app built it. [url] is absolute; header names are case-insensitive. */
data class HttpRequest(
    val url: String,
    val method: String = "GET",
    val headers: Map<String, String> = emptyMap(),
    val body: ByteArray? = null,
) {
    fun header(name: String): String? = headers.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value
}

/** One HTTP answer. [headers] keeps the first value of each header. */
data class HttpResponse(
    val status: Int,
    val headers: Map<String, String>,
    val body: ByteArray,
) {
    fun header(name: String): String? = headers.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value
}

/** Sends one request as is. Plug in OkHttp, Ktor... by implementing this; [UrlConnectionTransport] is the default. */
fun interface SecureTransport {
    @Throws(IOException::class)
    fun execute(request: HttpRequest): HttpResponse
}

/** [SecureTransport] over `HttpURLConnection` (no dependency). Blocking: call it off the main thread. */
class UrlConnectionTransport(
    private val connectTimeoutMs: Int = 15_000,
    private val readTimeoutMs: Int = 30_000,
) : SecureTransport {
    override fun execute(request: HttpRequest): HttpResponse {
        val connection = URL(request.url).openConnection() as HttpURLConnection
        try {
            connection.requestMethod = request.method
            connection.connectTimeout = connectTimeoutMs
            connection.readTimeout = readTimeoutMs
            connection.useCaches = false
            connection.instanceFollowRedirects = false
            request.headers.forEach { (name, value) -> connection.setRequestProperty(name, value) }
            val body = request.body
            if (body != null && body.isNotEmpty()) {
                connection.doOutput = true
                connection.setFixedLengthStreamingMode(body.size)
                connection.outputStream.use { it.write(body) }
            }
            val status = connection.responseCode
            val headers = TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER)
            connection.headerFields.forEach { (name, values) ->
                if (name != null && !values.isNullOrEmpty()) headers[name] = values.first()
            }
            val stream: InputStream? = if (status >= 400) connection.errorStream else connection.inputStream
            return HttpResponse(status, headers, stream?.use(::readAll) ?: ByteArray(0))
        } finally {
            connection.disconnect()
        }
    }

    private fun readAll(stream: InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        stream.copyTo(out)
        return out.toByteArray()
    }
}
