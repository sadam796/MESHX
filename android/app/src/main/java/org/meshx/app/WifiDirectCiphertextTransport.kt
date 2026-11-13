package org.meshx.app

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.InetAddress

/**
 * Wi-Fi Direct TCP transport for opaque, already-encrypted MESHX ciphertext.
 * The caller must use the correct MLS group to encrypt/authenticate messages.
 * All blocking calls must run off the Android main thread.
 */
internal object WifiDirectCiphertextTransport {
    const val PORT = 8988
    const val MAX_FRAME_BYTES = 1024 * 1024
    private const val CONNECT_TIMEOUT_MS = 15_000
    private const val SOCKET_TIMEOUT_MS = 20_000
    private const val ACCEPT_TIMEOUT_MS = 60_000

    fun writeFrame(output: OutputStream, ciphertext: ByteArray) {
        require(ciphertext.isNotEmpty()) { "MESHX Wi-Fi Direct ciphertext must not be empty." }
        require(ciphertext.size <= MAX_FRAME_BYTES) { "MESHX Wi-Fi Direct ciphertext exceeds 1 MiB." }
        val data = DataOutputStream(output)
        data.writeInt(ciphertext.size)
        data.write(ciphertext)
        data.flush()
    }

    fun readFrame(input: InputStream): ByteArray {
        val data = DataInputStream(input)
        val length = try {
            data.readInt()
        } catch (error: EOFException) {
            throw EOFException("MESHX Wi-Fi Direct peer closed before sending a frame header.")
        }
        require(length in 1..MAX_FRAME_BYTES) {
            "MESHX Wi-Fi Direct frame length is outside the 1-byte to 1-MiB limit."
        }
        return ByteArray(length).also { data.readFully(it) }
    }

    fun openServer(groupOwnerAddress: String): ServerSocket {
        require(groupOwnerAddress.isNotBlank()) { "Wi-Fi Direct group-owner address is unavailable." }
        val localAddress = InetAddress.getByName(groupOwnerAddress)
        return ServerSocket(PORT, 1, localAddress).apply {
            soTimeout = ACCEPT_TIMEOUT_MS
        }
    }

    fun acceptAndReceive(server: ServerSocket): ByteArray {
        val socket = server.accept()
        socket.soTimeout = SOCKET_TIMEOUT_MS
        socket.use {
            return readFrame(it.getInputStream())
        }
    }

    fun connectAndSend(groupOwnerAddress: String, ciphertext: ByteArray) {
        require(groupOwnerAddress.isNotBlank()) { "Wi-Fi Direct group-owner address is unavailable." }
        require(ciphertext.isNotEmpty() && ciphertext.size <= MAX_FRAME_BYTES) {
            "MESHX Wi-Fi Direct ciphertext must be between 1 byte and 1 MiB."
        }
        val socket = Socket()
        socket.connect(
            InetSocketAddress(groupOwnerAddress, PORT),
            CONNECT_TIMEOUT_MS
        )
        socket.soTimeout = SOCKET_TIMEOUT_MS
        socket.use {
            writeFrame(it.getOutputStream(), ciphertext)
        }
    }
}
