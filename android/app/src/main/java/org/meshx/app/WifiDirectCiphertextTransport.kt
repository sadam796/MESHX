package org.meshx.app

import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import java.util.UUID

/**
 * Wi-Fi Direct TCP transport for opaque, already-encrypted MESHX ciphertext.
 * A receiver acknowledges only after the caller has authenticated and durably saved it.
 * All blocking calls must run off the Android main thread.
 */
internal object WifiDirectCiphertextTransport {
    const val PORT = 8988
    const val MAX_CIPHERTEXT_BYTES = 1024 * 1024
    private const val MESSAGE_ID_BYTES = 16
    private const val MAX_FRAME_BYTES = MESSAGE_ID_BYTES + MAX_CIPHERTEXT_BYTES
    private const val ACK_MAGIC = 0x4D584131 // "MXA1"
    private const val CONNECT_TIMEOUT_MS = 15_000
    private const val SOCKET_TIMEOUT_MS = 20_000
    private const val ACCEPT_TIMEOUT_MS = 60_000

    internal data class IncomingSession(
        val messageId: String,
        val ciphertext: ByteArray,
        private val socket: Socket
    ) : Closeable {
        fun acknowledge() {
            writeAck(socket.getOutputStream(), messageId)
        }

        override fun close() {
            socket.close()
        }
    }

    fun newMessageId(): String = UUID.randomUUID().toString().replace("-", "")

    private fun idBytes(messageId: String): ByteArray {
        require(messageId.matches(Regex("[0-9a-fA-F]{32}"))) {
            "MESHX message ID must be exactly 128-bit hexadecimal."
        }
        return ByteArray(MESSAGE_ID_BYTES) { index ->
            messageId.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    private fun hex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    fun writeMessage(output: OutputStream, messageId: String, ciphertext: ByteArray) {
        require(ciphertext.isNotEmpty() && ciphertext.size <= MAX_CIPHERTEXT_BYTES) {
            "MESHX ciphertext must be between 1 byte and 1 MiB."
        }
        val id = idBytes(messageId)
        val data = DataOutputStream(output)
        data.writeInt(id.size + ciphertext.size)
        data.write(id)
        data.write(ciphertext)
        data.flush()
    }

    fun readMessage(input: InputStream): Pair<String, ByteArray> {
        val data = DataInputStream(input)
        val length = try {
            data.readInt()
        } catch (error: EOFException) {
            throw EOFException("MESHX Wi-Fi Direct peer closed before sending a frame header.")
        }
        require(length in (MESSAGE_ID_BYTES + 1)..MAX_FRAME_BYTES) {
            "MESHX Wi-Fi Direct frame length is outside the message limits."
        }
        val id = ByteArray(MESSAGE_ID_BYTES)
        data.readFully(id)
        val ciphertext = ByteArray(length - MESSAGE_ID_BYTES)
        data.readFully(ciphertext)
        return hex(id) to ciphertext
    }

    private fun writeAck(output: OutputStream, messageId: String) {
        val data = DataOutputStream(output)
        data.writeInt(ACK_MAGIC)
        data.write(idBytes(messageId))
        data.flush()
    }

    fun readAck(input: InputStream, expectedMessageId: String) {
        val data = DataInputStream(input)
        require(data.readInt() == ACK_MAGIC) { "MESHX delivery acknowledgement header is invalid." }
        val receivedId = ByteArray(MESSAGE_ID_BYTES)
        data.readFully(receivedId)
        require(MessageDigest.isEqual(receivedId, idBytes(expectedMessageId))) {
            "MESHX delivery acknowledgement message ID does not match."
        }
    }

    fun openServer(groupOwnerAddress: String): ServerSocket {
        require(groupOwnerAddress.isNotBlank()) { "Wi-Fi Direct group-owner address is unavailable." }
        val localAddress = InetAddress.getByName(groupOwnerAddress)
        return ServerSocket(PORT, 1, localAddress).apply {
            soTimeout = ACCEPT_TIMEOUT_MS
        }
    }

    fun acceptAndReceive(server: ServerSocket): IncomingSession {
        val socket = server.accept()
        try {
            socket.soTimeout = SOCKET_TIMEOUT_MS
            val (messageId, ciphertext) = readMessage(socket.getInputStream())
            return IncomingSession(messageId, ciphertext, socket)
        } catch (error: Exception) {
            socket.close()
            throw error
        }
    }

    fun connectAndSend(groupOwnerAddress: String, messageId: String, ciphertext: ByteArray) {
        require(groupOwnerAddress.isNotBlank()) { "Wi-Fi Direct group-owner address is unavailable." }
        require(ciphertext.isNotEmpty() && ciphertext.size <= MAX_CIPHERTEXT_BYTES) {
            "MESHX ciphertext must be between 1 byte and 1 MiB."
        }
        val socket = Socket()
        socket.connect(InetSocketAddress(groupOwnerAddress, PORT), CONNECT_TIMEOUT_MS)
        socket.soTimeout = SOCKET_TIMEOUT_MS
        socket.use {
            writeMessage(it.getOutputStream(), messageId, ciphertext)
            readAck(it.getInputStream(), messageId)
        }
    }
}
