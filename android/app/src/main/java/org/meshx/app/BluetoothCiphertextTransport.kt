package org.meshx.app

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothServerSocket
import android.bluetooth.BluetoothSocket
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.util.UUID

/**
 * Nearby RFCOMM transport for already-encrypted MESHX ciphertext.
 * Callers must encrypt/authenticate with MLS before sending. Android 12+
 * BLUETOOTH_CONNECT permission must be granted before socket calls.
 * Run blocking operations off the main thread, e.g. on Dispatchers.IO.
 */
internal object BluetoothCiphertextTransport {
    val SERVICE_UUID: UUID = UUID.fromString("a32f4b10-7c6d-4b20-9f12-4d4553485831")
    const val SERVICE_NAME = "MESHX encrypted nearby"
    const val MAX_FRAME_BYTES = 1024 * 1024

    fun writeFrame(output: OutputStream, ciphertext: ByteArray) {
        require(ciphertext.isNotEmpty()) { "MESHX Bluetooth ciphertext must not be empty." }
        require(ciphertext.size <= MAX_FRAME_BYTES) { "MESHX Bluetooth ciphertext exceeds 1 MiB." }
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
            throw EOFException("MESHX Bluetooth peer closed before sending a frame header.")
        }
        require(length in 1..MAX_FRAME_BYTES) {
            "MESHX Bluetooth frame length is outside the 1-byte to 1-MiB limit."
        }
        return ByteArray(length).also { data.readFully(it) }
    }

    @SuppressLint("MissingPermission")
    fun openServer(adapter: BluetoothAdapter): BluetoothServerSocket {
        check(adapter.isEnabled) { "Turn on Bluetooth before receiving nearby messages." }
        return adapter.listenUsingRfcommWithServiceRecord(SERVICE_NAME, SERVICE_UUID)
    }

    @SuppressLint("MissingPermission")
    fun connectAndSend(device: BluetoothDevice, ciphertext: ByteArray) {
        require(ciphertext.isNotEmpty() && ciphertext.size <= MAX_FRAME_BYTES) {
            "MESHX Bluetooth ciphertext must be between 1 byte and 1 MiB."
        }
        val socket: BluetoothSocket = device.createRfcommSocketToServiceRecord(SERVICE_UUID)
        socket.use {
            it.connect()
            writeFrame(it.outputStream, ciphertext)
        }
    }

    fun acceptAndReceive(server: BluetoothServerSocket): ByteArray {
        val socket = server.accept()
        socket.use { return readFrame(it.inputStream) }
    }
}
