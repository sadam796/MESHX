package org.meshx.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException

@RunWith(AndroidJUnit4::class)
class WifiDirectCiphertextTransportInstrumentedTest {
    @Test
    fun ciphertextMessageRoundTripsWithStable128BitId() {
        val id = "0123456789abcdef0123456789abcdef"
        val original = ByteArray(4096) { index -> (index % 251).toByte() }
        val output = ByteArrayOutputStream()
        WifiDirectCiphertextTransport.writeMessage(output, id, original)
        val (receivedId, receivedCiphertext) =
            WifiDirectCiphertextTransport.readMessage(ByteArrayInputStream(output.toByteArray()))
        assertEquals(id, receivedId)
        assertArrayEquals(original, receivedCiphertext)
    }

    @Test
    fun invalidMessageIdsAndEmptyOrOversizedCiphertextAreRejected() {
        assertThrows(IllegalArgumentException::class.java) {
            WifiDirectCiphertextTransport.writeMessage(ByteArrayOutputStream(), "bad-id", byteArrayOf(1))
        }
        assertThrows(IllegalArgumentException::class.java) {
            WifiDirectCiphertextTransport.writeMessage(ByteArrayOutputStream(), "0123456789abcdef0123456789abcdef", byteArrayOf())
        }
        assertThrows(IllegalArgumentException::class.java) {
            WifiDirectCiphertextTransport.writeMessage(
                ByteArrayOutputStream(),
                "0123456789abcdef0123456789abcdef",
                ByteArray(WifiDirectCiphertextTransport.MAX_CIPHERTEXT_BYTES + 1)
            )
        }
    }

    @Test
    fun invalidAndTruncatedMessagesAreRejected() {
        assertThrows(IllegalArgumentException::class.java) {
            WifiDirectCiphertextTransport.readMessage(ByteArrayInputStream(byteArrayOf(0, 0, 0, 0)))
        }
        assertThrows(EOFException::class.java) {
            WifiDirectCiphertextTransport.readMessage(ByteArrayInputStream(byteArrayOf(0, 0, 0, 20, 1, 2)))
        }
    }

    @Test
    fun acknowledgementMustMatchMessageId() {
        val id = "0123456789abcdef0123456789abcdef"
        val output = ByteArrayOutputStream()
        val method = WifiDirectCiphertextTransport::class.java
            .getDeclaredMethod("writeAck", java.io.OutputStream::class.java, String::class.java)
        method.isAccessible = true
        method.invoke(WifiDirectCiphertextTransport, output, id)
        WifiDirectCiphertextTransport.readAck(ByteArrayInputStream(output.toByteArray()), id)
        assertThrows(IllegalArgumentException::class.java) {
            WifiDirectCiphertextTransport.readAck(
                ByteArrayInputStream(output.toByteArray()),
                "fedcba9876543210fedcba9876543210"
            )
        }
    }
}
