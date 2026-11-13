package org.meshx.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException

@RunWith(AndroidJUnit4::class)
class WifiDirectCiphertextTransportInstrumentedTest {
    @Test
    fun ciphertextFrameRoundTripsWithLengthPrefix() {
        val original = ByteArray(4096) { index -> (index % 251).toByte() }
        val output = ByteArrayOutputStream()
        WifiDirectCiphertextTransport.writeFrame(output, original)
        assertArrayEquals(
            original,
            WifiDirectCiphertextTransport.readFrame(ByteArrayInputStream(output.toByteArray()))
        )
    }

    @Test
    fun emptyAndOversizedCiphertextAreRejectedBeforeWrite() {
        assertThrows(IllegalArgumentException::class.java) {
            WifiDirectCiphertextTransport.writeFrame(ByteArrayOutputStream(), byteArrayOf())
        }
        assertThrows(IllegalArgumentException::class.java) {
            WifiDirectCiphertextTransport.writeFrame(
                ByteArrayOutputStream(),
                ByteArray(WifiDirectCiphertextTransport.MAX_FRAME_BYTES + 1)
            )
        }
    }

    @Test
    fun invalidAndTruncatedFramesAreRejected() {
        assertThrows(IllegalArgumentException::class.java) {
            WifiDirectCiphertextTransport.readFrame(ByteArrayInputStream(byteArrayOf(0, 0, 0, 0)))
        }
        assertThrows(EOFException::class.java) {
            WifiDirectCiphertextTransport.readFrame(ByteArrayInputStream(byteArrayOf(0, 0, 0, 4, 1, 2)))
        }
    }
}
