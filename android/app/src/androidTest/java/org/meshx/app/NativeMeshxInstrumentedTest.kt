package org.meshx.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class NativeMeshxInstrumentedTest {
    @Test
    fun packagedRustLibraryLoadsAndAnswersJniCall() {
        val status = NativeMeshx.status()
        assertTrue(
            "Expected Rust JNI bridge to load, got: $status",
            status.startsWith("MESHX native bridge loaded; transport not started")
        )
        assertTrue(status.contains("max ciphertext"))
    }
}
