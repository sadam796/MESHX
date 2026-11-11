package org.meshx.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class NativeMeshxInstrumentedTest {
    @Test
    fun packagedRustLibraryDerivesStableTransportIdentityAndStarts() {
        val privateIdentity = NativeMeshx.generateIdentity()
        assertTrue("Native identity must not be empty", privateIdentity.isNotEmpty())

        val publicKey = NativeMeshx.transportPublicKey(privateIdentity)
        assertTrue("Transport public key must not be empty", publicKey.isNotEmpty())

        val peerId = NativeMeshx.transportPeerId(publicKey)
        assertTrue("Expected an Ed25519 libp2p Peer ID, got: $peerId", peerId.startsWith("12D3Koo"))

        assertArrayEquals(publicKey, NativeMeshx.transportPublicKey(privateIdentity))
        assertTrue(
            "Expected Rust JNI bridge to start, got: ${NativeMeshx.start(privateIdentity)}",
            NativeMeshx.start(privateIdentity).let {
                it.startsWith("MESHX libp2p swarm starting") ||
                    it.contains("MESHX libp2p TCP listener active")
            }
        )
    }
}
