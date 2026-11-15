package org.meshx.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

@RunWith(AndroidJUnit4::class)
class RecoveryIdentityInstrumentedTest {
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    @Test
    fun sameRecoveryPhraseRestoresSameTransportAndSigningIdentity() {
        val seed = Bip39Recovery.toSeed(phrase)
        try {
            val transportA = NativeMeshx.deriveRecoveryTransportIdentity(seed)
            val transportB = NativeMeshx.deriveRecoveryTransportIdentity(seed)
            val signingPrivateA = NativeMeshx.deriveRecoverySigningPrivateKey(seed)
            val signingPrivateB = NativeMeshx.deriveRecoverySigningPrivateKey(seed)
            val signingPublicA = NativeMeshx.deriveRecoverySigningPublicKey(seed)
            val signingPublicB = NativeMeshx.deriveRecoverySigningPublicKey(seed)

            assertArrayEquals(transportA, transportB)
            assertArrayEquals(signingPrivateA, signingPrivateB)
            assertArrayEquals(signingPublicA, signingPublicB)

            val peerA = NativeMeshx.transportPeerId(NativeMeshx.transportPublicKey(transportA))
            val peerB = NativeMeshx.transportPeerId(NativeMeshx.transportPublicKey(transportB))
            assertEquals(peerA, peerB)

            val privateKey = KeyFactory.getInstance("EC")
                .generatePrivate(PKCS8EncodedKeySpec(signingPrivateA))
            val publicKey = KeyFactory.getInstance("EC")
                .generatePublic(X509EncodedKeySpec(signingPublicA))
            val message = "MESHX recovery identity proof".toByteArray(Charsets.UTF_8)
            val signer = Signature.getInstance("SHA256withECDSA")
            signer.initSign(privateKey)
            signer.update(message)
            val signature = signer.sign()
            val verifier = Signature.getInstance("SHA256withECDSA")
            verifier.initVerify(publicKey)
            verifier.update(message)
            assertTrue(verifier.verify(signature))

            transportA.fill(0)
            transportB.fill(0)
            signingPrivateA.fill(0)
            signingPrivateB.fill(0)
            signingPublicA.fill(0)
            signingPublicB.fill(0)
        } finally {
            seed.fill(0)
        }
    }

    @Test
    fun differentRecoveryPhraseProducesDifferentIdentity() {
        val seedA = Bip39Recovery.toSeed(phrase)
        val seedB = Bip39Recovery.toSeed(
            "legal winner thank year wave sausage worth useful legal winner thank yellow"
        )
        try {
            val transportA = NativeMeshx.deriveRecoveryTransportIdentity(seedA)
            val transportB = NativeMeshx.deriveRecoveryTransportIdentity(seedB)
            val peerA = NativeMeshx.transportPeerId(NativeMeshx.transportPublicKey(transportA))
            val peerB = NativeMeshx.transportPeerId(NativeMeshx.transportPublicKey(transportB))
            assertFalse(peerA == peerB)

            val publicA = NativeMeshx.deriveRecoverySigningPublicKey(seedA)
            val publicB = NativeMeshx.deriveRecoverySigningPublicKey(seedB)
            assertFalse(publicA.contentEquals(publicB))

            transportA.fill(0)
            transportB.fill(0)
            publicA.fill(0)
            publicB.fill(0)
        } finally {
            seedA.fill(0)
            seedB.fill(0)
        }
    }
}
