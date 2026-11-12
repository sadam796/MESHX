package org.meshx.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MlsContactExchangeInstrumentedTest {
    @Test
    fun twoIndependentKeystoreVaultsJoinAndExchangeEncryptedMessage() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val suffix = System.nanoTime().toString()
        val alice = MlsStateRepository(context)
        val bob = MlsStateRepository(context)
        val aliceGroupId = "alice-group-$suffix"
        val bobKeyPackageId = "bob-key-package-$suffix"
        val bobGroupId = "bob-group-$suffix"

        try {
            alice.createAndSaveGroupState(aliceGroupId, "meshx-alice-$suffix".toByteArray())
            val bobPublicKeyPackage = bob.createAndSaveKeyPackage(
                bobKeyPackageId, "meshx-bob-$suffix".toByteArray()
            )
            val invitation = alice.addContactToGroup(aliceGroupId, bobPublicKeyPackage)
            bob.joinAndSaveInvitedGroup(
                bobKeyPackageId, bobGroupId,
                invitation.welcomeMessage, invitation.ratchetTree
            )

            val message = "MESHX real two-member MLS test".toByteArray(Charsets.UTF_8)
            val ciphertext = alice.encryptAndAdvanceGroupState(aliceGroupId, message)
            val plaintext = bob.decryptAndAdvanceGroupState(bobGroupId, ciphertext)
            assertArrayEquals("Recipient must recover authenticated sender plaintext", message, plaintext)
        } finally {
            alice.delete(aliceGroupId)
            bob.delete(bobKeyPackageId)
            bob.delete(bobGroupId)
        }
    }
}
