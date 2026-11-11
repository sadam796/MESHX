package org.meshx.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MlsStateVaultInstrumentedTest {
    private val context
        get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun mlsStateIsEncryptedAndSurvivesVaultRecreation() {
        val groupId = "vault-round-trip-" + System.nanoTime()
        val state = ByteArray(4096) { index -> ((index * 31) % 251).toByte() }
        val vault = MlsStateVault(context)

        vault.save(groupId, state)

        val file = vault.fileForTesting(groupId)
        assertTrue("Encrypted MLS snapshot should be persisted", file.isFile)
        val stored = file.readBytes()
        assertTrue("Stored record must use the versioned encrypted format",
            String(stored.copyOfRange(0, "MESHXMLS1:".length), Charsets.US_ASCII) == "MESHXMLS1:")
        assertFalse(
            "Raw serialized MLS state must not appear in the file",
            String(stored, Charsets.ISO_8859_1).contains(String(state, Charsets.ISO_8859_1))
        )
        assertArrayEquals("A fresh vault instance must restore the exact snapshot", state, MlsStateVault(context).load(groupId))

        vault.delete(groupId)
        assertFalse("Deleted MLS state file should no longer exist", file.exists())
    }

    @Test
    fun tamperedMlsStateIsRejectedAndStoredBytesAreNotSilentlyReplaced() {
        val groupId = "vault-tamper-" + System.nanoTime()
        val vault = MlsStateVault(context)
        vault.save(groupId, "sensitive MLS group state".toByteArray(Charsets.UTF_8))

        val file = vault.fileForTesting(groupId)
        val original = file.readBytes()
        val tampered = original.copyOf()
        tampered[tampered.lastIndex] = (tampered.last().toInt() xor 0x01).toByte()
        file.writeBytes(tampered)

        var rejected = false
        try {
            vault.load(groupId)
        } catch (_: IllegalStateException) {
            rejected = true
        }
        assertTrue("AES-GCM authentication must reject a modified snapshot", rejected)
        assertArrayEquals("A failed read must not overwrite or erase the tampered record", tampered, file.readBytes())
        vault.delete(groupId)
    }

    @Test
    fun mlsGroupIdsAreBoundToSeparateEncryptedRecords() {
        val firstGroup = "vault-group-a-" + System.nanoTime()
        val secondGroup = "vault-group-b-" + System.nanoTime()
        val vault = MlsStateVault(context)
        val state = "group A only".toByteArray(Charsets.UTF_8)

        vault.save(firstGroup, state)

        assertArrayEquals(state, vault.load(firstGroup))
        assertTrue("Different group IDs must map to separate records",
            vault.fileForTesting(firstGroup) != vault.fileForTesting(secondGroup))
        assertTrue("The second group must not have a stored snapshot",
            !vault.fileForTesting(secondGroup).exists())
        vault.delete(firstGroup)
    }
}
