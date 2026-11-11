package org.meshx.app

import android.content.Context
import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MlsStateVaultInstrumentedTest {
    private val context: Context
        get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun mlsStateIsEncryptedAndSurvivesVaultRecreation() {
        val groupId = "vault-round-trip-" + System.nanoTime()
        val state = ByteArray(4096) { index -> ((index * 31) % 251).toByte() }
        val vault = MlsStateVault(context)

        vault.save(groupId, state)

        val preferences = context.getSharedPreferences(
            "meshx_mls_encrypted_state_v1",
            Context.MODE_PRIVATE
        )
        val stored = preferences.getString(vault.storageKeyForTesting(groupId), null)
        assertNotNull("Encrypted MLS record should be persisted", stored)
        val storedValue = stored ?: error("Encrypted MLS record missing")
        assertTrue("Stored record must use the versioned encrypted format", storedValue.startsWith("MESHXMLS1:"))
        assertFalse(
            "Raw serialized MLS state must not appear in preferences",
            storedValue.contains(Base64.encodeToString(state, Base64.NO_WRAP))
        )
        assertArrayEquals("A fresh vault instance must restore the exact snapshot", state, MlsStateVault(context).load(groupId))

        vault.delete(groupId)
        assertNull("Deleted MLS state should no longer be present", vault.load(groupId))
    }

    @Test
    fun tamperedMlsStateIsRejectedAndStoredBytesAreNotSilentlyReplaced() {
        val groupId = "vault-tamper-" + System.nanoTime()
        val vault = MlsStateVault(context)
        vault.save(groupId, "sensitive MLS group state".toByteArray(Charsets.UTF_8))

        val preferences = context.getSharedPreferences(
            "meshx_mls_encrypted_state_v1",
            Context.MODE_PRIVATE
        )
        val key = vault.storageKeyForTesting(groupId)
        val original = preferences.getString(key, null)!!
        val bytes = Base64.decode(original.removePrefix("MESHXMLS1:"), Base64.DEFAULT)
        bytes[bytes.lastIndex] = (bytes.last().toInt() xor 0x01).toByte()
        val tampered = "MESHXMLS1:" + Base64.encodeToString(bytes, Base64.NO_WRAP)
        assertTrue(preferences.edit().putString(key, tampered).commit())

        var rejected = false
        try {
            vault.load(groupId)
        } catch (_: IllegalStateException) {
            rejected = true
        }
        assertTrue("AES-GCM authentication must reject a modified snapshot", rejected)
        assertTrue("The failed read must not overwrite or erase the tampered record", preferences.getString(key, null) == tampered)
    }

    @Test
    fun mlsGroupIdsAreBoundToSeparateEncryptedRecords() {
        val firstGroup = "vault-group-a-" + System.nanoTime()
        val secondGroup = "vault-group-b-" + System.nanoTime()
        val vault = MlsStateVault(context)
        val state = "group A only".toByteArray(Charsets.UTF_8)

        vault.save(firstGroup, state)

        assertArrayEquals(state, vault.load(firstGroup))
        assertNull("A different group ID must not read another group's snapshot", vault.load(secondGroup))
        vault.delete(firstGroup)
    }
}
