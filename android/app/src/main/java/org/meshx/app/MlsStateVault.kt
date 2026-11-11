package org.meshx.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyGenerator
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator as JcaKeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Android-side encrypted persistence boundary for future OpenMLS group snapshots.
 *
 * The Rust MLS engine must pass opaque serialized state bytes through this vault;
 * plaintext MLS state must never be written to SharedPreferences or SQLite.
 */
internal class MlsStateVault(context: Context) {
    private val preferences = context.applicationContext.getSharedPreferences(
        PREFERENCES_NAME,
        Context.MODE_PRIVATE
    )

    fun save(groupId: String, state: ByteArray) {
        validateGroupId(groupId)
        require(state.isNotEmpty()) { "MLS state snapshot must not be empty." }
        require(state.size <= MAX_STATE_BYTES) { "MLS state snapshot exceeds the 16 MiB limit." }

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        cipher.updateAAD(associatedData(groupId))
        val ciphertext = cipher.doFinal(state)
        val encoded = FORMAT_PREFIX + Base64.encodeToString(cipher.iv + ciphertext, Base64.NO_WRAP)
        check(preferences.edit().putString(storageKey(groupId), encoded).commit()) {
            "Encrypted MLS state could not be saved."
        }
    }

    fun load(groupId: String): ByteArray? {
        validateGroupId(groupId)
        val encoded = preferences.getString(storageKey(groupId), null) ?: return null
        require(encoded.startsWith(FORMAT_PREFIX)) {
            "Saved MLS state has an unknown format; it was kept unchanged."
        }
        val combined = try {
            Base64.decode(encoded.removePrefix(FORMAT_PREFIX), Base64.DEFAULT)
        } catch (error: IllegalArgumentException) {
            throw IllegalStateException("Saved MLS state is malformed; it was kept unchanged.", error)
        }
        require(combined.size > GCM_IV_BYTES + GCM_TAG_BYTES) {
            "Saved MLS state is incomplete; it was kept unchanged."
        }

        val key = getExistingKey()
            ?: throw IllegalStateException(
                "The Android Keystore key for saved MLS state is missing. Data was kept unchanged."
            )
        val iv = combined.copyOfRange(0, GCM_IV_BYTES)
        val ciphertext = combined.copyOfRange(GCM_IV_BYTES, combined.size)
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
            cipher.updateAAD(associatedData(groupId))
            cipher.doFinal(ciphertext).also {
                check(it.size <= MAX_STATE_BYTES) { "Decrypted MLS state exceeds the 16 MiB limit." }
            }
        } catch (error: AEADBadTagException) {
            throw IllegalStateException(
                "MLS state authentication failed. The saved record was not changed.",
                error
            )
        }
    }

    fun delete(groupId: String) {
        validateGroupId(groupId)
        check(preferences.edit().remove(storageKey(groupId)).commit()) {
            "Encrypted MLS state could not be deleted."
        }
    }

    internal fun storageKeyForTesting(groupId: String): String = storageKey(groupId)

    private fun getExistingKey(): SecretKey? {
        val store = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return store.getKey(KEY_ALIAS, null) as? SecretKey
    }

    private fun getOrCreateKey(): SecretKey {
        getExistingKey()?.let { return it }
        val generator = JcaKeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        return generator.generateKey()
    }

    private fun associatedData(groupId: String): ByteArray =
        "$FORMAT_PREFIX$groupId".toByteArray(Charsets.UTF_8)

    private fun storageKey(groupId: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(groupId.toByteArray(Charsets.UTF_8))
        return "group_" + digest.joinToString("") { "%02x".format(it) }
    }

    private fun validateGroupId(groupId: String) {
        require(groupId.isNotBlank() && groupId.length <= MAX_GROUP_ID_CHARS) {
            "MLS group ID must contain 1–256 characters."
        }
    }

    private companion object {
        const val PREFERENCES_NAME = "meshx_mls_encrypted_state_v1"
        const val KEY_ALIAS = "meshx_mls_state_aes_v1"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val FORMAT_PREFIX = "MESHXMLS1:"
        const val GCM_IV_BYTES = 12
        const val GCM_TAG_BITS = 128
        const val GCM_TAG_BYTES = 16
        const val MAX_STATE_BYTES = 16 * 1024 * 1024
        const val MAX_GROUP_ID_CHARS = 256
    }
}
