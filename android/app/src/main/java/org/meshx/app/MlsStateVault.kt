package org.meshx.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.system.Os
import java.io.File
import java.io.FileOutputStream
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
 * plaintext MLS state must never be written to disk.
 */
internal class MlsStateVault(context: Context) {
    private val directory = File(context.applicationContext.filesDir, DIRECTORY_NAME)

    fun save(groupId: String, state: ByteArray) {
        validateGroupId(groupId)
        require(state.isNotEmpty()) { "MLS state snapshot must not be empty." }
        require(state.size <= MAX_STATE_BYTES) { "MLS state snapshot exceeds the 16 MiB limit." }

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        cipher.updateAAD(associatedData(groupId))
        val ciphertext = cipher.doFinal(state)
        val record = FORMAT_PREFIX + cipher.iv + ciphertext

        ensureDirectory()
        val destination = fileFor(groupId)
        val temporary = File(directory, destination.name + "." + java.util.UUID.randomUUID() + ".tmp")
        try {
            FileOutputStream(temporary).use { output ->
                output.write(record)
                output.fd.sync()
            }
            // Atomic replacement keeps the previous complete snapshot if writing fails.
            Os.rename(temporary.absolutePath, destination.absolutePath)
        } catch (error: Exception) {
            temporary.delete()
            throw IllegalStateException("Encrypted MLS state could not be saved.", error)
        }
    }

    fun load(groupId: String): ByteArray? {
        validateGroupId(groupId)
        val file = fileFor(groupId)
        if (!file.exists()) return null
        val maximumRecordBytes = FORMAT_PREFIX.size + GCM_IV_BYTES + GCM_TAG_BYTES + MAX_STATE_BYTES
        require(file.length() in (FORMAT_PREFIX.size + GCM_IV_BYTES + GCM_TAG_BYTES + 1).toLong()..maximumRecordBytes.toLong()) {
            "Saved MLS state has an invalid size; it was kept unchanged."
        }
        val record = file.readBytes()
        require(record.copyOfRange(0, FORMAT_PREFIX.size).contentEquals(FORMAT_PREFIX)) {
            "Saved MLS state has an unknown format; it was kept unchanged."
        }

        val key = getExistingKey()
            ?: throw IllegalStateException(
                "The Android Keystore key for saved MLS state is missing. Data was kept unchanged."
            )
        val ivStart = FORMAT_PREFIX.size
        val iv = record.copyOfRange(ivStart, ivStart + GCM_IV_BYTES)
        val ciphertext = record.copyOfRange(ivStart + GCM_IV_BYTES, record.size)
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
        val file = fileFor(groupId)
        check(!file.exists() || file.delete()) { "Encrypted MLS state could not be deleted." }
    }

    internal fun fileForTesting(groupId: String): File = fileFor(groupId)

    private fun ensureDirectory() {
        check(directory.isDirectory || directory.mkdirs()) {
            "Private MESHX MLS storage directory could not be created."
        }
    }

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
        FORMAT_PREFIX + groupId.toByteArray(Charsets.UTF_8)

    private fun fileFor(groupId: String): File {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(groupId.toByteArray(Charsets.UTF_8))
        val name = digest.joinToString("") { "%02x".format(it.toInt() and 0xff) } + ".mls"
        return File(directory, name)
    }

    private fun validateGroupId(groupId: String) {
        require(groupId.isNotBlank() && groupId.length <= MAX_GROUP_ID_CHARS) {
            "MLS group ID must contain 1–256 characters."
        }
    }

    private companion object {
        val FORMAT_PREFIX = "MESHXMLS1:".toByteArray(Charsets.US_ASCII)
        const val DIRECTORY_NAME = "meshx_mls_state_v1"
        const val KEY_ALIAS = "meshx_mls_state_aes_v1"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_IV_BYTES = 12
        const val GCM_TAG_BITS = 128
        const val GCM_TAG_BYTES = 16
        const val MAX_STATE_BYTES = 16 * 1024 * 1024
        const val MAX_GROUP_ID_CHARS = 256
    }
}
