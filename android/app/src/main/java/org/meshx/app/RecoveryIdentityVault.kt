package org.meshx.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONObject
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Stores only the derived account keys, never the mnemonic or BIP-39 seed.
 * The bundle is authenticated/encrypted with a non-exportable Android Keystore
 * AES key. A missing Keystore key is treated as data loss, never silently
 * replaced with a new key.
 */
internal class RecoveryIdentityVault(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    data class Material(
        val transportPrivateKey: ByteArray,
        val signingPrivateKeyPkcs8: ByteArray,
        val signingPublicKeySpki: ByteArray
    )

    fun exists(): Boolean = prefs.contains(RECORD_KEY)

    fun save(material: Material) {
        require(material.transportPrivateKey.isNotEmpty())
        require(material.signingPrivateKeyPkcs8.isNotEmpty())
        require(material.signingPublicKeySpki.isNotEmpty())
        val json = JSONObject()
            .put("version", 1)
            .put("transport", Base64.encodeToString(material.transportPrivateKey, Base64.NO_WRAP))
            .put("signing_private", Base64.encodeToString(material.signingPrivateKeyPkcs8, Base64.NO_WRAP))
            .put("signing_public", Base64.encodeToString(material.signingPublicKeySpki, Base64.NO_WRAP))
            .toString()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        cipher.updateAAD(AAD)
        val encrypted = cipher.doFinal(json.toByteArray(Charsets.UTF_8))
        val record = Base64.encodeToString(cipher.iv + encrypted, Base64.NO_WRAP)
        check(prefs.edit().putString(RECORD_KEY, record).commit()) {
            "Encrypted MESHX recovery identity could not be saved."
        }
    }

    fun load(): Material? {
        val record = prefs.getString(RECORD_KEY, null) ?: return null
        val store = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val key = store.getKey(KEY_ALIAS, null) as? SecretKey
            ?: throw IllegalStateException(
                "MESHX recovery vault key is missing. Saved identity was kept unchanged; do not clear app data."
            )
        val combined = Base64.decode(record, Base64.DEFAULT)
        require(combined.size > IV_BYTES + TAG_BYTES) { "MESHX recovery vault record is incomplete." }
        val iv = combined.copyOfRange(0, IV_BYTES)
        val encrypted = combined.copyOfRange(IV_BYTES, combined.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
        cipher.updateAAD(AAD)
        val json = JSONObject(String(cipher.doFinal(encrypted), Charsets.UTF_8))
        require(json.getInt("version") == 1) { "Unsupported MESHX recovery vault version." }
        return Material(
            Base64.decode(json.getString("transport"), Base64.DEFAULT),
            Base64.decode(json.getString("signing_private"), Base64.DEFAULT),
            Base64.decode(json.getString("signing_public"), Base64.DEFAULT)
        )
    }

    private fun getOrCreateKey(): SecretKey {
        val store = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (store.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        check(!exists()) {
            "MESHX recovery identity exists but its Keystore key is missing. Refusing to overwrite it."
        }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
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

    private companion object {
        const val PREFS = "meshx_recovery_vault"
        const val RECORD_KEY = "encrypted_recovery_identity_v1"
        const val KEY_ALIAS = "meshx_recovery_identity_aes_v1"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_BYTES = 12
        const val TAG_BYTES = 16
        const val TAG_BITS = 128
        val AAD = "MESHX-RECOVERY-VAULT-V1".toByteArray(Charsets.US_ASCII)
    }
}
