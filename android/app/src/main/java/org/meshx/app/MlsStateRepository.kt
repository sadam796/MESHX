package org.meshx.app

import android.content.Context
import org.json.JSONObject

/**
 * App-facing boundary between the native OpenMLS provider and Android Keystore.
 * Secret snapshot byte arrays are cleared from the Kotlin heap after each operation.
 */
internal class MlsStateRepository(context: Context) {
    private val vault = MlsStateVault(context)

    fun createAndSaveSignerState(recordId: String) {
        val snapshot = NativeMeshx.createMlsSignerSnapshot()
        try {
            vault.save(recordId, snapshot)
        } finally {
            snapshot.fill(0)
        }
    }

    fun restoreAndValidateSignerState(recordId: String): Boolean {
        val snapshot = vault.load(recordId) ?: return false
        return try {
            NativeMeshx.validateMlsSignerSnapshot(snapshot)
        } finally {
            snapshot.fill(0)
        }
    }



    /**
     * Creates a signed one-use MLS KeyPackage, saves its private init key material
     * inside the Keystore-encrypted vault, and returns only the public package.
     * The caller must deliver the returned bytes securely and avoid reusing them.
     */
    fun createAndSaveKeyPackage(recordId: String, credentialIdentity: ByteArray): ByteArray {
        val snapshot = NativeMeshx.createMlsKeyPackageSnapshot(credentialIdentity)
        try {
            val publicPackage = NativeMeshx.extractMlsKeyPackage(snapshot)
            vault.save(recordId, snapshot)
            return publicPackage
        } finally {
            snapshot.fill(0)
        }
    }

    /**
     * Joins a contact invitation using a previously saved KeyPackage private state.
     * The one-use KeyPackage vault record is deleted only after the joined group
     * has been safely persisted.
     */
    fun joinAndSaveInvitedGroup(
        keyPackageRecordId: String,
        groupRecordId: String,
        welcomeMessage: ByteArray,
        ratchetTree: ByteArray
    ) {
        val keyPackageState = vault.load(keyPackageRecordId)
            ?: throw IllegalStateException("Saved one-use MLS KeyPackage state was not found.")
        var joinedGroupSnapshot: ByteArray? = null
        try {
            joinedGroupSnapshot = NativeMeshx.joinMlsGroupFromWelcome(
                keyPackageState, welcomeMessage, ratchetTree
            )
            vault.save(groupRecordId, joinedGroupSnapshot)
            check(NativeMeshx.validateMlsGroupSnapshot(joinedGroupSnapshot)) {
                "Joined MLS group failed restore validation."
            }
            vault.delete(keyPackageRecordId)
        } finally {
            keyPackageState.fill(0)
            joinedGroupSnapshot?.fill(0)
        }
    }

    /** Creates an RFC 9420 group and immediately encrypts its state at rest. */
    fun createAndSaveGroupState(recordId: String, credentialIdentity: ByteArray) {
        val snapshot = NativeMeshx.createMlsGroupSnapshot(credentialIdentity)
        try {
            vault.save(recordId, snapshot)
        } finally {
            snapshot.fill(0)
        }
    }

    /** Loads the encrypted group state and verifies the native OpenMLS group. */
    fun restoreAndValidateGroupState(recordId: String): Boolean {
        val snapshot = vault.load(recordId) ?: return false
        return try {
            NativeMeshx.validateMlsGroupSnapshot(snapshot)
        } finally {
            snapshot.fill(0)
        }
    }

    /**
     * Encrypts a chat payload with the saved MLS group and persists the advanced
     * sender ratchet before returning opaque ciphertext for transport.
     */
    fun encryptAndAdvanceGroupState(groupRecordId: String, plaintext: ByteArray): ByteArray {
        val state = vault.load(groupRecordId)
            ?: throw IllegalStateException("Saved MLS group state was not found.")
        var result: ByteArray? = null
        try {
            result = NativeMeshx.encryptMlsApplicationMessage(state, plaintext)
            val bundle = JSONObject(result.toString(Charsets.UTF_8))
            val updatedState = bundle.getJSONArray("updated_group_snapshot").toByteArrayValue()
            val ciphertext = bundle.getJSONArray("ciphertext").toByteArrayValue()
            try {
                vault.save(groupRecordId, updatedState)
                check(NativeMeshx.validateMlsGroupSnapshot(updatedState)) {
                    "Advanced sender MLS state failed validation."
                }
            } finally {
                updatedState.fill(0)
            }
            return ciphertext
        } finally {
            state.fill(0)
            result?.fill(0)
        }
    }

    /**
     * Authenticates incoming MLS ciphertext and persists the advanced receiver
     * ratchet before returning the decrypted application payload.
     */
    fun decryptAndAdvanceGroupState(groupRecordId: String, ciphertext: ByteArray): ByteArray {
        val state = vault.load(groupRecordId)
            ?: throw IllegalStateException("Saved MLS group state was not found.")
        var result: ByteArray? = null
        try {
            result = NativeMeshx.decryptMlsApplicationMessage(state, ciphertext)
            val bundle = JSONObject(result.toString(Charsets.UTF_8))
            val updatedState = bundle.getJSONArray("updated_group_snapshot").toByteArrayValue()
            val plaintext = bundle.getJSONArray("ciphertext").toByteArrayValue()
            try {
                check(NativeMeshx.validateMlsGroupSnapshot(updatedState)) {
                    "Advanced receiver MLS state failed validation."
                }
                vault.save(groupRecordId, updatedState)
            } finally {
                updatedState.fill(0)
            }
            return plaintext
        } finally {
            state.fill(0)
            result?.fill(0)
        }
    }

    private fun org.json.JSONArray.toByteArrayValue(): ByteArray =
        ByteArray(length()) { index -> getInt(index).toByte() }

    fun delete(recordId: String) = vault.delete(recordId)
}
