package org.meshx.app

import android.content.Context

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

    fun delete(recordId: String) = vault.delete(recordId)
}
