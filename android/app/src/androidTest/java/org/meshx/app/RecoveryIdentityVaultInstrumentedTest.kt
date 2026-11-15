package org.meshx.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RecoveryIdentityVaultInstrumentedTest {
    @Test
    fun savesAndRestoresOnlyEncryptedDerivedKeyMaterial() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val vault = RecoveryIdentityVault(context)
        val material = RecoveryIdentityVault.Material(
            transportPrivateKey = byteArrayOf(1, 2, 3, 4, 5),
            signingPrivateKeyPkcs8 = byteArrayOf(6, 7, 8, 9),
            signingPublicKeySpki = byteArrayOf(10, 11, 12)
        )
        vault.save(material)
        val restored = assertNotNullAndReturn(vault.load())
        assertArrayEquals(material.transportPrivateKey, restored.transportPrivateKey)
        assertArrayEquals(material.signingPrivateKeyPkcs8, restored.signingPrivateKeyPkcs8)
        assertArrayEquals(material.signingPublicKeySpki, restored.signingPublicKeySpki)
        material.transportPrivateKey.fill(0)
        material.signingPrivateKeyPkcs8.fill(0)
        material.signingPublicKeySpki.fill(0)
        restored.transportPrivateKey.fill(0)
        restored.signingPrivateKeyPkcs8.fill(0)
        restored.signingPublicKeySpki.fill(0)
    }

    private fun assertNotNullAndReturn(value: RecoveryIdentityVault.Material?): RecoveryIdentityVault.Material {
        assertNotNull(value)
        return value!!
    }
}
