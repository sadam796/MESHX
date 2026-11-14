package org.meshx.app

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MlsIdentityBindingInstrumentedTest {
    private fun assertRejected(block: () -> Unit) {
        var rejected = false
        try {
            block()
        } catch (_: Exception) {
            rejected = true
        }
        assertTrue("Expected invalid or mismatched MLS identity envelope to be rejected", rejected)
    }

    private fun identityAndSigner(): Pair<MeshxIdentity, java.security.PrivateKey> {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val prefs = context.getSharedPreferences("meshx_local_contacts", android.content.Context.MODE_PRIVATE)
        val identity = loadOrCreateIdentity(prefs)
        return identity to loadIdentitySigningPrivateKey()
    }

    @Test
    fun signedKeyPackageIsBoundToTheSavedMESHX2IdentityAndCannotBeTampered() {
        val (identity, signer) = identityAndSigner()
        val expected = parsePublicIdentity(identity.qrPayload)
        val keyPackage = ByteArray(128) { index -> (index * 13).toByte() }

        val envelope = createSignedMlsKeyPackageEnvelope(identity.qrPayload, keyPackage, signer)
        assertArrayEquals(keyPackage, verifySignedMlsKeyPackageEnvelope(envelope, expected))
        assertRejected {
            verifySignedMlsKeyPackageEnvelope(envelope, expected.copy(fingerprint = "0000-0000-0000-0000"))
        }
        val alteredIdentityKey = expected.identityPublicKey!!.copyOf()
        alteredIdentityKey[alteredIdentityKey.lastIndex] =
            (alteredIdentityKey.last().toInt() xor 1).toByte()
        assertRejected {
            verifySignedMlsKeyPackageEnvelope(envelope, expected.copy(identityPublicKey = alteredIdentityKey))
        }

        val json = JSONObject(String(
            Base64.decode(envelope.removePrefix("MESHXK1:"), Base64.DEFAULT),
            Charsets.UTF_8
        ))
        val tamperedPackage = Base64.decode(json.getString("key_package"), Base64.DEFAULT)
        tamperedPackage[0] = (tamperedPackage[0].toInt() xor 1).toByte()
        json.put("key_package", Base64.encodeToString(tamperedPackage, Base64.NO_WRAP))
        val tamperedEnvelope = "MESHXK1:" +
            Base64.encodeToString(json.toString().toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
        assertRejected { verifySignedMlsKeyPackageEnvelope(tamperedEnvelope, expected) }
    }

    @Test
    fun signedWelcomeAndRatchetTreeAreBoundToTheInvitersMESHX2Identity() {
        val (identity, signer) = identityAndSigner()
        val expected = parsePublicIdentity(identity.qrPayload)
        val invitation = MlsInvitation(
            "welcome-message-test".toByteArray(Charsets.UTF_8),
            "ratchet-tree-test".toByteArray(Charsets.UTF_8)
        )

        val envelope = createSignedMlsInvitationEnvelope(identity.qrPayload, invitation, signer)
        val restored = verifySignedMlsInvitationEnvelope(envelope, expected)
        assertArrayEquals(invitation.welcomeMessage, restored.welcomeMessage)
        assertArrayEquals(invitation.ratchetTree, restored.ratchetTree)
        assertRejected {
            verifySignedMlsInvitationEnvelope(envelope, expected.copy(transportPeerId = "12D3KooWChanged"))
        }

        val json = JSONObject(String(
            Base64.decode(envelope.removePrefix("MESHXI1:"), Base64.DEFAULT),
            Charsets.UTF_8
        ))
        val tamperedTree = Base64.decode(json.getString("tree"), Base64.DEFAULT)
        tamperedTree[0] = (tamperedTree[0].toInt() xor 1).toByte()
        json.put("tree", Base64.encodeToString(tamperedTree, Base64.NO_WRAP))
        val tamperedEnvelope = "MESHXI1:" +
            Base64.encodeToString(json.toString().toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
        assertRejected { verifySignedMlsInvitationEnvelope(tamperedEnvelope, expected) }
    }

    @Test
    fun legacyMESHX1ContactsCannotBeUsedForSignedMlsExchange() {
        val (identity, _) = identityAndSigner()
        val json = JSONObject(String(
            Base64.decode(identity.qrPayload.removePrefix("MESHX2:"), Base64.DEFAULT),
            Charsets.UTF_8
        ))
        val legacyPayload = "MESHX1:" + json.getString("identity_public_key")
        val legacy = parsePublicIdentity(legacyPayload)
        assertRejected {
            findSignedMlsContactIdentity(setOf(legacyPayload), legacy.fingerprint)
        }
    }
}
