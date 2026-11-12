package org.meshx.app

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class NativeMeshxInstrumentedTest {
    @Test
    fun openMlsProviderSnapshotCrossesJniAndAndroidKeystoreVault() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val recordId = "jni-openmls-vault-" + System.nanoTime()
        val repository = MlsStateRepository(context)

        repository.createAndSaveSignerState(recordId)
        assertTrue(
            "Rust must restore the original MLS signing key after the Android vault round trip",
            repository.restoreAndValidateSignerState(recordId)
        )
        repository.delete(recordId)
    }


    @Test
    fun nativeOpenMlsGroupIsCreatedAndRestoredThroughKeystoreVault() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val recordId = "jni-openmls-group-" + System.nanoTime()
        val repository = MlsStateRepository(context)

        repository.createAndSaveGroupState(recordId, "meshx-android-test-identity".toByteArray())
        assertTrue(
            "Rust must restore the RFC 9420 group and signer after the encrypted vault round trip",
            repository.restoreAndValidateGroupState(recordId)
        )
        repository.delete(recordId)
    }

    @Test
    fun nativeOpenMlsCreatesTwoMembersAndDecryptsApplicationMessage() {
        assertTrue(
            "Independent Alice and Bob MLS providers must complete Welcome join and decrypt the encrypted application message",
            NativeMeshx.mlsTwoMemberRoundTripSelfTest()
        )
    }

    @Test
    fun packagedRustLibraryDerivesStableTransportIdentityAndStarts() {
        val privateIdentity = NativeMeshx.generateIdentity()
        assertTrue("Native identity must not be empty", privateIdentity.isNotEmpty())

        val publicKey = NativeMeshx.transportPublicKey(privateIdentity)
        assertTrue("Transport public key must not be empty", publicKey.isNotEmpty())

        val peerId = NativeMeshx.transportPeerId(publicKey)
        assertTrue("Expected an Ed25519 libp2p Peer ID, got: $peerId", peerId.startsWith("12D3Koo"))

        assertTrue(publicKey.contentEquals(NativeMeshx.transportPublicKey(privateIdentity)))
        val startResult = NativeMeshx.start(privateIdentity)
        assertTrue(
            "Expected Rust JNI bridge to start, got: $startResult",
            startResult.startsWith("MESHX libp2p swarm starting") ||
                startResult.contains("MESHX libp2p TCP listener active")
        )
    }

    @Test
    fun nativeCiphertextBridgeRejectsMalformedPeerAndEmptyPayload() {
        val malformedPeer = NativeMeshx.sendCiphertext("not-a-peer-id", byteArrayOf(1))
        assertTrue(
            "Expected malformed destination to be rejected by native JNI, got: $malformedPeer",
            malformedPeer.startsWith("MESHX send error: Invalid MESHX transport Peer ID.")
        )

        val identity = NativeMeshx.generateIdentity()
        val publicKey = NativeMeshx.transportPublicKey(identity)
        val validPeer = NativeMeshx.transportPeerId(publicKey)
        val emptyPayload = NativeMeshx.sendCiphertext(validPeer, byteArrayOf())
        assertTrue(
            "Expected empty ciphertext to be rejected before queueing, got: $emptyPayload",
            emptyPayload.startsWith("MESHX send error: Encrypted payload must be between 1 byte and 1 MiB.")
        )
    }

    @Test
    fun nativeDhtLookupRejectsMalformedPeerId() {
        val result = NativeMeshx.findPeer("not-a-peer-id")
        assertTrue(
            "Expected invalid Peer ID to be rejected, got: $result",
            result.startsWith("MESHX peer discovery error: Invalid MESHX transport Peer ID.")
        )
    }

    @Test
    fun contactTransportKeyChangesRequireExplicitConfirmationAndDowngradesAreBlocked() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val prefs = context.getSharedPreferences("meshx_local_contacts", android.content.Context.MODE_PRIVATE)
        val identity = loadOrCreateIdentity(prefs)
        val signed = parsePublicIdentity(identity.qrPayload)
        val changedTransport = signed.copy(transportPeerId = "12D3KooWChangedTransportPeerIdForTest")
        assertEquals(ContactImportDecision.SAME_IDENTITY, classifyParsedContactImport(signed, signed))
        assertEquals(ContactImportDecision.TRANSPORT_KEY_CHANGED, classifyParsedContactImport(signed, changedTransport))

        val jsonBytes = Base64.decode(identity.qrPayload.removePrefix("MESHX2:"), Base64.DEFAULT)
        val json = JSONObject(String(jsonBytes, Charsets.UTF_8))
        val identityPublicKey = Base64.decode(json.getString("identity_public_key"), Base64.DEFAULT)
        val legacy = parsePublicIdentity("MESHX1:" + Base64.encodeToString(identityPublicKey, Base64.NO_WRAP))
        assertEquals(ContactImportDecision.UPGRADE_LEGACY, classifyParsedContactImport(legacy, signed))
        assertEquals(ContactImportDecision.SIGNED_BINDING_DOWNGRADE, classifyParsedContactImport(signed, legacy))
    }

    @Test
    fun signedMESHX2QrBindsIdentityKeyToTransportPeerAndRejectsTampering() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val prefs = context.getSharedPreferences("meshx_local_contacts", android.content.Context.MODE_PRIVATE)
        val identity = loadOrCreateIdentity(prefs)

        val parsed = parsePublicIdentity(identity.qrPayload)
        assertEquals(identity.fingerprint, parsed.fingerprint)
        assertEquals(identity.transportPeerId, parsed.transportPeerId)
        assertTrue(parsed.authenticatedBinding)

        val jsonBytes = Base64.decode(identity.qrPayload.removePrefix("MESHX2:"), Base64.DEFAULT)
        val json = JSONObject(String(jsonBytes, Charsets.UTF_8))
        val transportKey = Base64.decode(json.getString("transport_public_key"), Base64.DEFAULT)
        transportKey[transportKey.lastIndex] = (transportKey.last().toInt() xor 1).toByte()
        json.put("transport_public_key", Base64.encodeToString(transportKey, Base64.NO_WRAP))
        val tampered = "MESHX2:" + Base64.encodeToString(json.toString().toByteArray(Charsets.UTF_8), Base64.NO_WRAP)

        var rejected = false
        try {
            parsePublicIdentity(tampered)
        } catch (_: IllegalArgumentException) {
            rejected = true
        }
        assertTrue("A changed transport key must fail signature verification", rejected)
    }
}
