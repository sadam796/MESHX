package org.meshx.app

import android.os.Bundle
import android.graphics.BitmapFactory
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeWriter
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import org.json.JSONObject
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlinx.coroutines.delay

private const val IDENTITY_ALIAS = "meshx_identity_v1"
private const val PREFS_NAME = "meshx_local_contacts"

private const val MESSAGE_KEY_ALIAS = "meshx_local_messages_aes_v1"
private const val TRANSPORT_IDENTITY_KEY_ALIAS = "meshx_transport_identity_aes_v1"
private const val TRANSPORT_IDENTITY_PREF = "native_transport_identity_v1"

private fun getOrCreateTransportIdentityKey(): SecretKey {
    val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val existing = store.getKey(TRANSPORT_IDENTITY_KEY_ALIAS, null) as? SecretKey
    if (existing != null) return existing
    val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    generator.init(
        KeyGenParameterSpec.Builder(
            TRANSPORT_IDENTITY_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .build()
    )
    return generator.generateKey()
}

private fun encryptTransportIdentity(value: ByteArray): String {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, getOrCreateTransportIdentityKey())
    val encrypted = cipher.doFinal(value)
    return "MESHXENC1:" + Base64.encodeToString(cipher.iv + encrypted, Base64.NO_WRAP)
}

private fun decryptTransportIdentity(value: String): ByteArray {
    require(value.startsWith("MESHXENC1:")) { "Saved MESHX transport identity has an unknown format." }
    val combined = Base64.decode(value.removePrefix("MESHXENC1:"), Base64.DEFAULT)
    require(combined.size > 28) { "Saved MESHX transport identity is incomplete." }
    val iv = combined.copyOfRange(0, 12)
    val encrypted = combined.copyOfRange(12, combined.size)
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, getOrCreateTransportIdentityKey(), GCMParameterSpec(128, iv))
    return cipher.doFinal(encrypted)
}

private fun loadOrCreateTransportIdentity(prefs: android.content.SharedPreferences): ByteArray {
    val saved = prefs.getString(TRANSPORT_IDENTITY_PREF, null)
    if (saved != null) {
        return try {
            decryptTransportIdentity(saved)
        } catch (error: Exception) {
            throw IllegalStateException(
                "Saved MESHX transport identity could not be unlocked. It was kept unchanged; do not clear app data.",
                error
            )
        }
    }

    val generated = NativeMeshx.generateIdentity()
    val encrypted = encryptTransportIdentity(generated)
    check(prefs.edit().putString(TRANSPORT_IDENTITY_PREF, encrypted).commit()) {
        "MESHX transport identity could not be saved securely."
    }
    return generated
}

private fun getOrCreateMessageKey(): SecretKey {
    val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val existing = store.getKey(MESSAGE_KEY_ALIAS, null) as? SecretKey
    if (existing != null) return existing
    val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    generator.init(
        KeyGenParameterSpec.Builder(
            MESSAGE_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .build()
    )
    return generator.generateKey()
}

private fun encryptLocalRecord(value: String): String {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, getOrCreateMessageKey())
    val encrypted = cipher.doFinal(value.toByteArray(Charsets.UTF_8))
    val combined = cipher.iv + encrypted
    return "ENC1:" + Base64.encodeToString(combined, Base64.NO_WRAP)
}

private fun decryptLocalRecord(value: String): String {
    require(value.startsWith("ENC1:")) { "Legacy record" }
    val combined = Base64.decode(value.removePrefix("ENC1:"), Base64.DEFAULT)
    require(combined.size > 12) { "Encrypted record is incomplete" }
    val iv = combined.copyOfRange(0, 12)
    val encrypted = combined.copyOfRange(12, combined.size)
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, getOrCreateMessageKey(), GCMParameterSpec(128, iv))
    return String(cipher.doFinal(encrypted), Charsets.UTF_8)
}

private fun loadLocalMessages(prefs: android.content.SharedPreferences): Set<String> {
    val stored = prefs.getStringSet("local_messages", emptySet())?.toSet() ?: emptySet()
    val plaintext = linkedSetOf<String>()
    val encrypted = linkedSetOf<String>()
    stored.forEach { item ->
        if (item.startsWith("ENC1:")) {
            try {
                val decoded = decryptLocalRecord(item)
                plaintext.add(decoded)
                encrypted.add(item)
            } catch (_: Exception) {
                // Skip records that cannot be authenticated or decrypted.
            }
        } else {
            // One-time migration from the early local-only prototype format.
            plaintext.add(item)
            try { encrypted.add(encryptLocalRecord(item)) } catch (_: Exception) { }
        }
    }
    if (encrypted != stored) prefs.edit().putStringSet("local_messages", encrypted).apply()
    return plaintext
}

private fun loadProcessedIncomingIds(prefs: android.content.SharedPreferences): Set<String> {
    val stored = prefs.getStringSet("processed_incoming_ids", emptySet())?.toSet() ?: emptySet()
    val processed = linkedSetOf<String>()
    val encrypted = linkedSetOf<String>()
    stored.forEach { item ->
        try {
            val decoded = if (item.startsWith("ENC1:")) decryptLocalRecord(item) else item
            if (decoded.matches(Regex("[0-9a-fA-F]{32}"))) processed.add(decoded.lowercase())
            encrypted.add(if (item.startsWith("ENC1:")) item else encryptLocalRecord(item))
        } catch (_: Exception) {
            // Ignore corrupt markers; never treat unauthenticated data as processed.
        }
    }
    if (encrypted != stored) prefs.edit().putStringSet("processed_incoming_ids", encrypted).apply()
    return processed
}

private fun loadPendingIncomingEnvelopes(prefs: android.content.SharedPreferences): Map<String, String> {
    val stored = prefs.getStringSet("pending_incoming_ciphertexts", emptySet())?.toSet() ?: emptySet()
    val pending = linkedMapOf<String, String>()
    stored.forEach { record ->
        try {
            val json = if (record.startsWith("ENC1:")) decryptLocalRecord(record) else record
            val id = JSONObject(json).getString("message_id").lowercase()
            if (id.matches(Regex("[0-9a-f]{32}"))) pending[id] = json
        } catch (_: Exception) {
            // Keep unreadable encrypted records untouched for diagnosis/recovery.
        }
    }
    return pending
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { MeshxHome() }
    }
}

private const val IDENTITY_BINDING_DOMAIN = "MESHX-TRANSPORT-BINDING-V2:"

internal data class MeshxIdentity(
    val fingerprint: String,
    val qrPayload: String,
    val transportPeerId: String
)

internal data class ParsedPublicIdentity(
    val fingerprint: String,
    val transportPeerId: String?,
    val authenticatedBinding: Boolean,
    val identityPublicKey: ByteArray? = null
)

internal enum class ContactImportDecision { ADD, SAME_IDENTITY, UPGRADE_LEGACY, TRANSPORT_KEY_CHANGED, SIGNED_BINDING_DOWNGRADE }
internal data class PendingContactTransportRotation(val rawPayload: String, val parsed: ParsedPublicIdentity)
internal fun classifyParsedContactImport(existing: ParsedPublicIdentity?, incoming: ParsedPublicIdentity): ContactImportDecision {
    if (existing == null) return ContactImportDecision.ADD
    if (existing.fingerprint != incoming.fingerprint) return ContactImportDecision.ADD
    if (existing.authenticatedBinding && !incoming.authenticatedBinding) return ContactImportDecision.SIGNED_BINDING_DOWNGRADE
    if (existing.transportPeerId != null && incoming.transportPeerId != null && existing.transportPeerId != incoming.transportPeerId) return ContactImportDecision.TRANSPORT_KEY_CHANGED
    if (!existing.authenticatedBinding && incoming.authenticatedBinding) return ContactImportDecision.UPGRADE_LEGACY
    return ContactImportDecision.SAME_IDENTITY
}

internal fun classifyContactImport(existingPayloads: Set<String>, incoming: ParsedPublicIdentity): ContactImportDecision {
    val existing = existingPayloads.asSequence().mapNotNull { raw ->
        try { parsePublicIdentity(raw) } catch (_: Exception) { null }
    }.firstOrNull { it.fingerprint == incoming.fingerprint }
    return classifyParsedContactImport(existing, incoming)
}

private fun fingerprint(publicKey: ByteArray): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(publicKey)
    return digest.take(16).joinToString("") { "%02X".format(it) }.chunked(4).joinToString("-")
}

private fun identityBindingBytes(transportPublicKey: ByteArray): ByteArray =
    IDENTITY_BINDING_DOMAIN.toByteArray(Charsets.UTF_8) + transportPublicKey

internal fun parsePublicIdentity(raw: String): ParsedPublicIdentity {
    require(raw.startsWith("MESHX1:") || raw.startsWith("MESHX2:")) {
        "MESHX1 ya signed MESHX2 public identity required."
    }
    if (raw.startsWith("MESHX1:")) {
        val keyBytes = Base64.decode(raw.removePrefix("MESHX1:"), Base64.DEFAULT)
        KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(keyBytes))
        return ParsedPublicIdentity(fingerprint(keyBytes), null, false, keyBytes)
    }

    val payloadBytes = Base64.decode(raw.removePrefix("MESHX2:"), Base64.DEFAULT)
    val payload = JSONObject(String(payloadBytes, Charsets.UTF_8))
    require(payload.getInt("version") == 2) { "Unsupported MESHX identity version." }
    val identityPublicKey = Base64.decode(payload.getString("identity_public_key"), Base64.DEFAULT)
    val transportPublicKey = Base64.decode(payload.getString("transport_public_key"), Base64.DEFAULT)
    val bindingSignature = Base64.decode(payload.getString("binding_signature"), Base64.DEFAULT)
    val expectedPeerId = payload.getString("transport_peer_id")
    val identityKey = KeyFactory.getInstance("EC")
        .generatePublic(X509EncodedKeySpec(identityPublicKey))
    val verifier = Signature.getInstance("SHA256withECDSA")
    verifier.initVerify(identityKey)
    verifier.update(identityBindingBytes(transportPublicKey))
    require(verifier.verify(bindingSignature)) {
        "MESHX2 transport-key signature is invalid. Contact was not added."
    }
    val actualPeerId = NativeMeshx.transportPeerId(transportPublicKey)
    require(actualPeerId == expectedPeerId) {
        "MESHX2 transport Peer ID does not match its public key."
    }
    return ParsedPublicIdentity(fingerprint(identityPublicKey), actualPeerId, true, identityPublicKey)
}

internal fun loadOrCreateIdentity(prefs: android.content.SharedPreferences): MeshxIdentity {
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    if (!keyStore.containsAlias(IDENTITY_ALIAS)) {
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        generator.initialize(KeyGenParameterSpec.Builder(
            IDENTITY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        ).setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256).build())
        generator.generateKeyPair()
    }
    val identityPublicKey = keyStore.getCertificate(IDENTITY_ALIAS).publicKey.encoded
    val identityPrivateKey = keyStore.getKey(IDENTITY_ALIAS, null) as? PrivateKey
        ?: throw IllegalStateException("MESHX identity signing key is unavailable in Android Keystore.")
    val transportIdentity = loadOrCreateTransportIdentity(prefs)
    val transportPublicKey = NativeMeshx.transportPublicKey(transportIdentity)
    val transportPeerId = NativeMeshx.transportPeerId(transportPublicKey)
    val signer = Signature.getInstance("SHA256withECDSA")
    signer.initSign(identityPrivateKey)
    signer.update(identityBindingBytes(transportPublicKey))
    val bindingSignature = signer.sign()
    val payload = JSONObject()
        .put("version", 2)
        .put("identity_public_key", Base64.encodeToString(identityPublicKey, Base64.NO_WRAP))
        .put("transport_public_key", Base64.encodeToString(transportPublicKey, Base64.NO_WRAP))
        .put("transport_peer_id", transportPeerId)
        .put("binding_signature", Base64.encodeToString(bindingSignature, Base64.NO_WRAP))
        .toString()
    return MeshxIdentity(
        fingerprint(identityPublicKey),
        "MESHX2:" + Base64.encodeToString(payload.toByteArray(Charsets.UTF_8), Base64.NO_WRAP),
        transportPeerId
    )
}


private const val MLS_KEY_PACKAGE_ENVELOPE_PREFIX = "MESHXK1:"
private const val MLS_INVITATION_ENVELOPE_PREFIX = "MESHXI1:"
private const val MLS_KEY_PACKAGE_DOMAIN = "MESHX-MLS-KEYPACKAGE-V1"
private const val MLS_INVITATION_DOMAIN = "MESHX-MLS-INVITATION-V1"
private const val MAX_MLS_ENVELOPE_PART_BYTES = 1024 * 1024

internal fun loadIdentitySigningPrivateKey(): PrivateKey {
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    return keyStore.getKey(IDENTITY_ALIAS, null) as? PrivateKey
        ?: throw IllegalStateException("MESHX identity signing key is unavailable in Android Keystore.")
}

private fun meshxIdentityPublicKey(identityPayload: String): java.security.PublicKey {
    require(identityPayload.length <= 16_384) { "MESHX identity payload is too large." }
    val parsed = parsePublicIdentity(identityPayload)
    require(parsed.authenticatedBinding) { "MLS exchange requires a signed MESHX2 identity." }
    val payloadBytes = Base64.decode(identityPayload.removePrefix("MESHX2:"), Base64.DEFAULT)
    val payload = JSONObject(String(payloadBytes, Charsets.UTF_8))
    val encoded = Base64.decode(payload.getString("identity_public_key"), Base64.DEFAULT)
    return KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(encoded))
}

private fun mlsEnvelopeSignatureInput(
    domain: String,
    identityPublicKey: ByteArray,
    parts: List<ByteArray>
): ByteArray {
    val output = ByteArrayOutputStream()
    DataOutputStream(output).use { data ->
        fun writeField(value: ByteArray) {
            data.writeInt(value.size)
            data.write(value)
        }
        writeField(domain.toByteArray(Charsets.UTF_8))
        writeField(identityPublicKey)
        parts.forEach { writeField(it) }
    }
    return output.toByteArray()
}

private fun signMlsEnvelope(
    identityPayload: String,
    domain: String,
    parts: List<ByteArray>,
    signingKey: PrivateKey
): ByteArray {
    val publicKey = meshxIdentityPublicKey(identityPayload)
    val signer = Signature.getInstance("SHA256withECDSA")
    signer.initSign(signingKey)
    val signedBytes = mlsEnvelopeSignatureInput(domain, publicKey.encoded, parts)
    signer.update(signedBytes)
    val signatureBytes = signer.sign()
    val verifier = Signature.getInstance("SHA256withECDSA")
    verifier.initVerify(publicKey)
    verifier.update(signedBytes)
    require(verifier.verify(signatureBytes)) {
        "MESHX identity signing key does not match the supplied signed identity."
    }
    return signatureBytes
}

private fun verifyMlsEnvelopeSignature(
    identityPayload: String,
    expectedIdentity: ParsedPublicIdentity,
    domain: String,
    parts: List<ByteArray>,
    encodedSignature: String
) {
    require(expectedIdentity.authenticatedBinding && expectedIdentity.transportPeerId != null) {
        "MLS exchange requires a saved, signed MESHX2 contact."
    }
    val incomingIdentity = parsePublicIdentity(identityPayload)
    require(incomingIdentity.authenticatedBinding &&
        incomingIdentity.fingerprint == expectedIdentity.fingerprint &&
        incomingIdentity.transportPeerId == expectedIdentity.transportPeerId &&
        expectedIdentity.identityPublicKey?.contentEquals(incomingIdentity.identityPublicKey ?: byteArrayOf()) == true
    ) {
        "MLS envelope identity does not match this saved contact and transport key."
    }
    val publicKey = meshxIdentityPublicKey(identityPayload)
    val signatureBytes = Base64.decode(encodedSignature, Base64.DEFAULT)
    require(signatureBytes.isNotEmpty() && signatureBytes.size <= 256) {
        "MLS identity signature has an invalid size."
    }
    val verifier = Signature.getInstance("SHA256withECDSA")
    verifier.initVerify(publicKey)
    verifier.update(mlsEnvelopeSignatureInput(domain, publicKey.encoded, parts))
    require(verifier.verify(signatureBytes)) {
        "MLS envelope signature is invalid. Do not accept this invitation."
    }
}

internal fun findSignedMlsContactIdentity(
    contactPayloads: Set<String>,
    expectedFingerprint: String
): ParsedPublicIdentity {
    val matching = contactPayloads.mapNotNull { raw ->
        try {
            parsePublicIdentity(raw).takeIf { it.fingerprint == expectedFingerprint }
        } catch (_: Exception) {
            null
        }
    }
    return matching.firstOrNull { it.authenticatedBinding && it.transportPeerId != null }
        ?: throw IllegalArgumentException(
            "MLS exchange ke liye saved signed MESHX2 contact zaroori hai. MESHX1 legacy contact supported nahi."
        )
}

internal fun createSignedMlsKeyPackageEnvelope(
    identityPayload: String,
    keyPackage: ByteArray,
    signingKey: PrivateKey
): String {
    require(keyPackage.isNotEmpty() && keyPackage.size <= MAX_MLS_ENVELOPE_PART_BYTES) {
        "MLS KeyPackage must be between 1 byte and 1 MiB."
    }
    val signature = signMlsEnvelope(
        identityPayload, MLS_KEY_PACKAGE_DOMAIN, listOf(keyPackage), signingKey
    )
    val json = JSONObject()
        .put("version", 1)
        .put("identity", identityPayload)
        .put("key_package", Base64.encodeToString(keyPackage, Base64.NO_WRAP))
        .put("signature", Base64.encodeToString(signature, Base64.NO_WRAP))
    return MLS_KEY_PACKAGE_ENVELOPE_PREFIX +
        Base64.encodeToString(json.toString().toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
}

internal fun verifySignedMlsKeyPackageEnvelope(
    raw: String,
    expectedIdentity: ParsedPublicIdentity
): ByteArray {
    require(raw.startsWith(MLS_KEY_PACKAGE_ENVELOPE_PREFIX) && raw.length <= 2_000_000) {
        "Signed MESHX MLS KeyPackage envelope required."
    }
    val payload = Base64.decode(raw.removePrefix(MLS_KEY_PACKAGE_ENVELOPE_PREFIX), Base64.DEFAULT)
    require(payload.size <= 1_500_000) { "MLS KeyPackage envelope is too large." }
    val json = JSONObject(String(payload, Charsets.UTF_8))
    require(json.getInt("version") == 1) { "Unsupported MLS KeyPackage envelope version." }
    val identityPayload = json.getString("identity")
    val keyPackage = Base64.decode(json.getString("key_package"), Base64.DEFAULT)
    require(keyPackage.isNotEmpty() && keyPackage.size <= MAX_MLS_ENVELOPE_PART_BYTES) {
        "MLS KeyPackage must be between 1 byte and 1 MiB."
    }
    verifyMlsEnvelopeSignature(
        identityPayload, expectedIdentity, MLS_KEY_PACKAGE_DOMAIN,
        listOf(keyPackage), json.getString("signature")
    )
    return keyPackage
}

internal fun createSignedMlsInvitationEnvelope(
    identityPayload: String,
    invitation: MlsInvitation,
    signingKey: PrivateKey
): String {
    require(invitation.welcomeMessage.isNotEmpty() &&
        invitation.welcomeMessage.size <= MAX_MLS_ENVELOPE_PART_BYTES &&
        invitation.ratchetTree.isNotEmpty() &&
        invitation.ratchetTree.size <= MAX_MLS_ENVELOPE_PART_BYTES
    ) { "MLS Welcome and ratchet tree must each be between 1 byte and 1 MiB." }
    val signature = signMlsEnvelope(
        identityPayload, MLS_INVITATION_DOMAIN,
        listOf(invitation.welcomeMessage, invitation.ratchetTree), signingKey
    )
    val json = JSONObject()
        .put("version", 1)
        .put("identity", identityPayload)
        .put("welcome", Base64.encodeToString(invitation.welcomeMessage, Base64.NO_WRAP))
        .put("tree", Base64.encodeToString(invitation.ratchetTree, Base64.NO_WRAP))
        .put("signature", Base64.encodeToString(signature, Base64.NO_WRAP))
    return MLS_INVITATION_ENVELOPE_PREFIX +
        Base64.encodeToString(json.toString().toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
}

internal fun verifySignedMlsInvitationEnvelope(
    raw: String,
    expectedIdentity: ParsedPublicIdentity
): MlsInvitation {
    require(raw.startsWith(MLS_INVITATION_ENVELOPE_PREFIX) && raw.length <= 4_000_000) {
        "Signed MESHX MLS invitation envelope required."
    }
    val payload = Base64.decode(raw.removePrefix(MLS_INVITATION_ENVELOPE_PREFIX), Base64.DEFAULT)
    require(payload.size <= 3_000_000) { "MLS invitation envelope is too large." }
    val json = JSONObject(String(payload, Charsets.UTF_8))
    require(json.getInt("version") == 1) { "Unsupported MLS invitation envelope version." }
    val identityPayload = json.getString("identity")
    val welcome = Base64.decode(json.getString("welcome"), Base64.DEFAULT)
    val tree = Base64.decode(json.getString("tree"), Base64.DEFAULT)
    require(welcome.isNotEmpty() && welcome.size <= MAX_MLS_ENVELOPE_PART_BYTES &&
        tree.isNotEmpty() && tree.size <= MAX_MLS_ENVELOPE_PART_BYTES
    ) { "MLS Welcome or ratchet tree has an invalid size." }
    verifyMlsEnvelopeSignature(
        identityPayload, expectedIdentity, MLS_INVITATION_DOMAIN,
        listOf(welcome, tree), json.getString("signature")
    )
    return MlsInvitation(welcome, tree)
}

private fun pendingMlsSetupPreferenceKey(kind: String, chatId: String): String =
    "pending_mls_${kind}_${chatId}"

private fun loadPendingMlsSetupEnvelope(
    prefs: android.content.SharedPreferences,
    kind: String,
    chatId: String
): String {
    val stored = prefs.getString(pendingMlsSetupPreferenceKey(kind, chatId), null) ?: return ""
    return decryptLocalRecord(stored)
}

private fun sendMlsSetupEnvelope(peerId: String, envelope: String): String {
    val bytes = envelope.toByteArray(Charsets.UTF_8)
    require(bytes.isNotEmpty() && bytes.size <= 1024 * 1024) {
        "Signed MLS setup envelope exceeds the 1 MiB transport limit."
    }
    return try {
        NativeMeshx.sendCiphertext(peerId, bytes)
    } finally {
        bytes.fill(0)
    }
}

private fun makeQrBitmap(payload: String): android.graphics.Bitmap {
    val matrix = QRCodeWriter().encode(payload, BarcodeFormat.QR_CODE, 640, 640)
    val bitmap = android.graphics.Bitmap.createBitmap(640, 640, android.graphics.Bitmap.Config.ARGB_8888)
    for (x in 0 until 640) for (y in 0 until 640) {
        bitmap.setPixel(x, y, if (matrix[x, y]) android.graphics.Color.BLACK else android.graphics.Color.WHITE)
    }
    return bitmap
}

@Composable
private fun MeshxHome() {
    val context = LocalContext.current
    val prefs = remember { context.getSharedPreferences(PREFS_NAME, android.content.Context.MODE_PRIVATE) }
    var nativeTransportStatus by remember { mutableStateOf("Preparing secure MESHX identity…") }
    var nativeTransportReady by remember { mutableStateOf(false) }
    var relayAddress by remember { mutableStateOf(prefs.getString("relay_address", "") ?: "") }
    var bootstrapAddresses by remember {
        mutableStateOf(prefs.getString("bootstrap_peers", "") ?: "")
    }
    LaunchedEffect(Unit) {
        try {
            val transportIdentity = loadOrCreateTransportIdentity(prefs)
            val startResult = NativeMeshx.start(transportIdentity)
            nativeTransportStatus = startResult
            nativeTransportReady = startResult.startsWith("MESHX libp2p swarm starting")
                || startResult.contains("MESHX libp2p TCP listener active")
            val savedBootstrapPeers = prefs.getString("bootstrap_peers", "") ?: ""
            if (nativeTransportReady && savedBootstrapPeers.isNotBlank()) {
                nativeTransportStatus = NativeMeshx.addBootstrapPeers(savedBootstrapPeers)
            }
            val savedRelayAddress = prefs.getString("relay_address", "") ?: ""
            if (nativeTransportReady && savedRelayAddress.isNotBlank()) {
                nativeTransportStatus = NativeMeshx.addRelayPeer(savedRelayAddress)
            }
        } catch (error: Exception) {
            nativeTransportStatus = "MESHX transport identity error: ${error.localizedMessage ?: "secure identity unavailable"}"
            nativeTransportReady = false
        }
    }
    LaunchedEffect(nativeTransportReady) {
        if (nativeTransportReady) {
            while (true) {
                delay(1500)
                nativeTransportStatus = NativeMeshx.status()
            }
        }
    }
    var identity by remember { mutableStateOf<MeshxIdentity?>(null) }
    var importText by remember { mutableStateOf("") }
    var contactPublicKeys by remember {
        mutableStateOf(prefs.getStringSet("contact_public_keys", emptySet())?.toSet() ?: emptySet())
    }
    var contacts by remember {
        mutableStateOf(
            contactPublicKeys.mapNotNull { payload ->
                try { parsePublicIdentity(payload).fingerprint } catch (_: Exception) { null }
            }.distinct().ifEmpty {
                prefs.getStringSet("contacts", emptySet())?.toList() ?: emptyList()
            }
        )
    }
    var contactTransportPeers by remember {
        mutableStateOf(prefs.getStringSet("contact_transport_peers", emptySet())?.toSet() ?: emptySet())
    }
    var verifiedContacts by remember {
        mutableStateOf(prefs.getStringSet("verified_contacts", emptySet())?.toSet() ?: emptySet())
    }
    var pendingTransportRotation by remember { mutableStateOf<PendingContactTransportRotation?>(null) }
    var status by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var selectedChat by remember { mutableStateOf<String?>(null) }
    var messageDraft by remember { mutableStateOf("") }
    var localMessages by remember { mutableStateOf(loadLocalMessages(prefs)) }
    val latestLocalMessages by rememberUpdatedState(localMessages)
    val latestContactPublicKeys by rememberUpdatedState(contactPublicKeys)
    val latestContactTransportPeers by rememberUpdatedState(contactTransportPeers)
    val latestVerifiedContacts by rememberUpdatedState(verifiedContacts)
    val mlsRepository = remember { MlsStateRepository(context) }
    var mlsChatStatus by remember { mutableStateOf<String?>(null) }
    var mlsKeyPackageText by remember { mutableStateOf("") }
    var mlsInvitationText by remember { mutableStateOf("") }
    var mlsCiphertextText by remember { mutableStateOf("") }
    var mlsIncomingCiphertextText by remember { mutableStateOf("") }
    var mlsBusy by remember { mutableStateOf(false) }
    LaunchedEffect(selectedChat) {
        mlsCiphertextText = ""
        mlsIncomingCiphertextText = ""
        val chatId = selectedChat
        mlsKeyPackageText = if (chatId == null) "" else
            runCatching { loadPendingMlsSetupEnvelope(prefs, "key_package", chatId) }.getOrDefault("")
        mlsInvitationText = if (chatId == null) "" else
            runCatching { loadPendingMlsSetupEnvelope(prefs, "invitation", chatId) }.getOrDefault("")
    }

    // Poll the currently open contact for signed MLS setup envelopes and chat
    // ciphertext. Ordinary messages stay queued until the MLS group is joined.
    LaunchedEffect(nativeTransportReady, selectedChat) {
        val chatId = selectedChat
        if (nativeTransportReady && chatId != null) {
            while (true) {
                delay(1500)
                try {
                    val currentIdentity = identity ?: loadOrCreateIdentity(prefs).also { identity = it }
                    val peerId = latestContactTransportPeers.firstOrNull { it.startsWith("$chatId#") }
                        ?.substringAfter("#")
                    val groupRecordId = "meshx-chat-" +
                        listOf(currentIdentity.fingerprint, chatId).sorted().joinToString("-")
                    if (peerId != null) {
                        val rawBatch = NativeMeshx.pollIncomingCiphertexts(peerId)
                        // First persist every received opaque envelope locally (AES-GCM)
                        // so a process restart does not discard messages already read from libp2p.
                        val pending = loadPendingIncomingEnvelopes(prefs).toMutableMap()
                        val batch = org.json.JSONArray(rawBatch)
                        for (index in 0 until batch.length()) {
                            val item = batch.getJSONObject(index)
                            if (item.getString("sender_peer_id") != peerId) continue
                            val id = item.getString("message_id").lowercase()
                            if (id !in pending) pending[id] = item.toString()
                        }
                        check(prefs.edit().putStringSet(
                            "pending_incoming_ciphertexts",
                            pending.values.map { encryptLocalRecord(it) }.toSet()
                        ).commit()) { "Pending encrypted messages could not be saved to device storage." }

                        val processedIncomingIds = loadProcessedIncomingIds(prefs).toMutableSet()
                        for ((messageId, rawEnvelope) in pending.toMap()) {
                            val item = JSONObject(rawEnvelope)
                            if (item.getString("sender_peer_id") != peerId) continue
                            if (messageId in processedIncomingIds) {
                                NativeMeshx.ackIncomingCiphertext(messageId)
                                pending.remove(messageId)
                                prefs.edit().putStringSet(
                                    "pending_incoming_ciphertexts",
                                    pending.values.map { encryptLocalRecord(it) }.toSet()
                                ).commit()
                                continue
                            }
                            val byteArray = item.getJSONArray("ciphertext")
                            val encrypted = ByteArray(byteArray.length()) { byteArray.getInt(it).toByte() }
                            try {
                                val setupText = String(encrypted, Charsets.UTF_8)
                                if (setupText.startsWith("MESHXK1:") || setupText.startsWith("MESHXI1:")) {
                                    require(chatId in latestVerifiedContacts) {
                                        "Contact fingerprint verify karein; signed MLS setup abhi accept nahi kiya gaya."
                                    }
                                    val expectedContact = findSignedMlsContactIdentity(latestContactPublicKeys, chatId)
                                    if (setupText.startsWith("MESHXK1:")) {
                                        val publicPackage = verifySignedMlsKeyPackageEnvelope(setupText, expectedContact)
                                        publicPackage.fill(0)
                                        val storageKey = pendingMlsSetupPreferenceKey("key_package", chatId)
                                        val existingStored = prefs.getString(storageKey, null)
                                        val existing = existingStored?.let { decryptLocalRecord(it) }
                                        require(existing == null || existing == setupText) {
                                            "Ek signed KeyPackage pehle se pending hai. Pehle usko resolve karein."
                                        }
                                        val updatedProcessedIds = processedIncomingIds + messageId
                                        check(prefs.edit()
                                            .putString(storageKey, encryptLocalRecord(setupText))
                                            .putStringSet("processed_incoming_ids", updatedProcessedIds.map { encryptLocalRecord(it) }.toSet())
                                            .commit()) { "Signed KeyPackage device par securely save nahi hua." }
                                        processedIncomingIds.add(messageId)
                                        mlsKeyPackageText = setupText
                                        mlsChatStatus = "Signed KeyPackage Internet se receive aur verify ho gaya. Ab invitation banayein."
                                    } else {
                                        val invitation = verifySignedMlsInvitationEnvelope(setupText, expectedContact)
                                        try {
                                            val storageKey = pendingMlsSetupPreferenceKey("invitation", chatId)
                                            val existingStored = prefs.getString(storageKey, null)
                                            val existing = existingStored?.let { decryptLocalRecord(it) }
                                            require(existing == null || existing == setupText) {
                                                "Ek signed invitation pehle se pending hai. Pehle usko resolve karein."
                                            }
                                            val updatedProcessedIds = processedIncomingIds + messageId
                                            check(prefs.edit()
                                                .putString(storageKey, encryptLocalRecord(setupText))
                                                .putStringSet("processed_incoming_ids", updatedProcessedIds.map { encryptLocalRecord(it) }.toSet())
                                                .commit()) { "Signed invitation device par securely save nahi hui." }
                                            processedIncomingIds.add(messageId)
                                            mlsInvitationText = setupText
                                            mlsChatStatus = "Signed Welcome invitation Internet se receive aur verify ho gayi. Ab join karein."
                                        } finally {
                                            invitation.welcomeMessage.fill(0)
                                            invitation.ratchetTree.fill(0)
                                        }
                                    }
                                    NativeMeshx.ackIncomingCiphertext(messageId)
                                    pending.remove(messageId)
                                    check(prefs.edit().putStringSet(
                                        "pending_incoming_ciphertexts",
                                        pending.values.map { encryptLocalRecord(it) }.toSet()
                                    ).commit()) { "Received MLS setup envelope cleanup could not be saved." }
                                    continue
                                }
                                if (!mlsRepository.restoreAndValidateGroupState(groupRecordId)) {
                                    // Keep ordinary MLS messages queued until this contact's group is joined.
                                    continue
                                }
                                val plaintext = mlsRepository.decryptAndAdvanceGroupState(groupRecordId, encrypted)
                                try {
                                    val encoded = Base64.encodeToString(plaintext, Base64.NO_WRAP)
                                    val entry = "$chatId#${System.currentTimeMillis()}#$encoded"
                                    val updated = latestLocalMessages + entry
                                    val updatedProcessedIds = processedIncomingIds + messageId
                                    check(prefs.edit()
                                        .putStringSet("local_messages", updated.map { encryptLocalRecord(it) }.toSet())
                                        .putStringSet("processed_incoming_ids", updatedProcessedIds.map { encryptLocalRecord(it) }.toSet())
                                        .commit()) { "Received message and duplicate-protection marker could not be saved securely." }
                                    localMessages = updated
                                    processedIncomingIds.add(messageId)
                                    NativeMeshx.ackIncomingCiphertext(messageId)
                                    pending.remove(messageId)
                                    check(prefs.edit().putStringSet(
                                        "pending_incoming_ciphertexts",
                                        pending.values.map { encryptLocalRecord(it) }.toSet()
                                    ).commit()) { "Processed message cleanup could not be saved." }
                                    mlsChatStatus = "New encrypted message received, authenticated, saved, and acknowledged."
                                } finally {
                                    plaintext.fill(0)
                                }
                            } catch (messageError: Exception) {
                                mlsChatStatus = "Incoming message could not be authenticated/decrypted: ${messageError.localizedMessage ?: "unknown error"}"
                            } finally {
                                encrypted.fill(0)
                            }
                        }
                    }
                } catch (receiveError: Exception) {
                    mlsChatStatus = "Receive error: ${receiveError.localizedMessage ?: "unknown error"}"
                }
            }
        }
    }
    val persistContactIdentity: (String, ParsedPublicIdentity) -> Unit = { raw, parsed ->
        val id = parsed.fingerprint
        val updated = (contacts + id).distinct()
        val updatedKeys = contactPublicKeys.filterNot { existing ->
            try { parsePublicIdentity(existing).fingerprint == id } catch (_: Exception) { false }
        }.toSet() + raw
        val updatedTransportPeers = contactTransportPeers.filterNot { it.startsWith("$id#") }.toMutableSet().apply {
            parsed.transportPeerId?.let { add("$id#$it") }
        }.toSet()
        check(prefs.edit().putStringSet("contacts", updated.toSet()).putStringSet("contact_public_keys", updatedKeys)
            .putStringSet("contact_transport_peers", updatedTransportPeers).commit()) { "Contact identity could not be saved." }
        contacts = updated
        contactPublicKeys = updatedKeys
        contactTransportPeers = updatedTransportPeers
    }
    val qrImagePicker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) {
            try {
                val bitmap = context.contentResolver.openInputStream(uri)?.use {
                    BitmapFactory.decodeStream(it)
                } ?: throw IllegalStateException("Image could not be opened.")
                val pixels = IntArray(bitmap.width * bitmap.height)
                bitmap.getPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)
                val source = RGBLuminanceSource(bitmap.width, bitmap.height, pixels)
                val result = MultiFormatReader().decode(BinaryBitmap(HybridBinarizer(source)))
                importText = result.text
                status = "QR read ho gaya. Ab Add contact dabayein."
                error = null
            } catch (e: Exception) {
                error = "Is image mein readable MESHX QR nahi mila."
                status = null
            }
        }
    }

    MaterialTheme {
        Surface(Modifier.fillMaxSize()) {
            Column(
                Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Spacer(Modifier.height(24.dp))
                Text("MESHX", style = MaterialTheme.typography.headlineLarge)
                Text("Global private messaging")
                NearbyBluetoothPanel()
                NearbyWifiDirectPanel(
                    activeChatName = selectedChat,
                    outgoingCiphertextBase64 = mlsCiphertextText,
                    onDecryptCiphertext = { chatId, encrypted ->
                        val currentIdentity = identity ?: loadOrCreateIdentity(prefs)
                        val groupRecordId = "meshx-chat-" +
                            listOf(currentIdentity.fingerprint, chatId).sorted().joinToString("-")
                        check(mlsRepository.restoreAndValidateGroupState(groupRecordId)) {
                            "This chat has no valid joined MLS group on this device."
                        }
                        mlsRepository.decryptAndAdvanceGroupState(groupRecordId, encrypted)
                    },
                    isMessageAlreadyProcessed = { messageId ->
                        messageId in loadProcessedIncomingIds(prefs)
                    },
                    onAuthenticatedMessage = { chatId, messageId, plaintext ->
                        val processed = loadProcessedIncomingIds(prefs)
                        check(messageId !in processed) { "Nearby message was already processed." }
                        val encoded = Base64.encodeToString(plaintext, Base64.NO_WRAP)
                        val entry = "$chatId#${System.currentTimeMillis()}#$encoded"
                        val updated = latestLocalMessages + entry
                        val updatedProcessed = processed + messageId
                        check(prefs.edit()
                            .putStringSet("local_messages", updated.map { encryptLocalRecord(it) }.toSet())
                            .putStringSet("processed_incoming_ids", updatedProcessed.map { encryptLocalRecord(it) }.toSet())
                            .commit()) { "Authenticated nearby message and duplicate marker could not be saved securely." }
                        localMessages = updated
                        mlsChatStatus = "Nearby Wi-Fi Direct message authenticated, saved, and ready for acknowledgement."
                    }
                )
                Text("Android prototype — Internet delivery and end-to-end chat are still in development.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                Spacer(Modifier.height(24.dp))
                Text("Your digital identity", style = MaterialTheme.typography.titleLarge)
                Text("No phone number or email required. Your private key stays in Android Keystore on this device.")
                Button(onClick = {
                    try {
                        identity = loadOrCreateIdentity(prefs)
                        error = null
                    } catch (e: Exception) {
                        error = e.localizedMessage ?: "Identity could not be created."
                    }
                }) { Text(if (identity == null) "Create / Load my identity" else "Refresh my identity") }

                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                identity?.let { current ->
                    Card(Modifier.fillMaxWidth().padding(top = 12.dp)) {
                        Column(Modifier.padding(16.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                            Text("MESHX ID", style = MaterialTheme.typography.titleMedium)
                            Text(current.fingerprint, style = MaterialTheme.typography.headlineSmall)
                            Image(
                                bitmap = makeQrBitmap(current.qrPayload).asImageBitmap(),
                                contentDescription = "Public identity QR code",
                                modifier = Modifier.height(220.dp)
                            )
                            Text("Signed MESHX2 identity. Transport Peer ID: ${current.transportPeerId}")
                            Text("QR mein sirf public keys aur unka signature hai. Private keys kabhi share nahi hoti.")
                        }
                    }
                }

                Spacer(Modifier.height(24.dp))
                Text("Add a contact", style = MaterialTheme.typography.titleLarge)
                Text("MESHX2 QR signed transport-key binding ke saath preferred hai. Older MESHX1 identity bhi import ho sakti hai, lekin usmein transport binding nahi hoti.")
                Text("Security: contact ka fingerprint us person se kisi alag trusted channel par compare karein. Sirf QR scan karna identity verify nahi karta.", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                OutlinedButton(onClick = { qrImagePicker.launch("image/*") }) { Text("Import QR image from gallery") }
                OutlinedTextField(
                    value = importText,
                    onValueChange = { importText = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Paste public identity") },
                    minLines = 2
                )
                Button(onClick = {
                    try {
                        val raw = importText.trim()
                        val parsed = parsePublicIdentity(raw)
                        require(identity?.fingerprint != parsed.fingerprint) { "This is your own identity." }
                        when (classifyContactImport(contactPublicKeys, parsed)) {
                            ContactImportDecision.TRANSPORT_KEY_CHANGED -> {
                                pendingTransportRotation = PendingContactTransportRotation(raw, parsed)
                                status = null
                                error = "SECURITY WARNING: Contact ki signed transport key badli hai. Confirm se pehle fingerprint trusted channel par dobara compare karein."
                            }
                            ContactImportDecision.SIGNED_BINDING_DOWNGRADE ->
                                throw IllegalArgumentException("Signed MESHX2 contact ko unsigned MESHX1 par downgrade nahi kar sakte.")
                            ContactImportDecision.SAME_IDENTITY -> {
                                status = "Yeh contact pehle se saved hai. Koi key change nahi hua."
                                error = null
                            }
                            ContactImportDecision.ADD, ContactImportDecision.UPGRADE_LEGACY -> {
                                persistContactIdentity(raw, parsed)
                                status = if (parsed.authenticatedBinding) "Signed MESHX2 identity saved: ${parsed.fingerprint}"
                                    else "Legacy MESHX1 identity added: ${parsed.fingerprint}. Transport binding nahi hai."
                                importText = ""
                                error = null
                            }
                        }
                    } catch (e: Exception) {
                        error = e.localizedMessage ?: "Invalid public identity."
                        status = null
                    }
                }) { Text("Add contact") }
                status?.let { Text(it, color = MaterialTheme.colorScheme.primary) }
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                pendingTransportRotation?.let { pending ->
                    Card(Modifier.fillMaxWidth().padding(top = 10.dp)) {
                        Column(Modifier.padding(16.dp)) {
                            Text("Transport key change detected", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.error)
                            Text("Identity fingerprint same hai, lekin signed transport Peer ID badal gaya. Yeh legitimate device migration bhi ho sakta hai aur account takeover bhi. Purani key bina confirm replace nahi hogi.")
                            Text("New Peer ID: ${pending.parsed.transportPeerId ?: "Unavailable"}", style = MaterialTheme.typography.bodySmall)
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Button(onClick = {
                                    persistContactIdentity(pending.rawPayload, pending.parsed)
                                    pendingTransportRotation = null
                                    importText = ""
                                    error = null
                                    status = "Transport key replacement explicitly accepted. Fingerprint independently verify karein."
                                }) { Text("Confirm key change") }
                                TextButton(onClick = {
                                    pendingTransportRotation = null
                                    importText = ""
                                    error = null
                                    status = "Key change rejected. Saved contact key unchanged."
                                }) { Text("Reject") }
                            }
                        }
                    }
                }

                Spacer(Modifier.height(16.dp))
                Text("Saved contacts (" + contacts.size + ")", style = MaterialTheme.typography.titleMedium)
                if (contacts.isEmpty()) Text("Abhi koi contact nahi hai.")
                contacts.forEach { contact ->
                    Card(Modifier.fillMaxWidth().padding(top = 8.dp)) {
                        Row(
                            Modifier.fillMaxWidth().padding(14.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(Modifier.weight(1f)) {
                                Text(contact, style = MaterialTheme.typography.bodySmall)
                                val boundPeerId = contactTransportPeers.firstOrNull { it.startsWith("$contact#") }?.substringAfter("#")
                                Text(
                                    if (boundPeerId != null) "Signed transport binding: ${boundPeerId.take(18)}…" else "Legacy identity — transport key not bound",
                                    color = if (boundPeerId != null) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                                    style = MaterialTheme.typography.labelSmall
                                )
                                Text(if (contact in verifiedContacts) "Manually fingerprint-verified" else "Not verified", color = if (contact in verifiedContacts) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall)
                                TextButton(onClick = {
                                    val updated = if (contact in verifiedContacts) verifiedContacts - contact else verifiedContacts + contact
                                    prefs.edit().putStringSet("verified_contacts", updated).apply()
                                    verifiedContacts = updated
                                }) { Text(if (contact in verifiedContacts) "Remove verification" else "I compared fingerprint") }
                                if (boundPeerId != null) {
                                    TextButton(
                                        onClick = {
                                            val result = NativeMeshx.findPeer(boundPeerId)
                                            status = result
                                            error = result.takeIf { it.startsWith("MESHX peer discovery error:") }
                                        },
                                        enabled = nativeTransportReady
                                    ) { Text("Search via DHT") }
                                }
                            }
                            TextButton(onClick = {
                                selectedChat = contact
                                messageDraft = ""
                            }) { Text("Open chat") }
                        }
                    }
                }

                selectedChat?.let { chatId ->
                    Spacer(Modifier.height(16.dp))
                    Card(Modifier.fillMaxWidth()) {
                        Column(Modifier.fillMaxWidth().padding(16.dp)) {
                            Text("Chat with $chatId", style = MaterialTheme.typography.titleMedium)
                            Text("MLS ciphertext aur signed setup envelopes direct peer ko bheje ja sakte hain. Configured relay connected ho to app mailbox storage ki request karti hai; receiver ka open chat har 1.5 second baad pending inbox check karta hai. Auto setup receive ke liye contact chat open rakhein. Public offline delivery tabhi chalegi jab compatible relay server live aur reachable ho; manual copy/paste fallback bhi available hai.", color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.bodySmall)
                            val ownIdentity = identity ?: runCatching { loadOrCreateIdentity(prefs).also { identity = it } }.getOrNull()
                            val groupRecordId = ownIdentity?.let { "meshx-chat-" + listOf(it.fingerprint, chatId).sorted().joinToString("-") }
                            val keyPackageRecordId = ownIdentity?.let { "meshx-keypackage-" + it.fingerprint + "-" + chatId }
                            val chatTransportPeerId = contactTransportPeers.firstOrNull { it.startsWith("$chatId#") }?.substringAfter("#")
                            mlsChatStatus?.let { Text(it, color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.bodySmall) }
                            Text("1. Recipient: create a signed one-time KeyPackage", style = MaterialTheme.typography.titleSmall)
                            Text("MLS setup ke liye dono taraf signed MESHX2 identity aur independently compared fingerprint zaroori hai.", style = MaterialTheme.typography.bodySmall)
                            Button(enabled = !mlsBusy && ownIdentity != null && keyPackageRecordId != null, onClick = {
                                mlsBusy = true
                                try {
                                    require(chatId in verifiedContacts) { "Pehle contact ka fingerprint trusted channel par compare karke 'I compared fingerprint' dabayein." }
                                    findSignedMlsContactIdentity(contactPublicKeys, chatId)
                                    val bytes = mlsRepository.createAndSaveKeyPackage(keyPackageRecordId!!, ownIdentity!!.fingerprint.toByteArray(Charsets.UTF_8))
                                    try {
                                        mlsKeyPackageText = createSignedMlsKeyPackageEnvelope(
                                            ownIdentity!!.qrPayload, bytes, loadIdentitySigningPrivateKey()
                                        )
                                    } finally { bytes.fill(0) }
                                    mlsChatStatus = "Signed KeyPackage ready. Is MESHXK1 code ko contact ko share karein."
                                } catch (e: Exception) { mlsChatStatus = "KeyPackage error: ${e.localizedMessage ?: "unknown"}" }
                                finally { mlsBusy = false }
                            }) { Text("Create signed KeyPackage") }
                            OutlinedTextField(value = mlsKeyPackageText, onValueChange = { mlsKeyPackageText = it }, modifier = Modifier.fillMaxWidth(), label = { Text("Signed MESHXK1 KeyPackage") }, minLines = 2)
                            Button(
                                enabled = !mlsBusy && nativeTransportReady && chatTransportPeerId != null && mlsKeyPackageText.startsWith("MESHXK1:"),
                                onClick = {
                                    mlsBusy = true
                                    try {
                                        mlsChatStatus = sendMlsSetupEnvelope(chatTransportPeerId!!, mlsKeyPackageText.trim())
                                    } catch (e: Exception) {
                                        mlsChatStatus = "KeyPackage send error: ${e.localizedMessage ?: "unknown"}"
                                    } finally { mlsBusy = false }
                                }
                            ) { Text("Send KeyPackage via Internet") }
                            Text("2. Inviter: verify KeyPackage and sign Welcome invitation", style = MaterialTheme.typography.titleSmall)
                            Button(enabled = !mlsBusy && ownIdentity != null && groupRecordId != null && mlsKeyPackageText.isNotBlank(), onClick = {
                                mlsBusy = true
                                try {
                                    require(chatId in verifiedContacts) { "Pehle contact ka fingerprint trusted channel par compare karein." }
                                    val expectedContact = findSignedMlsContactIdentity(contactPublicKeys, chatId)
                                    val publicKeyPackage = verifySignedMlsKeyPackageEnvelope(mlsKeyPackageText.trim(), expectedContact)
                                    try {
                                        if (!mlsRepository.restoreAndValidateGroupState(groupRecordId!!)) {
                                            mlsRepository.createAndSaveGroupState(groupRecordId, ownIdentity!!.fingerprint.toByteArray(Charsets.UTF_8))
                                        }
                                        val invite = mlsRepository.addContactToGroup(groupRecordId, publicKeyPackage)
                                        try {
                                            mlsInvitationText = createSignedMlsInvitationEnvelope(
                                                ownIdentity!!.qrPayload, invite, loadIdentitySigningPrivateKey()
                                            )
                                        } finally {
                                            invite.welcomeMessage.fill(0)
                                            invite.ratchetTree.fill(0)
                                        }
                                    } finally { publicKeyPackage.fill(0) }
                                    prefs.edit().remove(pendingMlsSetupPreferenceKey("key_package", chatId)).commit()
                                    mlsChatStatus = "Signed Welcome ready. MESHXI1 invitation contact ko share karein."
                                } catch (e: Exception) { mlsChatStatus = "Invitation error: ${e.localizedMessage ?: "unknown"}" }
                                finally { mlsBusy = false }
                            }) { Text("Verify and create signed invitation") }
                            OutlinedTextField(value = mlsInvitationText, onValueChange = { mlsInvitationText = it }, modifier = Modifier.fillMaxWidth(), label = { Text("Signed MESHXI1 Welcome invitation") }, minLines = 2)
                            Button(
                                enabled = !mlsBusy && nativeTransportReady && chatTransportPeerId != null && mlsInvitationText.startsWith("MESHXI1:"),
                                onClick = {
                                    mlsBusy = true
                                    try {
                                        mlsChatStatus = sendMlsSetupEnvelope(chatTransportPeerId!!, mlsInvitationText.trim())
                                    } catch (e: Exception) {
                                        mlsChatStatus = "Invitation send error: ${e.localizedMessage ?: "unknown"}"
                                    } finally { mlsBusy = false }
                                }
                            ) { Text("Send invitation via Internet") }
                            Text("3. Recipient: verify inviter identity and join", style = MaterialTheme.typography.titleSmall)
                            Button(enabled = !mlsBusy && ownIdentity != null && groupRecordId != null && keyPackageRecordId != null && mlsInvitationText.isNotBlank(), onClick = {
                                mlsBusy = true
                                try {
                                    require(chatId in verifiedContacts) { "Pehle inviter ka fingerprint trusted channel par compare karein." }
                                    val expectedContact = findSignedMlsContactIdentity(contactPublicKeys, chatId)
                                    val invitation = verifySignedMlsInvitationEnvelope(mlsInvitationText.trim(), expectedContact)
                                    try {
                                        mlsRepository.joinAndSaveInvitedGroup(
                                            keyPackageRecordId!!, groupRecordId!!,
                                            invitation.welcomeMessage, invitation.ratchetTree
                                        )
                                    } finally {
                                        invitation.welcomeMessage.fill(0)
                                        invitation.ratchetTree.fill(0)
                                    }
                                    prefs.edit().remove(pendingMlsSetupPreferenceKey("invitation", chatId)).commit()
                                    mlsChatStatus = "Signed MLS invitation verified; group join successful."
                                } catch (e: Exception) { mlsChatStatus = "Group join error: ${e.localizedMessage ?: "unknown"}" }
                                finally { mlsBusy = false }
                            }) { Text("Verify and join encrypted chat") }
                            Divider()
                            Text("4. Encrypt and exchange messages", style = MaterialTheme.typography.titleSmall)
                            OutlinedTextField(value = messageDraft, onValueChange = { messageDraft = it }, modifier = Modifier.fillMaxWidth(), label = { Text("Message to encrypt") }, minLines = 2)
                            Button(enabled = !mlsBusy && groupRecordId != null && messageDraft.isNotBlank() && runCatching { mlsRepository.restoreAndValidateGroupState(groupRecordId) }.getOrDefault(false), onClick = {
                                mlsBusy = true
                                try {
                                    val ciphertext = mlsRepository.encryptAndAdvanceGroupState(groupRecordId!!, messageDraft.trim().toByteArray(Charsets.UTF_8))
                                    mlsCiphertextText = Base64.encodeToString(ciphertext, Base64.NO_WRAP)
                                    ciphertext.fill(0); messageDraft = ""
                                    mlsChatStatus = "MLS encrypted message ready. Ciphertext recipient ko share karein."
                                } catch (e: Exception) { mlsChatStatus = "Encryption error: ${e.localizedMessage ?: "unknown"}" }
                                finally { mlsBusy = false }
                            }) { Text("Encrypt message") }
                            OutlinedTextField(value = mlsCiphertextText, onValueChange = { mlsCiphertextText = it }, modifier = Modifier.fillMaxWidth(), label = { Text("Encrypted ciphertext (retry / manual fallback)") }, minLines = 2)
                            Button(
                                enabled = !mlsBusy && nativeTransportReady && chatTransportPeerId != null && mlsCiphertextText.isNotBlank(),
                                onClick = {
                                    mlsBusy = true
                                    try {
                                        val encrypted = Base64.decode(mlsCiphertextText.trim(), Base64.DEFAULT)
                                        try {
                                            mlsChatStatus = NativeMeshx.sendCiphertext(chatTransportPeerId!!, encrypted)
                                        } finally {
                                            encrypted.fill(0)
                                        }
                                    } catch (sendError: Exception) {
                                        mlsChatStatus = "Send error: ${sendError.localizedMessage ?: "unknown error"}"
                                    } finally {
                                        mlsBusy = false
                                    }
                                }
                            ) { Text("Send encrypted message (direct + relay mailbox)") }
                            OutlinedTextField(value = mlsIncomingCiphertextText, onValueChange = { mlsIncomingCiphertextText = it }, modifier = Modifier.fillMaxWidth(), label = { Text("Paste received ciphertext (manual fallback)") }, minLines = 2)
                            Button(enabled = !mlsBusy && groupRecordId != null && mlsIncomingCiphertextText.isNotBlank() && runCatching { mlsRepository.restoreAndValidateGroupState(groupRecordId) }.getOrDefault(false), onClick = {
                                mlsBusy = true
                                try {
                                    val encrypted = Base64.decode(mlsIncomingCiphertextText.trim(), Base64.DEFAULT)
                                    val plaintext = mlsRepository.decryptAndAdvanceGroupState(groupRecordId!!, encrypted)
                                    try {
                                        val encoded = Base64.encodeToString(plaintext, Base64.NO_WRAP)
                                        val entry = "$chatId#${System.currentTimeMillis()}#$encoded"
                                        val updated = localMessages + entry
                                        check(prefs.edit().putStringSet("local_messages", updated.map { encryptLocalRecord(it) }.toSet()).commit())
                                        localMessages = updated
                                        mlsIncomingCiphertextText = ""
                                        mlsChatStatus = "Authenticated message decrypted and saved."
                                    } finally { encrypted.fill(0); plaintext.fill(0) }
                                } catch (e: Exception) { mlsChatStatus = "Decryption error: ${e.localizedMessage ?: "unknown"}" }
                                finally { mlsBusy = false }
                            }) { Text("Decrypt received message") }
                            Text("Decrypted chat history", style = MaterialTheme.typography.titleSmall)
                            val chatEntries = localMessages.mapNotNull { entry ->
                                val parts = entry.split("#", limit = 3)
                                if (parts.size == 3 && parts[0] == chatId) try { parts[1].toLong() to String(Base64.decode(parts[2], Base64.DEFAULT), Charsets.UTF_8) } catch (_: Exception) { null } else null
                            }.sortedBy { it.first }
                            chatEntries.forEach { (_, body) ->
                                Surface(color = MaterialTheme.colorScheme.secondaryContainer, shape = MaterialTheme.shapes.medium, modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp)) {
                                    Text(body, Modifier.padding(10.dp))
                                }
                            }
                            TextButton(onClick = { selectedChat = null }) { Text("Close") }
                        }
                    }
                }

                Spacer(Modifier.height(24.dp))
                Text("Circuit relay + offline mailbox", style = MaterialTheme.typography.titleMedium)
                Text("Optional: enter a live MESHX relay server multiaddress. The app requests offline mailbox storage and fetches pending messages while connected. The relay cannot read properly MLS-encrypted ciphertext.")
                OutlinedTextField(
                    value = relayAddress,
                    onValueChange = { relayAddress = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Relay / mailbox server multiaddress") },
                    placeholder = { Text("/ip4/host/tcp/4001/p2p/RELAY_PEER_ID") },
                    minLines = 1
                )
                Button(
                    onClick = {
                        val result = NativeMeshx.addRelayPeer(relayAddress.trim())
                        status = result
                        val rejected = result.contains("error:", ignoreCase = true)
                            || result.contains("rejected", ignoreCase = true)
                        error = if (rejected) result else null
                        if (!rejected) {
                            relayAddress = relayAddress.trim()
                            prefs.edit().putString("relay_address", relayAddress).apply()
                        }
                    },
                    enabled = nativeTransportReady && relayAddress.isNotBlank()
                ) { Text("Connect to relay server") }
                Text("Relay connection aur mailbox request status neeche update hoga. Sirf address save karna live server ya successful offline delivery ka saboot nahi hai.")

                Text("Internet peer discovery", style = MaterialTheme.typography.titleMedium)
                Text("Optional: add bootstrap node multiaddresses, one per line. These are network entry points, not contacts. You must use a live MESHX-compatible node operated by you or a trusted independent operator.")
                OutlinedTextField(
                    value = bootstrapAddresses,
                    onValueChange = { bootstrapAddresses = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Bootstrap multiaddresses") },
                    placeholder = { Text("/ip4/host/tcp/port/p2p/PeerID") },
                    minLines = 2
                )
                Button(
                    onClick = {
                        prefs.edit().putString("bootstrap_peers", bootstrapAddresses.trim()).apply()
                        status = NativeMeshx.addBootstrapPeers(bootstrapAddresses)
                        error = if (status?.startsWith("MESHX bootstrap error:") == true) status else null
                    },
                    enabled = nativeTransportReady && bootstrapAddresses.isNotBlank()
                ) { Text("Connect to bootstrap peers") }
                Text(nativeTransportStatus, style = MaterialTheme.typography.bodySmall)
                Text("A bootstrap address only starts peer discovery. It does not guarantee that another contact is reachable, that messages are delivered, or that a relay is available.")
                Text("MESHX2 contacts can be searched by their signed transport Peer ID. DHT results are candidate routing peers only; they do not prove that the recipient is online.")
                Spacer(Modifier.height(8.dp))
                Text("Direct encrypted messaging", style = MaterialTheme.typography.titleMedium)
                Text("Chat screen MLS ciphertext ko saved contact ke signed Peer ID par bhejti hai. Configured relay par offline mailbox store/fetch/ack protocol bhi connect hai. Public server deployment, background delivery, media transfer aur Bluetooth / Wi-Fi abhi complete ya verify nahi hue hain.")
                Spacer(Modifier.height(12.dp))
                Text("Send request queue hona delivery/read receipt nahi hai. Message ciphertext retry field mein rehta hai; incoming messages sirf matching contact ke joined MLS group mein decrypt hote hain. Recovery phrase aur encrypted backup abhi baaki hain.", style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}
