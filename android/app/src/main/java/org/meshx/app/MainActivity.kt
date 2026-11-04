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
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

private const val IDENTITY_ALIAS = "meshx_identity_v1"
private const val PREFS_NAME = "meshx_local_contacts"

private const val MESSAGE_KEY_ALIAS = "meshx_local_messages_aes_v1"

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

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { MeshxHome() }
    }
}

private data class MeshxIdentity(val fingerprint: String, val qrPayload: String)

private fun fingerprint(publicKey: ByteArray): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(publicKey)
    return digest.take(16).joinToString("") { "%02X".format(it) }.chunked(4).joinToString("-")
}

private fun loadOrCreateIdentity(): MeshxIdentity {
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
    val publicKey = keyStore.getCertificate(IDENTITY_ALIAS).publicKey.encoded
    return MeshxIdentity(
        fingerprint(publicKey),
        "MESHX1:" + Base64.encodeToString(publicKey, Base64.NO_WRAP)
    )
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
    val nativeTransportStatus = remember { NativeMeshx.status() }
    val prefs = remember { context.getSharedPreferences(PREFS_NAME, android.content.Context.MODE_PRIVATE) }
    var identity by remember { mutableStateOf<MeshxIdentity?>(null) }
    var importText by remember { mutableStateOf("") }
    var contactPublicKeys by remember {
        mutableStateOf(prefs.getStringSet("contact_public_keys", emptySet())?.toSet() ?: emptySet())
    }
    var contacts by remember {
        mutableStateOf(
            contactPublicKeys.mapNotNull { payload ->
                try {
                    val encoded = payload.removePrefix("MESHX1:")
                    fingerprint(Base64.decode(encoded, Base64.DEFAULT))
                } catch (_: Exception) { null }
            }.distinct().ifEmpty {
                prefs.getStringSet("contacts", emptySet())?.toList() ?: emptyList()
            }
        )
    }
    var verifiedContacts by remember {
        mutableStateOf(prefs.getStringSet("verified_contacts", emptySet())?.toSet() ?: emptySet())
    }
    var status by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var selectedChat by remember { mutableStateOf<String?>(null) }
    var messageDraft by remember { mutableStateOf("") }
    var localMessages by remember { mutableStateOf(loadLocalMessages(prefs)) }
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
                Text("Android prototype — Internet delivery and end-to-end chat are still in development.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                Spacer(Modifier.height(24.dp))
                Text("Your digital identity", style = MaterialTheme.typography.titleLarge)
                Text("No phone number or email required. Your private key stays in Android Keystore on this device.")
                Button(onClick = {
                    try {
                        identity = loadOrCreateIdentity()
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
                            Text("QR mein sirf public key hai. Private key kabhi share na karein.")
                        }
                    }
                }

                Spacer(Modifier.height(24.dp))
                Text("Add a contact", style = MaterialTheme.typography.titleLarge)
                Text("QR image gallery se select karein, ya public identity text paste karein.")
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
                        require(raw.startsWith("MESHX1:")) { "MESHX1 public identity required." }
                        val keyBytes = Base64.decode(raw.removePrefix("MESHX1:"), Base64.DEFAULT)
                        KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(keyBytes))
                        val id = fingerprint(keyBytes)
                        require(identity?.fingerprint != id) { "This is your own identity." }
                        val updated = (contacts + id).distinct()
                        val publicIdentity = "MESHX1:" + Base64.encodeToString(keyBytes, Base64.NO_WRAP)
                        val updatedKeys = contactPublicKeys + publicIdentity
                        prefs.edit()
                            .putStringSet("contacts", updated.toSet())
                            .putStringSet("contact_public_keys", updatedKeys)
                            .apply()
                        contacts = updated
                        contactPublicKeys = updatedKeys
                        importText = ""
                        status = "Contact added: $id"
                        error = null
                    } catch (e: Exception) {
                        error = e.localizedMessage ?: "Invalid public identity."
                        status = null
                    }
                }) { Text("Add contact") }
                status?.let { Text(it, color = MaterialTheme.colorScheme.primary) }
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }

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
                                Text(if (contact in verifiedContacts) "Manually fingerprint-verified" else "Not verified", color = if (contact in verifiedContacts) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall)
                                TextButton(onClick = {
                                    val updated = if (contact in verifiedContacts) verifiedContacts - contact else verifiedContacts + contact
                                    prefs.edit().putStringSet("verified_contacts", updated).apply()
                                    verifiedContacts = updated
                                }) { Text(if (contact in verifiedContacts) "Remove verification" else "I compared fingerprint") }
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
                            Text(
                                "LOCAL PROTOTYPE — saved only on this phone. No Internet delivery or end-to-end encryption yet.",
                                color = MaterialTheme.colorScheme.error,
                                style = MaterialTheme.typography.bodySmall
                            )
                            Spacer(Modifier.height(12.dp))
                            val chatEntries = localMessages.mapNotNull { entry ->
                                val parts = entry.split("#", limit = 3)
                                if (parts.size == 3 && parts[0] == chatId) {
                                    try {
                                        parts[1].toLong() to String(Base64.decode(parts[2], Base64.DEFAULT), Charsets.UTF_8)
                                    } catch (_: Exception) { null }
                                } else null
                            }.sortedBy { it.first }
                            if (chatEntries.isEmpty()) {
                                Text("No local messages yet.")
                            } else {
                                chatEntries.forEach { (_, body) ->
                                    Surface(
                                        color = MaterialTheme.colorScheme.secondaryContainer,
                                        shape = MaterialTheme.shapes.medium,
                                        modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp)
                                    ) {
                                        Text(body, Modifier.padding(10.dp))
                                    }
                                }
                            }
                            OutlinedTextField(
                                value = messageDraft,
                                onValueChange = { messageDraft = it },
                                modifier = Modifier.fillMaxWidth(),
                                label = { Text("Write a local test message") },
                                minLines = 2
                            )
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Button(onClick = {
                                    val body = messageDraft.trim()
                                    if (body.isNotEmpty()) {
                                        val encoded = Base64.encodeToString(body.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
                                        val entry = "$chatId#${System.currentTimeMillis()}#$encoded"
                                        val updated = localMessages + entry
                                        val encryptedRecords = updated.map { encryptLocalRecord(it) }.toSet()
                                        prefs.edit().putStringSet("local_messages", encryptedRecords).apply()
                                        localMessages = updated
                                        messageDraft = ""
                                    }
                                }, enabled = messageDraft.isNotBlank()) { Text("Save on this phone") }
                                TextButton(onClick = { selectedChat = null }) { Text("Close") }
                            }
                        }
                    }
                }

                Spacer(Modifier.height(24.dp))
                Text("Messaging engine — in development", style = MaterialTheme.typography.titleMedium)
                Text(nativeTransportStatus, style = MaterialTheme.typography.bodySmall)
                Text("Global Internet peer discovery, end-to-end encrypted delivery, media transfer, and nearby Bluetooth / Wi-Fi messaging are not connected yet.")
                Spacer(Modifier.height(12.dp))
                Text("Contact public keys and fingerprints are stored locally for future secure session setup. No message is sent yet. Recovery phrase, encrypted backup and messaging transport are still to be built.", style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}
