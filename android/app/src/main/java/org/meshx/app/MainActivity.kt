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

private const val IDENTITY_ALIAS = "meshx_identity_v1"
private const val PREFS_NAME = "meshx_local_contacts"

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { MeshxHome() }
    }
}

private data class MeshxIdentity(val fingerprint: String, val qrPayload: String)

private fun fingerprint(publicKey: ByteArray): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(publicKey)
    return digest.take(8).joinToString("") { "%02X".format(it) }.chunked(4).joinToString("-")
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
    val prefs = remember { context.getSharedPreferences(PREFS_NAME, android.content.Context.MODE_PRIVATE) }
    var identity by remember { mutableStateOf<MeshxIdentity?>(null) }
    var importText by remember { mutableStateOf("") }
    var contacts by remember { mutableStateOf(prefs.getStringSet("contacts", emptySet())?.toList() ?: emptyList()) }
    var status by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val qrImagePicker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) {
            try {
                val bitmap = context.contentResolver.openInputStream(uri)?.use {
                    BitmapFactory.decodeStream(it)
                } ?: error("Image could not be opened.")
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
                        prefs.edit().putStringSet("contacts", updated.toSet()).apply()
                        contacts = updated
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
                        Text(contact, Modifier.padding(14.dp))
                    }
                }

                Spacer(Modifier.height(24.dp))
                Text("Messaging engine — in development", style = MaterialTheme.typography.titleMedium)
                Text("Global Internet peer discovery, end-to-end encrypted delivery, media transfer, and nearby Bluetooth / Wi-Fi messaging are not connected yet.")
                Spacer(Modifier.height(12.dp))
                Text("Prototype only: contacts currently store public-key fingerprints on this device. Live camera scanning, recovery phrase, encrypted backup and messaging transport are still to be built.", style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}
