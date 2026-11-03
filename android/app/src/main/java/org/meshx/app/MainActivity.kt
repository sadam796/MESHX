package org.meshx.app

import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec

private const val IDENTITY_ALIAS = "meshx_identity_v1"

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { MeshxHome() }
    }
}

private data class MeshxIdentity(
    val fingerprint: String,
    val qrPayload: String
)

private fun loadOrCreateIdentity(): MeshxIdentity {
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    if (!keyStore.containsAlias(IDENTITY_ALIAS)) {
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore"
        )
        generator.initialize(
            KeyGenParameterSpec.Builder(
                IDENTITY_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build()
        )
        generator.generateKeyPair()
    }

    val publicKey = keyStore.getCertificate(IDENTITY_ALIAS).publicKey.encoded
    val digest = MessageDigest.getInstance("SHA-256").digest(publicKey)
    val fingerprint = digest.take(8).joinToString("") { "%02X".format(it) }
        .chunked(4).joinToString("-")
    val encodedKey = Base64.encodeToString(publicKey, Base64.NO_WRAP)
    return MeshxIdentity(fingerprint, "MESHX1:$encodedKey")
}

private fun makeQrBitmap(payload: String): android.graphics.Bitmap {
    val matrix = QRCodeWriter().encode(payload, BarcodeFormat.QR_CODE, 640, 640)
    val bitmap = android.graphics.Bitmap.createBitmap(640, 640, android.graphics.Bitmap.Config.ARGB_8888)
    for (x in 0 until 640) {
        for (y in 0 until 640) {
            bitmap.setPixel(x, y, if (matrix[x, y]) android.graphics.Color.BLACK else android.graphics.Color.WHITE)
        }
    }
    return bitmap
}

@androidx.compose.runtime.Composable
private fun MeshxHome() {
    var identity by remember { mutableStateOf<MeshxIdentity?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    MaterialTheme {
        Surface(modifier = Modifier.fillMaxSize()) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Top
            ) {
                Spacer(modifier = Modifier.height(28.dp))
                Text("MESHX", style = MaterialTheme.typography.headlineLarge)
                Text("Global private messaging", modifier = Modifier.padding(top = 8.dp))
                Spacer(modifier = Modifier.height(28.dp))

                Text("Your digital identity", style = MaterialTheme.typography.titleLarge)
                Text(
                    "Create an identity without a phone number or email. Your private key stays inside Android Keystore on this phone.",
                    modifier = Modifier.padding(top = 10.dp)
                )
                Spacer(modifier = Modifier.height(18.dp))

                Button(onClick = {
                    try {
                        identity = loadOrCreateIdentity()
                        error = null
                    } catch (e: Exception) {
                        error = e.localizedMessage ?: "Could not create identity."
                    }
                }) {
                    Text(if (identity == null) "Create / Load my identity" else "Refresh my identity")
                }

                error?.let {
                    Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(top = 12.dp))
                }

                identity?.let { current ->
                    Spacer(modifier = Modifier.height(20.dp))
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(
                            modifier = Modifier.padding(18.dp),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Text("MESHX ID", style = MaterialTheme.typography.titleMedium)
                            Text(current.fingerprint, style = MaterialTheme.typography.headlineSmall)
                            Spacer(modifier = Modifier.height(12.dp))
                            Image(
                                bitmap = makeQrBitmap(current.qrPayload).asImageBitmap(),
                                contentDescription = "MESHX public identity QR code",
                                modifier = Modifier.height(220.dp)
                            )
                            Text(
                                "This QR contains your public identity only. Never share your recovery phrase or private key.",
                                modifier = Modifier.padding(top = 12.dp)
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(24.dp))
                Text("Messaging engine — in development", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Internet peer discovery, encrypted message delivery, media transfer, and nearby Bluetooth / Wi-Fi messaging are not connected yet.",
                    modifier = Modifier.padding(top = 8.dp)
                )
                Spacer(modifier = Modifier.height(24.dp))
                Text(
                    "Prototype notice: this identity is stored on this device and is not yet recoverable on another phone. Recovery phrase and encrypted backup will be added before real-world use.",
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }
}
