package org.meshx.app

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.content.pm.PackageManager
import android.os.Build
import android.util.Base64
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@SuppressLint("MissingPermission")
@Composable
internal fun NearbyBluetoothPanel() {
    val context = LocalContext.current
    val adapter = remember { BluetoothAdapter.getDefaultAdapter() }
    val scope = rememberCoroutineScope()
    var permissionGranted by remember {
        mutableStateOf(
            Build.VERSION.SDK_INT < 31 ||
                context.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED
        )
    }
    var pairedDevices by remember { mutableStateOf(emptyList<android.bluetooth.BluetoothDevice>()) }
    var selectedAddress by remember { mutableStateOf("") }
    var ciphertextBase64 by remember { mutableStateOf("") }
    var receivedBase64 by remember { mutableStateOf("") }
    var nearbyStatus by remember { mutableStateOf("Nearby Bluetooth is optional. Pair devices in Android Bluetooth settings first.") }
    var listening by remember { mutableStateOf(false) }
    val permissionRequest = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        permissionGranted = granted
        if (granted) nearbyStatus = "Bluetooth permission granted. Refresh paired devices."
        else nearbyStatus = "Bluetooth permission denied. Nearby transfer remains disabled."
    }

    Card(Modifier.fillMaxWidth().padding(vertical = 12.dp)) {
        Column(
            Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text("Nearby Bluetooth (paired devices)", style = MaterialTheme.typography.titleMedium)
            Text("Internet is not needed nearby. First pair both phones in Android Bluetooth settings. This screen transfers MLS ciphertext only, not plaintext.")
            if (adapter == null) {
                Text("This device does not support Bluetooth.")
            } else {
                Button(onClick = {
                    if (!permissionGranted && Build.VERSION.SDK_INT >= 31) {
                        permissionRequest.launch(Manifest.permission.BLUETOOTH_CONNECT)
                    } else {
                        try {
                            pairedDevices = adapter.bondedDevices?.toList().orEmpty()
                            if (pairedDevices.isEmpty()) nearbyStatus = "No paired devices found. Pair the other phone in Android settings."
                            else {
                                selectedAddress = pairedDevices.first().address
                                nearbyStatus = "Found ${pairedDevices.size} paired device(s). Select a recipient."
                            }
                        } catch (error: Exception) {
                            nearbyStatus = "Bluetooth error: ${error.localizedMessage ?: "unknown"}"
                        }
                    }
                }) { Text(if (permissionGranted) "Refresh paired devices" else "Allow Bluetooth access") }

                pairedDevices.forEach { device ->
                    val label = runCatching { "${device.name ?: "Unknown device"} · ${device.address}" }.getOrDefault(device.address)
                    androidx.compose.material3.TextButton(onClick = { selectedAddress = device.address }) {
                        Text(if (selectedAddress == device.address) "✓ $label" else label)
                    }
                }

                OutlinedTextField(
                    value = ciphertextBase64,
                    onValueChange = { ciphertextBase64 = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("MLS ciphertext (Base64)") },
                    minLines = 2
                )
                Button(
                    enabled = permissionGranted && selectedAddress.isNotBlank() && ciphertextBase64.isNotBlank(),
                    onClick = {
                        val target = pairedDevices.firstOrNull { it.address == selectedAddress }
                        if (target == null) {
                            nearbyStatus = "Choose a paired recipient first."
                        } else {
                            scope.launch {
                                nearbyStatus = "Connecting to paired phone…"
                                try {
                                    val bytes = Base64.decode(ciphertextBase64.trim(), Base64.DEFAULT)
                                    try {
                                        withContext(Dispatchers.IO) {
                                            BluetoothCiphertextTransport.connectAndSend(target, bytes)
                                        }
                                        nearbyStatus = "Ciphertext sent over Bluetooth. Recipient must authenticate/decrypt it in the correct MLS group."
                                    } finally { bytes.fill(0) }
                                } catch (error: Exception) {
                                    nearbyStatus = "Bluetooth send failed: ${error.localizedMessage ?: "unknown"}"
                                }
                            }
                        }
                    }
                ) { Text("Send encrypted ciphertext") }

                Button(
                    enabled = permissionGranted && !listening,
                    onClick = {
                        scope.launch {
                            listening = true
                            nearbyStatus = "Waiting for a paired MESHX phone to connect… Keep this screen open."
                            try {
                                val received = withContext(Dispatchers.IO) {
                                    val server = BluetoothCiphertextTransport.openServer(adapter)
                                    try { BluetoothCiphertextTransport.acceptAndReceive(server) }
                                    finally { server.close() }
                                }
                                try {
                                    receivedBase64 = Base64.encodeToString(received, Base64.NO_WRAP)
                                    nearbyStatus = "Ciphertext received. Paste/import it into the matching MLS chat to authenticate and decrypt."
                                } finally { received.fill(0) }
                            } catch (error: Exception) {
                                nearbyStatus = "Bluetooth receive failed: ${error.localizedMessage ?: "unknown"}"
                            } finally { listening = false }
                        }
                    }
                ) { Text(if (listening) "Listening…" else "Receive encrypted ciphertext") }

                if (receivedBase64.isNotBlank()) {
                    OutlinedTextField(
                        value = receivedBase64,
                        onValueChange = { receivedBase64 = it },
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("Received ciphertext (Base64)") },
                        minLines = 2
                    )
                }
            }
            Text(nearbyStatus, style = MaterialTheme.typography.bodySmall)
            Text("This first UI uses already-paired devices and one transfer per receive session. Keep the app open. Background delivery, automatic MLS chat integration, device discovery without pairing, and two-phone radio testing are not complete.")
        }
    }
}
