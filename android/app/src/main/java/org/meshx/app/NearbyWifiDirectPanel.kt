package org.meshx.app

import android.Manifest
import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.wifi.p2p.WifiP2pConfig
import android.net.wifi.p2p.WifiP2pDevice
import android.net.wifi.p2p.WifiP2pInfo
import android.net.wifi.p2p.WifiP2pManager
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
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
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
internal fun NearbyWifiDirectPanel() {
    val context = LocalContext.current
    val manager = remember {
        context.getSystemService(Context.WIFI_P2P_SERVICE) as? WifiP2pManager
    }
    val channel = remember(manager) {
        manager?.initialize(context, context.mainLooper, null)
    }
    val scope = rememberCoroutineScope()
    val requiredPermissions = remember {
        if (Build.VERSION.SDK_INT >= 33) {
            listOf(Manifest.permission.NEARBY_WIFI_DEVICES)
        } else {
            listOf(Manifest.permission.ACCESS_FINE_LOCATION)
        }
    }
    var permissionGranted by remember {
        mutableStateOf(requiredPermissions.all {
            context.checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED
        })
    }
    var wifiP2pEnabled by remember { mutableStateOf(false) }
    var peers by remember { mutableStateOf(emptyList<WifiP2pDevice>()) }
    var groupFormed by remember { mutableStateOf(false) }
    var isGroupOwner by remember { mutableStateOf(false) }
    var groupOwnerAddress by remember { mutableStateOf("") }
    var ciphertextBase64 by remember { mutableStateOf("") }
    var receivedBase64 by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var wifiStatus by remember {
        mutableStateOf("Wi-Fi Direct is optional. Discover and connect to a nearby Android phone.")
    }

    val permissionRequest = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { grants ->
        permissionGranted = requiredPermissions.all {
            grants[it] == true || context.checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED
        }
        wifiStatus = if (permissionGranted) {
            "Permission granted. Tap Scan nearby phones."
        } else {
            "Nearby Wi-Fi permission denied. Wi-Fi Direct remains disabled."
        }
    }

    DisposableEffect(manager, channel, permissionGranted) {
        if (manager == null || channel == null) {
            onDispose { }
        } else {
            val receiver = object : BroadcastReceiver() {
                override fun onReceive(receiveContext: Context?, intent: Intent?) {
                    when (intent?.action) {
                        WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION -> {
                            val state = intent.getIntExtra(
                                WifiP2pManager.EXTRA_WIFI_STATE,
                                WifiP2pManager.WIFI_P2P_STATE_DISABLED
                            )
                            wifiP2pEnabled = state == WifiP2pManager.WIFI_P2P_STATE_ENABLED
                            if (!wifiP2pEnabled) {
                                groupFormed = false
                                groupOwnerAddress = ""
                                wifiStatus = "Turn on Wi-Fi to use Wi-Fi Direct."
                            }
                        }
                        WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION -> {
                            if (permissionGranted) {
                                manager.requestPeers(channel) { list ->
                                    peers = list.deviceList.toList()
                                    if (peers.isEmpty()) {
                                        wifiStatus = "No nearby MESHX-capable phone found yet. Keep both screens open and scan again."
                                    } else {
                                        wifiStatus = "Found " + peers.size + " nearby device(s). Choose the other phone."
                                    }
                                }
                            }
                        }
                        WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION -> {
                            if (permissionGranted) {
                                manager.requestConnectionInfo(channel) { info: WifiP2pInfo ->
                                    groupFormed = info.groupFormed
                                    isGroupOwner = info.isGroupOwner
                                    groupOwnerAddress = info.groupOwnerAddress?.hostAddress ?: ""
                                    wifiStatus = if (info.groupFormed) {
                                        if (info.isGroupOwner) {
                                            "Connected. This phone is the group owner; wait here to receive ciphertext."
                                        } else {
                                            "Connected. This phone can send ciphertext to the group owner."
                                        }
                                    } else {
                                        "Wi-Fi Direct connection is not active."
                                    }
                                }
                            }
                        }
                    }
                }
            }
            val filter = IntentFilter().apply {
                addAction(WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION)
                addAction(WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION)
                addAction(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION)
            }
            if (Build.VERSION.SDK_INT >= 33) {
                context.registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED)
            } else {
                context.registerReceiver(receiver, filter)
            }
            onDispose {
                runCatching { context.unregisterReceiver(receiver) }
            }
        }
    }

    Card(Modifier.fillMaxWidth().padding(vertical = 12.dp)) {
        Column(
            Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text("Nearby Wi-Fi Direct", style = MaterialTheme.typography.titleMedium)
            Text("Connect nearby Android phones without internet. This sends opaque MLS ciphertext only; it does not send plaintext or provide worldwide delivery.")

            if (manager == null || channel == null) {
                Text("Wi-Fi Direct is not supported by this device.")
            } else {
                Button(onClick = {
                    if (!permissionGranted) {
                        permissionRequest.launch(requiredPermissions.toTypedArray())
                    } else {
                        manager.discoverPeers(channel, object : WifiP2pManager.ActionListener {
                            override fun onSuccess() {
                                wifiStatus = "Scanning for nearby Wi-Fi Direct devices…"
                            }
                            override fun onFailure(reason: Int) {
                                wifiStatus = "Wi-Fi Direct scan failed. Android error code: " + reason
                            }
                        })
                    }
                }) {
                    Text(if (permissionGranted) "Scan nearby phones" else "Allow nearby Wi-Fi access")
                }

                peers.forEach { peer ->
                    val label = (peer.deviceName.ifBlank { "Nearby device" }) + " · " + peer.deviceAddress
                    TextButton(onClick = {
                        if (!permissionGranted) {
                            permissionRequest.launch(requiredPermissions.toTypedArray())
                        } else {
                            val config = WifiP2pConfig().apply {
                                deviceAddress = peer.deviceAddress
                                groupOwnerIntent = 0
                            }
                            wifiStatus = "Requesting Wi-Fi Direct connection to " + peer.deviceName + "…"
                            manager.connect(channel, config, object : WifiP2pManager.ActionListener {
                                override fun onSuccess() {
                                    wifiStatus = "Connection request sent. Accept the request on the other phone if Android asks."
                                }
                                override fun onFailure(reason: Int) {
                                    wifiStatus = "Connection request failed. Android error code: " + reason
                                }
                            })
                        }
                    }) {
                        Text(label)
                    }
                }

                Text(
                    if (groupFormed) {
                        if (isGroupOwner) "Connected role: group owner" else "Connected role: client"
                    } else {
                        "Status: not connected"
                    },
                    style = MaterialTheme.typography.bodySmall
                )

                OutlinedTextField(
                    value = ciphertextBase64,
                    onValueChange = { ciphertextBase64 = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("MLS ciphertext (Base64)") },
                    minLines = 2
                )

                Button(
                    enabled = groupFormed && !isGroupOwner && !busy && ciphertextBase64.isNotBlank(),
                    onClick = {
                        scope.launch {
                            busy = true
                            wifiStatus = "Sending encrypted ciphertext over Wi-Fi Direct…"
                            try {
                                val bytes = Base64.decode(ciphertextBase64.trim(), Base64.DEFAULT)
                                try {
                                    withContext(Dispatchers.IO) {
                                        WifiDirectCiphertextTransport.connectAndSend(groupOwnerAddress, bytes)
                                    }
                                    wifiStatus = "Ciphertext sent. The receiving phone must authenticate/decrypt it in the matching MLS group."
                                } finally {
                                    bytes.fill(0)
                                }
                            } catch (error: Exception) {
                                wifiStatus = "Wi-Fi Direct send failed: " + (error.localizedMessage ?: "unknown")
                            } finally {
                                busy = false
                            }
                        }
                    }
                ) {
                    Text("Send encrypted ciphertext")
                }

                Button(
                    enabled = groupFormed && isGroupOwner && !busy,
                    onClick = {
                        scope.launch {
                            busy = true
                            wifiStatus = "Waiting up to 60 seconds for the other phone to send ciphertext…"
                            try {
                                val received = withContext(Dispatchers.IO) {
                                    val server = WifiDirectCiphertextTransport.openServer(groupOwnerAddress)
                                    try {
                                        WifiDirectCiphertextTransport.acceptAndReceive(server)
                                    } finally {
                                        server.close()
                                    }
                                }
                                try {
                                    receivedBase64 = Base64.encodeToString(received, Base64.NO_WRAP)
                                    wifiStatus = "Ciphertext received. Import it into the matching MLS chat to authenticate and decrypt."
                                } finally {
                                    received.fill(0)
                                }
                            } catch (error: Exception) {
                                wifiStatus = "Wi-Fi Direct receive failed: " + (error.localizedMessage ?: "unknown")
                            } finally {
                                busy = false
                            }
                        }
                    }
                ) {
                    Text("Receive encrypted ciphertext")
                }

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

            Text(wifiStatus, style = MaterialTheme.typography.bodySmall)
            Text("Keep both phones awake and this screen open. One transfer is handled per receive session. Background delivery, automatic MLS chat integration, and physical two-phone radio testing are not complete.")
        }
    }
}
