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
internal fun NearbyWifiDirectPanel(
    activeChatName: String?,
    outgoingCiphertextBase64: String,
    onDecryptCiphertext: suspend (String, ByteArray) -> ByteArray,
    onAuthenticatedMessage: (String, ByteArray) -> Unit
) {
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
    var peers by remember { mutableStateOf(emptyList<WifiP2pDevice>()) }
    var groupFormed by remember { mutableStateOf(false) }
    var isGroupOwner by remember { mutableStateOf(false) }
    var groupOwnerAddress by remember { mutableStateOf("") }
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
                            if (state != WifiP2pManager.WIFI_P2P_STATE_ENABLED) {
                                groupFormed = false
                                groupOwnerAddress = ""
                                wifiStatus = "Turn on Wi-Fi to use Wi-Fi Direct."
                            }
                        }
                        WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION -> {
                            if (permissionGranted) {
                                manager.requestPeers(channel) { list ->
                                    peers = list.deviceList.toList()
                                    wifiStatus = if (peers.isEmpty()) {
                                        "No nearby device found yet. Keep both screens open and scan again."
                                    } else {
                                        "Found " + peers.size + " nearby device(s). Choose the other phone."
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
                                            "Connected as group owner. This phone receives; the other phone sends."
                                        } else {
                                            "Connected as client. This phone sends to the group owner."
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
            Text("Nearby Wi-Fi Direct · MLS chat", style = MaterialTheme.typography.titleMedium)
            Text("Nearby-only transfer without internet. Messages are created by the open MLS chat, then authenticated and decrypted before being saved. No plaintext is sent over the socket.")
            Text(
                activeChatName?.let { "Active encrypted chat: $it" } ?: "Open an encrypted chat below to use Wi-Fi Direct.",
                color = MaterialTheme.colorScheme.primary,
                style = MaterialTheme.typography.bodySmall
            )

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
                                    wifiStatus = "Connection request sent. Accept it on the other phone if Android asks."
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
                        if (isGroupOwner) "Connected role: group owner (receiver)" else "Connected role: client (sender)"
                    } else {
                        "Status: not connected"
                    },
                    style = MaterialTheme.typography.bodySmall
                )

                Button(
                    enabled = groupFormed && !isGroupOwner && !busy &&
                        activeChatName != null && outgoingCiphertextBase64.isNotBlank(),
                    onClick = {
                        val chatId = activeChatName ?: return@Button
                        scope.launch {
                            busy = true
                            wifiStatus = "Sending the active chat's MLS ciphertext…"
                            try {
                                val bytes = Base64.decode(outgoingCiphertextBase64.trim(), Base64.DEFAULT)
                                try {
                                    withContext(Dispatchers.IO) {
                                        WifiDirectCiphertextTransport.connectAndSend(groupOwnerAddress, bytes)
                                    }
                                    wifiStatus = "Encrypted message sent to the nearby phone. MLS will authenticate it before display."
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
                    Text("Send current MLS message")
                }

                Button(
                    enabled = groupFormed && isGroupOwner && !busy && activeChatName != null,
                    onClick = {
                        val chatId = activeChatName ?: return@Button
                        scope.launch {
                            busy = true
                            wifiStatus = "Waiting up to 60 seconds for an encrypted message…"
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
                                    val plaintext = withContext(Dispatchers.IO) {
                                        onDecryptCiphertext(chatId, received)
                                    }
                                    try {
                                        onAuthenticatedMessage(chatId, plaintext)
                                        wifiStatus = "MLS authenticated the nearby message. It was saved in the open chat."
                                    } finally {
                                        plaintext.fill(0)
                                    }
                                } finally {
                                    received.fill(0)
                                }
                            } catch (error: Exception) {
                                wifiStatus = "Message rejected or Wi-Fi Direct receive failed: " +
                                    (error.localizedMessage ?: "unknown")
                            } finally {
                                busy = false
                            }
                        }
                    }
                ) {
                    Text("Receive + authenticate MLS message")
                }
            }

            Text(wifiStatus, style = MaterialTheme.typography.bodySmall)
            Text("This prototype uses one direction per Wi-Fi Direct group: client sends, group owner receives. Keep both phones awake and this screen open. For a reply, reconnect with roles reversed. Background delivery, retries, and physical two-phone radio testing are still pending.")
        }
    }
}
