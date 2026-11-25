package org.meshx.app

import android.util.Base64
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

@Composable
internal fun MESHXChatHomeScreen(
    contacts: List<String>,
    localMessages: Set<String>,
    selectedChat: String?,
    verifiedContacts: Set<String>,
    contactTransportPeers: Set<String>,
    internetEnabled: Boolean,
    bluetoothEnabled: Boolean,
    wifiDirectEnabled: Boolean,
    onInternetEnabledChange: (Boolean) -> Unit,
    onBluetoothEnabledChange: (Boolean) -> Unit,
    onWifiDirectEnabledChange: (Boolean) -> Unit,
    messageDraft: String,
    onMessageDraftChange: (String) -> Unit,
    canSendMessage: Boolean,
    sendBusy: Boolean,
    status: String?,
    onOpenChat: (String) -> Unit,
    onAddPublicIdentity: (String) -> String,
    onBackToChats: () -> Unit,
    onSendMessage: () -> Unit,
    onOpenSecureSetup: () -> Unit
) {
    var search by remember { mutableStateOf("") }
    var activeTab by remember { mutableStateOf("Chats") }
    var publicIdentityInput by remember { mutableStateOf("") }
    var contactNameInput by remember { mutableStateOf("") }
    val context = LocalContext.current
    val aliasPrefs = remember { context.getSharedPreferences("meshx_contact_names", android.content.Context.MODE_PRIVATE) }
    var contactAliases by remember { mutableStateOf(aliasPrefs.all.mapValues { it.value.toString() }) }
    var publicIdentityStatus by remember { mutableStateOf<String?>(null) }
    var showAddContact by remember { mutableStateOf(false) }
    var showSavedDialog by remember { mutableStateOf(false) }
    var savedContactFingerprint by remember { mutableStateOf<String?>(null) }
    var savedContactName by remember { mutableStateOf("") }
    var callNotice by remember { mutableStateOf<String?>(null) }
    val navy = Color(0xFF102A43)
    val green = Color(0xFF087E5B)
    val page = Color(0xFFF5F7F8)

    fun messageParts(raw: String): Triple<String, Long, String>? {
        val parts = raw.split("#", limit = 3)
        if (parts.size != 3) return null
        return try { Triple(parts[0], parts[1].toLong(), String(Base64.decode(parts[2], Base64.DEFAULT), Charsets.UTF_8)) }
        catch (_: Exception) { null }
    }

    fun addContact() {
        val result = onAddPublicIdentity(publicIdentityInput.trim())
        publicIdentityStatus = result
        if (result.startsWith("Added:") || result.startsWith("Already added:")) {
            try {
                val fingerprint = parsePublicIdentity(publicIdentityInput.trim()).fingerprint
                val label = contactNameInput.trim()
                if (label.isNotBlank()) {
                    aliasPrefs.edit().putString(fingerprint, label).apply()
                    contactAliases = aliasPrefs.all.mapValues { it.value.toString() }
                }
                savedContactFingerprint = fingerprint
                savedContactName = label.ifBlank { fingerprint }
                publicIdentityInput = ""
                contactNameInput = ""
                showAddContact = false
                showSavedDialog = true
            } catch (_: Exception) {
                publicIdentityStatus = "Contact added, but display name could not be saved."
            }
        }
    }

    Column(Modifier.fillMaxSize().background(page)) {
        Surface(color = Color(0xFF075E54), modifier = Modifier.fillMaxWidth()) {
            Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("MESHX", color = Color.White, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
                    Text(if (selectedChat == null) "Private messaging" else "End-to-end private chat", color = Color(0xFFD1E9E2), style = MaterialTheme.typography.bodySmall)
                }
                if (selectedChat != null) TextButton(onClick = onBackToChats) { Text("‹", color = Color.White, style = MaterialTheme.typography.titleLarge) }
                else {
                    TextButton(onClick = { activeTab = "Chats"; showAddContact = true }) { Text("＋", color = Color.White, style = MaterialTheme.typography.headlineSmall) }
                    TextButton(onClick = { activeTab = "Chats" }) { Text("⌕", color = Color.White, style = MaterialTheme.typography.headlineSmall) }
                    TextButton(onClick = { activeTab = "Settings" }) { Text("⋮", color = Color.White, style = MaterialTheme.typography.headlineSmall) }
                }
            }
        }
        if (selectedChat == null) {
            Row(Modifier.fillMaxWidth().background(Color.White).padding(horizontal = 10.dp, vertical = 3.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically) {
                Text("CONNECTION", color = Color(0xFF637781), style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                Column(horizontalAlignment = Alignment.CenterHorizontally) { Text("Internet", color = navy, style = MaterialTheme.typography.labelSmall); Switch(checked = internetEnabled, onCheckedChange = onInternetEnabledChange) }
                Column(horizontalAlignment = Alignment.CenterHorizontally) { Text("Bluetooth", color = navy, style = MaterialTheme.typography.labelSmall); Switch(checked = bluetoothEnabled, onCheckedChange = onBluetoothEnabledChange) }
                Column(horizontalAlignment = Alignment.CenterHorizontally) { Text("Wi-Fi", color = navy, style = MaterialTheme.typography.labelSmall); Switch(checked = wifiDirectEnabled, onCheckedChange = onWifiDirectEnabledChange) }
            }
            if (activeTab == "Settings") {
                Column(Modifier.weight(1f).fillMaxWidth().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("Settings", color = navy, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
                    Text("Your private MESHX account and connection options", color = Color(0xFF637381))
                    Surface(color = Color.White, shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text("Connection preferences", color = navy, fontWeight = FontWeight.Bold)
                            Row(verticalAlignment = Alignment.CenterVertically) { Column(Modifier.weight(1f)) { Text("Internet", color = navy, fontWeight = FontWeight.SemiBold); Text("MESHX Internet send aur inbox polling", color = Color(0xFF637381), style = MaterialTheme.typography.bodySmall) }; Switch(checked = internetEnabled, onCheckedChange = onInternetEnabledChange) }
                            Divider()
                            Row(verticalAlignment = Alignment.CenterVertically) { Column(Modifier.weight(1f)) { Text("Bluetooth", color = navy, fontWeight = FontWeight.SemiBold); Text("Experimental paired-device ciphertext panel", color = Color(0xFF637381), style = MaterialTheme.typography.bodySmall) }; Switch(checked = bluetoothEnabled, onCheckedChange = onBluetoothEnabledChange) }
                            Divider()
                            Row(verticalAlignment = Alignment.CenterVertically) { Column(Modifier.weight(1f)) { Text("Wi-Fi Direct", color = navy, fontWeight = FontWeight.SemiBold); Text("Experimental nearby encrypted transfer panel", color = Color(0xFF637781), style = MaterialTheme.typography.bodySmall) }; Switch(checked = wifiDirectEnabled, onCheckedChange = onWifiDirectEnabledChange) }
                        }
                    }
                    Surface(color = Color(0xFFE7F5EF), shape = RoundedCornerShape(14.dp)) { Text("Internet OFF chat send aur inbox polling rokta hai. Bluetooth / Wi-Fi switches sirf experimental panels ko enable karte hain; ye abhi normal chat ka automatic transport nahi hain.", Modifier.padding(14.dp), color = Color(0xFF075E54), style = MaterialTheme.typography.bodySmall) }
                    listOf("Account & recovery", "Privacy & security", "Notifications").forEach { item -> Surface(color = Color.White, shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) { Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) { Text(item, modifier = Modifier.weight(1f), color = navy, fontWeight = FontWeight.SemiBold); Text("›", color = green, style = MaterialTheme.typography.titleLarge) } } }
                    Button(onClick = onOpenSecureSetup, colors = ButtonDefaults.buttonColors(containerColor = green)) { Text("Secure chat setup") }
                }
            } else {
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(value = search, onValueChange = { search = it; if (it.trim().startsWith("MESHX2:")) { publicIdentityInput = it.trim(); publicIdentityStatus = null } },
                    modifier = Modifier.fillMaxWidth(), singleLine = true, shape = RoundedCornerShape(18.dp), placeholder = { Text("Search by Public ID") }, leadingIcon = { Text("⌕", style = MaterialTheme.typography.headlineSmall) })
                if (search.trim().startsWith("MESHX2:")) TextButton(onClick = { publicIdentityInput = search.trim(); contactNameInput = ""; showAddContact = true; search = "" }) { Text("Search / Add this Public ID", color = green) }
                Spacer(Modifier.height(12.dp))
                Text(if (activeTab == "Contacts") "CONTACTS" else "CHATS", color = Color(0xFF637781), style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(6.dp))
                val filtered = contacts.filter { c -> c.contains(search.trim(), ignoreCase = true) || (contactAliases[c]?.contains(search.trim(), ignoreCase = true) == true) || (search.isBlank() && c.isNotBlank()) }
                if (filtered.isEmpty()) {
                    Column(Modifier.fillMaxWidth().padding(top = 54.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                        Text("✉", color = green, style = MaterialTheme.typography.displayMedium); Spacer(Modifier.height(12.dp))
                        Text("No chats yet", color = navy, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                        Text("Tap + to add a friend using their MESHX public ID.", color = Color(0xFF637781), style = MaterialTheme.typography.bodyMedium)
                        Spacer(Modifier.height(14.dp)); Button(onClick = { showAddContact = true }, colors = ButtonDefaults.buttonColors(containerColor = green)) { Text("＋ Add a friend") }
                    }
                } else {
                    Column(Modifier.weight(1f).verticalScroll(rememberScrollState())) {
                        filtered.forEach { contact ->
                            val latest = localMessages.mapNotNull(::messageParts).filter { it.first == contact }.maxByOrNull { it.second }
                            val bound = contactTransportPeers.any { it.startsWith("$contact#") }
                            Row(Modifier.fillMaxWidth().padding(vertical = 3.dp).background(Color.White, RoundedCornerShape(18.dp)).clickable { onOpenChat(contact) }.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                                Surface(color = Color(0xFFDCEFE8), shape = CircleShape, modifier = Modifier.size(48.dp)) { Box(contentAlignment = Alignment.Center) { Text((contactAliases[contact]?.takeIf { it.isNotBlank() } ?: contact).take(2).uppercase(), color = green, fontWeight = FontWeight.Bold) } }
                                Spacer(Modifier.width(12.dp))
                                Column(Modifier.weight(1f)) { Text(contactAliases[contact]?.takeIf { it.isNotBlank() } ?: contact, color = navy, fontWeight = FontWeight.SemiBold, maxLines = 1); Text(latest?.third ?: if (bound) "Tap to open chat" else "Saved contact", color = Color(0xFF637781), style = MaterialTheme.typography.bodySmall, maxLines = 1) }
                                Text("›", color = Color(0xFF637781), style = MaterialTheme.typography.titleLarge)
                            }
                        }
                    }
                }
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) { Button(onClick = { showAddContact = true }, shape = CircleShape, colors = ButtonDefaults.buttonColors(containerColor = green), contentPadding = PaddingValues(horizontal = 20.dp, vertical = 12.dp)) { Text("＋", style = MaterialTheme.typography.titleLarge) } }
                publicIdentityStatus?.let { Text(it, color = if (it.startsWith("Added:") || it.startsWith("Already")) green else MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
            }
            NavigationBar(containerColor = Color.White, tonalElevation = 2.dp) {
                listOf("Chats", "Contacts", "Settings").forEach { tab ->
                    NavigationBarItem(
                        selected = activeTab == tab,
                        onClick = { activeTab = tab; search = "" },
                        icon = {
                            Text(
                                when (tab) {
                                    "Chats" -> "▤"
                                    "Contacts" -> "♙"
                                    else -> "⚙"
                                },
                                color = if (activeTab == tab) green else Color(0xFF637781),
                                style = MaterialTheme.typography.titleLarge
                            )
                        },
                        label = { Text(tab) },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = green,
                            selectedTextColor = green,
                            indicatorColor = Color(0xFFDDF3ED),
                            unselectedTextColor = Color(0xFF637781)
                        )
                    )
                    )\n                }
            }
        } else {
            Spacer(Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Surface(color = Color(0xFFDCEFE8), shape = CircleShape, modifier = Modifier.size(44.dp)) { Box(contentAlignment = Alignment.Center) { Text(selectedChat.take(2), color = green, fontWeight = FontWeight.Bold) } }
                Spacer(Modifier.width(10.dp))
                Column(Modifier.weight(1f)) { Text(selectedChat, color = navy, fontWeight = FontWeight.Bold, maxLines = 1); Text(if (selectedChat in verifiedContacts) "Contact verified" else "Verify this contact before trusting", color = if (selectedChat in verifiedContacts) green else Color(0xFF9A6500), style = MaterialTheme.typography.labelSmall) }
                TextButton(onClick = { callNotice = "Voice calling is not connected yet." }) { Text("☎", color = green, style = MaterialTheme.typography.titleLarge) }
                TextButton(onClick = { callNotice = "Video calling is not connected yet." }) { Text("▣", color = green, style = MaterialTheme.typography.titleLarge) }
            }
            callNotice?.let { Text(it, color = Color(0xFF9A6500), style = MaterialTheme.typography.bodySmall) }
            Divider(Modifier.padding(vertical = 10.dp))
            val entries = localMessages.mapNotNull(::messageParts).filter { it.first == selectedChat }.sortedBy { it.second }
            Column(Modifier.weight(1f).fillMaxWidth().verticalScroll(rememberScrollState()).padding(vertical = 6.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (entries.isEmpty()) Text("Say hello 👋", color = Color(0xFF637781), style = MaterialTheme.typography.bodySmall)
                entries.forEach { entry -> Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) { Surface(color = Color(0xFFD8F5D0), shape = RoundedCornerShape(topStart = 16.dp, topEnd = 4.dp, bottomStart = 16.dp, bottomEnd = 16.dp), modifier = Modifier.widthIn(max = 290.dp)) { Text(entry.third, Modifier.padding(horizontal = 14.dp, vertical = 10.dp), color = navy) } } }
            }
            if (!canSendMessage) { Text("Secure chat setup is required before sending.", color = Color(0xFF9A6500), style = MaterialTheme.typography.bodySmall); TextButton(onClick = onOpenSecureSetup) { Text("Finish secure chat setup", color = green) } }
            Row(verticalAlignment = Alignment.Bottom) {
                OutlinedTextField(value = messageDraft, onValueChange = onMessageDraftChange, modifier = Modifier.weight(1f), shape = RoundedCornerShape(22.dp), placeholder = { Text("Message") }, minLines = 1, maxLines = 4)
                Spacer(Modifier.width(8.dp)); Button(onClick = onSendMessage, enabled = canSendMessage && messageDraft.isNotBlank() && !sendBusy, shape = CircleShape, colors = ButtonDefaults.buttonColors(containerColor = green), contentPadding = PaddingValues(14.dp)) { Text(if (sendBusy) "…" else "➤") }
            }
            status?.let { Text(it, Modifier.padding(top = 6.dp), color = green, style = MaterialTheme.typography.bodySmall) }
        }
    }

    if (showAddContact) AlertDialog(onDismissRequest = { showAddContact = false }, title = { Text("Add a friend") }, text = {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Friend ka naam aur signed MESHX2 public ID paste karein. ID verify hokar contacts mein save hogi.")
            OutlinedTextField(value = contactNameInput, onValueChange = { contactNameInput = it }, modifier = Modifier.fillMaxWidth(), singleLine = true, label = { Text("Friend ka naam") }, placeholder = { Text("Jaise: Ali") })
            OutlinedTextField(value = publicIdentityInput, onValueChange = { publicIdentityInput = it; publicIdentityStatus = null }, modifier = Modifier.fillMaxWidth(), minLines = 3, maxLines = 5, label = { Text("MESHX public ID") }, placeholder = { Text("MESHX2:…") })
            publicIdentityStatus?.let { Text(it, color = if (it.startsWith("Added:") || it.startsWith("Already")) green else MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
        }
    }, confirmButton = { TextButton(onClick = { addContact() }, enabled = publicIdentityInput.isNotBlank() && contactNameInput.isNotBlank()) { Text("Save contact") } }, dismissButton = { TextButton(onClick = { showAddContact = false }) { Text("Cancel") } })

    if (showSavedDialog) AlertDialog(onDismissRequest = { showSavedDialog = false }, title = { Text("Contact saved ✓") }, text = { Text("Public ID saved for $savedContactName. You can now open a chat.") }, confirmButton = { TextButton(onClick = { showSavedDialog = false; savedContactFingerprint?.let(onOpenChat) }) { Text("Open Chat") } }, dismissButton = { TextButton(onClick = { showSavedDialog = false }) { Text("Later") } })
}
