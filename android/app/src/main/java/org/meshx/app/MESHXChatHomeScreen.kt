package org.meshx.app

import android.util.Base64
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
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
    var publicIdentityInput by remember { mutableStateOf("") }
    var publicIdentityStatus by remember { mutableStateOf<String?>(null) }
    var showAddContact by remember { mutableStateOf(false) }
    var callNotice by remember { mutableStateOf<String?>(null) }
    val navy = Color(0xFF102A43)
    val green = Color(0xFF087E5B)
    val page = Color(0xFFF5F7F8)

    fun messageParts(raw: String): Triple<String, Long, String>? {
        val parts = raw.split("#", limit = 3)
        if (parts.size != 3) return null
        return try {
            Triple(parts[0], parts[1].toLong(), String(Base64.decode(parts[2], Base64.DEFAULT), Charsets.UTF_8))
        } catch (_: Exception) { null }
    }

    fun addContact() {
        publicIdentityStatus = onAddPublicIdentity(publicIdentityInput.trim())
        if (publicIdentityStatus?.startsWith("Added:") == true ||
            publicIdentityStatus?.startsWith("Already added:") == true) {
            publicIdentityInput = ""
            showAddContact = false
        }
    }

    Column(
        Modifier.fillMaxSize().background(page).padding(horizontal = 14.dp, vertical = 10.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("MESHX", color = navy, style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.ExtraBold)
                Text(if (selectedChat == null) "Private chats" else "End-to-end private chat",
                    color = Color(0xFF637381), style = MaterialTheme.typography.bodySmall)
            }
            if (selectedChat != null) {
                TextButton(onClick = onBackToChats) { Text("Chats", color = green) }
            } else {
                TextButton(onClick = { showAddContact = true }) { Text("＋ Add", color = green, fontWeight = FontWeight.Bold) }
            }
        }

        if (selectedChat == null) {
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = search,
                onValueChange = {
                    search = it
                    if (it.trim().startsWith("MESHX2:")) {
                        publicIdentityInput = it.trim()
                        publicIdentityStatus = null
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                shape = RoundedCornerShape(24.dp),
                placeholder = { Text("Search chats or paste a public ID") },
                leadingIcon = { Text("⌕", style = MaterialTheme.typography.headlineSmall) }
            )
            if (search.trim().startsWith("MESHX2:")) {
                TextButton(onClick = {
                    publicIdentityInput = search.trim()
                    addContact()
                    search = ""
                }) { Text("Add this public ID", color = green) }
            }
            Spacer(Modifier.height(12.dp))
            Text("CHATS", color = Color(0xFF637381), style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(6.dp))
            val filtered = contacts.filter { contact ->
                contact.contains(search.trim(), ignoreCase = true) ||
                    (search.isBlank() && contact.isNotBlank())
            }
            if (filtered.isEmpty()) {
                Column(
                    Modifier.fillMaxWidth().padding(top = 54.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text("✉", color = green, style = MaterialTheme.typography.displayMedium)
                    Spacer(Modifier.height(12.dp))
                    Text("No chats yet", color = navy, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                    Text("Tap + to add a friend using their MESHX public ID.",
                        color = Color(0xFF637381), style = MaterialTheme.typography.bodyMedium)
                    Spacer(Modifier.height(14.dp))
                    Button(onClick = { showAddContact = true }, colors = ButtonDefaults.buttonColors(containerColor = green)) {
                        Text("＋ Add a friend")
                    }
                }
            } else {
                Column(Modifier.weight(1f).verticalScroll(rememberScrollState())) {
                    filtered.forEach { contact ->
                        val latest = localMessages.mapNotNull(::messageParts)
                            .filter { it.first == contact }.maxByOrNull { it.second }
                        val bound = contactTransportPeers.any { it.startsWith("$contact#") }
                        Row(
                            Modifier.fillMaxWidth().padding(vertical = 3.dp)
                                .background(Color.White, RoundedCornerShape(16.dp)).padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Surface(color = Color(0xFFDCEFE8), shape = CircleShape, modifier = Modifier.size(48.dp)) {
                                Box(contentAlignment = Alignment.Center) {
                                    Text(contact.take(2), color = green, fontWeight = FontWeight.Bold)
                                }
                            }
                            Spacer(Modifier.width(12.dp))
                            Column(Modifier.weight(1f)) {
                                Text(contact, color = navy, fontWeight = FontWeight.SemiBold, maxLines = 1)
                                Text(latest?.third ?: if (bound) "Tap to open chat" else "New contact",
                                    color = Color(0xFF637381), style = MaterialTheme.typography.bodySmall, maxLines = 1)
                            }
                            TextButton(onClick = { onOpenChat(contact) }) { Text("Open", color = green) }
                        }
                    }
                }
            }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                Button(
                    onClick = { showAddContact = true },
                    shape = CircleShape,
                    colors = ButtonDefaults.buttonColors(containerColor = green),
                    contentPadding = PaddingValues(horizontal = 20.dp, vertical = 12.dp)
                ) { Text("＋", style = MaterialTheme.typography.titleLarge) }
            }
            publicIdentityStatus?.let { Text(it, color = if (it.startsWith("Added:") || it.startsWith("Already")) green else MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
        } else {
            Spacer(Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Surface(color = Color(0xFFDCEFE8), shape = CircleShape, modifier = Modifier.size(44.dp)) {
                    Box(contentAlignment = Alignment.Center) { Text(selectedChat.take(2), color = green, fontWeight = FontWeight.Bold) }
                }
                Spacer(Modifier.width(10.dp))
                Column(Modifier.weight(1f)) {
                    Text(selectedChat, color = navy, fontWeight = FontWeight.Bold, maxLines = 1)
                    Text(if (selectedChat in verifiedContacts) "Contact verified" else "Verify this contact before trusting",
                        color = if (selectedChat in verifiedContacts) green else Color(0xFF9A6500),
                        style = MaterialTheme.typography.labelSmall)
                }
                TextButton(onClick = { callNotice = "Voice calling is not connected yet." }) { Text("☎", color = green, style = MaterialTheme.typography.titleLarge) }
                TextButton(onClick = { callNotice = "Video calling is not connected yet." }) { Text("▣", color = green, style = MaterialTheme.typography.titleLarge) }
            }
            callNotice?.let { Text(it, color = Color(0xFF9A6500), style = MaterialTheme.typography.bodySmall) }
            Divider(Modifier.padding(vertical = 10.dp))
            val entries = localMessages.mapNotNull(::messageParts)
                .filter { it.first == selectedChat }.sortedBy { it.second }
            Column(
                Modifier.weight(1f).fillMaxWidth().verticalScroll(rememberScrollState()).padding(vertical = 6.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                if (entries.isEmpty()) {
                    Text("Say hello 👋", color = Color(0xFF637381), style = MaterialTheme.typography.bodySmall)
                }
                entries.forEach { entry ->
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                        Surface(color = Color(0xFFDCEFE8), shape = RoundedCornerShape(16.dp), modifier = Modifier.widthIn(max = 290.dp)) {
                            Text(entry.third, Modifier.padding(horizontal = 14.dp, vertical = 10.dp), color = navy)
                        }
                    }
                }
            }
            if (!canSendMessage) {
                Text("Secure chat setup is required before sending.", color = Color(0xFF9A6500), style = MaterialTheme.typography.bodySmall)
                TextButton(onClick = onOpenSecureSetup) { Text("Finish secure chat setup", color = green) }
            }
            Row(verticalAlignment = Alignment.Bottom) {
                OutlinedTextField(
                    value = messageDraft,
                    onValueChange = onMessageDraftChange,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(22.dp),
                    placeholder = { Text("Message") },
                    minLines = 1,
                    maxLines = 4
                )
                Spacer(Modifier.width(8.dp))
                Button(
                    onClick = onSendMessage,
                    enabled = canSendMessage && messageDraft.isNotBlank() && !sendBusy,
                    shape = CircleShape,
                    colors = ButtonDefaults.buttonColors(containerColor = green),
                    contentPadding = PaddingValues(14.dp)
                ) { Text(if (sendBusy) "…" else "➤") }
            }
            status?.let { Text(it, Modifier.padding(top = 6.dp), color = green, style = MaterialTheme.typography.bodySmall) }
        }
    }

    if (showAddContact) {
        AlertDialog(
            onDismissRequest = { showAddContact = false },
            title = { Text("Add a friend") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Friend ka complete signed MESHX public ID paste karein.")
                    OutlinedTextField(
                        value = publicIdentityInput,
                        onValueChange = { publicIdentityInput = it; publicIdentityStatus = null },
                        modifier = Modifier.fillMaxWidth(),
                        minLines = 3,
                        maxLines = 5,
                        label = { Text("MESHX public ID") },
                        placeholder = { Text("MESHX2:…") }
                    )
                    publicIdentityStatus?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                }
            },
            confirmButton = {
                TextButton(onClick = { addContact() }, enabled = publicIdentityInput.isNotBlank()) { Text("Search and add") }
            },
            dismissButton = { TextButton(onClick = { showAddContact = false }) { Text("Cancel") } }
        )
    }
}
