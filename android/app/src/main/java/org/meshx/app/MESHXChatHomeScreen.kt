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
    onBackToChats: () -> Unit,
    onSendMessage: () -> Unit,
    onOpenSecureSetup: () -> Unit
) {
    var search by remember { mutableStateOf("") }
    val navy = Color(0xFF071B35)
    val blue = Color(0xFF1769AA)
    val page = Color(0xFFF4F7FB)

    fun messageParts(raw: String): Triple<String, Long, String>? {
        val parts = raw.split("#", limit = 3)
        if (parts.size != 3) return null
        return try {
            Triple(parts[0], parts[1].toLong(), String(Base64.decode(parts[2], Base64.DEFAULT), Charsets.UTF_8))
        } catch (_: Exception) { null }
    }

    Column(
        Modifier.fillMaxWidth().background(page, RoundedCornerShape(22.dp)).padding(16.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("MESHX", color = navy, style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.ExtraBold)
                Text("Private messages", color = Color(0xFF526477), style = MaterialTheme.typography.bodySmall)
            }
            Surface(color = Color(0xFFE3F3E9), shape = CircleShape) {
                Text("PRIVATE", Modifier.padding(horizontal = 12.dp, vertical = 7.dp), color = Color(0xFF176B3A), style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold)
            }
        }
        Spacer(Modifier.height(18.dp))

        if (selectedChat == null) {
            Text("Chats", color = navy, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(10.dp))
            OutlinedTextField(
                value = search,
                onValueChange = { search = it },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                shape = RoundedCornerShape(14.dp),
                placeholder = { Text("Search contacts") },
                label = { Text("Search") }
            )
            Spacer(Modifier.height(12.dp))
            val filtered = contacts.filter { it.contains(search.trim(), ignoreCase = true) }
            if (filtered.isEmpty()) {
                Surface(color = Color.White, shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(18.dp)) {
                        Text(if (contacts.isEmpty()) "Abhi koi chat nahi hai" else "No matching contact", color = navy, fontWeight = FontWeight.SemiBold)
                        Spacer(Modifier.height(4.dp))
                        Text(
                            if (contacts.isEmpty()) "Pehle apni identity banayein aur kisi contact ka public MESHX QR ya identity add karein. Contact add hone ke baad yahan chat dikhegi."
                            else "Search ka naam ya fingerprint dobara check karein.",
                            color = Color(0xFF526477), style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            } else {
                filtered.forEach { contact ->
                    val latest = localMessages.mapNotNull(::messageParts)
                        .filter { it.first == contact }.maxByOrNull { it.second }
                    val bound = contactTransportPeers.any { it.startsWith("$contact#") }
                    Row(
                        Modifier.fillMaxWidth().padding(vertical = 5.dp)
                            .background(Color.White, RoundedCornerShape(16.dp))
                            .padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Surface(color = Color(0xFFDCEAF7), shape = CircleShape, modifier = Modifier.size(48.dp)) {
                            Box(contentAlignment = Alignment.Center) {
                                Text(contact.take(2), color = navy, fontWeight = FontWeight.Bold)
                            }
                        }
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(contact, color = navy, fontWeight = FontWeight.SemiBold, maxLines = 1)
                            Text(
                                latest?.third ?: if (bound) "Ready for secure setup" else "Identity saved · transport not linked",
                                color = Color(0xFF607184), style = MaterialTheme.typography.bodySmall, maxLines = 1
                            )
                            Text(
                                if (contact in verifiedContacts) "✓ Fingerprint verified" else "Fingerprint not verified",
                                color = if (contact in verifiedContacts) Color(0xFF16834A) else Color(0xFFB36B16),
                                style = MaterialTheme.typography.labelSmall
                            )
                        }
                        TextButton(onClick = { onOpenChat(contact) }) { Text("Open") }
                    }
                }
            }
            Spacer(Modifier.height(8.dp))
            Text("Your messages stay on this device encrypted at rest. Internet delivery still depends on a reachable peer or configured relay.", color = Color(0xFF607184), style = MaterialTheme.typography.bodySmall)
        } else {
            Row(verticalAlignment = Alignment.CenterVertically) {
                TextButton(onClick = onBackToChats) { Text("‹ Chats") }
                Column(Modifier.weight(1f)) {
                    Text(selectedChat, color = navy, fontWeight = FontWeight.Bold, maxLines = 1)
                    Text(if (selectedChat in verifiedContacts) "Fingerprint verified" else "Verify fingerprint before trusting", color = if (selectedChat in verifiedContacts) Color(0xFF16834A) else Color(0xFFB36B16), style = MaterialTheme.typography.labelSmall)
                }
                Surface(color = Color(0xFFE3F3E9), shape = CircleShape) {
                    Text("E2E", Modifier.padding(horizontal = 10.dp, vertical = 6.dp), color = Color(0xFF176B3A), style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold)
                }
            }
            Divider(Modifier.padding(vertical = 10.dp))
            val entries = localMessages.mapNotNull(::messageParts)
                .filter { it.first == selectedChat }.sortedBy { it.second }
            Column(
                Modifier.fillMaxWidth().heightIn(min = 180.dp, max = 420.dp)
                    .verticalScroll(rememberScrollState()).padding(vertical = 6.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                if (entries.isEmpty()) {
                    Text("No messages yet. Secure setup complete hone ke baad pehla message bhej sakte hain.", color = Color(0xFF607184), style = MaterialTheme.typography.bodySmall)
                }
                entries.forEach { entry ->
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                        Surface(color = Color(0xFFDCEAF7), shape = RoundedCornerShape(16.dp), modifier = Modifier.widthIn(max = 290.dp)) {
                            Text(entry.third, Modifier.padding(horizontal = 14.dp, vertical = 10.dp), color = navy)
                        }
                    }
                }
            }
            if (!canSendMessage) {
                Surface(color = Color(0xFFFFF3D9), shape = RoundedCornerShape(12.dp), modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(12.dp)) {
                        Text("Secure chat setup required", color = Color(0xFF80520A), fontWeight = FontWeight.SemiBold)
                        Text("MLS group join aur contact ka fingerprint verification complete karein. Tab message send hoga.", color = Color(0xFF80520A), style = MaterialTheme.typography.bodySmall)
                        TextButton(onClick = onOpenSecureSetup) { Text("Open secure setup") }
                    }
                }
            } else {
                OutlinedTextField(
                    value = messageDraft,
                    onValueChange = onMessageDraftChange,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    placeholder = { Text("Type a message…") },
                    minLines = 1,
                    maxLines = 4
                )
                Spacer(Modifier.height(8.dp))
                Button(
                    onClick = onSendMessage,
                    enabled = messageDraft.isNotBlank() && !sendBusy,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(14.dp)
                ) {
                    Text(if (sendBusy) "Sending…" else "Send message")
                }
            }
            status?.let {
                Text(it, Modifier.padding(top = 8.dp), color = blue, style = MaterialTheme.typography.bodySmall)
            }
            TextButton(onClick = onOpenSecureSetup, modifier = Modifier.align(Alignment.End)) {
                Text("Advanced secure setup")
            }
        }
    }
}
