package org.meshx.app

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import java.security.KeyFactory
import java.security.spec.PKCS8EncodedKeySpec

@Composable
internal fun RecoverySetupDialog(
    onDismiss: () -> Unit,
    onRecoverySaved: () -> Unit
) {
    val context = LocalContext.current
    val words = remember {
        context.assets.open("bip39-english.txt").bufferedReader().useLines { it.toList() }
    }
    var mode by remember { mutableStateOf("choose") }
    var phrase by remember { mutableStateOf("") }
    var generatedPhrase by remember { mutableStateOf<List<String>>(emptyList()) }
    var backupConfirmed by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    fun savePhrase(value: String) {
        busy = true
        error = null
        var seed: ByteArray? = null
        var transport: ByteArray? = null
        var signingPrivate: ByteArray? = null
        var signingPublic: ByteArray? = null
        try {
            require(Bip39Recovery.validate24(value, words)) {
                "24 English words ya unka valid checksum sahi nahi hai."
            }
            seed = Bip39Recovery.toSeed(value)
            transport = NativeMeshx.deriveRecoveryTransportIdentity(seed)
            signingPrivate = NativeMeshx.deriveRecoverySigningPrivateKey(seed)
            signingPublic = NativeMeshx.deriveRecoverySigningPublicKey(seed)
            // Parse once before storing so malformed private-key DER cannot be committed.
            KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(signingPrivate))
            RecoveryIdentityVault(context).save(
                RecoveryIdentityVault.Material(transport, signingPrivate, signingPublic)
            )
            onRecoverySaved()
            onDismiss()
        } catch (e: Exception) {
            error = e.localizedMessage ?: "Recovery identity save nahi ho saki."
        } finally {
            seed?.fill(0)
            transport?.fill(0)
            signingPrivate?.fill(0)
            signingPublic?.fill(0)
            busy = false
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("MESHX account recovery") },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth().heightIn(max = 520.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                when (mode) {
                    "choose" -> {
                        Text("Is process se recovery keys wala MESHX account activate hoga. Agar aapka pehle se purana MESHX ID hai, uska fingerprint badal jayega; purane contacts ko naya public ID dobara share karna hoga. Purana account apne aap convert nahi hota.")
                        Button(onClick = {
                            generatedPhrase = Bip39Recovery.generate24(words)
                            phrase = generatedPhrase.joinToString(" ")
                            backupConfirmed = false
                            error = null
                            mode = "create"
                        }, modifier = Modifier.fillMaxWidth()) { Text("Create new recovery account") }
                        OutlinedButton(onClick = {
                            phrase = ""
                            error = null
                            mode = "restore"
                        }, modifier = Modifier.fillMaxWidth()) { Text("Restore with 24 words") }
                    }
                    "create" -> {
                        Text("Apne 24 words paper par likhein. Screenshot, chat ya kisi ko share mat karein. Ye naya account hoga; purana ID automatically recover nahi hoga.")
                        Text(phrase)
                        Row {
                            Checkbox(checked = backupConfirmed, onCheckedChange = { backupConfirmed = it })
                            Text("Maine 24 words ko safe jagah likh liya hai.")
                        }
                        Button(
                            enabled = backupConfirmed && !busy,
                            onClick = { savePhrase(phrase) },
                            modifier = Modifier.fillMaxWidth()
                        ) { Text(if (busy) "Saving…" else "Save and activate recovery account") }
                        OutlinedButton(onClick = { mode = "choose"; phrase = ""; generatedPhrase = emptyList() }) {
                            Text("Back")
                        }
                    }
                    "restore" -> {
                        Text("Apne 24 words yahan type karein. Phrase sirf isi device par process hogi.")
                        OutlinedTextField(
                            value = phrase,
                            onValueChange = { phrase = it.lowercase(); error = null },
                            modifier = Modifier.fillMaxWidth(),
                            label = { Text("24 recovery words") },
                            minLines = 4,
                            maxLines = 6
                        )
                        Button(
                            enabled = !busy && phrase.isNotBlank(),
                            onClick = { savePhrase(phrase) },
                            modifier = Modifier.fillMaxWidth()
                        ) { Text(if (busy) "Restoring…" else "Restore account") }
                        OutlinedButton(onClick = { mode = "choose"; phrase = "" }) { Text("Back") }
                    }
                }
                error?.let { Text(it) }
            }
        },
        confirmButton = {},
        dismissButton = { OutlinedButton(onClick = onDismiss) { Text("Close") } }
    )
}
