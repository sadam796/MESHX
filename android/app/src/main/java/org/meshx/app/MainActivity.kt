package org.meshx.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.Button
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { MeshxHome() }
    }
}

@Composable
private fun MeshxHome() {
    MaterialTheme {
        Surface(modifier = Modifier.fillMaxSize()) {
            Column(
                modifier = Modifier.fillMaxSize().padding(24.dp),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text("MESHX", style = MaterialTheme.typography.headlineLarge)
                Text("Global private messaging", modifier = Modifier.padding(top = 8.dp))
                Text(
                    "Android prototype scaffold. Internet peer discovery, encryption, and message transport are not connected yet.",
                    modifier = Modifier.padding(top = 24.dp)
                )
                Button(onClick = { /* Messaging transport is implemented in a later milestone. */ }, modifier = Modifier.padding(top = 20.dp)) {
                    Text("Messaging engine — in development")
                }
            }
        }
    }
}
