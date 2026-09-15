package dev.okhsunrog.netdiag

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import dev.okhsunrog.netdiag.ui.NetDiagApp
import dev.okhsunrog.netdiag.ui.NetDiagTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContent {
            NetDiagTheme {
                NetDiagApp()
            }
        }
    }
}
