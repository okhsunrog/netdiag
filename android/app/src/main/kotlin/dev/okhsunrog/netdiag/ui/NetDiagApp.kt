package dev.okhsunrog.netdiag.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material.icons.filled.HealthAndSafety
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.RadioButtonChecked
import androidx.compose.material.icons.filled.Route
import androidx.compose.material.icons.filled.SettingsEthernet
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import dev.okhsunrog.netdiag.ipc.ConnectionState
import dev.okhsunrog.netdiag.ui.screens.AppsScreen
import dev.okhsunrog.netdiag.ui.screens.CaptureScreen
import dev.okhsunrog.netdiag.ui.screens.DiagnoseScreen
import dev.okhsunrog.netdiag.ui.screens.OverviewScreen
import dev.okhsunrog.netdiag.ui.screens.RoutingScreen
import dev.okhsunrog.netdiag.ui.screens.SocketsScreen
import dev.okhsunrog.netdiag.ui.screens.TimelineScreen

private enum class Tab(val label: String, val icon: ImageVector) {
    Overview("Overview", Icons.Default.Dashboard),
    Diagnose("Diagnose", Icons.Default.HealthAndSafety),
    Routing("Routing", Icons.Default.Route),
    Sockets("Sockets", Icons.Default.SettingsEthernet),
    Apps("Apps", Icons.Default.Apps),
    Timeline("Timeline", Icons.Default.History),
    Capture("Capture", Icons.Default.RadioButtonChecked),
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NetDiagApp(viewModel: NetDiagViewModel = viewModel()) {
    val connection by viewModel.connectionState.collectAsStateWithLifecycle()
    val connectError by viewModel.connectError.collectAsStateWithLifecycle()
    val snapshot by viewModel.snapshot.collectAsStateWithLifecycle()
    val diagnosis by viewModel.diagnosis.collectAsStateWithLifecycle()
    val apps by viewModel.apps.collectAsStateWithLifecycle()
    val timeline by viewModel.timeline.collectAsStateWithLifecycle()
    val capture by viewModel.capture.collectAsStateWithLifecycle()

    var tab by remember { mutableStateOf(Tab.Overview) }

    // Loading the app list needs a PackageManager query that takes a moment on
    // a device with hundreds of apps; do it when that tab is first opened
    // rather than at startup.
    LaunchedEffect(tab) {
        if (tab == Tab.Apps && apps.apps.isEmpty()) {
            viewModel.loadApps()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Network Inspector") },
                actions = {
                    when (connection) {
                        is ConnectionState.Connected -> {
                            TextButton(onClick = { viewModel.disconnect() }) {
                                Text("Disconnect")
                            }
                        }
                        ConnectionState.Connecting -> Text(
                            "Connecting…",
                            style = MaterialTheme.typography.labelMedium,
                            modifier = Modifier.padding(end = 12.dp),
                        )
                        else -> {
                            TextButton(onClick = { viewModel.connect() }) { Text("Connect") }
                        }
                    }
                },
            )
        },
        bottomBar = {
            NavigationBar {
                Tab.entries.forEach { entry ->
                    NavigationBarItem(
                        selected = tab == entry,
                        onClick = { tab = entry },
                        icon = { Icon(entry.icon, contentDescription = entry.label) },
                        label = { Text(entry.label) },
                    )
                }
            }
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            if (connection !is ConnectionState.Connected) {
                ConnectPanel(
                    state = connection,
                    error = connectError,
                    daemonBundled = viewModel.isDaemonBundled,
                    onConnect = { viewModel.connect() },
                )
                return@Column
            }

            when (tab) {
                Tab.Overview -> OverviewScreen(
                    state = snapshot,
                    onRefresh = { viewModel.refreshSnapshot() },
                )
                Tab.Diagnose -> DiagnoseScreen(
                    state = diagnosis,
                    onDiagnose = { viewModel.diagnose() },
                    onCancel = { viewModel.cancelDiagnosis() },
                )
                Tab.Routing -> RoutingScreen(state = snapshot)
                Tab.Sockets -> SocketsScreen(
                    state = snapshot,
                    packagesForUid = { uid ->
                        apps.apps.filter { it.uid == uid }.map { it.packageName }
                    },
                )
                Tab.Apps -> AppsScreen(
                    state = apps,
                    onLoad = { viewModel.loadApps(it) },
                    onSelect = { viewModel.selectApp(it) },
                    onClear = { viewModel.clearSelectedApp() },
                )
                Tab.Timeline -> TimelineScreen(
                    state = timeline,
                    onStart = { viewModel.startTimeline() },
                    onStop = { viewModel.stopTimeline() },
                    onClear = { viewModel.clearTimeline() },
                )
                Tab.Capture -> CaptureScreen(
                    state = capture,
                    interfaces = viewModel.captureInterfaces(),
                    onStart = { viewModel.startCapture(it) },
                    onStop = { viewModel.stopCapture() },
                    onSave = { viewModel.saveCapture() },
                    onSelectInterface = { viewModel.selectCaptureInterface(it) },
                )
            }
        }
    }
}

@Composable
private fun ConnectPanel(
    state: ConnectionState,
    error: String?,
    daemonBundled: Boolean,
    onConnect: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            "Not connected to the daemon",
            style = MaterialTheme.typography.titleMedium,
        )
        Spacer(Modifier.height(8.dp))
        Text(
            "This app reads kernel networking state through a small root daemon. " +
                "Connecting starts it through su and authorizes only this app's uid.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        if (!daemonBundled) {
            Spacer(Modifier.height(16.dp))
            SectionCard(title = "The daemon is not bundled") {
                Text(
                    "This build has no libnetdiagd.so. Run scripts/build-daemon.sh to " +
                        "cross-compile it and rebuild the app.",
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }

        error?.let {
            Spacer(Modifier.height(16.dp))
            SectionCard(title = "Could not connect") {
                Text(it, style = MaterialTheme.typography.bodyMedium)
            }
        }

        Spacer(Modifier.height(24.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(
                onClick = onConnect,
                enabled = state != ConnectionState.Connecting,
            ) {
                Text(if (state == ConnectionState.Connecting) "Connecting…" else "Connect")
            }
        }
    }
}
