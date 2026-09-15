package dev.okhsunrog.netdiag.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.okhsunrog.netdiag.proto.EventSeverity
import dev.okhsunrog.netdiag.proto.EventSource
import dev.okhsunrog.netdiag.proto.NetworkEvent
import dev.okhsunrog.netdiag.ui.EmptyState
import dev.okhsunrog.netdiag.ui.ExpandableRow
import dev.okhsunrog.netdiag.ui.KeyValueRow
import dev.okhsunrog.netdiag.ui.MonoText
import dev.okhsunrog.netdiag.ui.StatusChip
import dev.okhsunrog.netdiag.ui.TimelineState
import dev.okhsunrog.netdiag.ui.display
import dev.okhsunrog.netdiag.ui.eventSeverityColor
import dev.okhsunrog.netdiag.ui.formatTimeMillis

/**
 * The realtime timeline.
 *
 * Kernel events and framework events share one axis, which is the point: the
 * lag between "the kernel dropped the route" and "ConnectivityManager noticed"
 * is only visible when the two are interleaved, and that lag is where a lot of
 * Android networking bugs live.
 */
@Composable
fun TimelineScreen(
    state: TimelineState,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onClear: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var showKernel by remember { mutableStateOf(true) }
    var showFramework by remember { mutableStateOf(true) }
    var noiseFiltered by remember { mutableStateOf(true) }

    val visible = remember(state.events, showKernel, showFramework, noiseFiltered) {
        state.events.filter { event ->
            val sourceOk = when (event.source) {
                EventSource.EVENT_SOURCE_FRAMEWORK -> showFramework
                EventSource.EVENT_SOURCE_KERNEL -> showKernel
                else -> true
            }
            val severityOk = !noiseFiltered ||
                event.severity != EventSeverity.EVENT_SEVERITY_DEBUG
            sourceOk && severityOk
        }
    }

    Column(modifier = modifier.fillMaxSize()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 6.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (state.running) {
                TextButton(onClick = onStop) { Text("Pause") }
            } else {
                TextButton(onClick = onStart) { Text("Resume") }
            }
            TextButton(onClick = onClear) { Text("Clear") }
            Text(
                text = "${visible.size} events",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        Row(
            modifier = Modifier.padding(horizontal = 12.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            FilterChip(
                selected = showKernel,
                onClick = { showKernel = !showKernel },
                label = { Text("Kernel") },
            )
            FilterChip(
                selected = showFramework,
                onClick = { showFramework = !showFramework },
                label = { Text("Framework") },
            )
            FilterChip(
                selected = noiseFiltered,
                onClick = { noiseFiltered = !noiseFiltered },
                label = { Text("Hide noise") },
            )
        }

        state.error?.let { error ->
            Text(
                text = error,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
            )
        }

        if (visible.isEmpty()) {
            EmptyState(
                message = if (state.running) {
                    "Watching for network changes…"
                } else {
                    "The timeline is paused."
                },
                hint = "Toggle Wi-Fi or a VPN to see events appear from both the kernel " +
                    "and the framework.",
            )
            return@Column
        }

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp),
        ) {
            items(visible, key = { "${it.sequence}-${it.monotonicNs}-${it.unixMs}" }) { event ->
                EventRow(event)
            }
        }
    }
}

@Composable
private fun EventRow(event: NetworkEvent) {
    val color = eventSeverityColor(event.severity)
    val sourceLabel = when (event.source) {
        EventSource.EVENT_SOURCE_KERNEL -> "KRNL"
        EventSource.EVENT_SOURCE_FRAMEWORK -> "FMWK"
        EventSource.EVENT_SOURCE_DAEMON -> "DMON"
        else -> "????"
    }

    ExpandableRow(
        summary = {
            Row(
                modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
                verticalAlignment = Alignment.Top,
            ) {
                MonoText(
                    text = formatTimeMillis(event.unixMs),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    // Wide enough for HH:MM:SS.SSS; narrower and the
                    // milliseconds wrap onto their own line.
                    modifier = Modifier.width(108.dp),
                    maxLines = 1,
                )
                StatusChip(sourceLabel, color, modifier = Modifier.width(52.dp))
                MonoText(
                    text = event.summary,
                    modifier = Modifier
                        .weight(1f)
                        .padding(start = 8.dp),
                )
            }
        },
        detail = {
            when {
                event.hasLink() -> {
                    val link = event.link
                    KeyValueRow("interface", link.`interface`.name)
                    KeyValueRow("index", link.`interface`.index.toString())
                    if (link.mtuChanged) {
                        KeyValueRow("mtu", "${link.previousMtu} -> ${link.`interface`.mtu}")
                    }
                }
                event.hasAddress() -> {
                    val address = event.address
                    KeyValueRow("interface", address.interfaceName)
                    KeyValueRow("address", address.address.prefix.display())
                    KeyValueRow("added", address.added.toString())
                    if (address.familyGained) KeyValueRow("family", "gained")
                    if (address.familyLost) KeyValueRow("family", "lost")
                }
                event.hasRoute() -> {
                    val route = event.route.route
                    KeyValueRow("table", route.table.toString())
                    KeyValueRow("default", route.isDefault.toString())
                    KeyValueRow("added", event.route.added.toString())
                }
                event.hasRule() -> {
                    KeyValueRow("rule", event.rule.rule.display())
                    KeyValueRow("added", event.rule.added.toString())
                }
                event.hasNeighbor() -> {
                    val neighbor = event.neighbor.neighbor
                    KeyValueRow("address", neighbor.address.display())
                    KeyValueRow("interface", neighbor.interfaceName)
                    KeyValueRow("state", neighbor.state.name.removePrefix("NEIGHBOR_STATE_"))
                    KeyValueRow("router", neighbor.isRouter.toString())
                }
                event.hasSocket() -> {
                    val socket = event.socket.socket
                    KeyValueRow("uid", socket.uid.toString())
                    KeyValueRow("socket", socket.display())
                    if (socket.hasMark) {
                        KeyValueRow("mark", "0x${socket.mark.toString(16)}")
                    }
                }
                event.hasFramework() -> {
                    val framework = event.framework
                    KeyValueRow("kind", framework.kind.name.removePrefix("FRAMEWORK_EVENT_KIND_"))
                    if (framework.changeSummary.isNotEmpty()) {
                        KeyValueRow("change", framework.changeSummary, mono = false)
                    }
                    if (framework.hasNetwork()) {
                        KeyValueRow("netId", framework.network.netId.toString())
                        KeyValueRow(
                            "interface",
                            framework.network.linkProperties.interfaceName,
                        )
                    }
                }
                event.hasDaemon() -> {
                    KeyValueRow("message", event.daemon.message, mono = false)
                }
            }
            if (event.sequence > 0) {
                KeyValueRow("sequence", event.sequence.toString())
            }
        },
    )
}
