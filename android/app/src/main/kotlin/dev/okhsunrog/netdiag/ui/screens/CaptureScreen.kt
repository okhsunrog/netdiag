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
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.okhsunrog.netdiag.proto.CapturedPacket
import dev.okhsunrog.netdiag.proto.CheckStatus
import dev.okhsunrog.netdiag.ui.CaptureState
import dev.okhsunrog.netdiag.ui.EmptyState
import dev.okhsunrog.netdiag.ui.ExpandableRow
import dev.okhsunrog.netdiag.ui.KeyValueRow
import dev.okhsunrog.netdiag.ui.MonoText
import dev.okhsunrog.netdiag.ui.SectionCard
import dev.okhsunrog.netdiag.ui.StatusChip
import dev.okhsunrog.netdiag.ui.display
import dev.okhsunrog.netdiag.ui.formatBytes
import dev.okhsunrog.netdiag.ui.formatTimeMillis
import dev.okhsunrog.netdiag.ui.statusColor

/**
 * Packet capture.
 *
 * This captures from a real interface with AF_PACKET rather than standing up a
 * `VpnService`. Android permits exactly one active VpnService, so the
 * tun-based approach cannot run while the user's VPN is up — which is the case
 * they most often need to capture. It also only sees what is routed into the
 * tun, and traffic escaping the VPN is precisely what would be missing.
 */
@Composable
fun CaptureScreen(
    state: CaptureState,
    interfaces: List<String>,
    onStart: (interfaceName: String) -> Unit,
    onStop: () -> Unit,
    onSave: () -> Unit,
    onSelectInterface: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxSize()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (state.running) {
                Button(onClick = onStop, modifier = Modifier.weight(1f)) { Text("Stop") }
            } else {
                Button(
                    onClick = { onStart(state.interfaceName) },
                    modifier = Modifier.weight(1f),
                    enabled = state.interfaceName.isNotEmpty(),
                ) {
                    Text("Start capture")
                }
            }
            if (state.packets.isNotEmpty() && !state.running) {
                OutlinedButton(onClick = onSave) { Text("Save .pcap") }
            }
        }

        if (interfaces.isNotEmpty()) {
            LazyColumn(
                modifier = Modifier.fillMaxWidth(),
                contentPadding = PaddingValues(horizontal = 12.dp),
            ) {
                item {
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        interfaces.forEach { name ->
                            FilterChip(
                                selected = state.interfaceName == name,
                                onClick = { onSelectInterface(name) },
                                label = { Text(name) },
                            )
                        }
                    }
                }
            }
        }

        state.savedPath?.let { path ->
            SectionCard(
                title = "Saved",
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
            ) {
                MonoText(path)
                Text(
                    "Open it with Wireshark or tcpdump -r.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        state.error?.let { error ->
            SectionCard(
                title = "Capture failed",
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
            ) {
                Text(error, style = MaterialTheme.typography.bodyMedium)
            }
        }

        if (state.packets.isEmpty()) {
            EmptyState(
                message = if (state.running) {
                    "Capturing on ${state.interfaceName}…"
                } else {
                    "No packets captured."
                },
                hint = "Captures from the real interface with AF_PACKET, so it works " +
                    "alongside an active VPN instead of replacing it.",
            )
            return@Column
        }

        Row(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                "${state.packets.size} packets · ${formatBytes(state.bytes)}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp),
        ) {
            items(state.packets, key = { it.sequence }) { packet ->
                PacketRow(packet)
            }
        }
    }
}

@Composable
private fun PacketRow(packet: CapturedPacket) {
    val summary = packet.summary
    // An ICMP "fragmentation needed" or "packet too big" is the single most
    // valuable thing a capture can contain when chasing an MTU problem, so it
    // is coloured rather than left to blend into the list.
    val interesting = summary.icmpMtu > 0 || summary.rst
    val color = statusColor(
        when {
            summary.icmpMtu > 0 -> CheckStatus.CHECK_STATUS_FAIL
            summary.rst -> CheckStatus.CHECK_STATUS_WARN
            summary.syn -> CheckStatus.CHECK_STATUS_INFO
            else -> CheckStatus.CHECK_STATUS_SKIP
        },
    )

    ExpandableRow(
        summary = {
            Row(
                modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
                verticalAlignment = Alignment.Top,
            ) {
                MonoText(
                    text = formatTimeMillis(packet.unixMs),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    // Wide enough for HH:MM:SS.SSS; narrower and the
                    // milliseconds wrap onto their own line.
                    modifier = Modifier.width(108.dp),
                    maxLines = 1,
                )
                MonoText(
                    text = if (packet.outgoing) "out" else "in ",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.width(32.dp),
                )
                MonoText(
                    text = summary.description.ifEmpty { "${packet.originalLength} bytes" },
                    color = if (interesting) color else MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.weight(1f),
                    maxLines = 2,
                )
            }
        },
        detail = {
            KeyValueRow("length", "${packet.originalLength} bytes")
            KeyValueRow("interface", packet.interfaceName)
            if (summary.hasSource()) {
                KeyValueRow("source", "${summary.source.display()}:${summary.sourcePort}")
            }
            if (summary.hasDestination()) {
                KeyValueRow(
                    "destination",
                    "${summary.destination.display()}:${summary.destinationPort}",
                )
            }
            KeyValueRow("protocol", summary.protocolName)
            if (summary.ttl > 0) KeyValueRow("ttl", summary.ttl.toString())
            if (summary.icmpMtu > 0) {
                KeyValueRow(
                    "next-hop MTU",
                    summary.icmpMtu.toString(),
                    valueColor = statusColor(CheckStatus.CHECK_STATUS_FAIL),
                )
            }
            if (packet.data.size() > 0) {
                KeyValueRow("captured", "${packet.data.size()} bytes")
            }
        },
    )
}
