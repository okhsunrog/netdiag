package dev.okhsunrog.netdiag.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.okhsunrog.netdiag.data.InstalledApp
import dev.okhsunrog.netdiag.proto.AppNetworkState
import dev.okhsunrog.netdiag.proto.CheckStatus
import dev.okhsunrog.netdiag.proto.RouteLookup
import dev.okhsunrog.netdiag.proto.Socket
import dev.okhsunrog.netdiag.proto.TcpState
import dev.okhsunrog.netdiag.ui.AppsState
import dev.okhsunrog.netdiag.ui.EmptyState
import dev.okhsunrog.netdiag.ui.ExpandableRow
import dev.okhsunrog.netdiag.ui.KeyValueRow
import dev.okhsunrog.netdiag.ui.MonoText
import dev.okhsunrog.netdiag.ui.SectionCard
import dev.okhsunrog.netdiag.ui.StatusChip
import dev.okhsunrog.netdiag.ui.ThinDivider
import dev.okhsunrog.netdiag.ui.display
import dev.okhsunrog.netdiag.ui.label
import dev.okhsunrog.netdiag.ui.statusColor

/**
 * Per-app network path.
 *
 * The whole point of this screen is the chain: package name to uid to sockets
 * to policy rules to routing table to interface. Each section is one link, in
 * that order, so the path reads top to bottom the way the packet travels.
 */
@Composable
fun AppsScreen(
    state: AppsState,
    onLoad: (includeSystem: Boolean) -> Unit,
    onSelect: (InstalledApp) -> Unit,
    onClear: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val selected = state.selected
    if (selected != null) {
        AppDetail(selected, onClear, modifier)
        return
    }

    var query by remember { mutableStateOf("") }
    val filtered = remember(state.apps, query) {
        if (query.isBlank()) {
            state.apps
        } else {
            state.apps.filter {
                it.label.contains(query, ignoreCase = true) ||
                    it.packageName.contains(query, ignoreCase = true) ||
                    it.uid.toString() == query
            }
        }
    }

    Column(modifier = modifier.fillMaxSize()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                label = { Text("Filter by name, package or uid") },
                singleLine = true,
                modifier = Modifier.weight(1f),
            )
        }
        Row(
            modifier = Modifier.padding(horizontal = 12.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            FilterChip(
                selected = state.includeSystem,
                onClick = { onLoad(!state.includeSystem) },
                label = { Text("Include system apps") },
            )
        }

        if (state.loading && state.apps.isEmpty()) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(24.dp),
                horizontalArrangement = Arrangement.Center,
            ) { CircularProgressIndicator() }
            return@Column
        }

        if (state.apps.isEmpty()) {
            EmptyState(
                "No apps loaded.",
                hint = "Tap Include system apps, or reconnect to the daemon.",
            )
            return@Column
        }

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(12.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            items(filtered, key = { it.packageName }) { app ->
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onSelect(app) }
                        .padding(vertical = 8.dp, horizontal = 4.dp),
                ) {
                    Text(app.label, style = MaterialTheme.typography.bodyLarge)
                    MonoText(
                        text = "${app.packageName}  uid ${app.uid}",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

@Composable
private fun AppDetail(
    state: AppNetworkState,
    onClear: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val app = state.app
    val routing = state.routing
    val vpn = state.vpn

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        contentPadding = PaddingValues(vertical = 12.dp),
    ) {
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        app.label.ifEmpty { app.packageName },
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                    )
                    MonoText("${app.packageName}  uid ${app.uid}")
                }
                TextButton(onClick = onClear) { Text("Back") }
            }
        }

        item {
            SectionCard(title = "Summary") {
                Text(state.summary, style = MaterialTheme.typography.bodyMedium)
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    StatusChip(
                        text = if (state.ipv4PathOk) "IPv4 OK" else "IPv4 FAILED",
                        color = statusColor(
                            if (state.ipv4PathOk) CheckStatus.CHECK_STATUS_PASS
                            else CheckStatus.CHECK_STATUS_FAIL,
                        ),
                    )
                    StatusChip(
                        text = if (state.ipv6PathOk) "IPv6 OK" else "IPv6 FAILED",
                        color = statusColor(
                            if (state.ipv6PathOk) CheckStatus.CHECK_STATUS_PASS
                            else CheckStatus.CHECK_STATUS_FAIL,
                        ),
                    )
                }
            }
        }

        if (state.hasAndroidNetwork()) {
            item {
                val network = state.androidNetwork
                SectionCard(
                    title = "Android network",
                    subtitle = "what the framework says",
                ) {
                    KeyValueRow(
                        "Transport",
                        network.transportsList.joinToString(" + ") { it.label() },
                        mono = false,
                    )
                    KeyValueRow("Interface", network.linkProperties.interfaceName.ifEmpty { "—" })
                    KeyValueRow("Network ID", network.netId.toString())
                    KeyValueRow(
                        "VALIDATED",
                        if (network.capabilities.validated) "yes" else "no",
                        valueColor = statusColor(
                            if (network.capabilities.validated) CheckStatus.CHECK_STATUS_PASS
                            else CheckStatus.CHECK_STATUS_WARN,
                        ),
                    )
                    KeyValueRow(
                        "Metered",
                        if (network.capabilities.notMetered) "no" else "yes",
                    )
                }
            }
        }

        item {
            SectionCard(
                title = "Routing",
                subtitle = "what the kernel actually does for uid ${app.uid}",
            ) {
                if (routing.matchingRulesCount == 0) {
                    Text(
                        "No uid or fwmark rule matches this app; it follows the default " +
                            "policy.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                } else {
                    Text(
                        "Matching rules, in the order the kernel evaluates them:",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(4.dp))
                    routing.matchingRulesList.take(12).forEach { rule ->
                        MonoText(rule.display())
                    }
                    if (routing.matchingRulesCount > 12) {
                        MonoText(
                            "… and ${routing.matchingRulesCount - 12} more",
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }

                ThinDivider()
                LookupRow("IPv4", routing.lookupV4, routing.egressInterfaceV4, routing.tableV4)
                LookupRow("IPv6", routing.lookupV6, routing.egressInterfaceV6, routing.tableV6)
            }
        }

        if (vpn.vpnPresent) {
            item {
                SectionCard(
                    title = "VPN",
                    subtitle = vpn.vpnInterface,
                    trailing = {
                        StatusChip(
                            text = if (vpn.appUsesVpn) "IN TUNNEL" else "BYPASSES",
                            color = statusColor(
                                if (vpn.appUsesVpn) CheckStatus.CHECK_STATUS_PASS
                                else CheckStatus.CHECK_STATUS_WARN,
                            ),
                        )
                    },
                ) {
                    KeyValueRow("Interface", vpn.vpnInterface)
                    KeyValueRow(
                        "This app",
                        if (vpn.appUsesVpn) "goes through the VPN" else "bypasses the VPN",
                        mono = false,
                    )
                    if (vpn.bypassReason.isNotEmpty()) {
                        KeyValueRow("Reason", vpn.bypassReason, mono = false)
                    }
                    if (vpn.splitTunnel) {
                        KeyValueRow(
                            "Split tunnel",
                            "one address family is inside the tunnel and the other is not",
                            valueColor = statusColor(CheckStatus.CHECK_STATUS_WARN),
                            mono = false,
                        )
                    }
                    if (vpn.disagreement) {
                        ThinDivider()
                        KeyValueRow(
                            "Disagreement",
                            "the framework says this app is " +
                                (if (vpn.frameworkSaysInVpn) "inside" else "outside") +
                                " the VPN, but the kernel routes it " +
                                (if (vpn.appUsesVpn) "into" else "around") + " the tunnel",
                            valueColor = statusColor(CheckStatus.CHECK_STATUS_FAIL),
                            mono = false,
                        )
                    }
                }
            }
        }

        item {
            SectionCard(
                title = "Sockets",
                subtitle = "${state.socketSummary.total} open",
            ) {
                val s = state.socketSummary
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    if (s.established > 0) {
                        StatusChip(
                            "${s.established} ESTABLISHED",
                            statusColor(CheckStatus.CHECK_STATUS_PASS),
                        )
                    }
                    if (s.synSent > 0) {
                        StatusChip(
                            "${s.synSent} SYN_SENT",
                            statusColor(CheckStatus.CHECK_STATUS_WARN),
                        )
                    }
                    if (s.closeWait > 0) {
                        StatusChip(
                            "${s.closeWait} CLOSE_WAIT",
                            statusColor(CheckStatus.CHECK_STATUS_WARN),
                        )
                    }
                }

                if (state.observedNetIdsCount > 0) {
                    Spacer(Modifier.height(8.dp))
                    KeyValueRow(
                        "Pinned to",
                        "netId " + state.observedNetIdsList.joinToString(", "),
                    )
                }

                if (state.socketsCount > 0) {
                    ThinDivider()
                    state.socketsList.take(25).forEach { socket ->
                        SocketRow(socket)
                    }
                    if (state.socketsCount > 25) {
                        MonoText(
                            "… and ${state.socketsCount - 25} more",
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                } else {
                    Text(
                        "This app has no open sockets right now.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

        if (state.firewallNote.isNotEmpty()) {
            item {
                SectionCard(title = "Firewall") {
                    Text(state.firewallNote, style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
    }
}

@Composable
private fun LookupRow(
    family: String,
    lookup: RouteLookup,
    egress: String,
    table: Int,
) {
    if (lookup.hasError()) {
        KeyValueRow(
            label = family,
            value = "no route: ${lookup.error.message}",
            valueColor = statusColor(CheckStatus.CHECK_STATUS_FAIL),
            mono = false,
        )
        return
    }
    if (!lookup.hasRoute()) {
        KeyValueRow(family, "not looked up", mono = false)
        return
    }
    val hop = lookup.route.nextHopsList.firstOrNull()
    val via = hop?.takeIf { it.hasGateway() && it.gateway.addr.size() > 0 }
        ?.gateway?.display()
        ?: "on-link"
    KeyValueRow(
        label = family,
        value = "table $table via $via dev ${egress.ifEmpty { "—" }}",
    )
}

@Composable
private fun SocketRow(socket: Socket) {
    ExpandableRow(
        summary = {
            Row(
                modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                MonoText(
                    text = socket.state.label().padEnd(12),
                    color = statusColor(
                        when (socket.state) {
                            TcpState.TCP_STATE_ESTABLISHED ->
                                CheckStatus.CHECK_STATUS_PASS
                            TcpState.TCP_STATE_SYN_SENT ->
                                CheckStatus.CHECK_STATUS_WARN
                            else -> CheckStatus.CHECK_STATUS_SKIP
                        },
                    ),
                )
                MonoText(
                    text = socket.display(),
                    modifier = Modifier.weight(1f),
                    maxLines = 1,
                )
            }
        },
        detail = {
            if (socket.hasMark) {
                KeyValueRow(
                    "mark",
                    "0x${socket.mark.toString(16)} (netId ${socket.netId})",
                )
            }
            if (socket.interfaceName.isNotEmpty()) {
                KeyValueRow("bound to", socket.interfaceName)
            }
            KeyValueRow("inode", socket.inode.toString())
            if (socket.hasTcpInfo()) {
                val info = socket.tcpInfo
                KeyValueRow("rtt", "${info.rttUs / 1000} ms")
                KeyValueRow("retransmits", info.totalRetrans.toString())
                KeyValueRow("cwnd", info.sndCwnd.toString())
                if (info.pmtu > 0) KeyValueRow("pmtu", info.pmtu.toString())
            }
        },
    )
}
