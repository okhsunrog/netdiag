package dev.okhsunrog.netdiag.ui.screens

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
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.okhsunrog.netdiag.proto.AndroidNetwork
import dev.okhsunrog.netdiag.proto.AndroidNetworkState
import dev.okhsunrog.netdiag.proto.CheckStatus
import dev.okhsunrog.netdiag.proto.Interface
import dev.okhsunrog.netdiag.proto.Snapshot
import dev.okhsunrog.netdiag.proto.Transport
import dev.okhsunrog.netdiag.ui.EmptyState
import dev.okhsunrog.netdiag.ui.ExpandableRow
import dev.okhsunrog.netdiag.ui.KeyValueRow
import dev.okhsunrog.netdiag.ui.MonoText
import dev.okhsunrog.netdiag.ui.SectionCard
import dev.okhsunrog.netdiag.ui.SnapshotState
import dev.okhsunrog.netdiag.ui.StatusChip
import dev.okhsunrog.netdiag.ui.ThinDivider
import dev.okhsunrog.netdiag.ui.addressSummary
import dev.okhsunrog.netdiag.ui.display
import dev.okhsunrog.netdiag.ui.formatBytes
import dev.okhsunrog.netdiag.ui.isUp
import dev.okhsunrog.netdiag.ui.label
import dev.okhsunrog.netdiag.ui.statusColor

/**
 * The overview: what Android believes, and what the kernel has, side by side.
 *
 * The two are shown as separate cards rather than merged, because the
 * difference between them is exactly what this tool exists to expose. Merging
 * them into one "current state" would hide the disagreement.
 */
@Composable
fun OverviewScreen(
    state: SnapshotState,
    onRefresh: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snapshot = state.snapshot

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
                Text(
                    text = if (state.loading) "Collecting…" else "Current state",
                    style = MaterialTheme.typography.titleMedium,
                )
                OutlinedButton(onClick = onRefresh, enabled = !state.loading) {
                    Text("Refresh")
                }
            }
        }

        state.error?.let { error ->
            item {
                SectionCard(title = "Could not collect state") {
                    Text(error, style = MaterialTheme.typography.bodyMedium)
                }
            }
        }

        if (snapshot == null) {
            if (state.loading) {
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(24.dp),
                        horizontalArrangement = Arrangement.Center,
                    ) {
                        CircularProgressIndicator()
                    }
                }
            } else if (state.error == null) {
                item { EmptyState("Connect to the daemon to see the current state.") }
            }
            return@LazyColumn
        }

        state.framework?.let { framework ->
            item { FrameworkCard(framework) }
        }

        item { KernelCard(snapshot) }

        item {
            Text(
                "Interfaces",
                style = MaterialTheme.typography.titleSmall,
                modifier = Modifier.padding(top = 4.dp),
            )
        }

        // Interfaces that are down are almost always the platform's dozens of
        // pre-created rmnet devices; showing them first would bury the two or
        // three that matter.
        val sorted = snapshot.interfacesList.sortedWith(
            compareByDescending<Interface> { it.isUp() }
                .thenByDescending { it.addressesCount }
                .thenBy { it.index },
        )
        items(sorted, key = { it.index }) { iface ->
            InterfaceCard(iface)
        }

        item {
            SectionCard(
                title = "Collection",
                subtitle = "${snapshot.collectionDurationMs} ms",
            ) {
                KeyValueRow("kernel", snapshot.kernelRelease)
                KeyValueRow("routes", snapshot.routesCount.toString())
                KeyValueRow("rules", snapshot.rulesCount.toString())
                KeyValueRow("neighbours", snapshot.neighborsCount.toString())
                KeyValueRow("sockets", snapshot.socketsCount.toString())
                if (snapshot.hasFirewall()) {
                    KeyValueRow("firewall", snapshot.firewall.collectionNote, mono = false)
                }
                snapshot.collectionWarningsList.forEach {
                    KeyValueRow("warning", it, mono = false)
                }
            }
        }
    }
}

@Composable
private fun FrameworkCard(framework: AndroidNetworkState) {
    val active = framework.networksList.firstOrNull { it.netId == framework.activeNetId }
    SectionCard(
        title = "Android framework",
        subtitle = "ConnectivityManager",
    ) {
        if (active == null) {
            Text(
                "No active network",
                style = MaterialTheme.typography.bodyMedium,
                color = statusColor(CheckStatus.CHECK_STATUS_FAIL),
            )
        } else {
            NetworkSummary(active)
        }

        if (framework.networksCount > 1) {
            ThinDivider()
            Text(
                "${framework.networksCount} networks total",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            framework.networksList
                .filter { it.netId != framework.activeNetId }
                .forEach { network ->
                    Spacer(Modifier.height(6.dp))
                    MonoText(
                        text = "netId ${network.netId}  " +
                            network.transportsList.joinToString("+") { it.label() } +
                            "  " + network.linkProperties.interfaceName,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
        }

        if (framework.dataSaverEnabled) {
            ThinDivider()
            KeyValueRow(
                label = "Data Saver",
                value = "enabled — background traffic is restricted",
                valueColor = statusColor(CheckStatus.CHECK_STATUS_WARN),
                mono = false,
            )
        }
    }
}

@Composable
private fun NetworkSummary(network: AndroidNetwork) {
    val caps = network.capabilities
    val lp = network.linkProperties

    KeyValueRow("Transport", network.transportsList.joinToString(" + ") { it.label() }, mono = false)
    KeyValueRow("Interface", lp.interfaceName.ifEmpty { "—" })
    KeyValueRow("Network ID", network.netId.toString())

    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        StatusChip(
            text = if (caps.validated) "VALIDATED" else "NOT VALIDATED",
            color = statusColor(
                if (caps.validated) CheckStatus.CHECK_STATUS_PASS
                else CheckStatus.CHECK_STATUS_WARN,
            ),
        )
        StatusChip(
            text = if (caps.notMetered) "UNMETERED" else "METERED",
            color = statusColor(
                if (caps.notMetered) CheckStatus.CHECK_STATUS_PASS
                else CheckStatus.CHECK_STATUS_INFO,
            ),
        )
        if (caps.captivePortal) {
            StatusChip("PORTAL", statusColor(CheckStatus.CHECK_STATUS_FAIL))
        }
        if (network.transportsList.contains(Transport.TRANSPORT_VPN)) {
            StatusChip("VPN", statusColor(CheckStatus.CHECK_STATUS_INFO))
        }
    }

    if (lp.dnsServersCount > 0) {
        KeyValueRow("DNS", lp.dnsServersList.joinToString(", ") { it.display() })
    }
    if (lp.privateDnsActive) {
        KeyValueRow(
            "Private DNS",
            lp.privateDnsServerName.ifEmpty { "opportunistic" },
            mono = false,
        )
    }
    if (lp.mtu > 0) {
        KeyValueRow("MTU", lp.mtu.toString())
    }
    if (lp.hasNat64Prefix()) {
        KeyValueRow("NAT64 prefix", lp.nat64Prefix.display())
    }
    if (lp.hasHttpProxy) {
        KeyValueRow("Proxy", "${lp.httpProxyHost}:${lp.httpProxyPort}")
    }
}

@Composable
private fun KernelCard(snapshot: Snapshot) {
    val defaults = snapshot.routesList.filter { it.isDefault }
    SectionCard(
        title = "Linux kernel",
        subtitle = "netlink",
    ) {
        if (defaults.isEmpty()) {
            Text(
                "No default route in any table",
                style = MaterialTheme.typography.bodyMedium,
                color = statusColor(CheckStatus.CHECK_STATUS_FAIL),
            )
        } else {
            defaults.forEach { route ->
                val hop = route.nextHopsList.firstOrNull()
                val via = hop?.takeIf { it.hasGateway() && it.gateway.addr.size() > 0 }
                    ?.gateway?.display()
                    ?: "on-link"
                MonoText(
                    "default via $via dev ${hop?.outInterfaceName.orEmpty()} " +
                        "table ${route.table}",
                )
            }
        }

        if (snapshot.hasClat() && snapshot.clat.active) {
            ThinDivider()
            KeyValueRow(
                "464XLAT",
                "active on ${snapshot.clat.clatInterface} over ${snapshot.clat.baseInterface}",
                mono = false,
            )
        }

        if (snapshot.hasSocketSummary()) {
            ThinDivider()
            val s = snapshot.socketSummary
            KeyValueRow("Sockets", "${s.total} total, ${s.established} established")
            if (s.synSent > 0) {
                KeyValueRow(
                    "SYN_SENT",
                    s.synSent.toString(),
                    valueColor = statusColor(
                        if (s.synSent >= 5) CheckStatus.CHECK_STATUS_FAIL
                        else CheckStatus.CHECK_STATUS_WARN,
                    ),
                )
            }
        }
    }
}

@Composable
private fun InterfaceCard(iface: Interface) {
    val up = iface.isUp()
    SectionCard(
        title = iface.name,
        subtitle = "${iface.kind.label()} · index ${iface.index} · MTU ${iface.mtu}",
        trailing = {
            StatusChip(
                text = if (up) "UP" else "DOWN",
                color = statusColor(
                    if (up) CheckStatus.CHECK_STATUS_PASS else CheckStatus.CHECK_STATUS_SKIP,
                ),
            )
        },
    ) {
        ExpandableRow(
            summary = {
                MonoText(iface.addressSummary())
            },
            detail = {
                iface.addressesList.forEach { address ->
                    val scope = address.scope.name.removePrefix("ADDRESS_SCOPE_").lowercase()
                    val flags = buildList {
                        if (address.flags.temporary) add("temporary")
                        if (address.flags.deprecated) add("deprecated")
                        if (address.flags.tentative) add("tentative")
                        if (address.flags.stablePrivacy) add("stable-privacy")
                    }
                    MonoText(
                        text = address.prefix.display() + "  " + scope +
                            if (flags.isEmpty()) "" else "  " + flags.joinToString(","),
                    )
                }
                if (iface.hasStats()) {
                    KeyValueRow("rx", formatBytes(iface.stats.rxBytes))
                    KeyValueRow("tx", formatBytes(iface.stats.txBytes))
                    if (iface.stats.rxDropped > 0 || iface.stats.txDropped > 0) {
                        KeyValueRow(
                            "dropped",
                            "rx ${iface.stats.rxDropped} / tx ${iface.stats.txDropped}",
                            valueColor = statusColor(CheckStatus.CHECK_STATUS_WARN),
                        )
                    }
                }
                if (iface.hasSysctls()) {
                    val sysctls = iface.sysctls
                    if (sysctls.ipv6Disabled) {
                        KeyValueRow(
                            "disable_ipv6",
                            "1 — IPv6 is off on this interface",
                            valueColor = statusColor(CheckStatus.CHECK_STATUS_FAIL),
                            mono = false,
                        )
                    }
                    KeyValueRow("accept_ra", sysctls.acceptRa.toString())
                }
                if (iface.macAddress.size() > 0) {
                    KeyValueRow(
                        "mac",
                        iface.macAddress.toByteArray().joinToString(":") {
                            "%02x".format(it)
                        },
                    )
                }
            },
        )
    }
}
