package dev.okhsunrog.netdiag.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.okhsunrog.netdiag.proto.CheckStatus
import dev.okhsunrog.netdiag.proto.IpFamily
import dev.okhsunrog.netdiag.proto.NeighborState
import dev.okhsunrog.netdiag.proto.Route
import dev.okhsunrog.netdiag.proto.Snapshot
import dev.okhsunrog.netdiag.ui.EmptyState
import dev.okhsunrog.netdiag.ui.ExpandableRow
import dev.okhsunrog.netdiag.ui.KeyValueRow
import dev.okhsunrog.netdiag.ui.MonoText
import dev.okhsunrog.netdiag.ui.SectionCard
import dev.okhsunrog.netdiag.ui.SnapshotState
import dev.okhsunrog.netdiag.ui.StatusChip
import dev.okhsunrog.netdiag.ui.display
import dev.okhsunrog.netdiag.ui.displayDestination
import dev.okhsunrog.netdiag.ui.displayVia
import dev.okhsunrog.netdiag.ui.statusColor

/**
 * Routes, policy rules and the neighbour table.
 *
 * Routes are grouped by table because that is how Android uses them: one table
 * per Network, selected by a policy rule. A flat list sorted by destination
 * would scramble networks together and make the per-network structure
 * invisible, which is the one thing worth seeing here.
 */
@Composable
fun RoutingScreen(
    state: SnapshotState,
    modifier: Modifier = Modifier,
) {
    val snapshot = state.snapshot
    if (snapshot == null) {
        EmptyState("No data yet. Refresh the overview first.", modifier = modifier)
        return
    }

    var family by remember { mutableStateOf(IpFamily.IP_FAMILY_UNSPECIFIED) }
    var showAllRules by remember { mutableStateOf(false) }

    Column(modifier = modifier.fillMaxSize()) {
        Row(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            FilterChip(
                selected = family == IpFamily.IP_FAMILY_UNSPECIFIED,
                onClick = { family = IpFamily.IP_FAMILY_UNSPECIFIED },
                label = { Text("All") },
            )
            FilterChip(
                selected = family == IpFamily.IP_FAMILY_V4,
                onClick = { family = IpFamily.IP_FAMILY_V4 },
                label = { Text("IPv4") },
            )
            FilterChip(
                selected = family == IpFamily.IP_FAMILY_V6,
                onClick = { family = IpFamily.IP_FAMILY_V6 },
                label = { Text("IPv6") },
            )
        }

        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(horizontal = 12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            contentPadding = PaddingValues(vertical = 8.dp),
        ) {
            val rules = snapshot.rulesList.filter {
                family == IpFamily.IP_FAMILY_UNSPECIFIED || it.family == family
            }
            // Android installs hundreds of per-uid rules; showing them all by
            // default would bury the handful that define the overall policy.
            val interestingRules = rules.filter { it.hasUidRange || it.hasFwmark }
            val shownRules = if (showAllRules) rules else rules.take(RULE_PREVIEW_COUNT)

            item {
                SectionCard(
                    title = "Policy rules",
                    subtitle = "${rules.size} total, ${interestingRules.size} with a uid " +
                        "range or fwmark",
                    trailing = {
                        FilterChip(
                            selected = showAllRules,
                            onClick = { showAllRules = !showAllRules },
                            label = { Text(if (showAllRules) "Fewer" else "All") },
                        )
                    },
                ) {
                    if (rules.isEmpty()) {
                        Text(
                            "No rules for this family.",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    shownRules.forEach { rule ->
                        MonoText(rule.display())
                    }
                    if (!showAllRules && rules.size > RULE_PREVIEW_COUNT) {
                        MonoText(
                            "… ${rules.size - RULE_PREVIEW_COUNT} more",
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }

            val routesByTable = snapshot.routesList
                .filter { family == IpFamily.IP_FAMILY_UNSPECIFIED || it.family == family }
                .groupBy { it.table }
                .toSortedMap()

            routesByTable.forEach { (table, routes) ->
                item {
                    RouteTableCard(table, routes, snapshot)
                }
            }

            if (snapshot.neighborsCount > 0) {
                item {
                    SectionCard(
                        title = "Neighbours",
                        subtitle = "${snapshot.neighborsCount} entries",
                    ) {
                        snapshot.neighborsList
                            .filter {
                                family == IpFamily.IP_FAMILY_UNSPECIFIED || it.family == family
                            }
                            .forEach { neighbor ->
                                val usable = neighbor.state in USABLE_NEIGHBOR_STATES
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                                ) {
                                    StatusChip(
                                        text = neighbor.state.name
                                            .removePrefix("NEIGHBOR_STATE_"),
                                        color = statusColor(
                                            if (usable) CheckStatus.CHECK_STATUS_PASS
                                            else CheckStatus.CHECK_STATUS_FAIL,
                                        ),
                                    )
                                    MonoText(
                                        text = neighbor.address.display() + "  " +
                                            neighbor.interfaceName +
                                            if (neighbor.isRouter) "  (router)" else "",
                                        modifier = Modifier.weight(1f),
                                    )
                                }
                            }
                    }
                }
            }
        }
    }
}

@Composable
private fun RouteTableCard(table: Int, routes: List<Route>, snapshot: Snapshot) {
    val name = snapshot.tableNamesMap[table].orEmpty()
    val defaults = routes.count { it.isDefault }
    SectionCard(
        title = if (name.isEmpty()) "Table $table" else "Table $table ($name)",
        subtitle = "${routes.size} routes" +
            if (defaults > 0) ", $defaults default" else "",
    ) {
        ExpandableRow(
            summary = { expanded ->
                val preview = routes.filter { it.isDefault }.ifEmpty { routes.take(2) }
                preview.forEach { route ->
                    MonoText("${route.displayDestination()} ${route.displayVia()}")
                }
                if (!expanded && routes.size > preview.size) {
                    MonoText(
                        "tap for ${routes.size - preview.size} more",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            },
            detail = {
                routes.forEach { route ->
                    MonoText(
                        buildString {
                            append(route.displayDestination())
                            append(' ')
                            append(route.displayVia())
                            if (route.priority != 0) append(" metric ").append(route.priority)
                            if (route.hasMetrics() && route.metrics.mtu != 0) {
                                append(" mtu ").append(route.metrics.mtu)
                            }
                            if (route.expiresSec != 0) {
                                append(" expires ").append(route.expiresSec).append('s')
                            }
                        },
                    )
                }
            },
        )
    }
}

private const val RULE_PREVIEW_COUNT = 15

private val USABLE_NEIGHBOR_STATES = setOf(
    NeighborState.NEIGHBOR_STATE_REACHABLE,
    NeighborState.NEIGHBOR_STATE_STALE,
    NeighborState.NEIGHBOR_STATE_DELAY,
    NeighborState.NEIGHBOR_STATE_PROBE,
    NeighborState.NEIGHBOR_STATE_PERMANENT,
    NeighborState.NEIGHBOR_STATE_NOARP,
)
