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
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.okhsunrog.netdiag.proto.CheckStatus
import dev.okhsunrog.netdiag.proto.Socket
import dev.okhsunrog.netdiag.proto.SocketProtocol
import dev.okhsunrog.netdiag.proto.TcpState
import dev.okhsunrog.netdiag.ui.EmptyState
import dev.okhsunrog.netdiag.ui.ExpandableRow
import dev.okhsunrog.netdiag.ui.KeyValueRow
import dev.okhsunrog.netdiag.ui.MonoText
import dev.okhsunrog.netdiag.ui.SectionCard
import dev.okhsunrog.netdiag.ui.SnapshotState
import dev.okhsunrog.netdiag.ui.StatusChip
import dev.okhsunrog.netdiag.ui.display
import dev.okhsunrog.netdiag.ui.label
import dev.okhsunrog.netdiag.ui.statusColor

/**
 * Every socket on the device, with the uid that owns it and the netId its mark
 * points at. Those two columns are what make this more than `ss -tanp`: they
 * connect a connection to an app and to a framework Network.
 */
@Composable
fun SocketsScreen(
    state: SnapshotState,
    packagesForUid: (Int) -> List<String>,
    modifier: Modifier = Modifier,
) {
    val snapshot = state.snapshot
    if (snapshot == null || snapshot.socketsCount == 0) {
        EmptyState(
            "No socket data.",
            hint = "Refresh the overview; socket diagnostics need the daemon.",
            modifier = modifier,
        )
        return
    }

    var onlyEstablished by remember { mutableStateOf(false) }
    var onlyApps by remember { mutableStateOf(false) }
    var hideListen by remember { mutableStateOf(false) }

    val sockets = remember(snapshot, onlyEstablished, onlyApps, hideListen) {
        snapshot.socketsList
            .filter { !onlyEstablished || it.state == TcpState.TCP_STATE_ESTABLISHED }
            // uid >= 10000 is the first app uid on Android; below that is the
            // platform.
            .filter { !onlyApps || it.uid >= FIRST_APP_UID }
            .filter { !hideListen || it.state != TcpState.TCP_STATE_LISTEN }
            .sortedWith(
                compareBy<Socket> { it.uid }
                    .thenBy { it.state.number }
                    .thenBy { it.localPort },
            )
    }

    Column(modifier = modifier.fillMaxSize()) {
        snapshot.socketSummary?.let { summary ->
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                StatusChip(
                    "${summary.established} EST",
                    statusColor(CheckStatus.CHECK_STATUS_PASS),
                )
                if (summary.synSent > 0) {
                    StatusChip(
                        "${summary.synSent} SYN_SENT",
                        statusColor(CheckStatus.CHECK_STATUS_WARN),
                    )
                }
                if (summary.closeWait > 0) {
                    StatusChip(
                        "${summary.closeWait} CLOSE_WAIT",
                        statusColor(CheckStatus.CHECK_STATUS_WARN),
                    )
                }
                StatusChip("${summary.listen} LISTEN", statusColor(CheckStatus.CHECK_STATUS_INFO))
            }
        }

        Row(
            modifier = Modifier.padding(horizontal = 12.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            FilterChip(
                selected = onlyEstablished,
                onClick = { onlyEstablished = !onlyEstablished },
                label = { Text("Established") },
            )
            FilterChip(
                selected = onlyApps,
                onClick = { onlyApps = !onlyApps },
                label = { Text("Apps only") },
            )
            FilterChip(
                selected = hideListen,
                onClick = { hideListen = !hideListen },
                label = { Text("Hide LISTEN") },
            )
        }

        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(horizontal = 12.dp),
            contentPadding = PaddingValues(vertical = 8.dp),
        ) {
            items(
                sockets,
                key = { "${it.socketCookie}-${it.inode}-${it.localPort}-${it.remotePort}" },
            ) { socket ->
                SocketRow(socket, packagesForUid)
            }
        }
    }
}

@Composable
private fun SocketRow(socket: Socket, packagesForUid: (Int) -> List<String>) {
    val stateColor = statusColor(
        when (socket.state) {
            TcpState.TCP_STATE_ESTABLISHED -> CheckStatus.CHECK_STATUS_PASS
            TcpState.TCP_STATE_SYN_SENT, TcpState.TCP_STATE_CLOSE_WAIT ->
                CheckStatus.CHECK_STATUS_WARN
            TcpState.TCP_STATE_LISTEN -> CheckStatus.CHECK_STATUS_INFO
            else -> CheckStatus.CHECK_STATUS_SKIP
        },
    )

    ExpandableRow(
        summary = {
            Row(
                modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                StatusChip(
                    text = socket.state.label().take(11),
                    color = stateColor,
                    modifier = Modifier.width(96.dp),
                )
                Column(modifier = Modifier.weight(1f).padding(start = 8.dp)) {
                    MonoText(socket.display(), maxLines = 1)
                    MonoText(
                        text = buildString {
                            append("uid ").append(socket.uid)
                            if (socket.hasMark && socket.netId != 0) {
                                append("  netId ").append(socket.netId)
                            }
                            if (socket.protocol == SocketProtocol.SOCKET_PROTOCOL_UDP) {
                                append("  udp")
                            }
                        },
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        },
        detail = {
            val packages = packagesForUid(socket.uid)
            if (packages.isNotEmpty()) {
                KeyValueRow("packages", packages.joinToString(", "))
            }
            if (socket.hasMark) {
                KeyValueRow(
                    "mark",
                    "0x${socket.mark.toString(16)} (netId ${socket.netId})",
                )
            }
            if (socket.interfaceName.isNotEmpty()) {
                KeyValueRow("bound to", socket.interfaceName)
            }
            KeyValueRow("queues", "rx ${socket.rxQueue} / tx ${socket.txQueue}")
            KeyValueRow("inode", socket.inode.toString())
            if (socket.congestionControl.isNotEmpty()) {
                KeyValueRow("congestion", socket.congestionControl)
            }
            if (socket.hasTcpInfo()) {
                val info = socket.tcpInfo
                KeyValueRow("rtt", "${info.rttUs / 1000}.${(info.rttUs % 1000) / 100} ms")
                KeyValueRow("retransmits", info.totalRetrans.toString())
                KeyValueRow("cwnd", info.sndCwnd.toString())
                if (info.pmtu > 0) KeyValueRow("pmtu", info.pmtu.toString())
                if (info.retransmitting) {
                    KeyValueRow(
                        "status",
                        "actively retransmitting",
                        valueColor = statusColor(CheckStatus.CHECK_STATUS_WARN),
                        mono = false,
                    )
                }
            }
        },
    )
}

private const val FIRST_APP_UID = 10000
