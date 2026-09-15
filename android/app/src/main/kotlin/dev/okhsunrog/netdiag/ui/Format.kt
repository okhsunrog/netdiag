package dev.okhsunrog.netdiag.ui

import dev.okhsunrog.netdiag.proto.Check
import dev.okhsunrog.netdiag.proto.CheckStatus
import dev.okhsunrog.netdiag.proto.FindingSeverity
import dev.okhsunrog.netdiag.proto.Interface
import dev.okhsunrog.netdiag.proto.IpAddress
import dev.okhsunrog.netdiag.proto.IpPrefix
import dev.okhsunrog.netdiag.proto.LinkKind
import dev.okhsunrog.netdiag.proto.Route
import dev.okhsunrog.netdiag.proto.RoutingRule
import dev.okhsunrog.netdiag.proto.Socket
import dev.okhsunrog.netdiag.proto.TcpState
import dev.okhsunrog.netdiag.proto.Transport
import java.net.InetAddress
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Rendering helpers shared by every screen.
 *
 * Address formatting in particular lives here rather than in the schema: the
 * wire format carries raw bytes so both sides agree on exactly what an address
 * is, and turning those into text is a presentation concern.
 */

fun IpAddress.display(): String = when (addr.size()) {
    4, 16 -> runCatching { InetAddress.getByAddress(addr.toByteArray()).hostAddress }
        .getOrNull()
        .orEmpty()
        .ifEmpty { "?" }
    else -> "-"
}

fun IpAddress.isSet(): Boolean = addr.size() == 4 || addr.size() == 16

fun IpPrefix.display(): String = when {
    !hasAddress() || !address.isSet() -> "::/$prefixLen"
    else -> "${address.display()}/$prefixLen"
}

fun Route.displayDestination(): String = when {
    isDefault -> "default"
    hasDestination() -> destination.display()
    else -> "?"
}

fun Route.displayVia(): String {
    val hop = nextHopsList.firstOrNull() ?: return "?"
    val gateway = if (hop.hasGateway() && hop.gateway.isSet()) {
        "via ${hop.gateway.display()} "
    } else {
        ""
    }
    val dev = hop.outInterfaceName.ifEmpty { "if${hop.outInterfaceIndex}" }
    return "$gateway dev $dev".trim()
}

/**
 * Render a rule the way `ip rule` does, because that is the form anyone
 * debugging this will recognise from a terminal.
 */
fun RoutingRule.display(): String = buildString {
    append(priority).append(":\t")
    if (hasSource() && source.hasAddress()) append("from ").append(source.display()).append(' ')
    if (hasDestination() && destination.hasAddress()) {
        append("to ").append(destination.display()).append(' ')
    }
    if (inputInterface.isNotEmpty()) append("iif ").append(inputInterface).append(' ')
    if (outputInterface.isNotEmpty()) append("oif ").append(outputInterface).append(' ')
    if (hasFwmark) {
        append("fwmark 0x").append(fwmark.toString(16))
        if (fwmask != 0) append("/0x").append(fwmask.toString(16))
        append(' ')
    }
    if (hasUidRange) {
        if (invert) append("not ")
        append("uidrange ").append(uidRangeStart).append('-').append(uidRangeEnd).append(' ')
    }
    if (hasSuppressPrefixLen) append("suppress_prefixlength ").append(suppressPrefixLen).append(' ')
    append("lookup ").append(if (tableName.isNotEmpty()) tableName else table.toString())
}

fun Socket.display(): String {
    val local = "${localAddress.display()}:$localPort"
    val remote = if (remotePort != 0) "${remoteAddress.display()}:$remotePort" else "*:*"
    return "$local -> $remote"
}

fun TcpState.label(): String = when (this) {
    TcpState.TCP_STATE_ESTABLISHED -> "ESTABLISHED"
    TcpState.TCP_STATE_SYN_SENT -> "SYN_SENT"
    TcpState.TCP_STATE_SYN_RECV -> "SYN_RECV"
    TcpState.TCP_STATE_FIN_WAIT1 -> "FIN_WAIT1"
    TcpState.TCP_STATE_FIN_WAIT2 -> "FIN_WAIT2"
    TcpState.TCP_STATE_TIME_WAIT -> "TIME_WAIT"
    TcpState.TCP_STATE_CLOSE -> "CLOSE"
    TcpState.TCP_STATE_CLOSE_WAIT -> "CLOSE_WAIT"
    TcpState.TCP_STATE_LAST_ACK -> "LAST_ACK"
    TcpState.TCP_STATE_LISTEN -> "LISTEN"
    TcpState.TCP_STATE_CLOSING -> "CLOSING"
    TcpState.TCP_STATE_NEW_SYN_RECV -> "NEW_SYN_RECV"
    else -> "UNKNOWN"
}

fun LinkKind.label(): String = when (this) {
    LinkKind.LINK_KIND_LOOPBACK -> "loopback"
    LinkKind.LINK_KIND_WIFI -> "Wi-Fi"
    LinkKind.LINK_KIND_CELLULAR -> "cellular"
    LinkKind.LINK_KIND_ETHERNET -> "Ethernet"
    LinkKind.LINK_KIND_VPN_TUN -> "VPN"
    LinkKind.LINK_KIND_BLUETOOTH -> "Bluetooth"
    LinkKind.LINK_KIND_CLAT -> "464XLAT"
    LinkKind.LINK_KIND_BRIDGE -> "bridge"
    LinkKind.LINK_KIND_DUMMY -> "dummy"
    else -> "other"
}

fun Transport.label(): String = when (this) {
    Transport.TRANSPORT_CELLULAR -> "Cellular"
    Transport.TRANSPORT_WIFI -> "Wi-Fi"
    Transport.TRANSPORT_BLUETOOTH -> "Bluetooth"
    Transport.TRANSPORT_ETHERNET -> "Ethernet"
    Transport.TRANSPORT_VPN -> "VPN"
    Transport.TRANSPORT_WIFI_AWARE -> "Wi-Fi Aware"
    Transport.TRANSPORT_LOWPAN -> "LoWPAN"
    Transport.TRANSPORT_USB -> "USB"
    Transport.TRANSPORT_THREAD -> "Thread"
    Transport.TRANSPORT_SATELLITE -> "Satellite"
    else -> "Unknown"
}

fun CheckStatus.label(): String = when (this) {
    CheckStatus.CHECK_STATUS_PASS -> "PASS"
    CheckStatus.CHECK_STATUS_FAIL -> "FAIL"
    CheckStatus.CHECK_STATUS_WARN -> "WARN"
    CheckStatus.CHECK_STATUS_SKIP -> "SKIP"
    CheckStatus.CHECK_STATUS_INFO -> "INFO"
    CheckStatus.CHECK_STATUS_RUNNING -> "RUN"
    else -> "?"
}

fun FindingSeverity.label(): String = when (this) {
    FindingSeverity.FINDING_SEVERITY_CRITICAL -> "Critical"
    FindingSeverity.FINDING_SEVERITY_HIGH -> "High"
    FindingSeverity.FINDING_SEVERITY_MEDIUM -> "Medium"
    FindingSeverity.FINDING_SEVERITY_LOW -> "Low"
    FindingSeverity.FINDING_SEVERITY_INFO -> "Info"
    else -> "Unknown"
}

fun Interface.addressSummary(): String = addressesList
    .filter { it.hasPrefix() }
    .joinToString(", ") { it.prefix.display() }
    .ifEmpty { "no addresses" }

fun Interface.isUp(): Boolean = hasFlags() && flags.up

private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.US)
private val timeMillisFormat = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

fun formatTime(unixMs: Long): String = timeFormat.format(Date(unixMs))

fun formatTimeMillis(unixMs: Long): String = timeMillisFormat.format(Date(unixMs))

fun formatBytes(bytes: Long): String = when {
    bytes < 1024 -> "$bytes B"
    bytes < 1024 * 1024 -> String.format(Locale.US, "%.1f KiB", bytes / 1024.0)
    bytes < 1024L * 1024 * 1024 -> String.format(Locale.US, "%.1f MiB", bytes / (1024.0 * 1024))
    else -> String.format(Locale.US, "%.2f GiB", bytes / (1024.0 * 1024 * 1024))
}

fun formatDuration(ms: Long): String = when {
    ms < 1000 -> "$ms ms"
    ms < 60_000 -> String.format(Locale.US, "%.1f s", ms / 1000.0)
    else -> "${ms / 60_000} min ${(ms % 60_000) / 1000} s"
}

/** Evidence rows, ordered so the same check always reads the same way. */
fun Check.orderedEvidence(): List<Pair<String, String>> =
    evidenceMap.entries.sortedBy { it.key }.map { it.key to it.value }
