package dev.okhsunrog.netdiag.framework

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log
import dev.okhsunrog.netdiag.proto.EventSeverity
import dev.okhsunrog.netdiag.proto.EventSource
import dev.okhsunrog.netdiag.proto.FrameworkEventKind
import dev.okhsunrog.netdiag.proto.NetworkEvent
import dev.okhsunrog.netdiag.proto.frameworkEvent
import dev.okhsunrog.netdiag.proto.networkEvent
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow

private const val TAG = "NetworkEventSource"

/**
 * Turns `ConnectivityManager.NetworkCallback` into a flow of timeline events.
 *
 * The callbacks fire far more often than anything a person wants to read:
 * `onCapabilitiesChanged` arrives on every signal strength change. So rather
 * than forwarding each callback, this remembers the previous capabilities and
 * link properties per network and only emits when something a human would call
 * a change actually changed — validation flipping, DNS servers moving, a VPN
 * appearing, IPv6 coming or going.
 */
class NetworkEventSource(
    context: Context,
    private val collector: FrameworkCollector,
) {
    private val connectivity: ConnectivityManager =
        context.getSystemService(ConnectivityManager::class.java)

    private data class Remembered(
        val validated: Boolean,
        val captivePortal: Boolean,
        val metered: Boolean,
        val transports: Set<Int>,
        val interfaceName: String,
        val dnsServers: List<String>,
        val hasIpv6: Boolean,
        val hasIpv4: Boolean,
        val privateDnsActive: Boolean,
        val nat64Prefix: String,
    )

    fun events(): Flow<NetworkEvent> = callbackFlow {
        val remembered = mutableMapOf<Long, Remembered>()

        fun emit(
            network: Network,
            kind: FrameworkEventKind,
            summary: String,
            severity: EventSeverity = EventSeverity.EVENT_SEVERITY_INFO,
            changeSummary: String = "",
        ) {
            val described = runCatching { collector.describe(network, isDefault = false) }
                .getOrNull()
            val event = networkEvent {
                unixMs = System.currentTimeMillis()
                source = EventSource.EVENT_SOURCE_FRAMEWORK
                this.severity = severity
                this.summary = summary
                framework = frameworkEvent {
                    this.kind = kind
                    this.changeSummary = changeSummary
                    described?.let { this.network = it }
                }
            }
            trySend(event)
        }

        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val name = interfaceNameOf(network)
                emit(
                    network,
                    FrameworkEventKind.FRAMEWORK_EVENT_KIND_AVAILABLE,
                    "$name available",
                    EventSeverity.EVENT_SEVERITY_NOTICE,
                )
            }

            override fun onLost(network: Network) {
                val name = remembered[network.networkHandle]?.interfaceName
                    ?: interfaceNameOf(network)
                remembered.remove(network.networkHandle)
                emit(
                    network,
                    FrameworkEventKind.FRAMEWORK_EVENT_KIND_LOST,
                    "$name lost",
                    EventSeverity.EVENT_SEVERITY_WARNING,
                )
            }

            override fun onLosing(network: Network, maxMsToLive: Int) {
                emit(
                    network,
                    FrameworkEventKind.FRAMEWORK_EVENT_KIND_LOSING,
                    "${interfaceNameOf(network)} losing connectivity " +
                        "(${maxMsToLive}ms to live)",
                    EventSeverity.EVENT_SEVERITY_WARNING,
                )
            }

            override fun onCapabilitiesChanged(
                network: Network,
                capabilities: NetworkCapabilities,
            ) {
                update(network, capabilities = capabilities)
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                update(network, linkProperties = linkProperties)
            }

            override fun onBlockedStatusChanged(network: Network, blocked: Boolean) {
                emit(
                    network,
                    FrameworkEventKind.FRAMEWORK_EVENT_KIND_BLOCKED_STATUS_CHANGED,
                    "this app's traffic on ${interfaceNameOf(network)} is " +
                        if (blocked) "blocked" else "no longer blocked",
                    if (blocked) EventSeverity.EVENT_SEVERITY_WARNING
                    else EventSeverity.EVENT_SEVERITY_NOTICE,
                )
            }

            /**
             * Compare against what we saw last time and emit one event per
             * meaningful difference, rather than one per callback.
             */
            private fun update(
                network: Network,
                capabilities: NetworkCapabilities? = null,
                linkProperties: LinkProperties? = null,
            ) {
                val nc = capabilities
                    ?: runCatching { connectivity.getNetworkCapabilities(network) }.getOrNull()
                val lp = linkProperties
                    ?: runCatching { connectivity.getLinkProperties(network) }.getOrNull()
                val current = snapshot(nc, lp) ?: return
                val previous = remembered.put(network.networkHandle, current)
                val name = current.interfaceName.ifEmpty { interfaceNameOf(network) }

                if (previous == null) {
                    // First sighting; onAvailable already announced it.
                    return
                }

                if (previous.validated != current.validated) {
                    emit(
                        network,
                        FrameworkEventKind.FRAMEWORK_EVENT_KIND_VALIDATION_CHANGED,
                        "$name VALIDATED: ${previous.validated} -> ${current.validated}",
                        if (current.validated) EventSeverity.EVENT_SEVERITY_NOTICE
                        else EventSeverity.EVENT_SEVERITY_WARNING,
                        "VALIDATED ${previous.validated} -> ${current.validated}",
                    )
                }
                if (previous.captivePortal != current.captivePortal && current.captivePortal) {
                    emit(
                        network,
                        FrameworkEventKind.FRAMEWORK_EVENT_KIND_CAPTIVE_PORTAL,
                        "$name is behind a captive portal",
                        EventSeverity.EVENT_SEVERITY_WARNING,
                    )
                }
                if (previous.transports != current.transports) {
                    emit(
                        network,
                        FrameworkEventKind.FRAMEWORK_EVENT_KIND_TRANSPORT_CHANGED,
                        "$name transports changed",
                        EventSeverity.EVENT_SEVERITY_NOTICE,
                    )
                }
                if (previous.dnsServers != current.dnsServers) {
                    emit(
                        network,
                        FrameworkEventKind.FRAMEWORK_EVENT_KIND_DNS_SERVERS_CHANGED,
                        "$name DNS servers: ${current.dnsServers.joinToString(", ")}",
                        EventSeverity.EVENT_SEVERITY_NOTICE,
                    )
                }
                if (previous.hasIpv6 != current.hasIpv6) {
                    emit(
                        network,
                        FrameworkEventKind.FRAMEWORK_EVENT_KIND_LINK_PROPERTIES_CHANGED,
                        if (current.hasIpv6) "$name gained IPv6" else "$name lost IPv6",
                        if (current.hasIpv6) EventSeverity.EVENT_SEVERITY_NOTICE
                        else EventSeverity.EVENT_SEVERITY_WARNING,
                    )
                }
                if (previous.hasIpv4 != current.hasIpv4) {
                    emit(
                        network,
                        FrameworkEventKind.FRAMEWORK_EVENT_KIND_LINK_PROPERTIES_CHANGED,
                        if (current.hasIpv4) "$name gained IPv4" else "$name lost IPv4",
                        if (current.hasIpv4) EventSeverity.EVENT_SEVERITY_NOTICE
                        else EventSeverity.EVENT_SEVERITY_WARNING,
                    )
                }
                if (previous.privateDnsActive != current.privateDnsActive) {
                    emit(
                        network,
                        FrameworkEventKind.FRAMEWORK_EVENT_KIND_PRIVATE_DNS_CHANGED,
                        "$name Private DNS " +
                            if (current.privateDnsActive) "active" else "inactive",
                        EventSeverity.EVENT_SEVERITY_NOTICE,
                    )
                }
                if (previous.nat64Prefix != current.nat64Prefix) {
                    emit(
                        network,
                        FrameworkEventKind.FRAMEWORK_EVENT_KIND_NAT64_PREFIX_CHANGED,
                        if (current.nat64Prefix.isEmpty()) {
                            "$name NAT64 prefix withdrawn"
                        } else {
                            "$name NAT64 prefix ${current.nat64Prefix}"
                        },
                        EventSeverity.EVENT_SEVERITY_NOTICE,
                    )
                }
                if (previous.metered != current.metered) {
                    emit(
                        network,
                        FrameworkEventKind.FRAMEWORK_EVENT_KIND_CAPABILITIES_CHANGED,
                        "$name metered: ${previous.metered} -> ${current.metered}",
                        EventSeverity.EVENT_SEVERITY_NOTICE,
                    )
                }
            }
        }

        // The default-network callback fires separately from the per-network
        // one, and a Wi-Fi to cellular handover is only visible here.
        val defaultCallback = object : ConnectivityManager.NetworkCallback() {
            private var currentDefault: Long = 0

            override fun onAvailable(network: Network) {
                val previous = currentDefault
                currentDefault = network.networkHandle
                if (previous != 0L && previous != currentDefault) {
                    emit(
                        network,
                        FrameworkEventKind.FRAMEWORK_EVENT_KIND_DEFAULT_NETWORK_CHANGED,
                        "default network switched to ${interfaceNameOf(network)}",
                        EventSeverity.EVENT_SEVERITY_NOTICE,
                    )
                } else {
                    emit(
                        network,
                        FrameworkEventKind.FRAMEWORK_EVENT_KIND_DEFAULT_NETWORK_CHANGED,
                        "default network is ${interfaceNameOf(network)}",
                    )
                }
            }

            override fun onLost(network: Network) {
                currentDefault = 0
                emit(
                    network,
                    FrameworkEventKind.FRAMEWORK_EVENT_KIND_DEFAULT_NETWORK_CHANGED,
                    "no default network",
                    EventSeverity.EVENT_SEVERITY_WARNING,
                )
            }
        }

        val request = NetworkRequest.Builder()
            .clearCapabilities()
            .build()

        try {
            connectivity.registerNetworkCallback(request, callback)
            connectivity.registerDefaultNetworkCallback(defaultCallback)
        } catch (e: Exception) {
            Log.e(TAG, "could not register network callbacks: ${e.message}")
            close(e)
        }

        awaitClose {
            runCatching { connectivity.unregisterNetworkCallback(callback) }
            runCatching { connectivity.unregisterNetworkCallback(defaultCallback) }
        }
    }

    private fun snapshot(
        nc: NetworkCapabilities?,
        lp: LinkProperties?,
    ): Remembered? {
        if (nc == null && lp == null) return null
        return Remembered(
            validated = nc?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) ?: false,
            captivePortal = nc?.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL)
                ?: false,
            metered = nc?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
                ?.not() ?: false,
            transports = buildSet {
                nc ?: return@buildSet
                for (transport in 0..12) {
                    if (runCatching { nc.hasTransport(transport) }.getOrDefault(false)) {
                        add(transport)
                    }
                }
            },
            interfaceName = lp?.interfaceName.orEmpty(),
            dnsServers = lp?.dnsServers?.map { it.hostAddress.orEmpty() }.orEmpty(),
            // Only global addresses count: a link-local address is always
            // present and would make "has IPv6" meaningless.
            hasIpv6 = lp?.linkAddresses?.any {
                it.address?.let { addr ->
                    addr.address.size == 16 && !addr.isLinkLocalAddress && !addr.isLoopbackAddress
                } ?: false
            } ?: false,
            hasIpv4 = lp?.linkAddresses?.any {
                it.address?.let { addr -> addr.address.size == 4 && !addr.isLoopbackAddress }
                    ?: false
            } ?: false,
            privateDnsActive = lp?.isPrivateDnsActive ?: false,
            nat64Prefix = runCatching { lp?.nat64Prefix?.toString() }.getOrNull().orEmpty(),
        )
    }

    private fun interfaceNameOf(network: Network): String =
        runCatching { connectivity.getLinkProperties(network)?.interfaceName }
            .getOrNull()
            .orEmpty()
            .ifEmpty { "net${network.networkHandle ushr 32}" }
}
