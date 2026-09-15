package dev.okhsunrog.netdiag.framework

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings
import android.util.Log
import com.google.protobuf.ByteString
import dev.okhsunrog.netdiag.proto.AndroidNetwork
import dev.okhsunrog.netdiag.proto.AndroidNetworkState
import dev.okhsunrog.netdiag.proto.IpAddress
import dev.okhsunrog.netdiag.proto.IpPrefix
import dev.okhsunrog.netdiag.proto.LinkPropertiesInfo
import dev.okhsunrog.netdiag.proto.NetworkCapabilitiesInfo
import dev.okhsunrog.netdiag.proto.PrivateDnsMode
import dev.okhsunrog.netdiag.proto.Transport
import dev.okhsunrog.netdiag.proto.androidNetwork
import dev.okhsunrog.netdiag.proto.androidNetworkState
import dev.okhsunrog.netdiag.proto.androidRoute
import dev.okhsunrog.netdiag.proto.ipAddress
import dev.okhsunrog.netdiag.proto.ipPrefix
import dev.okhsunrog.netdiag.proto.linkPropertiesInfo
import dev.okhsunrog.netdiag.proto.networkCapabilitiesInfo
import java.net.InetAddress

private const val TAG = "FrameworkCollector"

/**
 * Captures the Android framework's view of networking as protobuf, so the root
 * daemon can compare it against the kernel's.
 *
 * Everything here goes through the same schema the daemon uses. That is the
 * point: the framework view has to cross the socket for the correlation checks
 * to run where the rules live, and defining a parallel Kotlin-only model would
 * mean two shapes for the same data.
 */
class FrameworkCollector(private val context: Context) {

    private val connectivity: ConnectivityManager =
        context.getSystemService(ConnectivityManager::class.java)

    fun collect(): AndroidNetworkState {
        val active = runCatching { connectivity.activeNetwork }.getOrNull()
        val networks = runCatching { connectivity.allNetworks.toList() }.getOrDefault(emptyList())

        return androidNetworkState {
            capturedAtUnixMs = System.currentTimeMillis()
            sdkInt = Build.VERSION.SDK_INT
            deviceModel = "${Build.MANUFACTURER} ${Build.MODEL}"
            buildFingerprint = Build.FINGERPRINT

            active?.let {
                activeNetworkHandle = it.networkHandle
                activeNetId = netIdOf(it)
                hasActiveNetwork = true
            }

            restrictBackgroundStatus =
                runCatching { connectivity.restrictBackgroundStatus }.getOrDefault(0)
            dataSaverEnabled = restrictBackgroundStatus ==
                ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED

            airplaneMode = runCatching {
                Settings.Global.getInt(context.contentResolver, Settings.Global.AIRPLANE_MODE_ON) != 0
            }.getOrDefault(false)

            // The global Private DNS setting, which is separate from the
            // per-network state reported in LinkProperties.
            val mode = runCatching {
                Settings.Global.getString(context.contentResolver, "private_dns_mode")
            }.getOrNull()
            globalPrivateDnsMode = when (mode) {
                "off" -> PrivateDnsMode.PRIVATE_DNS_MODE_OFF
                "hostname" -> PrivateDnsMode.PRIVATE_DNS_MODE_STRICT
                "opportunistic" -> PrivateDnsMode.PRIVATE_DNS_MODE_OPPORTUNISTIC
                else -> PrivateDnsMode.PRIVATE_DNS_MODE_UNSPECIFIED
            }
            globalPrivateDnsSpecifier = runCatching {
                Settings.Global.getString(context.contentResolver, "private_dns_specifier")
            }.getOrNull().orEmpty()

            this.networks += networks.mapNotNull { network ->
                runCatching { describe(network, isDefault = network == active) }
                    .onFailure { Log.w(TAG, "could not describe a network: ${it.message}") }
                    .getOrNull()
            }
        }
    }

    fun describe(network: Network, isDefault: Boolean): AndroidNetwork {
        val capabilities = connectivity.getNetworkCapabilities(network)
        val linkProperties = connectivity.getLinkProperties(network)

        return androidNetwork {
            networkHandle = network.networkHandle
            netId = netIdOf(network)
            this.isDefault = isDefault
            capabilities?.let {
                transports += transportsOf(it)
                this.capabilities = describeCapabilities(it)
            }
            linkProperties?.let { this.linkProperties = describeLinkProperties(it) }
        }
    }

    /**
     * Recover the netId from a Network handle.
     *
     * `Network.getNetworkHandle()` packs the netId into the high 32 bits with a
     * fixed marker in the low bits. The netId is what appears in routing table
     * numbers and in socket fwmarks, so it is the join key between the
     * framework's objects and everything the kernel reports — without it the
     * two views cannot be lined up at all.
     */
    private fun netIdOf(network: Network): Int {
        val handle = network.networkHandle
        if (handle == 0L) return 0
        return (handle ushr HANDLE_NET_ID_SHIFT).toInt()
    }

    private fun transportsOf(capabilities: NetworkCapabilities): List<Transport> = buildList {
        fun check(transport: Int, mapped: Transport) {
            if (runCatching { capabilities.hasTransport(transport) }.getOrDefault(false)) {
                add(mapped)
            }
        }
        check(NetworkCapabilities.TRANSPORT_CELLULAR, Transport.TRANSPORT_CELLULAR)
        check(NetworkCapabilities.TRANSPORT_WIFI, Transport.TRANSPORT_WIFI)
        check(NetworkCapabilities.TRANSPORT_BLUETOOTH, Transport.TRANSPORT_BLUETOOTH)
        check(NetworkCapabilities.TRANSPORT_ETHERNET, Transport.TRANSPORT_ETHERNET)
        check(NetworkCapabilities.TRANSPORT_VPN, Transport.TRANSPORT_VPN)
        check(NetworkCapabilities.TRANSPORT_WIFI_AWARE, Transport.TRANSPORT_WIFI_AWARE)
        check(NetworkCapabilities.TRANSPORT_LOWPAN, Transport.TRANSPORT_LOWPAN)
        check(NetworkCapabilities.TRANSPORT_USB, Transport.TRANSPORT_USB)
        check(NetworkCapabilities.TRANSPORT_THREAD, Transport.TRANSPORT_THREAD)
        check(NetworkCapabilities.TRANSPORT_SATELLITE, Transport.TRANSPORT_SATELLITE)
    }

    private fun describeCapabilities(nc: NetworkCapabilities): NetworkCapabilitiesInfo {
        fun has(capability: Int): Boolean =
            runCatching { nc.hasCapability(capability) }.getOrDefault(false)

        return networkCapabilitiesInfo {
            internet = has(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            validated = has(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            captivePortal = has(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL)
            notRestricted = has(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
            notMetered = has(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
            notRoaming = has(NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING)
            notCongested = has(NetworkCapabilities.NET_CAPABILITY_NOT_CONGESTED)
            notSuspended = has(NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED)
            notVpn = has(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            temporarilyNotMetered = has(NetworkCapabilities.NET_CAPABILITY_TEMPORARILY_NOT_METERED)
            // NET_CAPABILITY_PARTIAL_CONNECTIVITY is @SystemApi, so the
            // constant is not in the public SDK. The value is stable and
            // hasCapability accepts it, and "the portal let some traffic
            // through" is too useful a signal to drop.
            partialConnectivity = has(NET_CAPABILITY_PARTIAL_CONNECTIVITY)
            trusted = has(NetworkCapabilities.NET_CAPABILITY_TRUSTED)
            foreground = has(NetworkCapabilities.NET_CAPABILITY_FOREGROUND)

            linkDownstreamBandwidthKbps = nc.linkDownstreamBandwidthKbps
            linkUpstreamBandwidthKbps = nc.linkUpstreamBandwidthKbps
            signalStrength = runCatching { nc.signalStrength }.getOrDefault(0)
            // ownerUid, administratorUids and ssid are all @SystemApi and
            // unavailable to a normal app, so they stay unset. The daemon does
            // not need them: it identifies networks by netId, which is
            // visible here and also appears in socket marks.
            networkSpecifier = runCatching { nc.networkSpecifier?.toString() }.getOrNull().orEmpty()
        }
    }

    private fun describeLinkProperties(lp: LinkProperties): LinkPropertiesInfo =
        linkPropertiesInfo {
            interfaceName = lp.interfaceName.orEmpty()
            mtu = lp.mtu
            // LinkProperties exposes the search list as one space-separated
            // string; the schema stores it as a repeated field.
            domains += lp.domains.orEmpty().split(' ').filter { it.isNotBlank() }

            linkAddresses += lp.linkAddresses.mapNotNull { linkAddress ->
                linkAddress.address?.let { prefixOf(it, linkAddress.prefixLength) }
            }
            dnsServers += lp.dnsServers.map { addressOf(it) }

            routes += lp.routes.map { route ->
                androidRoute {
                    route.destination?.let {
                        destination = prefixOf(it.address, it.prefixLength)
                    }
                    route.gateway?.let { gateway = addressOf(it) }
                    interfaceName = route.`interface`.orEmpty()
                    isDefault = route.isDefaultRoute
                    type = runCatching { route.type }.getOrDefault(0)
                }
            }

            privateDnsActive = lp.isPrivateDnsActive
            privateDnsServerName = lp.privateDnsServerName.orEmpty()
            privateDnsMode = when {
                lp.privateDnsServerName != null -> PrivateDnsMode.PRIVATE_DNS_MODE_STRICT
                lp.isPrivateDnsActive -> PrivateDnsMode.PRIVATE_DNS_MODE_OPPORTUNISTIC
                else -> PrivateDnsMode.PRIVATE_DNS_MODE_OFF
            }

            // The NAT64 prefix is how we know the network is IPv6-only with
            // 464XLAT in front of it.
            runCatching { lp.nat64Prefix }.getOrNull()?.let {
                nat64Prefix = prefixOf(it.address, it.prefixLength)
            }

            lp.httpProxy?.let { proxy ->
                hasHttpProxy = true
                httpProxyHost = proxy.host.orEmpty()
                httpProxyPort = proxy.port
                httpProxyPacUrl = proxy.pacFileUrl?.toString().orEmpty()
                httpProxyExclusions = proxy.exclusionList.orEmpty().joinToString(",")
            }

            // captivePortalApiUrl and stackedLinks are @SystemApi. Neither is
            // a real loss: the captive portal capability bit is public, and
            // clatd's v4-* interface is visible to the daemon directly in the
            // kernel, which is the more trustworthy source anyway.
        }

    private fun addressOf(address: InetAddress): IpAddress = ipAddress {
        addr = ByteString.copyFrom(address.address)
    }

    private fun prefixOf(address: InetAddress, prefixLength: Int): IpPrefix = ipPrefix {
        this.address = addressOf(address)
        prefixLen = prefixLength
    }

    private companion object {
        /**
         * NET_CAPABILITY_PARTIAL_CONNECTIVITY from NetworkCapabilities. Hidden
         * from the public SDK but accepted by hasCapability().
         */
        const val NET_CAPABILITY_PARTIAL_CONNECTIVITY = 24

        /**
         * `Network.getNetworkHandle()` shifts the netId left by 32 and ORs in a
         * constant so that a handle of 0 is never a valid network.
         */
        const val HANDLE_NET_ID_SHIFT = 32
    }
}
