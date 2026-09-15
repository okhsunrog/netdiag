package dev.okhsunrog.netdiag;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;

import java.util.HashMap;

/**
 * Framework-side network events, forwarded to Rust.
 *
 * <p>This class exists because a Java abstract class cannot be subclassed from
 * Rust, and {@code ConnectivityManager.NetworkCallback} has to be subclassed to
 * receive anything. It is the one piece of this app that genuinely must be
 * Java; everything else talks to the framework over JNI from Rust.
 *
 * <p>It is deliberately thin, and it knows nothing about the wire schema. The
 * protobuf in this project exists to cross the boundary between the app and the
 * daemon: two separately built artifacts that can be different versions. This
 * class is not such a boundary. It is compiled by the same {@code cargo rapk}
 * invocation as the Rust consuming it, into the same APK, and loaded by the
 * same process, so the two can never be version-skewed. A schema protects
 * against skew, and there is none to protect against.
 *
 * <p>So the payload is four primitives in this class's own small vocabulary,
 * and Rust maps that vocabulary onto the wire enums in one place.
 *
 * <p>The filtering, on the other hand, belongs here. {@code
 * onCapabilitiesChanged} fires on every signal-strength change, so forwarding
 * every callback would flood the timeline with noise. Only transitions a person
 * would call a change are emitted, which means keeping a little previous state.
 */
public final class NetdiagFrameworkWatcher extends ConnectivityManager.NetworkCallback {

    // This class's own vocabulary, not the wire enum. Rust translates it; see
    // `event_kind` in platform/watcher.rs, which is unit tested against these
    // values so a change here cannot drift silently.
    static final int KIND_AVAILABLE = 1;
    static final int KIND_LOST = 2;
    static final int KIND_LOSING = 3;
    static final int KIND_IPV6_CHANGED = 4;
    static final int KIND_BLOCKED_CHANGED = 5;
    static final int KIND_VALIDATION_CHANGED = 6;
    static final int KIND_DNS_CHANGED = 7;

    static final int SEVERITY_INFO = 1;
    static final int SEVERITY_NOTICE = 2;
    static final int SEVERITY_WARNING = 3;

    private final ConnectivityManager connectivity;

    // Previous state per network, so only real transitions are reported. Only
    // ever touched from the callback thread.
    private final HashMap<Long, Boolean> validated = new HashMap<>();
    private final HashMap<Long, String> dnsServers = new HashMap<>();
    private final HashMap<Long, Boolean> hasIpv6 = new HashMap<>();

    public NetdiagFrameworkWatcher(Context context) {
        this.connectivity =
                (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
    }

    public void start() {
        // clearCapabilities() so this sees every network, including ones
        // without INTERNET, rather than only the ones an app would use.
        NetworkRequest request = new NetworkRequest.Builder().clearCapabilities().build();
        connectivity.registerNetworkCallback(request, this);
    }

    public void stop() {
        try {
            connectivity.unregisterNetworkCallback(this);
        } catch (IllegalArgumentException alreadyUnregistered) {
            // Unregistering twice is not an error worth propagating.
        }
    }

    @Override
    public void onAvailable(Network network) {
        emit(KIND_AVAILABLE, SEVERITY_NOTICE, network, name(network) + " available");
    }

    @Override
    public void onLost(Network network) {
        long handle = network.getNetworkHandle();
        String label = name(network);
        validated.remove(handle);
        dnsServers.remove(handle);
        hasIpv6.remove(handle);
        emit(KIND_LOST, SEVERITY_WARNING, network, label + " lost");
    }

    @Override
    public void onLosing(Network network, int maxMsToLive) {
        emit(
                KIND_LOSING,
                SEVERITY_WARNING,
                network,
                name(network) + " losing connectivity (" + maxMsToLive + " ms to live)");
    }

    @Override
    public void onCapabilitiesChanged(Network network, NetworkCapabilities capabilities) {
        long handle = network.getNetworkHandle();
        boolean now = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED);
        Boolean before = validated.put(handle, now);
        if (before != null && before != now) {
            emit(
                    KIND_VALIDATION_CHANGED,
                    now ? SEVERITY_NOTICE : SEVERITY_WARNING,
                    network,
                    name(network) + " VALIDATED: " + before + " -> " + now);
        }
    }

    @Override
    public void onLinkPropertiesChanged(Network network, LinkProperties link) {
        long handle = network.getNetworkHandle();
        String label = link.getInterfaceName() != null ? link.getInterfaceName() : name(network);

        String servers = link.getDnsServers().toString();
        String previousServers = dnsServers.put(handle, servers);
        if (previousServers != null && !previousServers.equals(servers)) {
            emit(KIND_DNS_CHANGED, SEVERITY_NOTICE, network, label + " DNS " + servers);
        }

        // Only global addresses count: a link-local address is always present,
        // which would make "has IPv6" meaningless.
        boolean ipv6 = false;
        for (android.net.LinkAddress address : link.getLinkAddresses()) {
            java.net.InetAddress inet = address.getAddress();
            if (inet instanceof java.net.Inet6Address
                    && !inet.isLinkLocalAddress()
                    && !inet.isLoopbackAddress()) {
                ipv6 = true;
                break;
            }
        }
        Boolean previousIpv6 = hasIpv6.put(handle, ipv6);
        if (previousIpv6 != null && previousIpv6 != ipv6) {
            emit(
                    KIND_IPV6_CHANGED,
                    ipv6 ? SEVERITY_NOTICE : SEVERITY_WARNING,
                    network,
                    label + (ipv6 ? " gained IPv6" : " lost IPv6"));
        }
    }

    @Override
    public void onBlockedStatusChanged(Network network, boolean blocked) {
        emit(
                KIND_BLOCKED_CHANGED,
                blocked ? SEVERITY_WARNING : SEVERITY_NOTICE,
                network,
                "this app's traffic on "
                        + name(network)
                        + (blocked ? " is blocked" : " is no longer blocked"));
    }

    /** Interface name, falling back to the netId when the network is already gone. */
    private String name(Network network) {
        LinkProperties link = connectivity.getLinkProperties(network);
        if (link != null && link.getInterfaceName() != null) {
            return link.getInterfaceName();
        }
        return "net" + (network.getNetworkHandle() >>> 32);
    }

    private void emit(int kind, int severity, Network network, String summary) {
        onFrameworkEvent(kind, severity, network.getNetworkHandle(), summary);
    }

    /**
     * Implemented in Rust, and bound with {@code RegisterNatives} before this
     * watcher is started.
     *
     * <p>Symbol lookup cannot resolve it. {@code NativeActivity} brings the
     * app's library up by {@code dlopen}, not {@code System.loadLibrary}, so
     * the VM has no record of it and never searches it — whatever class loader
     * this class came from.
     */
    private static native void onFrameworkEvent(
            int kind, int severity, long networkHandle, String summary);
}
