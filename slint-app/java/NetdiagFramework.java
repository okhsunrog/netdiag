package dev.okhsunrog.netdiag;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;

import java.net.InetAddress;
import java.util.List;

/**
 * The whole framework view of networking, collected in one call.
 *
 * <p>This is an anti-corruption layer, not a binding. Rust asks one question and
 * gets one answer; everything between here and the Android SDK is ordinary Java
 * that {@code javac} checks.
 *
 * <p>The alternative, and what this replaces, was transcribing the SDK into
 * {@code bind_java_type!} declarations and calling it method by method from
 * Rust. That cost roughly 150 JNI round trips per refresh on a device with five
 * networks, and — the real problem — nothing verified that
 * {@code "getLinkProperties"} and its signature were right until it ran.
 *
 * <p>Note what is gained beyond the call count: every SDK name below is a
 * symbol. {@code NET_CAPABILITY_VALIDATED} is imported, not the integer 16
 * copied into a Rust constant; a capability renamed or removed in a future SDK
 * fails the build here rather than silently reading as false on a device.
 *
 * <p>The result is text in this class's own format, for the same reason
 * {@link NetdiagPackages} returns text: the two sides are compiled together
 * into one APK and cannot be version-skewed, so a schema would protect against
 * nothing. Rust parses it in `platform/shim.rs`, next to the test that keeps the
 * two halves honest.
 */
public final class NetdiagFramework {

    /** Bumped if the line format changes; Rust refuses anything it does not know. */
    private static final String FORMAT_VERSION = "1";

    private static final char FIELD = '\t';
    private static final char RECORD = '\n';
    private static final char LIST = ',';

    private final ConnectivityManager connectivity;

    public NetdiagFramework(Context context) {
        this.connectivity =
                (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
    }

    /**
     * One line of header, then one line per network.
     *
     * <pre>
     * V  formatVersion  sdkInt  activeHandle  restrictBackgroundStatus
     * N  handle  transports  capabilities  iface  mtu  privateDns  dnsServer  domains  dns
     * </pre>
     *
     * Transports and capabilities are comma-separated names, not the integers
     * behind them, so the mapping on the Rust side is over strings this class
     * chose rather than over SDK numbering it would have to keep in step.
     */
    public String collectNetworkSnapshot() {
        StringBuilder out = new StringBuilder(1024);

        Network active = connectivity.getActiveNetwork();
        long activeHandle = active != null ? active.getNetworkHandle() : 0L;

        out.append("V")
                .append(FIELD)
                .append(FORMAT_VERSION)
                .append(FIELD)
                .append(Build.VERSION.SDK_INT)
                .append(FIELD)
                .append(activeHandle)
                .append(FIELD)
                .append(connectivity.getRestrictBackgroundStatus())
                .append(RECORD);

        for (Network network : connectivity.getAllNetworks()) {
            appendNetwork(out, network);
        }
        return out.toString();
    }

    private void appendNetwork(StringBuilder out, Network network) {
        out.append("N").append(FIELD).append(network.getNetworkHandle()).append(FIELD);

        NetworkCapabilities caps = connectivity.getNetworkCapabilities(network);
        appendTransports(out, caps);
        out.append(FIELD);
        appendCapabilities(out, caps);
        out.append(FIELD);

        LinkProperties link = connectivity.getLinkProperties(network);
        if (link == null) {
            // Still emit the network: that it exists and has no link properties
            // is itself worth reporting, and dropping it would make the count
            // disagree with getAllNetworks().
            out.append(FIELD).append(0).append(FIELD).append(0).append(FIELD).append(FIELD)
                    .append(FIELD).append(RECORD);
            return;
        }

        out.append(text(link.getInterfaceName()))
                .append(FIELD)
                .append(link.getMtu())
                .append(FIELD)
                .append(link.isPrivateDnsActive() ? 1 : 0)
                .append(FIELD)
                .append(text(link.getPrivateDnsServerName()))
                .append(FIELD)
                .append(text(link.getDomains()))
                .append(FIELD);

        appendDnsServers(out, link.getDnsServers());
        out.append(RECORD);
    }

    private void appendTransports(StringBuilder out, NetworkCapabilities caps) {
        if (caps == null) {
            return;
        }
        int written = 0;
        written = appendIf(out, written, caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR), "CELLULAR");
        written = appendIf(out, written, caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI), "WIFI");
        written = appendIf(out, written, caps.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH), "BLUETOOTH");
        written = appendIf(out, written, caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET), "ETHERNET");
        written = appendIf(out, written, caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN), "VPN");
        written = appendIf(out, written, caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI_AWARE), "WIFI_AWARE");
        written = appendIf(out, written, caps.hasTransport(NetworkCapabilities.TRANSPORT_LOWPAN), "LOWPAN");
        appendIf(out, written, caps.hasTransport(NetworkCapabilities.TRANSPORT_USB), "USB");
    }

    private void appendCapabilities(StringBuilder out, NetworkCapabilities caps) {
        if (caps == null) {
            return;
        }
        int written = 0;
        written = appendIf(out, written, caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET), "INTERNET");
        written = appendIf(out, written, caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED), "VALIDATED");
        written = appendIf(out, written, caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL), "CAPTIVE_PORTAL");
        written = appendIf(out, written, caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED), "NOT_RESTRICTED");
        written = appendIf(out, written, caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED), "NOT_METERED");
        written = appendIf(out, written, caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING), "NOT_ROAMING");
        written = appendIf(out, written, caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_CONGESTED), "NOT_CONGESTED");
        written = appendIf(out, written, caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED), "NOT_SUSPENDED");
        written = appendIf(out, written, caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN), "NOT_VPN");
        written = appendIf(out, written, caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED), "TRUSTED");
        appendIf(out, written, caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_FOREGROUND), "FOREGROUND");
    }

    /** Addresses as text; Rust parses them back into the bytes the schema stores. */
    private void appendDnsServers(StringBuilder out, List<InetAddress> servers) {
        int written = 0;
        for (InetAddress server : servers) {
            String address = server.getHostAddress();
            if (address == null) {
                continue;
            }
            written = appendIf(out, written, true, address);
        }
    }

    private int appendIf(StringBuilder out, int written, boolean present, String name) {
        if (!present) {
            return written;
        }
        if (written > 0) {
            out.append(LIST);
        }
        out.append(name);
        return written + 1;
    }

    /** Never null, and never containing a separator. */
    private static String text(String value) {
        if (value == null) {
            return "";
        }
        return value.replace(FIELD, ' ').replace(RECORD, ' ').replace(LIST, ' ');
    }
}
