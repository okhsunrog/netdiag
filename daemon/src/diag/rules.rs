//! Rule-based interpretation of check results.
//!
//! Each rule is a small function over the check outcomes. They are pure and
//! synchronous, which means they are cheap to test exhaustively — and that
//! matters, because a wrong interpretation is worse than none: it sends the
//! user to fix the wrong layer.
//!
//! Two conventions keep the output honest:
//!
//! * A rule only fires on evidence that is actually present. A SKIPped check
//!   is not a passing check, and no rule may treat it as one.
//! * `confidence` reflects how much of the expected pattern was observed, so a
//!   rule with partial evidence reports itself as such instead of either
//!   staying silent or overclaiming.

use std::collections::HashMap;

use super::DiagState;
use crate::proto;

/// Convenient view over the checks, keyed by their stable string key.
pub struct CheckIndex<'a> {
    by_key: HashMap<&'a str, &'a proto::Check>,
}

impl<'a> CheckIndex<'a> {
    pub fn new(checks: &'a [proto::Check]) -> Self {
        Self {
            by_key: checks.iter().map(|c| (c.key.as_str(), c)).collect(),
        }
    }

    fn status(&self, key: &str) -> Option<proto::CheckStatus> {
        self.by_key
            .get(key)
            .and_then(|c| proto::CheckStatus::try_from(c.status).ok())
    }

    pub fn passed(&self, key: &str) -> bool {
        self.status(key) == Some(proto::CheckStatus::Pass)
    }

    pub fn failed(&self, key: &str) -> bool {
        self.status(key) == Some(proto::CheckStatus::Fail)
    }

    pub fn warned(&self, key: &str) -> bool {
        self.status(key) == Some(proto::CheckStatus::Warn)
    }

    pub fn skipped(&self, key: &str) -> bool {
        self.status(key) == Some(proto::CheckStatus::Skip)
    }

    pub fn detail(&self, key: &str) -> String {
        self.by_key
            .get(key)
            .map(|c| c.detail.clone())
            .unwrap_or_default()
    }

    pub fn evidence(&self, key: &str, field: &str) -> Option<&'a str> {
        self.by_key
            .get(key)
            .and_then(|c| c.evidence.get(field))
            .map(|s| s.as_str())
    }
}

// Every field here is part of one finding and none of them group naturally
// into a sub-struct, so an intermediate type would add a name without adding
// clarity. The call sites pass them in a fixed, readable order.
#[allow(clippy::too_many_arguments)]
fn finding(
    id: proto::FindingId,
    key: &str,
    severity: proto::FindingSeverity,
    title: &str,
    interpretation: String,
    supporting: &[&str],
    actions: &[&str],
    confidence: u32,
) -> proto::Finding {
    proto::Finding {
        id: id as i32,
        key: key.to_string(),
        severity: severity as i32,
        title: title.to_string(),
        interpretation,
        supporting_checks: supporting.iter().map(|s| s.to_string()).collect(),
        suggested_actions: actions.iter().map(|s| s.to_string()).collect(),
        confidence,
    }
}

/// Run every rule and return the findings, most severe first.
pub fn evaluate(checks: &[proto::Check], state: &DiagState) -> Vec<proto::Finding> {
    let index = CheckIndex::new(checks);
    let mut findings: Vec<proto::Finding> = Vec::new();

    for rule in RULES {
        if let Some(f) = rule(&index, state) {
            findings.push(f);
        }
    }

    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.confidence.cmp(&a.confidence))
    });
    findings
}

type Rule = fn(&CheckIndex, &DiagState) -> Option<proto::Finding>;

const RULES: &[Rule] = &[
    rule_no_connectivity_at_all,
    rule_broken_upstream_ipv6,
    rule_ipv6_configured_no_route,
    rule_ipv6_disabled_by_sysctl,
    rule_gateway_unreachable,
    rule_dns_broken_transport_ok,
    rule_private_dns_blocking,
    rule_captive_portal,
    rule_validated_but_broken,
    rule_framework_kernel_disagreement,
    rule_vpn_leak,
    rule_vpn_ipv6_blackhole,
    rule_mtu_blackhole,
    rule_nat64_without_clat,
    rule_firewall_blocking_uid,
    rule_sockets_stuck_syn_sent,
    rule_sockets_stuck_close_wait,
    rule_multiple_default_routes,
    rule_metered_restriction,
];

// ---- Rules ------------------------------------------------------------------

fn rule_no_connectivity_at_all(index: &CheckIndex, _state: &DiagState) -> Option<proto::Finding> {
    let v4_dead = index.failed("tcp.v4") || index.skipped("tcp.v4");
    let v6_dead = index.failed("tcp.v6") || index.skipped("tcp.v6");
    let dns_dead = index.failed("dns.a") && index.failed("dns.aaaa");

    if !(v4_dead && v6_dead && dns_dead) {
        return None;
    }
    // If both families merely lack a route, a more specific rule explains it
    // better than this one would.
    if index.skipped("tcp.v4") && index.skipped("tcp.v6") && index.failed("iface.active") {
        return None;
    }

    Some(finding(
        proto::FindingId::NoConnectivityAtAll,
        "no_connectivity",
        proto::FindingSeverity::Critical,
        "Suspected problem: no working path to the internet",
        "Neither IPv4 nor IPv6 completed a TCP connection, and DNS failed over both \
         families. Nothing above the link layer is getting through.\n\n\
         When both families fail together the cause is usually below them: no usable \
         address, no default route, an unreachable first hop, or a firewall dropping this \
         device's traffic entirely. The checks above show which of those is the case."
            .to_string(),
        &["tcp.v4", "tcp.v6", "dns.a", "dns.aaaa"],
        &[
            "Check whether the gateway is reachable at all",
            "Confirm the interface has a global address and a default route",
            "If this is a captive portal network, open a browser and complete the portal",
        ],
        90,
    ))
}

/// The headline case: the stack believes IPv6 is fine, and it is not.
fn rule_broken_upstream_ipv6(index: &CheckIndex, _state: &DiagState) -> Option<proto::Finding> {
    // The pattern is specifically "configured correctly, does not work".
    let configured = index.passed("addr.v6") && index.passed("route.v6.default");
    let v6_transport_broken = index.failed("tcp.v6");
    let v4_works = index.passed("tcp.v4");

    if !(configured && v6_transport_broken && v4_works) {
        return None;
    }

    // AAAA records being returned is what makes this actively harmful rather
    // than merely untidy: without them, clients would never try IPv6.
    let aaaa_returned = index.passed("dns.aaaa");

    let mut confidence = 75;
    if aaaa_returned {
        confidence += 15;
    }
    if index.passed("gateway.v6") || index.warned("gateway.v6") {
        confidence += 5;
    }

    let extra = if aaaa_returned {
        "\n\nDNS is returning AAAA records, so applications will prefer IPv6 and try it \
         first. Happy Eyeballs (RFC 8305) normally hides a broken family behind a short \
         delay, but that only works when the IPv6 attempt fails quickly. A path that \
         silently drops packets makes every connection wait for a timeout instead, which \
         is what \"the internet is slow\" usually means on a network in this state."
    } else {
        "\n\nDNS is not returning AAAA records for the test host, which limits the damage: \
         most applications will not attempt IPv6 at all."
    };

    Some(finding(
        proto::FindingId::BrokenUpstreamIpv6,
        "broken_upstream_ipv6",
        proto::FindingSeverity::High,
        "Suspected problem: broken upstream IPv6",
        format!(
            "IPv6 is fully configured on this device: a global address is assigned and a \
             default route exists. IPv4 works end to end. But no TCP connection completes \
             over IPv6.\n\n\
             That combination points upstream, not at the device. The local configuration \
             is what it should be, so the packets are being dropped somewhere beyond the \
             first hop.{extra}"
        ),
        &[
            "addr.v6",
            "route.v6.default",
            "dns.aaaa",
            "tcp.v6",
            "tcp.v4",
        ],
        &[
            "Test the same device on a different network to confirm the problem follows the network",
            "If this is a home network, check whether the router's IPv6 delegation is still valid",
            "As a workaround, disabling IPv6 on this network removes the stall at the cost of IPv6 connectivity",
        ],
        confidence.min(100),
    ))
}

fn rule_ipv6_configured_no_route(index: &CheckIndex, _state: &DiagState) -> Option<proto::Finding> {
    if !(index.passed("addr.v6") && index.failed("route.v6.default")) {
        return None;
    }
    Some(finding(
        proto::FindingId::Ipv6ConfiguredNoRoute,
        "ipv6_no_default_route",
        proto::FindingSeverity::Medium,
        "IPv6 address assigned but no default route",
        format!(
            "The interface has a global IPv6 address but there is no IPv6 default route in \
             the table this traffic uses.\n\n\
             An address without a route usually means the router advertisement carried a \
             prefix but no router lifetime, or the route expired and was not refreshed. \
             Only on-link IPv6 destinations are reachable in this state.\n\n{}",
            index.detail("route.v6.default")
        ),
        &["addr.v6", "route.v6.default"],
        &[
            "Check whether router advertisements are still arriving on this link",
            "Confirm accept_ra is not disabled for this interface",
        ],
        85,
    ))
}

fn rule_ipv6_disabled_by_sysctl(index: &CheckIndex, _state: &DiagState) -> Option<proto::Finding> {
    if index.evidence("addr.v6", "disable_ipv6") != Some("true") {
        return None;
    }
    Some(finding(
        proto::FindingId::Ipv6DisabledBySysctl,
        "ipv6_disabled_sysctl",
        proto::FindingSeverity::Medium,
        "IPv6 is administratively disabled on this interface",
        "The `disable_ipv6` sysctl is set for the egress interface, so the kernel will not \
         configure or use IPv6 on it regardless of what the network offers.\n\n\
         This is a local setting, not a network problem. Something on the device set it: a \
         VPN app, a tethering configuration, or a manual change."
            .to_string(),
        &["addr.v6"],
        &["Identify what set disable_ipv6; VPN apps are the most common cause"],
        95,
    ))
}

fn rule_gateway_unreachable(index: &CheckIndex, _state: &DiagState) -> Option<proto::Finding> {
    let v4 = index.failed("gateway.v4");
    let v6 = index.failed("gateway.v6");
    if !(v4 || v6) {
        return None;
    }

    let which = match (v4, v6) {
        (true, true) => "both IPv4 and IPv6",
        (true, false) => "IPv4",
        _ => "IPv6",
    };

    Some(finding(
        proto::FindingId::GatewayUnreachable,
        "gateway_unreachable",
        if v4 && v6 {
            proto::FindingSeverity::Critical
        } else {
            proto::FindingSeverity::High
        },
        "Suspected problem: the first hop is not reachable",
        format!(
            "The {which} gateway does not answer, and the kernel has no usable neighbour \
             entry for it.\n\n\
             This is a link-layer problem rather than a routing one: the device has a route \
             pointing at a gateway that is not responding to ARP or neighbour discovery. \
             The association may look fine while the access point has actually stopped \
             forwarding, which is common right after a roam or when a router is rebooting.\n\n{}",
            index.detail(if v4 { "gateway.v4" } else { "gateway.v6" })
        ),
        &["gateway.v4", "gateway.v6"],
        &[
            "Re-associate with the network (toggle Wi-Fi) and see whether the neighbour entry recovers",
            "Check whether the router is up and forwarding for other devices",
        ],
        85,
    ))
}

fn rule_dns_broken_transport_ok(index: &CheckIndex, _state: &DiagState) -> Option<proto::Finding> {
    let dns_broken = index.failed("dns.a") && index.failed("dns.aaaa");
    let transport_ok = index.passed("tcp.v4") || index.passed("tcp.v6");
    if !(dns_broken && transport_ok) {
        return None;
    }

    let from_framework = index.evidence("dns.a", "from_framework") == Some("true");
    let servers = index.evidence("dns.a", "servers").unwrap_or("").to_string();

    Some(finding(
        proto::FindingId::DnsBrokenTransportOk,
        "dns_broken_transport_ok",
        proto::FindingSeverity::High,
        "Suspected problem: DNS is broken while the network itself works",
        format!(
            "TCP connections to literal addresses succeed, so packets reach the internet. \
             Name resolution fails against every configured server ({servers}).\n\n\
             Because the transport works, this is the resolver or the path to it, not \
             connectivity. Common causes are a resolver that is reachable but not \
             answering, a network that blocks port 53 to anything but its own resolver, or \
             a Private DNS hostname that no longer resolves.{}",
            if from_framework {
                ""
            } else {
                "\n\nNote: the framework supplied no DNS servers, so this test used public \
                 resolvers. The network's own resolver was not exercised."
            }
        ),
        &["dns.a", "dns.aaaa", "tcp.v4", "tcp.v6"],
        &[
            "Check the Private DNS setting; strict mode with an unreachable server disables DNS entirely",
            "Try a different resolver to see whether the configured one is the problem",
        ],
        85,
    ))
}

fn rule_private_dns_blocking(index: &CheckIndex, _state: &DiagState) -> Option<proto::Finding> {
    if !index.failed("dns.private") {
        return None;
    }
    Some(finding(
        proto::FindingId::PrivateDnsBlocking,
        "private_dns_blocking",
        proto::FindingSeverity::High,
        "Suspected problem: strict Private DNS has no reachable server",
        format!(
            "{}\n\nIn strict mode Android refuses to fall back to plaintext DNS. If the \
             configured DoT server cannot be reached on port 853, name resolution stops \
             completely, while everything that uses literal addresses keeps working. That \
             asymmetry is why this failure is so often misread as \"some apps work\".",
            index.detail("dns.private")
        ),
        &["dns.private", "dns.a"],
        &[
            "Switch Private DNS to Automatic to confirm the diagnosis",
            "Check whether this network blocks outbound port 853",
        ],
        90,
    ))
}

fn rule_captive_portal(index: &CheckIndex, _state: &DiagState) -> Option<proto::Finding> {
    if !index.failed("captive.portal") {
        return None;
    }
    Some(finding(
        proto::FindingId::CaptivePortal,
        "captive_portal",
        proto::FindingSeverity::Medium,
        "A captive portal is intercepting this network",
        "Android has classified this network as being behind a captive portal. Until the \
         portal is satisfied, DNS answers and HTTP responses may be forged, so other \
         checks in this report can show misleading results."
            .to_string(),
        &["captive.portal", "android.state"],
        &["Open the portal page and complete sign-in, then run the diagnosis again"],
        95,
    ))
}

/// Android says the network is VALIDATED, the kernel says traffic does not
/// flow. This is the specific disagreement the whole tool exists to surface.
fn rule_validated_but_broken(index: &CheckIndex, state: &DiagState) -> Option<proto::Finding> {
    let validated = state
        .network
        .as_ref()
        .and_then(|n| n.capabilities.as_ref())
        .map(|c| c.validated)
        .unwrap_or(false);
    if !validated {
        return None;
    }

    let transport_broken = index.failed("tcp.v4") && index.failed("tcp.v6");
    let dns_broken = index.failed("dns.a") && index.failed("dns.aaaa");
    if !(transport_broken || dns_broken) {
        return None;
    }

    Some(finding(
        proto::FindingId::ValidatedButBroken,
        "validated_but_broken",
        proto::FindingSeverity::High,
        "Android reports VALIDATED but connectivity is broken",
        format!(
            "NetworkCapabilities still carries NET_CAPABILITY_VALIDATED for this network, \
             but live probes fail{}.\n\n\
             Validation is a point-in-time result that Android caches and only re-runs \
             periodically or on specific triggers. A network that worked when it was \
             validated and broke afterwards keeps the flag, so apps keep using it and the \
             system does not switch to another network. This gap between the framework's \
             belief and the kernel's reality is exactly the situation where the framework \
             alone cannot tell you anything useful.",
            if transport_broken && dns_broken {
                " for both transport and DNS"
            } else if transport_broken {
                " for TCP on both families"
            } else {
                " for DNS on both families"
            }
        ),
        &["android.state", "tcp.v4", "tcp.v6", "dns.a", "dns.aaaa"],
        &[
            "Toggle the network off and on to force Android to re-validate it",
            "Compare with another device on the same network to separate device from network",
        ],
        88,
    ))
}

fn rule_framework_kernel_disagreement(
    index: &CheckIndex,
    _state: &DiagState,
) -> Option<proto::Finding> {
    if !index.failed("framework.kernel") {
        return None;
    }
    Some(finding(
        proto::FindingId::FrameworkKernelDisagreement,
        "framework_kernel_disagreement",
        proto::FindingSeverity::Medium,
        "The Android framework and the Linux kernel disagree",
        format!(
            "{}\n\nLinkProperties is what apps see; the kernel's tables are what packets \
             obey. When they diverge, an app can be told it has a route that does not \
             exist, or be handed an address the interface no longer holds. This usually \
             means a network transition was interrupted partway through, and it often \
             resolves itself when the network is next reconfigured.",
            index.detail("framework.kernel")
        ),
        &["framework.kernel"],
        &["Toggle the network to force the framework and netd to re-apply configuration"],
        80,
    ))
}

fn rule_vpn_leak(index: &CheckIndex, state: &DiagState) -> Option<proto::Finding> {
    if index.evidence("vpn.routing", "egress_is_vpn") != Some("false") {
        return None;
    }
    let vpn_interfaces = index
        .evidence("vpn.routing", "vpn_interfaces")
        .unwrap_or("");
    if vpn_interfaces.is_empty() {
        return None;
    }

    let framework_vpn = state
        .network
        .as_ref()
        .map(|n| n.transports.contains(&(proto::Transport::Vpn as i32)))
        .unwrap_or(false);

    Some(finding(
        proto::FindingId::VpnLeak,
        "vpn_leak",
        proto::FindingSeverity::High,
        "Traffic is bypassing the active VPN",
        format!(
            "A VPN interface ({vpn_interfaces}) is up, but the kernel's own route lookup \
             sends this traffic out of a different interface.\n\n\
             On Android that normally means a uid range rule excludes this traffic from the \
             VPN: either the VPN app's allowed/disallowed application list, or a bypass the \
             app requested explicitly. The framework {} report a VPN transport for the \
             network under test, which is a useful cross-check on which of those it is.",
            if framework_vpn { "does" } else { "does not" }
        ),
        &["vpn.routing", "route.lookup.v4", "route.lookup.v6"],
        &[
            "Check the VPN app's per-app settings for this uid",
            "Look at the uid range rules in the Routing view to see which rule matched",
        ],
        80,
    ))
}

fn rule_vpn_ipv6_blackhole(index: &CheckIndex, _state: &DiagState) -> Option<proto::Finding> {
    if index.evidence("vpn.routing", "vpn_has_ipv6_routes") != Some("false") {
        return None;
    }
    if index.evidence("vpn.routing", "egress_is_vpn") != Some("true") {
        return None;
    }

    let blackholed = index.evidence("vpn.routing", "ipv6_blackholed_in_vpn_table") == Some("true");
    let table = index.evidence("vpn.routing", "vpn_table").unwrap_or("?");

    // A deliberate blackhole is correct behaviour, not a fault. Reporting it
    // at the same severity as a leak would send people looking for a problem
    // that is not there — but staying silent would leave every IPv6 check in
    // this report looking unexplained.
    let (severity, title, interpretation, actions, confidence) = if blackholed {
        (
            proto::FindingSeverity::Info,
            "The VPN blocks IPv6 on purpose",
            format!(
                "Traffic goes through the VPN, the tunnel carries no IPv6, and the VPN's \
                 routing table ({table}) sends the IPv6 default route to loopback or to an \
                 unreachable route.\n\n\
                 That is Android deliberately blackholing IPv6 for a VPN that only supports \
                 IPv4. It is the correct behaviour: IPv6 connections fail immediately, \
                 applications fall back to IPv4 without a stall, and no IPv6 traffic escapes \
                 the tunnel. Every IPv6 failure elsewhere in this report follows from this \
                 and is expected."
            ),
            vec!["Nothing to fix; use a VPN with IPv6 support if you need IPv6"],
            90,
        )
    } else {
        (
            proto::FindingSeverity::Medium,
            "The VPN carries IPv4 but not IPv6, and IPv6 is not blocked",
            format!(
                "Traffic goes through the VPN, but the tunnel has no IPv6 default route and \
                 the VPN's routing table ({table}) does not blackhole IPv6 either.\n\n\
                 That combination is the leaky one. IPv6 traffic is not carried by the \
                 tunnel and is not stopped, so it can leave over the underlying network \
                 outside the VPN. This is a privacy problem rather than a connectivity one: \
                 things keep working, which is exactly why it goes unnoticed."
            ),
            vec![
                "Check whether the VPN app has an IPv6 or \"block IPv6\" setting",
                "Enable Always-on VPN with \"Block connections without VPN\" to stop the leak",
            ],
            75,
        )
    };

    Some(finding(
        proto::FindingId::VpnBlackhole,
        "vpn_ipv6_blackhole",
        severity,
        title,
        interpretation,
        &["vpn.routing", "tcp.v6", "route.v6.default"],
        &actions,
        confidence,
    ))
}

fn rule_mtu_blackhole(index: &CheckIndex, _state: &DiagState) -> Option<proto::Finding> {
    // The signature: TCP connects, TLS does not. The handshake is the first
    // packet large enough to hit a lower MTU.
    let tcp_ok = index.passed("tcp.v4") || index.passed("tcp.v6");
    let tls_broken = index.failed("tls.handshake");
    if !(tcp_ok && tls_broken) {
        return None;
    }

    // If a don't-fragment probe at the full interface MTU got through, the
    // path demonstrably carries large packets and this rule is contradicted by
    // its own evidence. Firing anyway would send the user to change an MTU
    // that is already fine, so stay silent and let the TLS failure be
    // explained by something else.
    if index.passed("mtu.pmtu") {
        return None;
    }

    let mtu_detail = index.detail("mtu.pmtu");
    let measured = index.evidence("mtu.pmtu", "measured_path_mtu");
    let interface_mtu = index.evidence("mtu.pmtu", "interface_mtu").unwrap_or("?");

    // A measured MTU below the interface MTU is direct corroboration. Without
    // it this is a plausible reading rather than a confident one, and the
    // confidence score should say so rather than the wording hedging.
    let confidence = if measured.is_some() { 80 } else { 55 };

    Some(finding(
        proto::FindingId::MtuBlackhole,
        "mtu_blackhole",
        proto::FindingSeverity::High,
        "Suspected problem: large packets are being dropped (MTU black hole)",
        format!(
            "TCP connections establish but the TLS handshake never completes. That is the \
             classic signature of a path MTU problem.\n\n\
             The three-way handshake uses small packets and gets through. The ClientHello \
             is the first substantial packet, and if something on the path cannot carry it \
             and does not send back an ICMP \"fragmentation needed\" or \"packet too big\" \
             message, the packet simply disappears. Path MTU discovery has nothing to learn \
             from, so the connection hangs rather than failing.\n\n\
             Interface MTU is {interface_mtu}. {}",
            if mtu_detail.is_empty() {
                "The MTU probe produced no measurement.".to_string()
            } else {
                mtu_detail
            }
        ),
        &["tcp.v4", "tcp.v6", "tls.handshake", "mtu.pmtu"],
        &[
            "Lower the interface MTU (1400 is a safe test value) and retry",
            "If a VPN is active, its encapsulation overhead is the most likely cause",
        ],
        confidence,
    ))
}

fn rule_nat64_without_clat(index: &CheckIndex, state: &DiagState) -> Option<proto::Finding> {
    if !index.warned("nat64.dns64") {
        return None;
    }
    let has_v4 = index.passed("addr.v4");
    if state.clat.active || has_v4 {
        return None;
    }

    Some(finding(
        proto::FindingId::Nat64WithoutClat,
        "nat64_without_clat",
        proto::FindingSeverity::Medium,
        "DNS64 is active but 464XLAT is not running",
        format!(
            "{}\n\nOn an IPv6-only network Android normally starts clatd, which presents a \
             synthetic IPv4 interface so that IPv4-only applications keep working. Without \
             it, anything that uses a hard-coded IPv4 literal or a raw IPv4 socket has no \
             path out, while everything that resolves names keeps working through DNS64. \
             Apps failing selectively, with no obvious pattern, is what that looks like \
             from the outside.",
            index.detail("nat64.dns64")
        ),
        &["nat64.dns64", "addr.v4"],
        &["Toggle the network; clatd is started as part of network setup"],
        75,
    ))
}

fn rule_firewall_blocking_uid(index: &CheckIndex, _state: &DiagState) -> Option<proto::Finding> {
    if !index.failed("firewall.anomaly") {
        return None;
    }
    Some(finding(
        proto::FindingId::FirewallBlockingUid,
        "firewall_blocking_uid",
        proto::FindingSeverity::High,
        "This app is blocked by a firewall rule",
        format!(
            "{}\n\nAndroid enforces per-app network restrictions in eBPF rather than in \
             netfilter, so this does not appear in any iptables dump. Data Saver, \
             background restriction, battery optimisation and OEM-specific power managers \
             all write into the same map. The app sees ordinary connection failures with \
             no indication that policy, rather than the network, is the cause.",
            index.detail("firewall.anomaly")
        ),
        &["firewall.anomaly"],
        &[
            "Check Data Saver and background data restrictions for this app",
            "Check battery optimisation and any OEM power-saving list",
        ],
        85,
    ))
}

fn rule_sockets_stuck_syn_sent(index: &CheckIndex, _state: &DiagState) -> Option<proto::Finding> {
    if index.evidence("sockets.states", "syn_sent").is_none() || !index.failed("sockets.states") {
        return None;
    }
    let count = index.evidence("sockets.states", "syn_sent").unwrap_or("?");

    Some(finding(
        proto::FindingId::SocketsStuckSynSent,
        "sockets_stuck_syn_sent",
        proto::FindingSeverity::Medium,
        "Connections are piling up in SYN_SENT",
        format!(
            "{count} sockets are sitting in SYN_SENT. The kernel has sent a SYN and is \
             waiting for a SYN-ACK that has not arrived.\n\n\
             This is what a silent drop looks like from the socket table: the packets are \
             leaving the device and nothing is answering, as opposed to a refused \
             connection (which produces a RST and closes immediately) or a routing failure \
             (which fails instantly with ENETUNREACH). A firewall that drops rather than \
             rejects, a broken path, or a dead peer all produce this."
        ),
        &["sockets.states"],
        &["Cross-reference with the per-app view to see which app owns these sockets"],
        80,
    ))
}

fn rule_sockets_stuck_close_wait(index: &CheckIndex, _state: &DiagState) -> Option<proto::Finding> {
    if !index.warned("sockets.states") {
        return None;
    }
    let count: u32 = index
        .evidence("sockets.states", "close_wait")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if count < 20 {
        return None;
    }

    Some(finding(
        proto::FindingId::SocketsStuckCloseWait,
        "sockets_stuck_close_wait",
        proto::FindingSeverity::Low,
        "Sockets are accumulating in CLOSE_WAIT",
        format!(
            "{count} sockets are in CLOSE_WAIT: the peer has closed its half of the \
             connection and the local application has not closed its own.\n\n\
             This is an application bug rather than a network fault, and it leaks file \
             descriptors. It is worth noting here because the symptom people report is \
             \"the app stops being able to connect\", which looks like a network problem \
             until you count the sockets."
        ),
        &["sockets.states"],
        &["Identify the owning app in the per-app view; the leak is in its code"],
        85,
    ))
}

fn rule_multiple_default_routes(index: &CheckIndex, _state: &DiagState) -> Option<proto::Finding> {
    let v4 = index.warned("route.v4.default");
    let v6 = index.warned("route.v6.default");
    if !(v4 || v6) {
        return None;
    }
    let key = if v4 {
        "route.v4.default"
    } else {
        "route.v6.default"
    };
    if !index.detail(key).contains("competing") {
        return None;
    }

    Some(finding(
        proto::FindingId::MultipleDefaultRoutes,
        "multiple_default_routes",
        proto::FindingSeverity::Low,
        "Several default routes compete in the same table",
        format!(
            "{}\n\nThe kernel will pick the lowest metric, so this is not broken on its own. \
             It usually means an interface went down without its routes being cleaned up, \
             and it becomes a real problem if the winning route points at a gateway that no \
             longer works.",
            index.detail(key)
        ),
        &[key],
        &["Check whether an old interface's routes were left behind"],
        70,
    ))
}

fn rule_metered_restriction(index: &CheckIndex, state: &DiagState) -> Option<proto::Finding> {
    let metered = index.evidence("android.state", "metered") == Some("true");
    if !metered {
        return None;
    }
    let restricted = state
        .network
        .as_ref()
        .and_then(|n| n.capabilities.as_ref())
        .map(|c| !c.not_restricted)
        .unwrap_or(false);
    if !restricted {
        return None;
    }

    Some(finding(
        proto::FindingId::MeteredRestriction,
        "metered_restriction",
        proto::FindingSeverity::Info,
        "This network is metered and restricted",
        "The network is marked metered and does not carry NET_CAPABILITY_NOT_RESTRICTED. \
         Background traffic for most apps will be blocked by policy, which produces \
         connection failures that look like network faults but are deliberate."
            .to_string(),
        &["android.state"],
        &["Check Data Saver, and whether the app is allowed unrestricted data"],
        90,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, SocketAddr};

    use crate::probe::ProbeContext;

    fn check(key: &str, status: proto::CheckStatus) -> proto::Check {
        proto::Check {
            key: key.to_string(),
            status: status as i32,
            ..Default::default()
        }
    }

    fn check_with(
        key: &str,
        status: proto::CheckStatus,
        evidence: &[(&str, &str)],
    ) -> proto::Check {
        let mut c = check(key, status);
        for (k, v) in evidence {
            c.evidence.insert(k.to_string(), v.to_string());
        }
        c
    }

    fn state() -> DiagState {
        DiagState {
            interfaces: Vec::new(),
            rules: Vec::new(),
            routes: Vec::new(),
            neighbors: Vec::new(),
            sockets: Vec::new(),
            socket_summary: Default::default(),
            clat: Default::default(),
            network: None,
            net_id: 0,
            probe_ctx_v4: ProbeContext::with_timeout(100),
            probe_ctx_v6: ProbeContext::with_timeout(100),
            lookup_v4: Default::default(),
            lookup_v6: Default::default(),
            egress_v4: None,
            egress_v6: None,
            dns_servers: Vec::new(),
            dns_from_framework: false,
            hostname: "example.test".into(),
            v4_endpoint: SocketAddr::new("1.1.1.1".parse::<IpAddr>().unwrap(), 443),
            v6_endpoint: SocketAddr::new("2606:4700:4700::1111".parse::<IpAddr>().unwrap(), 443),
            timeout_ms: 100,
        }
    }

    /// The canonical scenario from the spec: everything IPv6 looks right, and
    /// only the end-to-end connection fails.
    #[test]
    fn detects_broken_upstream_ipv6() {
        let checks = vec![
            check("addr.v6", proto::CheckStatus::Pass),
            check("route.v6.default", proto::CheckStatus::Pass),
            check("dns.aaaa", proto::CheckStatus::Pass),
            check("tcp.v6", proto::CheckStatus::Fail),
            check("tcp.v4", proto::CheckStatus::Pass),
            check("dns.a", proto::CheckStatus::Pass),
        ];
        let findings = evaluate(&checks, &state());
        let f = findings
            .iter()
            .find(|f| f.id == proto::FindingId::BrokenUpstreamIpv6 as i32)
            .expect("the broken-IPv6 rule should fire");
        assert_eq!(f.severity, proto::FindingSeverity::High as i32);
        assert!(f.confidence >= 90, "confidence was {}", f.confidence);
        assert!(f.interpretation.contains("Happy Eyeballs"));
    }

    #[test]
    fn broken_ipv6_rule_needs_working_ipv4_to_fire() {
        // With IPv4 broken too, this is not an IPv6-specific problem.
        let checks = vec![
            check("addr.v6", proto::CheckStatus::Pass),
            check("route.v6.default", proto::CheckStatus::Pass),
            check("tcp.v6", proto::CheckStatus::Fail),
            check("tcp.v4", proto::CheckStatus::Fail),
        ];
        let findings = evaluate(&checks, &state());
        assert!(
            !findings
                .iter()
                .any(|f| f.id == proto::FindingId::BrokenUpstreamIpv6 as i32)
        );
    }

    #[test]
    fn broken_ipv6_confidence_is_lower_without_aaaa_records() {
        let checks = vec![
            check("addr.v6", proto::CheckStatus::Pass),
            check("route.v6.default", proto::CheckStatus::Pass),
            check("dns.aaaa", proto::CheckStatus::Fail),
            check("tcp.v6", proto::CheckStatus::Fail),
            check("tcp.v4", proto::CheckStatus::Pass),
        ];
        let f = evaluate(&checks, &state())
            .into_iter()
            .find(|f| f.id == proto::FindingId::BrokenUpstreamIpv6 as i32)
            .unwrap();
        assert!(f.confidence < 90, "confidence was {}", f.confidence);
        assert!(f.interpretation.contains("not returning AAAA"));
    }

    #[test]
    fn a_skipped_check_is_never_treated_as_a_pass() {
        let checks = vec![
            check("addr.v6", proto::CheckStatus::Skip),
            check("route.v6.default", proto::CheckStatus::Skip),
            check("tcp.v6", proto::CheckStatus::Fail),
            check("tcp.v4", proto::CheckStatus::Pass),
        ];
        assert!(
            !evaluate(&checks, &state())
                .iter()
                .any(|f| f.id == proto::FindingId::BrokenUpstreamIpv6 as i32)
        );
    }

    #[test]
    fn healthy_network_produces_no_findings() {
        let checks = vec![
            check("addr.v4", proto::CheckStatus::Pass),
            check("addr.v6", proto::CheckStatus::Pass),
            check("route.v4.default", proto::CheckStatus::Pass),
            check("route.v6.default", proto::CheckStatus::Pass),
            check("gateway.v4", proto::CheckStatus::Pass),
            check("dns.a", proto::CheckStatus::Pass),
            check("dns.aaaa", proto::CheckStatus::Pass),
            check("tcp.v4", proto::CheckStatus::Pass),
            check("tcp.v6", proto::CheckStatus::Pass),
            check("tls.handshake", proto::CheckStatus::Pass),
            check("sockets.states", proto::CheckStatus::Pass),
            check("framework.kernel", proto::CheckStatus::Pass),
        ];
        assert!(evaluate(&checks, &state()).is_empty());
    }

    #[test]
    fn detects_validated_but_broken() {
        let mut s = state();
        s.network = Some(proto::AndroidNetwork {
            net_id: 101,
            capabilities: Some(proto::NetworkCapabilitiesInfo {
                validated: true,
                internet: true,
                ..Default::default()
            }),
            ..Default::default()
        });
        let checks = vec![
            check("tcp.v4", proto::CheckStatus::Fail),
            check("tcp.v6", proto::CheckStatus::Fail),
            check("dns.a", proto::CheckStatus::Pass),
            check("dns.aaaa", proto::CheckStatus::Pass),
        ];
        assert!(
            evaluate(&checks, &s)
                .iter()
                .any(|f| f.id == proto::FindingId::ValidatedButBroken as i32)
        );
    }

    #[test]
    fn validated_but_broken_does_not_fire_when_unvalidated() {
        let mut s = state();
        s.network = Some(proto::AndroidNetwork {
            capabilities: Some(proto::NetworkCapabilitiesInfo {
                validated: false,
                ..Default::default()
            }),
            ..Default::default()
        });
        let checks = vec![
            check("tcp.v4", proto::CheckStatus::Fail),
            check("tcp.v6", proto::CheckStatus::Fail),
        ];
        assert!(
            !evaluate(&checks, &s)
                .iter()
                .any(|f| f.id == proto::FindingId::ValidatedButBroken as i32)
        );
    }

    #[test]
    fn detects_dns_failure_with_working_transport() {
        let checks = vec![
            check_with(
                "dns.a",
                proto::CheckStatus::Fail,
                &[("from_framework", "true"), ("servers", "192.168.1.1")],
            ),
            check("dns.aaaa", proto::CheckStatus::Fail),
            check("tcp.v4", proto::CheckStatus::Pass),
        ];
        let f = evaluate(&checks, &state())
            .into_iter()
            .find(|f| f.id == proto::FindingId::DnsBrokenTransportOk as i32)
            .expect("DNS rule should fire");
        assert!(f.interpretation.contains("192.168.1.1"));
    }

    #[test]
    fn detects_an_mtu_black_hole_from_tcp_ok_tls_broken() {
        let checks = vec![
            check("tcp.v4", proto::CheckStatus::Pass),
            check("tls.handshake", proto::CheckStatus::Fail),
            check_with(
                "mtu.pmtu",
                proto::CheckStatus::Fail,
                &[("interface_mtu", "1500"), ("measured_path_mtu", "1400")],
            ),
        ];
        let f = evaluate(&checks, &state())
            .into_iter()
            .find(|f| f.id == proto::FindingId::MtuBlackhole as i32)
            .expect("MTU rule should fire");
        assert_eq!(f.confidence, 80);
        assert!(f.interpretation.contains("ClientHello"));
    }

    #[test]
    fn mtu_black_hole_is_less_confident_without_a_measurement() {
        let checks = vec![
            check("tcp.v4", proto::CheckStatus::Pass),
            check("tls.handshake", proto::CheckStatus::Fail),
        ];
        let f = evaluate(&checks, &state())
            .into_iter()
            .find(|f| f.id == proto::FindingId::MtuBlackhole as i32)
            .unwrap();
        assert_eq!(f.confidence, 55);
    }

    /// Regression: a passing MTU probe disproves the MTU explanation, and the
    /// rule used to fire anyway and tell the user to lower a healthy MTU.
    #[test]
    fn mtu_black_hole_does_not_fire_when_full_size_packets_get_through() {
        let checks = vec![
            check("tcp.v4", proto::CheckStatus::Pass),
            check("tls.handshake", proto::CheckStatus::Fail),
            check_with(
                "mtu.pmtu",
                proto::CheckStatus::Pass,
                &[("interface_mtu", "1420")],
            ),
        ];
        assert!(
            !evaluate(&checks, &state())
                .iter()
                .any(|f| f.id == proto::FindingId::MtuBlackhole as i32),
            "a successful full-size DF probe contradicts an MTU black hole"
        );
    }

    #[test]
    fn detects_a_vpn_bypass() {
        let checks = vec![check_with(
            "vpn.routing",
            proto::CheckStatus::Warn,
            &[("egress_is_vpn", "false"), ("vpn_interfaces", "tun0")],
        )];
        let f = evaluate(&checks, &state())
            .into_iter()
            .find(|f| f.id == proto::FindingId::VpnLeak as i32)
            .expect("VPN leak rule should fire");
        assert!(f.interpretation.contains("tun0"));
    }

    /// A v4-only VPN that blackholes IPv6 is working correctly, and must not
    /// be reported at the same severity as one that leaks it.
    #[test]
    fn a_deliberate_ipv6_blackhole_is_informational() {
        let checks = vec![check_with(
            "vpn.routing",
            proto::CheckStatus::Info,
            &[
                ("egress_is_vpn", "true"),
                ("vpn_has_ipv6_routes", "false"),
                ("ipv6_blackholed_in_vpn_table", "true"),
                ("vpn_table", "1051"),
            ],
        )];
        let f = evaluate(&checks, &state())
            .into_iter()
            .find(|f| f.id == proto::FindingId::VpnBlackhole as i32)
            .expect("the VPN IPv6 rule should fire");
        assert_eq!(f.severity, proto::FindingSeverity::Info as i32);
        assert!(
            f.interpretation.contains("deliberately"),
            "{}",
            f.interpretation
        );
        assert!(f.interpretation.contains("1051"));
    }

    #[test]
    fn an_unblocked_missing_ipv6_route_is_reported_as_a_leak_risk() {
        let checks = vec![check_with(
            "vpn.routing",
            proto::CheckStatus::Warn,
            &[
                ("egress_is_vpn", "true"),
                ("vpn_has_ipv6_routes", "false"),
                ("ipv6_blackholed_in_vpn_table", "false"),
                ("vpn_table", "1051"),
            ],
        )];
        let f = evaluate(&checks, &state())
            .into_iter()
            .find(|f| f.id == proto::FindingId::VpnBlackhole as i32)
            .unwrap();
        assert_eq!(f.severity, proto::FindingSeverity::Medium as i32);
        assert!(f.interpretation.contains("leak"), "{}", f.interpretation);
    }

    #[test]
    fn vpn_leak_does_not_fire_without_a_vpn_interface() {
        let checks = vec![check_with(
            "vpn.routing",
            proto::CheckStatus::Skip,
            &[("egress_is_vpn", "false"), ("vpn_interfaces", "")],
        )];
        assert!(
            !evaluate(&checks, &state())
                .iter()
                .any(|f| f.id == proto::FindingId::VpnLeak as i32)
        );
    }

    #[test]
    fn findings_are_sorted_most_severe_first() {
        let mut s = state();
        s.network = Some(proto::AndroidNetwork {
            capabilities: Some(proto::NetworkCapabilitiesInfo {
                validated: true,
                ..Default::default()
            }),
            ..Default::default()
        });
        let checks = vec![
            check("tcp.v4", proto::CheckStatus::Fail),
            check("tcp.v6", proto::CheckStatus::Fail),
            check("dns.a", proto::CheckStatus::Fail),
            check("dns.aaaa", proto::CheckStatus::Fail),
            check_with(
                "sockets.states",
                proto::CheckStatus::Warn,
                &[("close_wait", "40")],
            ),
        ];
        let findings = evaluate(&checks, &s);
        assert!(findings.len() >= 2);
        for pair in findings.windows(2) {
            assert!(
                pair[0].severity >= pair[1].severity,
                "findings are not sorted by severity"
            );
        }
    }

    #[test]
    fn every_finding_carries_supporting_checks_and_actions() {
        let mut s = state();
        s.network = Some(proto::AndroidNetwork {
            capabilities: Some(proto::NetworkCapabilitiesInfo {
                validated: true,
                ..Default::default()
            }),
            ..Default::default()
        });
        let checks = vec![
            check("addr.v6", proto::CheckStatus::Pass),
            check("route.v6.default", proto::CheckStatus::Pass),
            check("tcp.v6", proto::CheckStatus::Fail),
            check("tcp.v4", proto::CheckStatus::Pass),
            check("dns.aaaa", proto::CheckStatus::Pass),
            check("captive.portal", proto::CheckStatus::Fail),
        ];
        let findings = evaluate(&checks, &s);
        assert!(!findings.is_empty());
        for f in &findings {
            assert!(!f.key.is_empty());
            assert!(!f.title.is_empty());
            assert!(!f.interpretation.is_empty());
            assert!(!f.supporting_checks.is_empty(), "{} has no evidence", f.key);
            assert!(
                !f.suggested_actions.is_empty(),
                "{} suggests nothing",
                f.key
            );
            assert!(f.confidence > 0 && f.confidence <= 100);
        }
    }
}
