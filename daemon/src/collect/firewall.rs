//! Firewall state.
//!
//! This is the one area where "read the kernel directly" is genuinely hard on
//! Android, and it is worth being explicit about why.
//!
//! Android used to implement per-app network restrictions as iptables chains
//! (`fw_dozable`, `fw_standby`, `fw_powersave`, `bw_penalty_box`). Since
//! Android 13 that logic lives in eBPF programs loaded by bpfloader and driven
//! by maps that netd owns. The practical consequence for a diagnostic tool is
//! that an `iptables-save` dump can look completely empty on a device that is
//! actively blocking an app's traffic, which is exactly the kind of false
//! reassurance a tool like this must not give.
//!
//! So: read the eBPF maps when we can, fall back to dumping netfilter chains
//! when a vendor still uses them, and always report which of those actually
//! produced data so the UI can say "not determinable" instead of "fine".

use std::path::{Path, PathBuf};

use tokio::process::Command;
use tracing::debug;

use crate::proto;

/// Pin paths netd has used for the per-uid rule map across releases.
const UID_OWNER_MAP_PATHS: &[&str] = &[
    "/sys/fs/bpf/netd_shared/map_netd_uid_owner_map",
    "/sys/fs/bpf/net_shared/map_netd_uid_owner_map",
    "/sys/fs/bpf/map_netd_uid_owner_map",
];

/// Bits of `UidOwnerValue.rule` from netd's bpf_shared.h.
///
/// These are stable enough to be useful and not stable enough to be trusted
/// blindly, which is why `raw_match` is always reported alongside the decoded
/// names.
const MATCH_BITS: &[(u32, &str)] = &[
    (1 << 0, "HAPPY_BOX (metered allowlist)"),
    (1 << 1, "PENALTY_BOX (metered denylist)"),
    (1 << 2, "DOZABLE (allowlisted while dozing)"),
    (1 << 3, "STANDBY (denied while in app standby)"),
    (1 << 4, "POWERSAVE (allowlisted in battery saver)"),
    (1 << 5, "RESTRICTED (allowlisted in restricted mode)"),
    (1 << 6, "LOW_POWER_STANDBY (allowlisted)"),
    (1 << 7, "IIF (restricted to an input interface)"),
    (1 << 8, "LOCKDOWN_VPN (blocked outside the VPN)"),
    (1 << 9, "OEM_DENY_1"),
    (1 << 10, "OEM_DENY_2"),
    (1 << 11, "OEM_DENY_3"),
    (1 << 12, "BACKGROUND (denied in background)"),
];

/// Bits that unambiguously mean "this uid is denied", regardless of whether
/// the corresponding chain is currently enabled.
const DENY_BITS: u32 = (1 << 1) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11);

pub fn decode_match_bits(rule: u32) -> Vec<String> {
    let mut names: Vec<String> = MATCH_BITS
        .iter()
        .filter(|(bit, _)| rule & bit != 0)
        .map(|(_, name)| (*name).to_string())
        .collect();
    let known: u32 = MATCH_BITS.iter().map(|(bit, _)| bit).sum();
    let unknown = rule & !known;
    if unknown != 0 {
        names.push(format!("unknown bits 0x{unknown:x}"));
    }
    names
}

// ---- eBPF map access --------------------------------------------------------

const BPF_MAP_LOOKUP_ELEM: libc::c_int = 1;
const BPF_OBJ_GET: libc::c_int = 7;

#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct BpfAttrObj {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
    _pad: [u8; 104],
}

#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct BpfAttrLookup {
    map_fd: u32,
    _pad0: u32,
    key: u64,
    value: u64,
    flags: u64,
    _pad: [u8; 88],
}

// SAFETY contract for both helpers: the caller passes pointers that stay valid
// for the duration of the syscall, and the attribute structs are zero-filled
// except for the fields the command uses.
unsafe fn bpf(cmd: libc::c_int, attr: *mut libc::c_void, size: usize) -> libc::c_long {
    unsafe { libc::syscall(libc::SYS_bpf, cmd, attr, size) }
}

/// Open a pinned map by path. Returns the fd, which the caller must close.
fn bpf_obj_get(path: &Path) -> std::io::Result<libc::c_int> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let mut attr = BpfAttrObj {
        pathname: c_path.as_ptr() as u64,
        bpf_fd: 0,
        file_flags: 0,
        _pad: [0; 104],
    };
    // SAFETY: `attr` is a correctly sized, initialised attribute struct, and
    // `c_path` outlives the call.
    let fd = unsafe {
        bpf(
            BPF_OBJ_GET,
            &mut attr as *mut BpfAttrObj as *mut libc::c_void,
            std::mem::size_of::<BpfAttrObj>(),
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd as libc::c_int)
}

/// Look up a u32 key and read a value of `value_size` bytes.
fn bpf_map_lookup(map_fd: libc::c_int, key: u32, value_size: usize) -> std::io::Result<Vec<u8>> {
    let mut value = vec![0u8; value_size];
    let mut attr = BpfAttrLookup {
        map_fd: map_fd as u32,
        _pad0: 0,
        key: &key as *const u32 as u64,
        value: value.as_mut_ptr() as u64,
        flags: 0,
        _pad: [0; 88],
    };
    // SAFETY: key and value buffers outlive the call and match the sizes the
    // map was created with (u32 key, UidOwnerValue value).
    let ret = unsafe {
        bpf(
            BPF_MAP_LOOKUP_ELEM,
            &mut attr as *mut BpfAttrLookup as *mut libc::c_void,
            std::mem::size_of::<BpfAttrLookup>(),
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(value)
}

fn uid_owner_map_path() -> Option<PathBuf> {
    UID_OWNER_MAP_PATHS
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
}

/// Read one uid's entry from netd's uid_owner_map.
///
/// `struct UidOwnerValue { uint32_t iif; uint32_t rule; }` — 8 bytes. A missing
/// key means "no special rules for this uid", which is the common case and not
/// an error.
pub fn read_uid_firewall(uid: u32) -> proto::UidFirewallState {
    let mut state = proto::UidFirewallState {
        uid,
        ..Default::default()
    };

    let Some(path) = uid_owner_map_path() else {
        return state;
    };

    let fd = match bpf_obj_get(&path) {
        Ok(fd) => fd,
        Err(e) => {
            debug!("could not open {}: {e}", path.display());
            return state;
        }
    };

    // The map exists and we could open it, so absence of a key is a real
    // answer rather than a failure to look.
    state.source_available = true;

    match bpf_map_lookup(fd, uid, 8) {
        Ok(value) => {
            let rule = u32::from_ne_bytes([value[4], value[5], value[6], value[7]]);
            state.raw_match = rule;
            state.blocked_metered_deny_user = rule & (1 << 1) != 0;
            state.blocked_standby = rule & (1 << 3) != 0;
            state.blocked_dozable = rule & (1 << 2) == 0;
            state.blocked_powersave = rule & (1 << 4) == 0;
            state.blocked_restricted = rule & (1 << 5) == 0;
            state.blocked_low_power_standby = rule & (1 << 6) == 0;
            state.blocked_metered_allow = rule & (1 << 0) != 0;
            state.blocked_metered_deny_admin = rule & DENY_BITS & !(1 << 1) != 0;
        }
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
            // No entry: no per-uid rules apply.
        }
        Err(e) => {
            debug!("uid_owner_map lookup for {uid} failed: {e}");
            state.source_available = false;
        }
    }

    // SAFETY: `fd` came from bpf_obj_get and is not used after this point.
    unsafe { libc::close(fd) };
    state
}

/// Is this uid denied by a rule whose meaning does not depend on which chains
/// are currently enabled?
pub fn is_unambiguously_denied(state: &proto::UidFirewallState) -> bool {
    state.source_available && state.raw_match & DENY_BITS != 0
}

// ---- Netfilter --------------------------------------------------------------

/// Parse `iptables-save -c` output into chains with their counters.
fn parse_iptables_save(text: &str) -> Vec<proto::FirewallChain> {
    let mut chains: Vec<proto::FirewallChain> = Vec::new();
    let mut table = String::new();

    for line in text.lines() {
        let line = line.trim();
        if let Some(name) = line.strip_prefix('*') {
            table = name.to_string();
        } else if let Some(rest) = line.strip_prefix(':') {
            // ":INPUT ACCEPT [0:0]" or ":fw_dozable - [0:0]"
            let mut parts = rest.split_whitespace();
            let (Some(name), Some(policy)) = (parts.next(), parts.next()) else {
                continue;
            };
            let (packets, bytes) = parts.next().and_then(parse_counter).unwrap_or((0, 0));
            chains.push(proto::FirewallChain {
                table: table.clone(),
                name: name.to_string(),
                policy: policy.to_string(),
                packets,
                bytes,
                rules: Vec::new(),
            });
        } else if line.starts_with("-A ") || line.starts_with("[") {
            // Attach the rule to its chain. With -c the line starts with the
            // counter in brackets, then "-A <chain> ...".
            let rule_body = line
                .strip_prefix('[')
                .and_then(|r| r.split_once(']'))
                .map(|(_, r)| r.trim())
                .unwrap_or(line);
            let Some(chain_name) = rule_body
                .strip_prefix("-A ")
                .and_then(|r| r.split_whitespace().next())
            else {
                continue;
            };
            if let Some(chain) = chains
                .iter_mut()
                .rev()
                .find(|c| c.name == chain_name && c.table == table)
            {
                chain.rules.push(rule_body.to_string());
            }
        }
    }

    chains
}

/// "[12:3456]" -> (12, 3456)
fn parse_counter(token: &str) -> Option<(u64, u64)> {
    let inner = token.trim_start_matches('[').trim_end_matches(']');
    let (p, b) = inner.split_once(':')?;
    Some((p.parse().ok()?, b.parse().ok()?))
}

async fn run_tool(program: &str, args: &[&str]) -> Option<String> {
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        Command::new(program).args(args).output(),
    )
    .await
    .ok()?
    .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Every pinned eBPF object that looks network related. Listing these is cheap
/// and tells the user whether the eBPF firewall is even present.
fn list_bpf_pins() -> (Vec<String>, bool) {
    let mut found = Vec::new();
    let mut readable = false;

    for root in [
        "/sys/fs/bpf",
        "/sys/fs/bpf/netd_shared",
        "/sys/fs/bpf/net_shared",
    ] {
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        readable = true;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.contains("net")
                || name.contains("uid")
                || name.contains("clat")
                || name.contains("tether")
                || name.contains("cookie")
            {
                found.push(format!("{root}/{name}"));
            }
        }
    }

    found.sort();
    found.dedup();
    (found, readable)
}

pub async fn collect(use_shell_fallback: bool) -> proto::FirewallState {
    let (pins, bpf_readable) = list_bpf_pins();
    let uid_map_present = uid_owner_map_path().is_some();

    let mut backends = Vec::new();
    if uid_map_present || !pins.is_empty() {
        backends.push(proto::FirewallBackend::Ebpf as i32);
    }

    let mut state = proto::FirewallState {
        bpf_pinned_objects: pins,
        bpf_maps_readable: bpf_readable,
        ..Default::default()
    };

    if use_shell_fallback {
        // Kept as an explicit opt-in: these binaries may not exist, and on a
        // device that has moved to eBPF their output is misleadingly empty.
        if let Some(text) = run_tool("iptables-save", &["-c"]).await {
            state.ipv4_chains = parse_iptables_save(&text);
            if !state.ipv4_chains.is_empty() {
                backends.push(proto::FirewallBackend::Iptables as i32);
            }
            state.used_shell_fallback = true;
        }
        if let Some(text) = run_tool("ip6tables-save", &["-c"]).await {
            state.ipv6_chains = parse_iptables_save(&text);
            state.used_shell_fallback = true;
        }
        if run_tool("nft", &["list", "tables"]).await.is_some() {
            backends.push(proto::FirewallBackend::Nftables as i32);
        }
    }

    backends.sort_unstable();
    backends.dedup();
    state.backends_detected = backends;

    state.collection_note = if uid_map_present {
        "per-uid rules read from netd's eBPF uid_owner_map".to_string()
    } else if bpf_readable {
        "eBPF filesystem is present but netd's uid_owner_map was not found; per-uid \
         blocking state is not determinable"
            .to_string()
    } else {
        "no readable eBPF or netfilter state".to_string()
    };

    state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_known_match_bits() {
        let names = decode_match_bits((1 << 1) | (1 << 3));
        assert!(names.iter().any(|n| n.contains("PENALTY_BOX")));
        assert!(names.iter().any(|n| n.contains("STANDBY")));
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn reports_unknown_bits_rather_than_dropping_them() {
        let names = decode_match_bits(1 << 20);
        assert_eq!(names.len(), 1);
        assert!(names[0].contains("unknown bits"), "{names:?}");
    }

    #[test]
    fn deny_bits_are_recognised() {
        let denied = proto::UidFirewallState {
            raw_match: 1 << 1,
            source_available: true,
            ..Default::default()
        };
        assert!(is_unambiguously_denied(&denied));

        // An allowlist bit alone does not mean blocked.
        let allowlisted = proto::UidFirewallState {
            raw_match: 1 << 2,
            source_available: true,
            ..Default::default()
        };
        assert!(!is_unambiguously_denied(&allowlisted));
    }

    #[test]
    fn an_unreadable_map_never_claims_a_verdict() {
        let unknown = proto::UidFirewallState {
            raw_match: 1 << 1,
            source_available: false,
            ..Default::default()
        };
        assert!(!is_unambiguously_denied(&unknown));
    }

    #[test]
    fn parses_iptables_save_chains_and_rules() {
        let text = "\
*filter
:INPUT ACCEPT [10:2048]
:fw_dozable - [0:0]
[5:600] -A INPUT -i lo -j ACCEPT
[0:0] -A fw_dozable -m owner --uid-owner 10342 -j RETURN
COMMIT
";
        let chains = parse_iptables_save(text);
        assert_eq!(chains.len(), 2);
        let input = chains.iter().find(|c| c.name == "INPUT").unwrap();
        assert_eq!(input.table, "filter");
        assert_eq!(input.policy, "ACCEPT");
        assert_eq!(input.packets, 10);
        assert_eq!(input.bytes, 2048);
        assert_eq!(input.rules.len(), 1);

        let dozable = chains.iter().find(|c| c.name == "fw_dozable").unwrap();
        assert_eq!(dozable.rules.len(), 1);
        assert!(dozable.rules[0].contains("10342"));
    }

    #[test]
    fn parses_counters() {
        assert_eq!(parse_counter("[12:3456]"), Some((12, 3456)));
        assert_eq!(parse_counter("nonsense"), None);
    }
}
