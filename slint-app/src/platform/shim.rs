//! The Java shim's vocabulary, and the one place that translates it.
//!
//! Deliberately **not** gated on `target_os = "android"`. The values are plain
//! integers, and keeping them host-compilable is what lets the drift test below
//! run under a normal `cargo test` instead of only on a device.
//!
//! These are not the wire enum values. The shim is compiled by this crate's
//! build script and embedded in this binary, so the two can never be different
//! versions; the only real risk is someone editing the Java constants without
//! editing this table, and that is exactly what the test catches.

use netdiag_ipc::proto;

pub mod java_kind {
    pub const AVAILABLE: i32 = 1;
    pub const LOST: i32 = 2;
    pub const LOSING: i32 = 3;
    pub const IPV6_CHANGED: i32 = 4;
    pub const BLOCKED_CHANGED: i32 = 5;
    pub const VALIDATION_CHANGED: i32 = 6;
    pub const DNS_CHANGED: i32 = 7;
}

pub mod java_severity {
    pub const INFO: i32 = 1;
    pub const NOTICE: i32 = 2;
    pub const WARNING: i32 = 3;
}

/// Translate the shim's vocabulary into the wire enum.
pub fn event_kind(java: i32) -> proto::FrameworkEventKind {
    use proto::FrameworkEventKind as K;
    match java {
        java_kind::AVAILABLE => K::Available,
        java_kind::LOST => K::Lost,
        java_kind::LOSING => K::Losing,
        java_kind::IPV6_CHANGED => K::LinkPropertiesChanged,
        java_kind::BLOCKED_CHANGED => K::BlockedStatusChanged,
        java_kind::VALIDATION_CHANGED => K::ValidationChanged,
        java_kind::DNS_CHANGED => K::DnsServersChanged,
        _ => K::Unspecified,
    }
}

pub fn event_severity(java: i32) -> proto::EventSeverity {
    use proto::EventSeverity as S;
    match java {
        java_severity::INFO => S::Info,
        java_severity::NOTICE => S::Notice,
        java_severity::WARNING => S::Warning,
        _ => S::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read a constant straight out of the Java source.
    fn declared(name: &str) -> i32 {
        let java = include_str!("../../java/NetdiagFrameworkWatcher.java");
        let needle = format!("static final int {name} = ");
        let line = java
            .lines()
            .find(|line| line.contains(&needle))
            .unwrap_or_else(|| panic!("{name} is not declared in the Java shim"));
        line.rsplit("= ")
            .next()
            .and_then(|value| value.trim().trim_end_matches(';').parse().ok())
            .unwrap_or_else(|| panic!("could not parse the value of {name}"))
    }

    /// If someone renumbers the Java constants without updating this table,
    /// this is what fails — rather than events quietly arriving with the wrong
    /// label on a device, which is the one failure mode this design has.
    #[test]
    fn the_table_matches_the_java_shim() {
        assert_eq!(declared("KIND_AVAILABLE"), java_kind::AVAILABLE);
        assert_eq!(declared("KIND_LOST"), java_kind::LOST);
        assert_eq!(declared("KIND_LOSING"), java_kind::LOSING);
        assert_eq!(declared("KIND_IPV6_CHANGED"), java_kind::IPV6_CHANGED);
        assert_eq!(declared("KIND_BLOCKED_CHANGED"), java_kind::BLOCKED_CHANGED);
        assert_eq!(
            declared("KIND_VALIDATION_CHANGED"),
            java_kind::VALIDATION_CHANGED
        );
        assert_eq!(declared("KIND_DNS_CHANGED"), java_kind::DNS_CHANGED);

        assert_eq!(declared("SEVERITY_INFO"), java_severity::INFO);
        assert_eq!(declared("SEVERITY_NOTICE"), java_severity::NOTICE);
        assert_eq!(declared("SEVERITY_WARNING"), java_severity::WARNING);
    }

    #[test]
    fn every_java_kind_maps_to_a_real_wire_value() {
        for kind in [
            java_kind::AVAILABLE,
            java_kind::LOST,
            java_kind::LOSING,
            java_kind::IPV6_CHANGED,
            java_kind::BLOCKED_CHANGED,
            java_kind::VALIDATION_CHANGED,
            java_kind::DNS_CHANGED,
        ] {
            assert_ne!(
                event_kind(kind),
                proto::FrameworkEventKind::Unspecified,
                "java kind {kind} has no wire mapping"
            );
        }
    }

    #[test]
    fn an_unknown_value_degrades_instead_of_panicking() {
        // A shim from the future must not take the app down.
        assert_eq!(event_kind(9999), proto::FrameworkEventKind::Unspecified);
        assert_eq!(event_severity(9999), proto::EventSeverity::Info);
    }
}
