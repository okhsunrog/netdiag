//! The Java shim's vocabulary, and the one place that translates it.
//!
//! Deliberately **not** gated on `target_os = "android"`. The values are plain
//! integers, and keeping them host-compilable is what lets the drift test below
//! run under a normal `cargo test` instead of only on a device.
//!
//! These are not the wire enum values. The shim is compiled into the same APK
//! by the same `cargo rapk` invocation, so the two can never be different
//! versions; the only real risk is someone editing the Java constants without
//! editing this table, and that is exactly what the test catches.
//!
//! The package list is parsed here for the same reason: it is the other half of
//! a format defined in Java, and a host-runnable test is worth more than a
//! device-only one.

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

/// Parse what `NetdiagPackages.list()` returns: one application per line, as
/// `uid \t system \t package \t label`.
///
/// Malformed lines are skipped rather than failing the whole list. A label is
/// arbitrary user-visible text, and losing one app from the screen is a much
/// better failure than losing the screen.
///
/// `PackageManager` returns an arbitrary order, so the result is sorted: user
/// apps first, then system ones, each by label. The Compose build hides system
/// packages by default and takes a parameter to include them; this screen has
/// no such toggle, and a tool for reading sockets by uid should not make system
/// uids unreachable. They are sorted below rather than removed, and the filter
/// box finds them.
pub fn parse_packages(listing: &str) -> Vec<super::InstalledApp> {
    let mut apps = parse_package_lines(listing);
    apps.sort_by(|a, b| {
        a.is_system
            .cmp(&b.is_system)
            .then_with(|| a.label.to_lowercase().cmp(&b.label.to_lowercase()))
    });
    apps
}

fn parse_package_lines(listing: &str) -> Vec<super::InstalledApp> {
    listing
        .lines()
        .filter_map(|line| {
            let mut fields = line.splitn(4, '\t');
            let uid = fields.next()?.parse().ok()?;
            let is_system = fields.next()? == "1";
            let package = fields.next()?;
            // A label is allowed to be empty; the package name is not a
            // pleasant fallback but it is always meaningful.
            let label = match fields.next() {
                Some(label) if !label.is_empty() => label,
                _ => package,
            };
            Some(super::InstalledApp {
                package: package.to_owned(),
                label: label.to_owned(),
                uid,
                is_system,
            })
        })
        .collect()
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

    /// The separators here must be the ones the Java writes.
    #[test]
    fn package_separators_match_the_java() {
        let java = include_str!("../../java/NetdiagPackages.java");
        assert!(
            java.contains(r"char FIELD = '\t'"),
            "NetdiagPackages no longer separates fields with a tab"
        );
        assert!(
            java.contains(r"char RECORD = '\n'"),
            "NetdiagPackages no longer separates records with a newline"
        );
    }

    #[test]
    fn parses_a_package_listing() {
        let apps = parse_packages("10400\t0\tcom.example.shop\tShop\n1000\t1\tandroid\tSystem\n");
        assert_eq!(apps.len(), 2);
        assert_eq!(apps[0].uid, 10400);
        assert_eq!(apps[0].package, "com.example.shop");
        assert_eq!(apps[0].label, "Shop");
        assert!(!apps[0].is_system);
        assert!(apps[1].is_system);
    }

    #[test]
    fn user_apps_sort_first_then_by_label_ignoring_case() {
        let apps = parse_packages(
            "1\t1\tsys.a\tAaa system\n2\t0\tcom.z\tzebra\n3\t0\tcom.a\tApple\n4\t1\tsys.b\tBbb system\n",
        );
        let order: Vec<&str> = apps.iter().map(|a| a.label.as_str()).collect();
        // "Apple" before "zebra" needs the case-insensitive compare; a plain
        // sort puts every capital letter ahead of every lowercase one.
        assert_eq!(order, ["Apple", "zebra", "Aaa system", "Bbb system"]);
    }

    #[test]
    fn a_label_may_contain_spaces_and_be_empty() {
        let apps = parse_packages("101\t0\tcom.a\tSome Long Name\n102\t0\tcom.b\t\n");
        // Looked up by package, because the result is sorted by label.
        let find = |package: &str| {
            apps.iter()
                .find(|a| a.package == package)
                .unwrap_or_else(|| panic!("{package} is missing"))
        };
        assert_eq!(find("com.a").label, "Some Long Name");
        // An empty label falls back to something a person can still act on.
        assert_eq!(find("com.b").label, "com.b");
    }

    #[test]
    fn a_broken_line_drops_only_itself() {
        let apps = parse_packages("not-a-uid\t0\tcom.a\tA\n10\t0\tcom.b\tB\n\n");
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].package, "com.b");
    }
}
