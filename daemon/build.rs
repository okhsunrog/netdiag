use std::path::PathBuf;

fn main() {
    let proto_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("proto");

    let files = [
        "netdiag/v1/common.proto",
        "netdiag/v1/link.proto",
        "netdiag/v1/route.proto",
        "netdiag/v1/socket.proto",
        "netdiag/v1/system.proto",
        "netdiag/v1/android.proto",
        "netdiag/v1/event.proto",
        "netdiag/v1/diag.proto",
        "netdiag/v1/capture.proto",
        "netdiag/v1/service.proto",
    ];

    for f in &files {
        println!("cargo:rerun-if-changed={}", proto_root.join(f).display());
    }
    println!("cargo:rerun-if-env-changed=PROTOC");

    let paths: Vec<PathBuf> = files.iter().map(|f| proto_root.join(f)).collect();

    let mut cfg = prost_build::Config::new();
    // Derive Eq/Hash where possible so collected state can be diffed cheaply
    // for the event timeline.
    cfg.type_attribute(
        ".netdiag.v1",
        "#[allow(clippy::doc_overindented_list_items)]",
    );
    cfg.compile_protos(&paths, &[proto_root])
        .expect("failed to compile netdiag protos; is `protoc` installed and on PATH?");
}
