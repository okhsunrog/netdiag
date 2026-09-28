fn main() {
    // Keep standard widgets and the vendored Material components on the same
    // visual system. Both follow the platform color scheme.
    let config = slint_build::CompilerConfiguration::new()
        .with_style("material".to_string())
        .with_library_paths(std::collections::HashMap::from([(
            "material".to_string(),
            std::path::Path::new(&std::env::var_os("CARGO_MANIFEST_DIR").unwrap())
                .join("material-1.1.0/material.slint"),
        )]));
    slint_build::compile_with_config("ui/app.slint", config)
        .expect("failed to compile the Slint UI");
}

// The one Java class this app needs used to be compiled here, with `javac` and
// `d8` driven by the `android-build` crate, and embedded in the `.so` with
// `include_bytes!` because `cargo-apk` cannot put classes in an APK.
//
// `cargo rapk` can, so the class is now declared in `Cargo.toml`:
//
//     [package.metadata.android]
//     java_sources = ["java"]
//
// and compiled into the APK's own `classes.dex`. That removed this build
// script's JDK version guard, its `android.jar` discovery, and the
// `InMemoryDexClassLoader` and `RegisterNatives` that loading a dex out of the
// `.so` required at runtime. See `docs/slint-experiment.md`.
