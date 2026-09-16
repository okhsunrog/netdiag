fn main() {
    // The widget style is pinned rather than left to the default.
    //
    // This app draws its own dark palette, and the handful of std-widgets it
    // uses — Button, LineEdit, ListView, ScrollView — have to sit inside it.
    // Upgrading from a git revision of master to the 1.18 release changed the
    // default style, and the buttons came back light grey on a near-black
    // window. Nothing in the app had changed; it had simply been relying on
    // whatever the default happened to be.
    let config = slint_build::CompilerConfiguration::new().with_style("fluent-dark".to_string());
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
