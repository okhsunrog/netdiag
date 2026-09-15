fn main() {
    slint_build::compile("ui/app.slint").expect("failed to compile the Slint UI");
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
