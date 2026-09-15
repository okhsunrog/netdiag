fn main() {
    slint_build::compile("ui/app.slint").expect("failed to compile the Slint UI");

    #[cfg(unix)]
    android::build();
}

/// Compiling the one Java class this app needs, from the build script.
///
/// `NetworkCallback` has to be subclassed to receive framework events, and a
/// Java abstract class cannot be subclassed from Rust. So one small Java file
/// is compiled with `javac`, converted to a dex with `d8`, and embedded in the
/// Rust binary; it is loaded at runtime with `InMemoryDexClassLoader`.
///
/// Nothing about the APK changes: the dex rides inside the `.so`, so there is
/// no Gradle, no manifest edit and no packaging step. This is the same approach
/// Slint's own Android backend uses for its helper class.
#[cfg(unix)]
mod android {
    use std::path::PathBuf;

    const JAVA_SRC: &str = "java/NetdiagFrameworkWatcher.java";

    /// Slint's Android backend compiles its own helper with `-source 8`, which
    /// JDK 26 rejects outright, and JDK 21 is known to break `d8` with older
    /// SDK build tools. Rather than let either fail with a wall of javac
    /// output, check up front and say what to do.
    const MIN_JDK: u32 = 17;
    const MAX_JDK: u32 = 21;

    pub fn build() {
        println!("cargo:rerun-if-changed={JAVA_SRC}");
        println!("cargo:rerun-if-env-changed=ANDROID_JAR");
        println!("cargo:rerun-if-env-changed=ANDROID_HOME");
        println!("cargo:rerun-if-env-changed=JAVA_HOME");

        let target = std::env::var("TARGET").unwrap_or_default();
        if !target.contains("android") {
            return;
        }

        let java_home = android_build::java_home().unwrap_or_else(|| {
            panic!(
                "no JDK found. Set JAVA_HOME to a JDK between {MIN_JDK} and {MAX_JDK}; \
                 newer ones reject the `-source 8` that Slint's Android backend uses."
            )
        });

        match android_build::check_javac_version(&java_home) {
            Ok(version) if (MIN_JDK..=MAX_JDK).contains(&version) => {}
            Ok(version) => panic!(
                "JAVA_HOME points at JDK {version} ({}), which is outside the supported \
                 range {MIN_JDK}..={MAX_JDK}.\n\
                 JDK 22+ rejects the `-source 8` that Slint's Android backend compiles its \
                 own helper with, and older JDKs cannot read the SDK's class files.\n\
                 Set JAVA_HOME to a JDK in that range, for example:\n  \
                 JAVA_HOME=/usr/lib/jvm/java-21-openjdk cargo ndk -t arm64-v8a build",
                java_home.display()
            ),
            Err(e) => panic!("could not run javac from {}: {e}", java_home.display()),
        }

        let android_jar = android_build::android_jar(None).unwrap_or_else(|| {
            panic!(
                "no android.jar found. Set ANDROID_JAR explicitly; the automatic search \
                 picks the oldest installed platform, which is often too old."
            )
        });

        let out_dir: PathBuf = std::env::var_os("OUT_DIR").unwrap().into();
        let classes_dir = out_dir.join("java-classes");
        let _ = std::fs::remove_dir_all(&classes_dir);
        std::fs::create_dir_all(&classes_dir).expect("could not create the class output directory");

        let output = android_build::JavaBuild::new()
            .file(JAVA_SRC)
            .class_path(&android_jar)
            .classes_out_dir(&classes_dir)
            // 11 rather than 8: nothing here needs Java 8 bytecode, and it keeps
            // this file compiling on JDKs that have dropped `-source 8`.
            .java_source_version(11)
            .java_target_version(11)
            .command()
            .expect("could not build the javac command")
            .args(["-encoding", "UTF-8", "-Xlint:-options"])
            .output()
            .expect("could not run javac");

        if !output.status.success() {
            panic!(
                "javac failed for {JAVA_SRC}:\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let output = android_build::Dexer::new()
            .android_jar(&android_jar)
            .class_path(&classes_dir)
            .collect_classes(&classes_dir)
            .expect("could not collect the compiled classes")
            .release(std::env::var("PROFILE").as_deref() == Ok("release"))
            // Above 20 d8 emits a single classes.dex, which is what
            // InMemoryDexClassLoader wants.
            .android_min_api(31)
            .out_dir(&out_dir)
            .command()
            .expect("could not build the d8 command")
            .output()
            .expect("could not run d8");

        if !output.status.success() {
            panic!(
                "d8 failed:\n{}\n\nIf this mentions class file versions, the JDK and the SDK \
                 build tools disagree; try a newer ANDROID_BUILD_TOOLS_VERSION.",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let dex = out_dir.join("classes.dex");
        let size = std::fs::metadata(&dex).map(|m| m.len()).unwrap_or(0);
        println!("cargo:warning=built {} ({size} bytes)", dex.display());
    }
}
