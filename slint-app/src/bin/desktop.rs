//! Desktop harness.
//!
//! The same UI and the same client, pointed at a daemon running on this
//! machine. Being able to iterate on the interface without an attached phone
//! is the clearest practical win of writing the frontend in Rust: the Compose
//! build has no equivalent, because its UI cannot run outside Android.
//!
//! ```sh
//! sudo netdiagd --socket @netdiag --allow-uid "$(id -u)"
//! netdiag-slint-desktop --connect --tab 1
//! ```

use netdiag_slint::{app, platform, ui};
use slint::ComponentHandle;

struct Args {
    /// Connect on startup instead of waiting for the button.
    connect: bool,
    /// Which tab to open, so a screen can be opened directly while working
    /// on it.
    tab: i32,
    /// Render the window to this PNG and exit.
    ///
    /// Renders from inside the process rather than capturing the screen, so
    /// reviewing the UI never picks up whatever else is on the developer's
    /// desktop.
    snapshot: Option<String>,
    /// How long to let the UI settle before the snapshot.
    settle_ms: u64,
    /// Run the diagnosis once connected.
    diagnose: bool,
    capture: Option<String>,
    save_capture: bool,
}

fn parse_args() -> Args {
    let mut args = Args {
        connect: false,
        tab: 0,
        snapshot: None,
        settle_ms: 2500,
        diagnose: false,
        capture: None,
        save_capture: false,
    };
    let mut argv = std::env::args().skip(1);
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--connect" => args.connect = true,
            "--tab" => {
                args.tab = argv
                    .next()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0);
            }
            "--snapshot" => args.snapshot = argv.next(),
            "--diagnose" => args.diagnose = true,
            "--capture" => args.capture = argv.next(),
            "--save-capture" => args.save_capture = true,
            "--settle-ms" => {
                args.settle_ms = argv
                    .next()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(2500);
            }
            "-h" | "--help" => {
                println!(
                    "netdiag-slint-desktop [--connect] [--tab N] [--snapshot FILE] [--settle-ms MS]\n\
                     \t[--diagnose] [--capture IFACE] [--save-capture]\n\n\
                     Runs the Slint UI against a daemon on this machine.\n\
                     Tabs: 0 overview, 1 diagnose, 2 routing, 3 apps, 4 timeline\n\
                     --snapshot FILE renders the window to a PNG and exits."
                );
                std::process::exit(0);
            }
            other => eprintln!("ignoring unknown argument '{other}'"),
        }
    }
    args
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = parse_args();
    let state = app::AppState::new(std::sync::Arc::new(platform::desktop::DesktopPlatform))?;
    let window = ui::App::new()?;
    app::wire(&window, state);

    window.set_tab(args.tab);
    if args.connect {
        window.invoke_connect();
    }
    if args.diagnose {
        // Connecting is asynchronous, so the diagnosis has to wait for the
        // client to exist rather than firing immediately.
        let weak = window.as_weak();
        let timer = Box::leak(Box::new(slint::Timer::default()));
        timer.start(
            slint::TimerMode::SingleShot,
            std::time::Duration::from_millis(1500),
            move || {
                if let Some(window) = weak.upgrade() {
                    window.invoke_diagnose();
                }
            },
        );
    }

    // Capture is the one screen that cannot be checked by rendering alone: it
    // has to be started, has to receive packets, and has to write a file that
    // another tool can read back. Driving it from here verifies all three
    // without a phone.
    if let Some(interface) = args.capture {
        let weak = window.as_weak();
        let timer = Box::leak(Box::new(slint::Timer::default()));
        timer.start(
            slint::TimerMode::SingleShot,
            std::time::Duration::from_millis(1500),
            move || {
                if let Some(window) = weak.upgrade() {
                    window.set_capture_interface(interface.clone().into());
                    window.invoke_start_capture(interface.clone().into());
                }
            },
        );
    }
    if args.save_capture {
        // After the snapshot settles, so there is something to write.
        let weak = window.as_weak();
        let timer = Box::leak(Box::new(slint::Timer::default()));
        timer.start(
            slint::TimerMode::SingleShot,
            std::time::Duration::from_millis(args.settle_ms.saturating_sub(200).max(1600)),
            move || {
                if let Some(window) = weak.upgrade() {
                    window.invoke_save_capture();
                }
            },
        );
    }

    if let Some(path) = args.snapshot {
        schedule_snapshot(&window, path, args.settle_ms);
    }

    window.run()?;
    Ok(())
}

/// Render the window to a PNG once the data has arrived, then quit.
fn schedule_snapshot(window: &ui::App, path: String, settle_ms: u64) {
    let weak = window.as_weak();
    let timer = Box::leak(Box::new(slint::Timer::default()));
    timer.start(
        slint::TimerMode::SingleShot,
        std::time::Duration::from_millis(settle_ms),
        move || {
            let Some(window) = weak.upgrade() else { return };
            match window.window().take_snapshot() {
                Ok(buffer) => {
                    if let Err(e) = write_png(&path, &buffer) {
                        eprintln!("could not write {path}: {e}");
                    } else {
                        println!("wrote {path} ({}x{})", buffer.width(), buffer.height());
                    }
                }
                Err(e) => eprintln!("take_snapshot failed: {e}"),
            }
            let _ = slint::quit_event_loop();
        },
    );
}

fn write_png(
    path: &str,
    buffer: &slint::SharedPixelBuffer<slint::Rgba8Pixel>,
) -> anyhow::Result<()> {
    let file = std::fs::File::create(path)?;
    let mut encoder = png::Encoder::new(
        std::io::BufWriter::new(file),
        buffer.width(),
        buffer.height(),
    );
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header()?;
    let bytes: &[u8] = bytemuck_cast(buffer.as_slice());
    writer.write_image_data(bytes)?;
    Ok(())
}

/// Rgba8Pixel is `#[repr(C)]` with four u8 fields, so a slice of them has the
/// same layout as the tightly packed RGBA bytes a PNG encoder expects.
fn bytemuck_cast(pixels: &[slint::Rgba8Pixel]) -> &[u8] {
    // SAFETY: Rgba8Pixel is repr(C) { r, g, b, a: u8 }, so N pixels occupy
    // exactly 4N bytes with no padding.
    unsafe { std::slice::from_raw_parts(pixels.as_ptr() as *const u8, pixels.len() * 4) }
}
