//! Example: Minimal network session capture using `flodbadd`
//!
//! This example starts a short live capture on all validated interfaces,
//! waits a few seconds, then prints the number of sessions that were
//! observed.  It demonstrates the public `FlodbaddCapture` API.

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
use flodbadd::capture::FlodbaddCapture;
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
use flodbadd::interface::get_all_interfaces;
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(all(
        any(target_os = "macos", target_os = "linux", target_os = "windows"),
        feature = "packetcapture"
    ))]
    {
        tracing_subscriber::fmt::init();

        // Gather interfaces
        let interfaces = get_all_interfaces();
        if interfaces.is_empty() {
            eprintln!("No suitable interfaces found – exiting.");
            return Ok(());
        }
        println!("Starting capture on {} interface(s)...", interfaces.len());

        // Start the capture (requires `packetcapture` feature and sufficient privileges)
        let capture = FlodbaddCapture::new();
        capture.start(&interfaces).await;

        // Capture for 5 seconds
        sleep(Duration::from_secs(5)).await;

        // Stop capture and fetch sessions
        capture.stop().await;
        let sessions = capture.get_sessions(false).await;
        println!("Captured {} session(s).", sessions.len());
    }
    Ok(())
}
