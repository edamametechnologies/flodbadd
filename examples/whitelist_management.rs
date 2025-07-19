//! Example: Inspect current whitelists
//!
//! This very small example retrieves the currently loaded whitelist
//! information from `flodbadd` and prints it as prettified JSON.

use flodbadd::whitelists::current_json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let whitelists = current_json().await;
    println!("{}", serde_json::to_string_pretty(&whitelists)?);
    Ok(())
}
