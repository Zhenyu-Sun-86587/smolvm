//! Local worker resource service and Linux control client.

#[cfg(target_os = "linux")]
mod catalog;
#[cfg(target_os = "linux")]
pub mod client;
#[cfg(target_os = "linux")]
mod escrow;
#[cfg(target_os = "linux")]
mod escrow_catalog;
#[cfg(target_os = "linux")]
mod ipc;
#[cfg(target_os = "linux")]
mod worker;

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    worker::run()
}
