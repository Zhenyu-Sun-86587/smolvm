//! Local worker resource service and Linux control client.

#[cfg(target_os = "linux")]
mod activation_authority;
#[cfg(target_os = "linux")]
mod activation_catalog;
#[cfg(target_os = "linux")]
mod activation_runtime;
#[cfg(target_os = "linux")]
mod admission;
#[cfg(target_os = "linux")]
mod blocks;
#[cfg(target_os = "linux")]
mod catalog;
#[cfg(target_os = "linux")]
pub mod client;
#[cfg(target_os = "linux")]
mod escrow;
#[cfg(target_os = "linux")]
mod escrow_catalog;
#[cfg(target_os = "linux")]
mod grants;
#[cfg(target_os = "linux")]
mod guest_transport;
#[cfg(target_os = "linux")]
mod ipc;
#[cfg(target_os = "linux")]
pub mod managed;
#[cfg(target_os = "linux")]
mod managed_fork;
#[cfg(target_os = "linux")]
pub mod native_client;
#[cfg(target_os = "linux")]
mod native_control;
#[cfg(target_os = "linux")]
mod native_operations;
#[cfg(target_os = "linux")]
pub mod network;
#[cfg(target_os = "linux")]
mod network_catalog;
#[cfg(target_os = "linux")]
pub mod network_client;
#[cfg(target_os = "linux")]
mod network_dns;
#[cfg(target_os = "linux")]
mod network_lease_catalog;
#[cfg(target_os = "linux")]
mod network_runtime;
#[cfg(target_os = "linux")]
mod pivots;
#[cfg(target_os = "linux")]
mod product_volumes;
#[cfg(target_os = "linux")]
mod statepoint_capture;
#[cfg(target_os = "linux")]
mod statepoint_catalog;
#[cfg(target_os = "linux")]
mod statepoint_store;
#[cfg(target_os = "linux")]
mod statepoints;
#[cfg(target_os = "linux")]
mod worker;

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    worker::run()
}
