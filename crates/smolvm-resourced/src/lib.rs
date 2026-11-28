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
mod lifecycle_controller;
#[cfg(target_os = "linux")]
mod backing_identity;
#[cfg(target_os = "linux")]
mod blocks;
#[cfg(target_os = "linux")]
mod bucket_bases;
#[cfg(target_os = "linux")]
mod catalog;
#[cfg(target_os = "linux")]
pub mod client;
#[cfg(target_os = "linux")]
pub mod worker_scope;
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
mod kernel_mm_anchor;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod kernel_mm_anchor_process;
#[cfg(target_os = "linux")]
pub mod managed;
#[cfg(target_os = "linux")]
pub mod boot_environment;
#[cfg(target_os = "linux")]
mod managed_fork;
#[cfg(target_os = "linux")]
mod managed_kernel_cow;
pub mod managed_state_restore;
#[cfg(target_os = "linux")]
mod managed_retirement;
#[cfg(target_os = "linux")]
mod managed_statepoint;
#[cfg(target_os = "linux")]
mod backup_closure;
#[cfg(target_os = "linux")]
mod backup_import;
#[cfg(target_os = "linux")]
mod disk_closure_import;
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
mod host_bound;
#[cfg(target_os="linux")]
mod conntrack;
#[cfg(target_os = "linux")]
mod network_lease_catalog;
#[cfg(target_os = "linux")]
#[cfg(target_os = "linux")]
mod network_memberships;
#[cfg(target_os = "linux")]
mod network_peering;
#[cfg(target_os = "linux")]
mod network_runtime;
#[cfg(target_os = "linux")]
mod network_transfer;
#[cfg(target_os = "linux")]
mod packet_wake;
#[cfg(target_os = "linux")]
mod pivots;
#[cfg(target_os = "linux")]
mod product_volumes;
#[cfg(target_os = "linux")]
mod resource_resize;
#[cfg(target_os = "linux")]
mod saved_files;
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

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[doc(hidden)]
pub fn run_kernel_mm_anchor() -> std::io::Result<()> {
    kernel_mm_anchor_process::run()
}
