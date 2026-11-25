// SPDX-License-Identifier: Apache-2.0
#[cfg(target_os = "linux")]
mod linux;

fn main() {
    #[cfg(target_os = "linux")]
    if linux::run().is_ok() {
        return;
    }
    std::process::exit(1);
}
