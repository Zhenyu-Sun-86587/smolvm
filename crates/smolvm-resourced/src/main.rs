#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    match smolvm_resourced::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("smolvm-resourced: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("smolvm-resourced requires Linux");
    std::process::ExitCode::FAILURE
}
