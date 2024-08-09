#[cfg(windows)]
fn get_winfsp_install_dir() -> std::path::PathBuf {
    let winfsp_install = registry::Hive::LocalMachine
        .open("SOFTWARE\\WOW6432Node\\WinFsp", registry::Security::Read)
        .ok()
        .and_then(|u| u.value("InstallDir").ok())
        .expect("WinFsp installation directory not found.");
    match winfsp_install {
        registry::Data::String(path) => std::path::PathBuf::from(path.to_os_string()),
        _ => panic!("unexpected install directory"),
    }
}

#[cfg(windows)]
fn main() {
    let winfsp_install_dir = get_winfsp_install_dir();
    println!(
        "cargo:rustc-link-search={}/lib",
        winfsp_install_dir.to_string_lossy()
    );

    if cfg!(all(target_os = "windows", target_env = "msvc")) {
        if cfg!(target_arch = "x86_64") {
            println!("cargo:rustc-link-lib=dylib=winfsp-x64");
        } else if cfg!(target_arch = "x86") {
            println!("cargo:rustc-link-lib=dylib=winfsp-x86");
        } else if cfg!(target_arch = "aarch64") {
            println!("cargo:rustc-link-lib=dylib=winfsp-a64");
        } else {
            panic!("unsupported architecture")
        }
    } else {
        panic!("unsupported triple {}", std::env::var("TARGET").unwrap())
    };
}

// Compilation on non-Windows platform will obviously fail (as WinFSP is only available
// on Windows).
// However keeping the Rust part platform agnostic is still useful given it allows
// linter & IDE to work correctly when groking into the code from a non-Windows machine.
#[cfg(not(windows))]
fn main() {}
