/// WinFSP is provided as a DLL that our main binary must loaded.
/// By default Windows look for DLL in 1) the executable directory and 2) the Windows system folders.
/// However this doesn't work for WinFSP given it is distributed as a separate program
/// (and hence end up install in an arbitrary directory we must retrieve at the runtime
/// by querying the Windows Registry) .
/// Long story short, we are here here informing the linker the WinFSP DLL must be lazy
/// loaded ("delayload" option in MSVC) so that we will have time to first configure the
/// lookup directory.
pub fn build() {
    if cfg!(all(target_os = "windows", target_env = "msvc")) {
        if cfg!(target_arch = "x86_64") {
            println!("cargo:rustc-link-lib=dylib=delayimp");
            println!("cargo:rustc-link-arg=/DELAYLOAD:winfsp-x64.dll");
        } else if cfg!(target_arch = "x86") {
            println!("cargo:rustc-link-lib=dylib=delayimp");
            println!("cargo:rustc-link-arg=/DELAYLOAD:winfsp-x86.dll");
        } else if cfg!(target_arch = "aarch64") {
            println!("cargo:rustc-link-lib=dylib=delayimp");
            println!("cargo:rustc-link-arg=/DELAYLOAD:winfsp-a64.dll");
        } else {
            panic!("unsupported architecture")
        }
    }
}
