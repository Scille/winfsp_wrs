pub fn build() {
    if cfg!(all(target_os = "windows", target_env = "msvc")) {
        if cfg!(target_arch = "x86_64") {
            println!("cargo:rustc-link-lib=dylib=delayimp");
            println!("cargo:rustc-link-arg=/DELAYLOAD:winfsp-x64.dll");
        } else if cfg!(target_arch = "i686") {
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
