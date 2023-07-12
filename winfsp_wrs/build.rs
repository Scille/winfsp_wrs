use std::{fs::File, io::Write, path::PathBuf};

const HEADER: &str = r#"
#include <winfsp/winfsp.h>
#include <winfsp/fsctl.h>
#include <winfsp/launch.h>
"#;

fn include() -> String {
    #[cfg(not(feature = "vendored"))]
    {
        use registry::{Data, Hive, Security};
        let winfsp_install = Hive::LocalMachine
            .open("SOFTWARE\\WOW6432Node\\WinFsp", Security::Read)
            .ok()
            .and_then(|u| u.value("InstallDir").ok())
            .expect("WinFsp installation directory not found.");
        let directory = match winfsp_install {
            Data::String(string) => string.to_string_lossy(),
            _ => panic!("unexpected install directory"),
        };

        println!("cargo:rustc-link-search={}/lib", directory);

        format!("--include-directory={}/inc", directory)
    }
    // TODO: Add vendored feature
}

fn main() {
    if !cfg!(windows) {
        panic!("WinFSP is only supported on Windows.");
    }

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let link_include = include();

    let external_path = out_dir.join("ext.rs");

    if !external_path.exists() {
        let gen_h_path = out_dir.join("gen.h");
        let mut gen_h = File::create(&gen_h_path).unwrap();
        gen_h.write_all(HEADER.as_bytes()).unwrap();

        let bindings = bindgen::Builder::default()
            .header(gen_h_path.to_str().unwrap())
            .derive_default(true)
            .blocklist_type("_?P?IMAGE_TLS_DIRECTORY.*")
            .allowlist_function("Fsp.*")
            .allowlist_type("FSP.*")
            .allowlist_type("Fsp.*")
            .allowlist_var("FSP_.*")
            .allowlist_var("Fsp.*")
            .allowlist_var("CTL_CODE")
            .clang_arg("-DUNICODE")
            .clang_arg(link_include);

        let bindings = if cfg!(all(target_os = "windows", target_env = "msvc")) {
            println!("cargo:rustc-link-lib=dylib=delayimp");

            if cfg!(target_arch = "x86_64") {
                println!("cargo:rustc-link-lib=dylib=winfsp-x64");
                println!("cargo:rustc-link-arg=/DELAYLOAD:winfsp-x64.dll");
                bindings.clang_arg("--target=x86_64-pc-windows-msvc")
            } else if cfg!(target_arch = "i686") {
                println!("cargo:rustc-link-lib=dylib=winfsp-x86");
                println!("cargo:rustc-link-arg=/DELAYLOAD:winfsp-x86.dll");
                bindings.clang_arg("--target=i686-pc-windows-msvc")
            } else if cfg!(target_arch = "aarch64") {
                println!("cargo:rustc-link-lib=dylib=winfsp-a64");
                println!("cargo:rustc-link-arg=/DELAYLOAD:winfsp-a64.dll");
                bindings.clang_arg("--target=aarch64-pc-windows-msvc")
            } else {
                panic!("unsupported architecture")
            }
        } else {
            panic!("unsupported triple {}", std::env::var("TARGET").unwrap())
        };

        bindings
            .parse_callbacks(Box::new(bindgen::CargoCallbacks))
            .generate()
            .unwrap()
            .write_to_file(external_path)
            .unwrap();
    }
}
