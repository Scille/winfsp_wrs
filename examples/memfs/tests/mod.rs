use std::{
    path::Path,
    process::{Command, Stdio},
};

#[test]
fn winfsp_tests() {
    let mut fs = Command::new("cargo")
        .args(["run", "--bin", "memfs"])
        .stdout(Stdio::null())
        .spawn()
        .unwrap();

    while !Path::new("Z:").exists() {}

    let exe =
        std::env::var("WINFSP_TEST_EXE").expect("specify the path of winfsp_tests in TEST_EXE");

    let mut tests = Command::new(exe)
        .args([
            "--external",
            "--resilient",
            // GetFinalPathNameByHandle is not supported at the moment
            "-getfileinfo_name_test",
            // Reparse point are not supported at the moment
            "-reparse_guid_test",
            "-reparse_nfs_test",
            // Require administrator priviledge
            "-reparse_symlink_test",
            "-reparse_symlink_relative_test",
            "-stream_*",
        ])
        .current_dir("Z:")
        .spawn()
        .unwrap();

    let code = tests.wait().unwrap();
    fs.kill().unwrap();

    assert!(code.success());
}
