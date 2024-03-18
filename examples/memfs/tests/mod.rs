use std::{
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

use winfsp_wrs::{u16str, VolumeInfo};

#[test]
fn winfsp_tests() {
    let mut fs = Command::new("cargo")
        .args(["run", "--bin", "memfs", "--", "K:"])
        .stdout(Stdio::null())
        .spawn()
        .unwrap();

    let path = Path::new("K:");

    while !path.exists() {
        std::thread::sleep(Duration::from_millis(100))
    }

    let exe = std::env::var("WINFSP_TEST_EXE")
        .expect("specify the path of winfsp_tests with `WINFSP_TEST_EXE` env var");

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
        .current_dir(path)
        .spawn()
        .unwrap();

    let code = tests.wait().unwrap();
    fs.kill().unwrap();

    assert!(code.success());
}

#[test]
fn init_is_idempotent() {
    winfsp_wrs::init().unwrap();
    winfsp_wrs::init().unwrap();

    let mut fs = Command::new("cargo")
        .args(["run", "--bin", "memfs", "--", "Y:"])
        .stdout(Stdio::null())
        .spawn()
        .unwrap();

    let path = Path::new("Y:");

    while !path.exists() {}

    let dir = path.join("foo");

    std::fs::create_dir(&dir).unwrap();
    assert!(dir.exists());

    fs.kill().unwrap();
}

#[test]
fn too_long_volume_label() {
    let too_long = u16str!("012345678901234567890123456789123");
    assert_eq!(too_long.len(), 33); // Sanity check
    let max_size = u16str!("01234567890123456789012345678912");
    assert_eq!(max_size.len(), 32); // Sanity check

    VolumeInfo::new(0, 0, &too_long).unwrap_err();

    let mut vi = VolumeInfo::new(0, 0, &max_size).unwrap();
    assert_eq!(vi.volume_label(), max_size,);

    vi.set_volume_label(&too_long).unwrap_err();

    vi.set_volume_label(&max_size).unwrap();

    let small = u16str!("abc");
    vi.set_volume_label(&small).unwrap();
    assert_eq!(vi.volume_label(), &small,);
}
