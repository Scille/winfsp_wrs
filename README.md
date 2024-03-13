# Winfsp Wrapper Rust

[![actions status](https://img.shields.io/github/actions/workflow/status/Scille/winfsp_wrs/ci.yml?branch=main&logo=github&style=)](https://github.com/Scille/winfsp_wrs/actions)

## Requirements

This project has two dependencies:

- WinFSP obviously ;-p
- Clang, which is needed by [rust-bindgen](https://github.com/rust-lang/rust-bindgen) for parsing WinFPS C++ API headers.

Install WinFPS:
```cmd.exe
```

Install Clang (also [see rust-bindgen doc](https://rust-lang.github.io/rust-bindgen/requirements.html#windows))

```cmd.exe
winget install LLVM.LLVM
set LIBCLANG_PATH="C:\Program Files\LLVM\bin"
```

## Run example

```cmd.exe
cargo run -p memfs my-mountpoint
```

## Testing

Download winfsp-tests: `https://github.com/winfsp/winfsp/releases/`

`winfsp-tests` itself depends on WinFSP's DLL, hence the easiest way to avoid troubles
is to put the `winfsp-tests` executable in the `C:/Program Files (x86)/WinFsp/bin/` install folder
(the alternative being to copy `C:/Program Files (x86)/WinFsp/bin/winfsp-x64.dll` in the directory
where `winfsp-tests` executable resides).
