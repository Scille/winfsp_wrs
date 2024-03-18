#! /usr/bin/env python

import os
import subprocess
import pathlib
import tempfile
import argparse
import winreg


BASEDIR = pathlib.Path(__file__).parent.resolve()
FSP_HEADER = """
#include <assert.h>
#include <winfsp/winfsp.h>
#include <winfsp/fsctl.h>
#include <winfsp/launch.h>
"""

def winreg_get_value(rootkey, keyname, valname):
    try:
        with winreg.OpenKey(rootkey, keyname, 0, winreg.KEY_READ | winreg.KEY_WOW64_32KEY) as key:
            return str(winreg.QueryValueEx(key, valname)[0])
    except WindowsError:
        return None


def get_winfsp_dir() -> pathlib.Path:
    """Return base winfsp directory.

    It's used in three places:
    - {winfsp_dir}\\inc: include directory for building the _bindings module
    - {winfsp_dir}\\lib: library directory for building the _bindings module
    - {winfsp_dir}\\bin: used to load the winfsp DLL at runtime

    This path is found using either:
    - the user-provided environ variable %WINFSP_LIBRARY_PATH%
    - the windows registry: `HKEY_LOCAL_MACHINE\\SOFTWARE\\WinFsp\\InstallDir`
    """
    path = os.environ.get("WINFSP_LIBRARY_PATH")

    if not path:
        path = winreg_get_value(winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\WinFsp", r"InstallDir")

    if not path:
        raise RuntimeError("The WinFsp library path is not provided")

    path = pathlib.Path(path)
    if not path.exists():
        raise RuntimeError(f"The provided WinFsp library path does not exist: {path}")

    return path


def generate(output: pathlib.Path, target: str):
    (fsp_header_fd, fsp_header_path) = tempfile.mkstemp(suffix=".h", prefix="winfsp_wrs_bindgen_")
    fsp_header_path = pathlib.Path(fsp_header_path)
    try:
        os.write(fsp_header_fd, FSP_HEADER.encode("utf-8"))
        os.close(fsp_header_fd)

        winfsp_dir = get_winfsp_dir()
        winfsp_dir_inc = winfsp_dir / "inc"

        args = [
            "bindgen",
            str(fsp_header_path),
            "--output",
            str(output),
            "--with-derive-default",
            "--blocklist-type=_?P?IMAGE_TLS_DIRECTORY.*",
            "--allowlist-function=FSP.*",
            "--allowlist-function=Fsp.*",
            "--allowlist-type=FSP.*",
            "--allowlist-type=Fsp.*",
            "--allowlist-var=FSP.*",
            "--allowlist-var=Fsp.*",
            "--allowlist-var=CTL_CODE",
            "--",
            "-DUNICODE",
            f"--include-directory={winfsp_dir_inc}",
            f"--target={target}",
        ]

        print(">>> " + " ".join(args))
        subprocess.check_call(args)

    finally:
        fsp_header_path.unlink()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--target", default="x86_64-pc-windows-msvc")
    args = parser.parse_args()

    generate(args.output, args.target)
