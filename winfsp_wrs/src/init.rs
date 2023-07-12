use std::path::PathBuf;
use widestring::{U16CStr, U16CString};
use windows_sys::{
    w,
    Win32::Foundation::{ERROR_DELAY_LOAD_FAILED, ERROR_FILE_NOT_FOUND},
    Win32::System::LibraryLoader::LoadLibraryW,
};

fn get_lplibfilename() -> Result<U16CString, u32> {
    #[cfg(not(feature = "vendored"))]
    {
        use windows_sys::Win32::Foundation::MAX_PATH;
        use windows_sys::Win32::System::Registry::{
            RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ,
        };
        let mut path = [0u16; MAX_PATH as usize];
        let mut size = (path.len() * std::mem::size_of::<u16>()) as u32;

        let winfsp_install = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                w!("SOFTWARE\\WOW6432Node\\WinFsp"),
                w!("InstallDir"),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                path.as_mut_ptr().cast(),
                &mut size,
            )
        };

        if winfsp_install != 0 {
            return Err(ERROR_FILE_NOT_FOUND);
        }

        let path = U16CStr::from_slice(&path[0..(size as usize) / std::mem::size_of::<u16>()])
            .expect("Failed to load registry value");
        let mut path = PathBuf::from(path.to_os_string());

        path.push("bin");

        if cfg!(target_arch = "x86_64") {
            path.push("winfsp-x64.dll");
        } else if cfg!(target_arch = "i686") {
            path.push("winfsp-x86.dll");
        } else if cfg!(target_arch = "aarch64") {
            path.push("winfsp-a64.dll")
        } else {
            panic!("unsupported arch")
        }

        let path = U16CString::from_os_str(path.into_os_string()).unwrap();

        Ok(path)
    }
    // TODO: Add vendored feature
}

pub fn init() -> Result<(), u32> {
    unsafe {
        if LoadLibraryW(get_lplibfilename()?.as_ptr().cast_mut()) == 0 {
            Err(ERROR_DELAY_LOAD_FAILED)
        } else {
            Ok(())
        }
    }
}
