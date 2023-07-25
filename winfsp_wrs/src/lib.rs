mod callback;
pub mod ext;
mod file_system;
mod filetime;
mod flags;
mod info;
mod init;
mod security;

pub(crate) use callback::Interface;

pub use callback::FileSystemContext;
#[cfg(feature = "icon")]
pub use file_system::set_folder_icon;
pub use file_system::{FileContextMode, FileSystem, Params, VolumeParams};
pub use filetime::{filetime_from_utc, filetime_now};
pub use flags::{
    CleanupFlags, CreateOptions, FileAccessRights, FileAttributes, FileCreationDisposition,
    FileShareMode,
};
pub use info::{CreateFileInfo, DirInfo, FileInfo, VolumeInfo};
pub use init::init;
pub use security::{PSecurityDescriptor, SecurityDescriptor};

// Reexport
pub use widestring::*;
pub use windows_sys::Win32::Foundation::*;
