use std::{
    marker::PhantomData,
    path::Path,
    process::{Command, ExitStatus},
};
use widestring::{u16cstr, U16CStr, U16CString};
use windows_sys::Win32::Foundation::STATUS_SUCCESS;
#[cfg(feature = "icon")]
use windows_sys::Win32::{
    Foundation::CloseHandle,
    Storage::FileSystem::{CreateFileW, WriteFile},
    UI::Shell::PathMakeSystemFolderW,
};
use winfsp_wrs_sys::{
    FspFileSystemCreate, FspFileSystemRemoveMountPoint, FspFileSystemSetMountPoint,
    FspFileSystemSetOperationGuardStrategyF, FspFileSystemStartDispatcher,
    FspFileSystemStopDispatcher, FSP_FILE_SYSTEM, FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY,
    FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_COARSE,
    FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FINE,
    FSP_FSCTL_VOLUME_PARAMS, NTSTATUS,
};

use crate::{FileContextKind, FileSystemInterface, TrampolineInterface};

#[cfg(feature = "icon")]
use crate::{FileAccessRights, FileAttributes, FileCreationDisposition, FileShareMode};

#[repr(i32)]
#[derive(Debug, Default, Clone, Copy)]
/// User mode file system locking strategy.
pub enum OperationGuardStrategy {
    #[default]
    /// A fine-grained concurrency model where file system NAMESPACE accesses are
    /// guarded using an exclusive-shared (read-write) lock.
    ///
    /// File I/O is not guarded and concurrent reads/writes/etc. are possible. (Note
    /// that the FSD will still apply an exclusive-shared lock PER INDIVIDUAL FILE,
    /// but it will not limit I/O operations for different files.)
    ///
    /// The fine-grained concurrency model applies the exclusive-shared lock as follows:
    /// - EXCL: SetVolumeLabel, Flush(Volume), Create, Cleanup(Delete),
    ///   SetInformation(Rename)
    /// - SHRD: GetVolumeInfo, Open, SetInformation(Disposition), ReadDirectory
    /// - NONE: all other operations
    Fine = FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FINE,
    /// A coarse-grained concurrency model where all file system accesses are
    /// guarded by a mutually exclusive lock.
    Coarse =
        FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_COARSE,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct VolumeParams(FSP_FSCTL_VOLUME_PARAMS);

#[derive(Debug, Default, Clone, Copy)]
pub enum FileContextMode {
    #[default]
    /// - UmFileContextIsFullContext: 0
    /// - UmFileContextIsUserContext2: 0
    Node,
    /// - UmFileContextIsFullContext: 0
    /// - UmFileContextIsUserContext2: 1
    Descriptor,
    /// - UmFileContextIsFullContext: 1
    /// - UmFileContextIsUserContext2: 0
    Full,
}

impl VolumeParams {
    pub(crate) fn device_path(&self) -> &U16CStr {
        match self.0.Prefix[0] {
            0 => u16cstr!("WinFsp.Disk"),
            _ => u16cstr!("WinFsp.Net"),
        }
    }

    fn set_file_context_mode(&mut self, mode: FileContextMode) -> &mut Self {
        match mode {
            FileContextMode::Node => {
                self.0.set_UmFileContextIsFullContext(0);
                self.0.set_UmFileContextIsUserContext2(0);
            }
            FileContextMode::Descriptor => {
                self.0.set_UmFileContextIsFullContext(0);
                self.0.set_UmFileContextIsUserContext2(1);
            }
            FileContextMode::Full => {
                self.0.set_UmFileContextIsFullContext(1);
                self.0.set_UmFileContextIsUserContext2(0);
            }
        }
        self
    }

    pub fn set_case_sensitive_search(&mut self, val: bool) -> &mut Self {
        self.0.set_CaseSensitiveSearch(val as _);
        self
    }

    pub fn set_case_preserved_names(&mut self, val: bool) -> &mut Self {
        self.0.set_CasePreservedNames(val as _);
        self
    }

    pub fn set_unicode_on_disk(&mut self, val: bool) -> &mut Self {
        self.0.set_UnicodeOnDisk(val as _);
        self
    }

    pub fn set_persistent_acls(&mut self, val: bool) -> &mut Self {
        self.0.set_PersistentAcls(val as _);
        self
    }

    pub fn set_post_cleanup_when_modified_only(&mut self, val: bool) -> &mut Self {
        self.0.set_PostCleanupWhenModifiedOnly(val as _);
        self
    }

    pub fn set_read_only_volume(&mut self, val: bool) -> &mut Self {
        self.0.set_ReadOnlyVolume(val as _);
        self
    }

    pub fn set_reparse_point(&mut self, val: bool) -> &mut Self {
        self.0.set_ReparsePoints(val as _);
        self
    }

    pub fn set_reparse_point_access_check(&mut self, val: bool) -> &mut Self {
        self.0.set_ReparsePointsAccessCheck(val as _);
        self
    }

    pub fn set_named_streams(&mut self, val: bool) -> &mut Self {
        self.0.set_NamedStreams(val as _);
        self
    }

    pub fn set_hard_links(&mut self, val: bool) -> &mut Self {
        self.0.set_HardLinks(val as _);
        self
    }

    pub fn set_extended_attributes(&mut self, val: bool) -> &mut Self {
        self.0.set_ExtendedAttributes(val as _);
        self
    }

    pub fn set_flush_and_purge_on_cleanup(&mut self, val: bool) -> &mut Self {
        self.0.set_FlushAndPurgeOnCleanup(val as _);
        self
    }

    pub fn set_pass_query_directory_pattern(&mut self, val: bool) -> &mut Self {
        self.0.set_PassQueryDirectoryPattern(val as _);
        self
    }
    pub fn set_pass_query_directory_filename(&mut self, val: bool) -> &mut Self {
        self.0.set_PassQueryDirectoryFileName(val as _);
        self
    }
    pub fn set_always_use_double_buffering(&mut self, val: bool) -> &mut Self {
        self.0.set_AlwaysUseDoubleBuffering(val as _);
        self
    }
    pub fn set_device_control(&mut self, val: bool) -> &mut Self {
        self.0.set_DeviceControl(val as _);
        self
    }
    pub fn set_no_reparse_points_dir_check(&mut self, val: bool) -> &mut Self {
        self.0.set_UmNoReparsePointsDirCheck(val as _);
        self
    }
    pub fn set_allow_open_in_kernel_mode(&mut self, val: bool) -> &mut Self {
        self.0.set_AllowOpenInKernelMode(val as _);
        self
    }

    pub fn set_case_preseve_extended_attributes(&mut self, val: bool) -> &mut Self {
        self.0.set_CasePreservedExtendedAttributes(val as _);
        self
    }
    pub fn set_wsl_features(&mut self, val: bool) -> &mut Self {
        self.0.set_WslFeatures(val as _);
        self
    }
    pub fn set_directory_marker_as_next_offset(&mut self, val: bool) -> &mut Self {
        self.0.set_DirectoryMarkerAsNextOffset(val as _);
        self
    }
    pub fn set_supports_posix_unlink_rename(&mut self, val: bool) -> &mut Self {
        self.0.set_SupportsPosixUnlinkRename(val as _);
        self
    }

    pub fn set_post_disposition_only_when_necessary(&mut self, val: bool) -> &mut Self {
        self.0.set_PostDispositionWhenNecessaryOnly(val as _);
        self
    }

    pub fn set_version(&mut self, val: u16) -> &mut Self {
        self.0.Version = val;
        self
    }

    pub fn set_sector_size(&mut self, val: u16) -> &mut Self {
        self.0.SectorSize = val;
        self
    }

    pub fn set_max_component_length(&mut self, val: u16) -> &mut Self {
        self.0.MaxComponentLength = val;
        self
    }

    pub fn set_sectors_per_allocation_unit(&mut self, val: u16) -> &mut Self {
        self.0.SectorsPerAllocationUnit = val;
        self
    }

    pub fn set_volume_creation_time(&mut self, val: u64) -> &mut Self {
        self.0.VolumeCreationTime = val;
        self
    }

    pub fn set_volume_serial_number(&mut self, val: u32) -> &mut Self {
        self.0.VolumeSerialNumber = val;
        self
    }

    pub fn set_transact_timeout(&mut self, val: u32) -> &mut Self {
        self.0.TransactTimeout = val;
        self
    }

    pub fn set_irp_timeout(&mut self, val: u32) -> &mut Self {
        self.0.IrpTimeout = val;
        self
    }

    pub fn set_irp_capacity(&mut self, val: u32) -> &mut Self {
        self.0.IrpCapacity = val;
        self
    }

    pub fn set_file_info_timeout(&mut self, val: u32) -> &mut Self {
        self.0.FileInfoTimeout = val;
        self
    }

    /// # Error:
    /// The value is too long (max length: 192), so it has been truncated.
    pub fn set_prefix(&mut self, val: &U16CStr) -> Result<&mut Self, &mut Self> {
        let max_len = self.0.Prefix.len();

        if val.len() > max_len {
            self.0.Prefix.copy_from_slice(&val.as_slice()[..max_len]);
            Err(self)
        } else {
            self.0.Prefix[..val.len()].copy_from_slice(val.as_slice());
            Ok(self)
        }
    }

    /// # Error:
    /// The value is too long (max length: 16), so it has been truncated.
    pub fn set_file_system_name(&mut self, val: &U16CStr) -> Result<&mut Self, &mut Self> {
        let max_len = self.0.FileSystemName.len();

        if val.len() > max_len {
            self.0
                .FileSystemName
                .copy_from_slice(&val.as_slice()[..max_len]);
            Err(self)
        } else {
            self.0.FileSystemName[..val.len()].copy_from_slice(val.as_slice());
            Ok(self)
        }
    }

    pub fn set_volume_info_timeout(&mut self, val: u32) -> &mut Self {
        self.0.VolumeInfoTimeout = val;
        self
    }

    pub fn set_dir_info_timeout(&mut self, val: u32) -> &mut Self {
        self.0.DirInfoTimeout = val;
        self
    }

    pub fn set_security_timeout(&mut self, val: u32) -> &mut Self {
        self.0.SecurityTimeout = val;
        self
    }

    pub fn set_stream_info_timeout(&mut self, val: u32) -> &mut Self {
        self.0.StreamInfoTimeout = val;
        self
    }

    pub fn set_ea_timeout(&mut self, val: u32) -> &mut Self {
        self.0.EaTimeout = val;
        self
    }

    pub fn set_fsext_control_code(&mut self, val: u32) -> &mut Self {
        self.0.FsextControlCode = val;
        self
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Params {
    pub volume_params: VolumeParams,
    pub guard_strategy: OperationGuardStrategy,
}

#[derive(Debug, Clone)]
pub struct FileSystem<Ctx: FileSystemInterface> {
    // FileSystem inner value
    inner: FSP_FILE_SYSTEM,
    pub params: Params,
    phantom: PhantomData<Ctx>,
}

// SAFETY: FSP_FILE_SYSTEM contains `*mut c_void` pointers that cannot be send between threads
// by default. However this structure is only used by WinFSP (and not exposed to the user) which
// is deep in C++ land where Rust safety rules do not apply.
unsafe impl<Ctx: FileSystemInterface> Send for FileSystem<Ctx> {}

impl<Ctx: FileSystemInterface> FileSystem<Ctx> {
    pub fn volume_params(&self) -> &VolumeParams {
        &self.params.volume_params
    }

    pub fn volume_params_mut(&mut self) -> &mut VolumeParams {
        &mut self.params.volume_params
    }

    /// Start the mountpoint, i.e.:
    /// - Create a file system object (`FspFileSystemCreate`).
    /// - Set file system locking strategy (`FspFileSystemSetOperationGuardStrategyF`).
    /// - Set the mount point for a file system (`FspFileSystemSetMountPoint`).
    /// - Start the file system dispatcher (`FspFileSystemStartDispatcher`).
    ///
    /// A value of `None` for `mountpoint` means that the file system should use
    /// the next available drive letter counting downwards from `Z:`.
    pub fn start(
        mut params: Params,
        mountpoint: Option<&U16CStr>,
        context: Ctx,
    ) -> Result<Self, NTSTATUS> {
        unsafe {
            let mut p_inner = std::ptr::null_mut();
            let interface = Box::into_raw(Box::new(TrampolineInterface::interface::<Ctx>()));

            params
                .volume_params
                .set_file_context_mode(Ctx::FileContext::MODE);

            let device_name = params.volume_params.device_path();
            let res = FspFileSystemCreate(
                // `device_name` contains const data, so this `cast_mut` is a bit scary !
                // However, it is only a limitation in the type system (we need to cast
                // to `PWSTR`): in practice this parameter is never modified.
                device_name.as_ptr().cast_mut(),
                &params.volume_params.0,
                interface,
                &mut p_inner,
            );

            if res != STATUS_SUCCESS {
                return Err(res);
            }

            (*p_inner).UserContext = Box::into_raw(Box::new(context)).cast();

            #[cfg(feature = "debug")]
            {
                use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE};
                winfsp_wrs_sys::FspDebugLogSetHandle(
                    GetStdHandle(STD_ERROR_HANDLE) as *mut std::ffi::c_void
                );
                winfsp_wrs_sys::FspFileSystemSetDebugLogF(p_inner, u32::MAX);
            }

            FspFileSystemSetOperationGuardStrategyF(
                p_inner,
                params.guard_strategy as FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY,
            );

            let res = FspFileSystemSetMountPoint(
                p_inner,
                mountpoint
                    .map(|x| x.as_ptr().cast_mut())
                    .unwrap_or(std::ptr::null_mut()),
            );

            if res != STATUS_SUCCESS {
                return Err(res);
            }

            let res = FspFileSystemStartDispatcher(p_inner, 0);

            if res != STATUS_SUCCESS {
                return Err(res);
            }

            Ok(Self {
                inner: *p_inner,
                params,
                phantom: Default::default(),
            })
        }
    }

    #[cfg(feature = "icon")]
    /// Set an icon for the mountpoint folder
    pub fn set_icon(&self, icon: &Path, index: i32) {
        let mountpoint = unsafe { U16CStr::from_ptr_str(self.inner.MountPoint) };
        set_icon(mountpoint, icon, index);
    }

    pub fn restart(mut self) -> Result<Self, NTSTATUS> {
        unsafe {
            // Need to allocate, because it will be freed
            let mut mountpoint = U16CString::from_ptr_str(self.inner.MountPoint);

            FspFileSystemStopDispatcher(&mut self.inner);
            FspFileSystemRemoveMountPoint(&mut self.inner);

            let mut p_inner = std::ptr::null_mut();

            let device_name = self.params.volume_params.device_path();
            let res = FspFileSystemCreate(
                device_name.as_ptr().cast_mut(),
                &self.params.volume_params.0,
                self.inner.Interface,
                &mut p_inner,
            );

            if res != STATUS_SUCCESS {
                return Err(res);
            }

            (*p_inner).UserContext = self.inner.UserContext;

            #[cfg(feature = "debug")]
            {
                use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE};
                winfsp_wrs_sys::FspDebugLogSetHandle(
                    GetStdHandle(STD_ERROR_HANDLE) as *mut std::ffi::c_void
                );
                winfsp_wrs_sys::FspFileSystemSetDebugLogF(p_inner, u32::MAX);
            }

            FspFileSystemSetOperationGuardStrategyF(
                p_inner,
                self.params.guard_strategy as FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY,
            );

            let res = FspFileSystemSetMountPoint(p_inner, mountpoint.as_mut_ptr());

            if res != STATUS_SUCCESS {
                return Err(res);
            }

            let res = FspFileSystemStartDispatcher(p_inner, 0);

            if res != STATUS_SUCCESS {
                return Err(res);
            }

            Ok(Self {
                inner: *p_inner,
                params: self.params,
                phantom: PhantomData,
            })
        }
    }

    /// Stop the mountpoint, i.e.:
    /// - Stop the file system dispatcher (`FspFileSystemStopDispatcher`).
    /// - Remove the mount point for the file system (`FspFileSystemRemoveMountPoint`).
    pub fn stop(mut self) {
        unsafe {
            FspFileSystemStopDispatcher(&mut self.inner);
            FspFileSystemRemoveMountPoint(&mut self.inner);
            std::mem::drop(Box::from_raw(self.inner.UserContext.cast::<Ctx>()));
            std::mem::drop(Box::from_raw(self.inner.Interface.cast_mut()));
        }
    }
}

#[cfg(feature = "icon")]
fn set_icon(folder_path: &U16CStr, icon_path: &Path, index: i32) {
    unsafe {
        let mut path = [
            folder_path.as_slice(),
            u16cstr!("\\desktop.ini").as_slice_with_nul(),
        ]
        .concat();

        PathMakeSystemFolderW(folder_path.as_ptr());

        let handle = CreateFileW(
            path.as_mut_ptr(),
            (FileAccessRights::file_generic_read() | FileAccessRights::file_generic_write()).0,
            (FileShareMode::read() | FileShareMode::write()).0,
            std::ptr::null(),
            FileCreationDisposition::OpenAlways as _,
            (FileAttributes::hidden() | FileAttributes::system()).0,
            0,
        );

        let icon = icon_path.to_str().unwrap();

        let content = format!("[.ShellClassInfo]\nIconResource={icon},{index}\n");

        WriteFile(
            handle,
            content.as_ptr(),
            content.len() as u32,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        CloseHandle(handle);
    }
}

#[cfg(feature = "icon")]
/// Set an icon for the folder
pub fn set_folder_icon(folder_path: &Path, icon_path: &Path, index: i32) {
    let folder_path = U16CString::from_os_str(folder_path.as_os_str()).unwrap();
    set_icon(&folder_path, icon_path, index);
}

pub fn pin_to_quick_access(folder_path: &Path) -> std::io::Result<ExitStatus> {
    let folder_path = folder_path.to_str().unwrap();
    let cmd = format!("(new-object -com shell.application).Namespace('{folder_path}').Self.InvokeVerb('pintohome')");

    Command::new("powershell").arg("-c").arg(cmd).status()
}

pub fn unpin_to_quick_access(folder_path: &Path) -> std::io::Result<ExitStatus> {
    let folder_path = folder_path.to_str().unwrap();
    let quick_access = "shell:::{679f85cb-0220-4080-b29b-5540cc05aab6}";
    let cmd = format!(
        "((new-object -com shell.application).Namespace('{quick_access}').Items() | where {{$_.Path -eq '{folder_path}'}}).InvokeVerb('unpinfromhome')"
    );

    Command::new("powershell").arg("-c").arg(cmd).status()
}
