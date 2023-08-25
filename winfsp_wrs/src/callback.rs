use std::sync::Arc;

use widestring::{U16CStr, U16CString};
use windows_sys::Win32::Foundation::{
    STATUS_BUFFER_OVERFLOW, STATUS_NOT_IMPLEMENTED, STATUS_REPARSE, STATUS_SUCCESS,
};

use crate::{
    ext::{
        FspFileSystemAddDirInfo, FspFileSystemFindReparsePoint, FspFileSystemResolveReparsePoints,
        BOOLEAN, FSP_FILE_SYSTEM, FSP_FILE_SYSTEM_INTERFACE, FSP_FSCTL_DIR_INFO,
        FSP_FSCTL_FILE_INFO, FSP_FSCTL_VOLUME_INFO, NTSTATUS, PFILE_FULL_EA_INFORMATION,
        PIO_STATUS_BLOCK, PSECURITY_DESCRIPTOR, PSIZE_T, PUINT32, PULONG, PVOID, PWSTR,
        SECURITY_INFORMATION, SIZE_T, UINT32, UINT64, ULONG,
    },
    CleanupFlags, CreateFileInfo, CreateOptions, DirInfo, FileAccessRights, FileAttributes,
    FileContextMode, FileInfo, PSecurityDescriptor, SecurityDescriptor, VolumeInfo,
};

/// Implement only if necessary at your own risk
pub trait FileContextKind {
    const MODE: FileContextMode;
    /// # Safety
    ///
    /// Write the data into winfsp's `PVOID *PFileContext`
    /// This is called in winfsp-wrs after calling FileSystemContext::open
    unsafe fn write(self, out: *mut PVOID);
    /// # Safety
    ///
    /// Retrieve the data from winfsp's `FileContext`
    /// This is called in winfsp-wrs before calling FileSystemContext::read/write etc.
    unsafe fn access(raw: PVOID) -> Self;
    /// # Safety
    ///
    /// Retrieve the data from winfsp's `FileContext`
    /// This is called in winfsp-wrs before calling FileSystemContext::close
    unsafe fn access_for_close(raw: PVOID) -> Self;
}

impl<T> FileContextKind for Arc<T> {
    const MODE: FileContextMode = FileContextMode::Descriptor;

    unsafe fn write(self, out: *mut PVOID) {
        out.write(Arc::into_raw(self).cast_mut().cast())
    }

    // the refcount must be incremented to keep the arc alive after being consumed
    // by drop
    unsafe fn access(raw: PVOID) -> Self {
        Arc::increment_strong_count(raw as *const T);
        Self::access_for_close(raw)
    }

    // the refcount should not be incremented so that when all operations are
    // complete the arc can be freed
    unsafe fn access_for_close(raw: PVOID) -> Self {
        Arc::from_raw(raw as *const T)
    }
}

impl FileContextKind for usize {
    const MODE: FileContextMode = FileContextMode::Node;

    // basic write
    unsafe fn write(self, out: *mut PVOID) {
        out.write(self as *mut _)
    }

    // basic access
    unsafe fn access(raw: PVOID) -> Self {
        raw as usize
    }

    // basic access
    unsafe fn access_for_close(raw: PVOID) -> Self {
        raw as usize
    }
}

pub trait FileSystemContext {
    type FileContext: FileContextKind;

    /// Get volume information.
    fn get_volume_info(&self) -> Result<VolumeInfo, NTSTATUS>;

    /// Set volume label.
    fn set_volume_label(&self, _volume_label: &U16CStr) -> Result<(), NTSTATUS> {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    /// Get file or directory attributes and security descriptor given a file name.
    ///
    /// [out]:
    /// - file_attributes
    /// - security descriptor
    /// - reparse (false if `reparse_point` is not supported)
    ///
    /// [help]:
    /// - find_reparse_point (optional, can be ignored): helper to find reparse
    /// points (`get_reparse_point_by_name` should be implemented)
    /// if reparse point is found, return the `FileAttributes` and `reparse` should be
    /// set to `true`.
    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        find_reparse_point: impl Fn() -> Option<FileAttributes>,
    ) -> Result<(FileAttributes, PSecurityDescriptor, bool), NTSTATUS>;

    /// Create new file or directory.
    fn create(
        &self,
        _file_name: &U16CStr,
        _create_file_info: CreateFileInfo,
        _security_descriptor: SecurityDescriptor,
        _buffer: &[u8],
        _extra_buffer_is_reparse_point: bool,
    ) -> Result<Self::FileContext, NTSTATUS> {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    /// Open a file or directory.
    fn open(
        &self,
        file_name: &U16CStr,
        create_options: CreateOptions,
        granted_access: FileAccessRights,
    ) -> Result<Self::FileContext, NTSTATUS>;

    /// Overwrite a file.
    fn overwrite(
        &self,
        _file_context: Self::FileContext,
        _file_attributes: FileAttributes,
        _replace_file_attributes: bool,
        _allocation_size: u64,
        _buffer: &[u8],
    ) -> Result<(), NTSTATUS> {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    /// Cleanup a file.
    fn cleanup(
        &self,
        _file_context: Self::FileContext,
        _file_name: Option<&U16CStr>,
        _flags: CleanupFlags,
    ) {
    }

    /// Close a file.
    fn close(&self, _file_context: Self::FileContext) {}

    /// Read a file.
    fn read(
        &self,
        _file_context: Self::FileContext,
        _buffer: &mut [u8],
        _offset: u64,
    ) -> Result<usize, NTSTATUS> {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    /// Write a file.
    fn write(
        &self,
        _file_context: Self::FileContext,
        _buffer: &[u8],
        _offset: u64,
        _write_to_end_of_file: bool,
        _constrained_io: bool,
    ) -> Result<usize, NTSTATUS> {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    /// Flush a file or volume.
    fn flush(&self, _file_context: Self::FileContext) -> Result<(), NTSTATUS> {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    /// Get file or directory information.
    fn get_file_info(&self, file_context: Self::FileContext) -> Result<FileInfo, NTSTATUS>;

    /// Set file or directory basic information.
    fn set_basic_info(
        &self,
        _file_context: Self::FileContext,
        _file_attributes: FileAttributes,
        _creation_time: u64,
        _last_access_time: u64,
        _last_write_time: u64,
        _change_time: u64,
    ) -> Result<(), NTSTATUS> {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    /// Set file/allocation size.
    fn set_file_size(
        &self,
        _file_context: Self::FileContext,
        _new_size: u64,
        _set_allocation_size: bool,
    ) -> Result<(), NTSTATUS> {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    /// Determine whether a file or directory can be deleted.
    fn can_delete(
        &self,
        _file_context: Self::FileContext,
        _file_name: &U16CStr,
    ) -> Result<(), NTSTATUS> {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    /// Renames a file or directory.
    fn rename(
        &self,
        _file_context: Self::FileContext,
        _file_name: &U16CStr,
        _new_file_name: &U16CStr,
        _replace_if_exists: bool,
    ) -> Result<(), NTSTATUS> {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    /// Get file or directory security descriptor.
    fn get_security(
        &self,
        _file_context: Self::FileContext,
    ) -> Result<PSecurityDescriptor, NTSTATUS> {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    /// Set file or directory security descriptor.
    fn set_security(
        &self,
        _file_context: Self::FileContext,
        _security_information: u32,
        _modification_descriptor: PSecurityDescriptor,
    ) -> Result<(), NTSTATUS> {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    /// Read a directory.
    fn read_directory(
        &self,
        file_context: Self::FileContext,
        marker: Option<&U16CStr>,
    ) -> Result<Vec<(U16CString, FileInfo)>, NTSTATUS>;

    /// Get reparse point.
    fn get_reparse_point(
        &self,
        _file_context: Self::FileContext,
        _file_name: &U16CStr,
        _buffer: &mut [u8],
    ) -> Result<usize, NTSTATUS> {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    /// Set reparse point.
    fn set_reparse_point(
        &self,
        _file_context: Self::FileContext,
        _file_name: &U16CStr,
        _buffer: &mut [u8],
    ) -> Result<(), NTSTATUS> {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    /// Delete reparse point.
    fn delete_reparse_point(
        &self,
        _file_context: Self::FileContext,
        _file_name: &U16CStr,
        _buffer: &mut [u8],
    ) -> Result<(), NTSTATUS> {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    /// Get named streams information.
    fn get_stream_info(
        &self,
        _file_context: Self::FileContext,
        _buffer: &mut [u8],
    ) -> Result<usize, NTSTATUS> {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    /// Get directory information for a single file or directory within a parent
    /// directory.
    fn get_dir_info_by_name(
        &self,
        _file_context: Self::FileContext,
        _file_name: &U16CStr,
    ) -> Result<FileInfo, NTSTATUS> {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    /// Process control code.
    fn control(
        &self,
        _file_context: Self::FileContext,
        _control_code: u32,
        _input_buffer: &[u8],
        _output_buffer: &mut [u8],
    ) -> Result<usize, NTSTATUS> {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    /// Set the file delete flag.
    fn set_delete(
        &self,
        _file_context: Self::FileContext,
        _file_name: &U16CStr,
        _delete_file: bool,
    ) -> Result<(), NTSTATUS> {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    /// Get extended attributes.
    fn get_ea(&self, _file_context: Self::FileContext, _buffer: &[u8]) -> Result<usize, NTSTATUS> {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    /// Set extended attributes.
    fn set_ea(
        &self,
        _file_context: Self::FileContext,
        _buffer: &[u8],
    ) -> Result<FileInfo, NTSTATUS> {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    /// Get reparse point given a file name.
    fn get_reparse_point_by_name(
        &self,
        _file_name: &U16CStr,
        _is_directory: bool,
        _buffer: Option<&mut [u8]>,
    ) -> Result<usize, NTSTATUS> {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    fn dispatcher_stopped(&self, _normally: bool) {}
}

pub(crate) struct Interface;

impl Interface {
    /// Get volume information.
    /// - FileSystem - The file system on which this request is posted.
    /// - VolumeInfo - [out] Pointer to a structure that will receive the volume
    ///   information on successful return from this call.
    unsafe extern "C" fn get_volume_info_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        volume_info: *mut FSP_FSCTL_VOLUME_INFO,
    ) -> NTSTATUS {
        let fs = &*(*file_system).UserContext.cast::<C>();

        match C::get_volume_info(fs) {
            Err(e) => e,
            Ok(vi) => {
                *volume_info = vi.0;
                STATUS_SUCCESS
            }
        }
    }

    /// Set volume label.
    /// - FileSystem - The file system on which this request is posted.
    /// - VolumeLabel - The new label for the volume.
    /// - VolumeInfo - [out] Pointer to a structure that will receive the volume
    ///   information on successful return from this call.
    unsafe extern "C" fn set_volume_label_w_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        volume_label: PWSTR,
        volume_info: *mut FSP_FSCTL_VOLUME_INFO,
    ) -> NTSTATUS {
        let fs = &*(*file_system).UserContext.cast::<C>();

        match C::set_volume_label(fs, U16CStr::from_ptr_str(volume_label)) {
            Err(e) => e,
            Ok(()) => Self::get_volume_info_ext::<C>(file_system, volume_info),
        }
    }

    /// Get file or directory attributes and security descriptor given a file name.
    /// - FileSystem - The file system on which this request is posted.
    /// - FileName - The name of the file or directory to get the attributes and
    ///   security descriptor for.
    /// - PFileAttributes - Pointer to a memory location that will receive the file
    ///   attributes on successful return from this call. May be NULL.
    ///
    /// If this call returns STATUS_REPARSE, the file system MAY place here the
    /// index of the first reparse point within FileName. The file system MAY also
    /// leave this at its default value of 0.
    ///
    /// - SecurityDescriptor - Pointer to a buffer that will receive the file
    ///   security descriptor on successful return from this call. May be NULL.
    /// - PSecurityDescriptorSize - [in,out] Pointer to the security descriptor
    ///   buffer size. On input it contains the size of the security descriptor
    ///   buffer. On output it will contain the actual size of the security
    ///   descriptor copied into the security descriptor buffer. May be NULL.
    ///
    /// Remarks: STATUS_REPARSE should be returned by file systems that support
    /// reparse points when they encounter a FileName that contains reparse points
    /// anywhere but the final path component.
    unsafe extern "C" fn get_security_by_name_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        file_name: PWSTR,
        p_file_attributes: PUINT32,
        security_descriptor: PSECURITY_DESCRIPTOR,
        p_security_descriptor_size: *mut SIZE_T,
    ) -> NTSTATUS {
        let fs = &*(*file_system).UserContext.cast::<C>();

        let find_reparse_point = || -> Option<FileAttributes> {
            let mut reparse_index = 0;
            unsafe {
                if FspFileSystemFindReparsePoint(
                    file_system,
                    Some(Self::get_reparse_point_by_name_ext::<C>),
                    std::ptr::null_mut(),
                    file_name,
                    &mut reparse_index,
                ) != 0
                {
                    Some(FileAttributes(reparse_index))
                } else {
                    None
                }
            }
        };

        let file_name = U16CStr::from_ptr_str(file_name);

        match C::get_security_by_name(fs, file_name, find_reparse_point) {
            Err(e) => e,
            Ok((fa, sd, reparse)) => {
                if !p_file_attributes.is_null() {
                    p_file_attributes.write(fa.0)
                }

                if !p_security_descriptor_size.is_null() {
                    if sd.len() as SIZE_T > p_security_descriptor_size.read() {
                        // In case of overflow error, winfsp will retry with a new
                        // allocation based on `p_security_descriptor_size`. Hence we
                        // must update this value to the required size.
                        p_security_descriptor_size.write(sd.len() as SIZE_T);
                        return STATUS_BUFFER_OVERFLOW;
                    }

                    p_security_descriptor_size.write(sd.len() as SIZE_T);

                    if !security_descriptor.is_null() {
                        std::ptr::copy(sd.inner(), security_descriptor, sd.len());
                    }
                }

                if reparse {
                    STATUS_REPARSE
                } else {
                    STATUS_SUCCESS
                }
            }
        }
    }

    /// Open a file or directory.
    /// - FileSystem - The file system on which this request is posted.
    /// - FileName - The name of the file or directory to be opened.
    /// - CreateOptions - Create options for this request. This parameter has the
    ///   same meaning as the CreateOptions parameter of the NtCreateFile API. User
    ///   mode file systems typically do not need to do anything special with
    ///   respect to this parameter. Some file systems may also want to pay
    ///   attention to the FILE_NO_INTERMEDIATE_BUFFERING and FILE_WRITE_THROUGH
    ///   flags, although these are typically handled by the FSD component.
    /// - GrantedAccess - Determines the specific access rights that have been
    ///   granted for this request. Upon receiving this call all access checks have
    ///   been performed and the user mode file system need not perform any
    ///   additional checks. However this parameter may be useful to a user mode
    ///   file system; for example the WinFsp-FUSE layer uses this parameter to
    ///   determine which flags to use in its POSIX open() call.
    /// - PFileContext - [out] Pointer that will receive the file context on
    ///   successful return from this call.
    /// - FileInfo - [out] Pointer to a structure that will receive the file
    ///   information on successful return from this call. This information
    ///   includes file attributes, file times, etc.
    unsafe extern "C" fn open_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        file_name: PWSTR,
        create_options: UINT32,
        granted_access: UINT32,
        p_file_context: *mut PVOID,
        file_info: *mut FSP_FSCTL_FILE_INFO,
    ) -> NTSTATUS {
        let fs = &*(*file_system).UserContext.cast::<C>();
        let file_name = U16CStr::from_ptr_str(file_name);

        match C::open(
            fs,
            file_name,
            CreateOptions(create_options),
            FileAccessRights(granted_access),
        ) {
            Err(e) => e,
            Ok(fctx) => {
                C::FileContext::write(fctx, p_file_context);
                Self::get_file_info_ext::<C>(file_system, *p_file_context, file_info)
            }
        }
    }

    /// Cleanup a file.
    /// - FileSystem - The file system on which this request is posted.
    /// - FileContext - The file context of the file or directory to cleanup.
    /// - FileName - The name of the file or directory to cleanup. Sent only when a
    ///   Delete is requested.
    /// - Flags - These flags determine whether the file was modified and whether
    ///   to delete the file.
    unsafe extern "C" fn cleanup_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        file_context: PVOID,
        file_name: PWSTR,
        flags: ULONG,
    ) {
        let fs = &*(*file_system).UserContext.cast::<C>();
        let fctx = C::FileContext::access(file_context);

        let file_name = if file_name.is_null() {
            None
        } else {
            Some(U16CStr::from_ptr_str(file_name))
        };

        C::cleanup(fs, fctx, file_name, CleanupFlags(flags as i32))
    }

    /// Close a file.
    /// - FileSystem - The file system on which this request is posted.
    /// - FileContext - The file context of the file or directory to be closed.
    unsafe extern "C" fn close_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        file_context: PVOID,
    ) {
        let fs = &*(*file_system).UserContext.cast::<C>();
        let fctx = C::FileContext::access_for_close(file_context);
        C::close(fs, fctx);
    }

    /// Read a file.
    /// - FileSystem - The file system on which this request is posted.
    /// - FileContext - The file context of the file to be read.
    /// - Buffer - Pointer to a buffer that will receive the results of the read
    ///   operation.
    /// - Offset - Offset within the file to read from.
    /// - Length - Length of data to read.
    /// - PBytesTransferred - [out] Pointer to a memory location that will receive
    ///   the actual number of bytes read.
    unsafe extern "C" fn read_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        file_context: PVOID,
        buffer: PVOID,
        offset: UINT64,
        length: ULONG,
        p_bytes_transferred: PULONG,
    ) -> NTSTATUS {
        let fs = &*(*file_system).UserContext.cast::<C>();
        let fctx = C::FileContext::access(file_context);
        let buffer = std::slice::from_raw_parts_mut(buffer.cast(), length as usize);

        match C::read(fs, fctx, buffer, offset) {
            Err(e) => e,
            Ok(bytes_transferred) => {
                *p_bytes_transferred = bytes_transferred as ULONG;
                STATUS_SUCCESS
            }
        }
    }

    /// Write a file.
    /// - FileSystem - The file system on which this request is posted.
    /// - FileContext - The file context of the file to be written.
    /// - Buffer - Pointer to a buffer that contains the data to write.
    /// - Offset - Offset within the file to write to.
    /// - Length - Length of data to write.
    /// - WriteToEndOfFile - When TRUE the file system must write to the current
    ///   end of file. In this case the Offset parameter will contain the value -1.
    /// - ConstrainedIo - When TRUE the file system must not extend the file (i.e.
    ///   change the file size).
    /// - PBytesTransferred - [out] Pointer to a memory location that will receive
    ///   the actual number of bytes written.
    /// - FileInfo - [out] Pointer to a structure that will receive the file
    ///   information on successful return from this call. This information
    ///   includes file attributes, file times, etc.
    unsafe extern "C" fn write_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        file_context: PVOID,
        buffer: PVOID,
        offset: UINT64,
        length: ULONG,
        write_to_end_of_file: BOOLEAN,
        constrained_io: BOOLEAN,
        p_bytes_transferred: PULONG,
        file_info: *mut FSP_FSCTL_FILE_INFO,
    ) -> NTSTATUS {
        let fs = &*(*file_system).UserContext.cast::<C>();
        let fctx = C::FileContext::access(file_context);
        let buffer = std::slice::from_raw_parts(buffer.cast(), length as usize);

        match C::write(
            fs,
            fctx,
            buffer,
            offset,
            write_to_end_of_file != 0,
            constrained_io != 0,
        ) {
            Err(e) => e,
            Ok(bytes_transfered) => {
                *p_bytes_transferred = bytes_transfered as ULONG;

                Self::get_file_info_ext::<C>(file_system, file_context, file_info)
            }
        }
    }

    /// Flush a file or volume.
    /// - FileSystem - The file system on which this request is posted.
    /// - FileContext - The file context of the file to be flushed. When NULL the
    ///   whole volume is being flushed.
    /// - FileInfo - [out] Pointer to a structure that will receive the file
    ///   information on successful return from this call. This information
    ///   includes file attributes, file times, etc. Used when flushing file (not
    ///   volume).
    unsafe extern "C" fn flush_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        file_context: PVOID,
        file_info: *mut FSP_FSCTL_FILE_INFO,
    ) -> NTSTATUS {
        let fs = &*(*file_system).UserContext.cast::<C>();
        let fctx = C::FileContext::access(file_context);

        match C::flush(fs, fctx) {
            Err(e) => e,
            Ok(()) => Self::get_file_info_ext::<C>(file_system, file_context, file_info),
        }
    }

    /// Get file or directory information.
    /// - FileSystem - The file system on which this request is posted.
    /// - FileContext - The file context of the file or directory to get
    ///   information for.
    /// - FileInfo - [out] Pointer to a structure that will receive the file
    ///   information on successful return from this call. This information
    ///   includes file attributes, file times, etc.
    unsafe extern "C" fn get_file_info_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        file_context: PVOID,
        file_info: *mut FSP_FSCTL_FILE_INFO,
    ) -> NTSTATUS {
        let fs = &*(*file_system).UserContext.cast::<C>();
        let fctx = C::FileContext::access(file_context);

        match C::get_file_info(fs, fctx) {
            Err(e) => e,
            Ok(ret) => {
                *file_info = ret.0;
                STATUS_SUCCESS
            }
        }
    }

    /// Set file or directory basic information.
    /// - FileSystem - The file system on which this request is posted.
    /// - FileContext - The file context of the file or directory to set
    ///   information for.
    /// - FileAttributes - File attributes to apply to the file or directory. If
    ///   the value INVALID_FILE_ATTRIBUTES is sent, the file attributes should not
    ///   be changed.
    /// - CreationTime - Creation time to apply to the file or directory. If the
    ///   value 0 is sent, the creation time should not be changed.
    /// - LastAccessTime - Last access time to apply to the file or directory. If
    ///   the value 0 is sent, the last access time should not be changed.
    /// - LastWriteTime - Last write time to apply to the file or directory. If the
    ///   value 0 is sent, the last write time should not be changed.
    /// - ChangeTime - Change time to apply to the file or directory. If the value
    ///   0 is sent, the change time should not be changed.
    /// - FileInfo - [out] Pointer to a structure that will receive the file
    ///   information on successful return from this call. This information
    ///   includes file attributes, file times, etc.
    unsafe extern "C" fn set_basic_info_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        file_context: PVOID,
        file_attributes: UINT32,
        creation_time: UINT64,
        last_access_time: UINT64,
        last_write_time: UINT64,
        change_time: UINT64,
        file_info: *mut FSP_FSCTL_FILE_INFO,
    ) -> NTSTATUS {
        let fs = &*(*file_system).UserContext.cast::<C>();
        let fctx = C::FileContext::access(file_context);

        match C::set_basic_info(
            fs,
            fctx,
            FileAttributes(file_attributes),
            creation_time,
            last_access_time,
            last_write_time,
            change_time,
        ) {
            Err(e) => e,
            Ok(()) => Self::get_file_info_ext::<C>(file_system, file_context, file_info),
        }
    }

    /// Set file/allocation size.
    /// - FileSystem - The file system on which this request is posted.
    /// - FileContext - The file context of the file to set the file/allocation
    ///   size for.
    /// - NewSize - New file/allocation size to apply to the file.
    /// - SetAllocationSize - If TRUE, then the allocation size is being set. if
    ///   FALSE, then the file size is being set.
    /// - FileInfo - [out] Pointer to a structure that will receive the file
    ///   information on successful return from this call. This information
    ///   includes file attributes, file times, etc.
    unsafe extern "C" fn set_file_size_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        file_context: PVOID,
        new_size: UINT64,
        set_allocation_size: BOOLEAN,
        file_info: *mut FSP_FSCTL_FILE_INFO,
    ) -> NTSTATUS {
        let fs = &*(*file_system).UserContext.cast::<C>();
        let fctx = C::FileContext::access(file_context);

        match C::set_file_size(fs, fctx, new_size, set_allocation_size != 0) {
            Err(e) => e,
            Ok(()) => Self::get_file_info_ext::<C>(file_system, file_context, file_info),
        }
    }

    /// Determine whether a file or directory can be deleted.
    /// - FileSystem - The file system on which this request is posted.
    /// - FileContext - The file context of the file or directory to cleanup.
    /// - FileName - The name of the file or directory to cleanup. Sent only when a
    ///   Delete is requested.
    /// - Flags - These flags determine whether the file was modified and whether
    ///   to delete the file.
    unsafe extern "C" fn can_delete_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        file_context: PVOID,
        file_name: PWSTR,
    ) -> NTSTATUS {
        let fs = &*(*file_system).UserContext.cast::<C>();
        let fctx = C::FileContext::access(file_context);
        let file_name = U16CStr::from_ptr_str(file_name);

        match C::can_delete(fs, fctx, file_name) {
            Err(e) => e,
            Ok(()) => STATUS_SUCCESS,
        }
    }

    /// Renames a file or directory.
    /// - FileSystem - The file system on which this request is posted.
    /// - FileContext - The file context of the file or directory to be renamed.
    /// - FileName - The current name of the file or directory to rename.
    /// - NewFileName - The new name for the file or directory.
    /// - ReplaceIfExists - Whether to replace a file that already exists at
    ///   NewFileName.
    unsafe extern "C" fn rename_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        file_context: PVOID,
        file_name: PWSTR,
        new_file_name: PWSTR,
        replace_if_exists: BOOLEAN,
    ) -> NTSTATUS {
        let fs = &*(*file_system).UserContext.cast::<C>();
        let fctx = C::FileContext::access(file_context);
        let file_name = U16CStr::from_ptr_str(file_name);
        let new_file_name = U16CStr::from_ptr_str(new_file_name);

        match C::rename(fs, fctx, file_name, new_file_name, replace_if_exists != 0) {
            Err(e) => e,
            Ok(()) => STATUS_SUCCESS,
        }
    }

    /// Get file or directory security descriptor.
    /// - FileSystem - The file system on which this request is posted.
    /// - FileContext - The file context of the file or directory to get the
    ///   security descriptor for.
    /// - SecurityDescriptor - Pointer to a buffer that will receive the file
    ///   security descriptor on successful return from this call. May be NULL.
    /// - PSecurityDescriptorSize - [in,out] Pointer to the security descriptor
    ///   buffer size. On input it contains the size of the security descriptor
    ///   buffer. On output it will contain the actual size of the security
    ///   descriptor copied into the security descriptor buffer. Cannot be NULL.
    unsafe extern "C" fn get_security_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        file_context: PVOID,
        security_descriptor: PSECURITY_DESCRIPTOR,
        p_security_descriptor_size: *mut SIZE_T,
    ) -> NTSTATUS {
        let fs = &*(*file_system).UserContext.cast::<C>();
        let fctx = C::FileContext::access(file_context);

        match C::get_security(fs, fctx) {
            Err(e) => e,
            Ok(sd) => {
                if !p_security_descriptor_size.is_null() {
                    if sd.len() as SIZE_T > p_security_descriptor_size.read() {
                        return STATUS_BUFFER_OVERFLOW;
                    }
                    p_security_descriptor_size.write(sd.len() as SIZE_T);
                    if !security_descriptor.is_null() {
                        std::ptr::copy(sd.inner(), security_descriptor, sd.len())
                    }
                }

                STATUS_SUCCESS
            }
        }
    }

    /// Set file or directory security descriptor.
    /// - FileSystem - The file system on which this request is posted.
    /// - FileContext - The file context of the file or directory to set the
    ///   security descriptor for.
    /// - SecurityInformation - Describes what parts of the file or directory
    ///   security descriptor should be modified.
    /// - ModificationDescriptor - Describes the modifications to apply to the file
    ///   or directory security descriptor.
    unsafe extern "C" fn set_security_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        file_context: PVOID,
        security_information: SECURITY_INFORMATION,
        modification_descriptor: PSECURITY_DESCRIPTOR,
    ) -> NTSTATUS {
        let fs = &*(*file_system).UserContext.cast::<C>();
        let fctx = C::FileContext::access(file_context);

        let modification_descriptor = PSecurityDescriptor::from_ptr(modification_descriptor);

        match C::set_security(fs, fctx, security_information, modification_descriptor) {
            Err(e) => e,
            Ok(()) => STATUS_SUCCESS,
        }
    }

    /// Read a directory.
    /// - FileSystem - The file system on which this request is posted.
    /// - FileContext - The file context of the directory to be read.
    /// - Pattern - The pattern to match against files in this directory. Can be
    ///   NULL. The file system can choose to ignore this parameter as the FSD will
    ///   always perform its own pattern matching on the returned results.
    /// - Marker - A file name that marks where in the directory to start reading.
    ///   Files with names that are greater than (not equal to) this marker (in the
    ///   directory order determined by the file system) should be returned. Can be
    ///   NULL.
    /// - Buffer - Pointer to a buffer that will receive the results of the read
    ///   operation.
    /// - Length - Length of data to read.
    /// - PBytesTransferred - [out] Pointer to a memory location that will receive
    ///   the actual number of bytes read.
    unsafe extern "C" fn read_directory_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        file_context: PVOID,
        _pattern: PWSTR,
        marker: PWSTR,
        buffer: PVOID,
        length: ULONG,
        p_bytes_transferred: PULONG,
    ) -> NTSTATUS {
        let fs = &*(*file_system).UserContext.cast::<C>();
        let fctx = C::FileContext::access(file_context);

        let marker = if marker.is_null() {
            None
        } else {
            Some(U16CStr::from_ptr_str(marker))
        };

        match C::read_directory(fs, fctx, marker) {
            Err(e) => e,
            Ok(entries_info) => {
                for (file_name, file_info) in entries_info {
                    // FSP_FSCTL_DIR_INFO base struct + WCHAR[] string
                    // Note: Windows does not use NULL-terminated string
                    let dir_info = &mut DirInfo::new(file_info, &file_name);

                    if FspFileSystemAddDirInfo(
                        (dir_info as *mut DirInfo).cast(),
                        buffer,
                        length,
                        p_bytes_transferred,
                    ) == 0
                    {
                        return STATUS_SUCCESS;
                    }
                }

                // EOF marker
                FspFileSystemAddDirInfo(std::ptr::null_mut(), buffer, length, p_bytes_transferred);
                STATUS_SUCCESS
            }
        }
    }

    unsafe extern "C" fn get_reparse_point_by_name_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        _context: PVOID,
        file_name: PWSTR,
        is_directory: BOOLEAN,
        buffer: PVOID,
        psize: PSIZE_T,
    ) -> NTSTATUS {
        let fs = &*(*file_system).UserContext.cast::<C>();
        let file_name = U16CStr::from_ptr_str_mut(file_name);
        let buffer = if buffer.is_null() {
            None
        } else {
            Some(std::slice::from_raw_parts_mut(
                buffer.cast(),
                psize.read() as usize,
            ))
        };

        match C::get_reparse_point_by_name(fs, file_name, is_directory != 0, buffer) {
            Err(e) => e,
            Ok(bytes_transferred) => {
                psize.write(bytes_transferred as SIZE_T);
                STATUS_SUCCESS
            }
        }
    }

    /// Resolve reparse points.
    /// - FileSystem - The file system on which this request is posted.
    /// - FileName - The name of the file or directory to have its reparse points
    ///   resolved.
    /// - ReparsePointIndex - The index of the first reparse point within FileName.
    /// - ResolveLastPathComponent - If FALSE, the last path component of FileName
    ///   should not be resolved, even if it is a reparse point that can be
    ///   resolved. If TRUE, all path components should be resolved if possible.
    /// - PIoStatus - Pointer to storage that will receive the status to return to
    ///   the FSD. When this function succeeds it must set PIoStatus->Status to
    ///   STATUS_REPARSE and PIoStatus->Information to either IO_REPARSE or the
    ///   reparse tag.
    /// - Buffer - Pointer to a buffer that will receive the resolved file name
    ///   (IO_REPARSE) or reparse data (reparse tag). If the function returns a
    ///   file name, it should not be NULL terminated.
    /// - PSize - [in,out] Pointer to the buffer size. On input it contains the
    ///   size of the buffer. On output it will contain the actual size of data
    ///   copied.
    unsafe extern "C" fn resolve_reparse_points_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        file_name: PWSTR,
        reparse_point_index: UINT32,
        resolve_last_path_component: BOOLEAN,
        p_io_status: PIO_STATUS_BLOCK,
        buffer: PVOID,
        p_size: PSIZE_T,
    ) -> NTSTATUS {
        FspFileSystemResolveReparsePoints(
            file_system,
            Some(Self::get_reparse_point_by_name_ext::<C>),
            std::ptr::null_mut(),
            file_name,
            reparse_point_index,
            resolve_last_path_component,
            p_io_status,
            buffer,
            p_size,
        )
    }

    /// Get reparse point.
    /// - FileSystem - The file system on which this request is posted.
    /// - FileContext - The file context of the reparse point.
    /// - FileName - The file name of the reparse point.
    /// - Buffer - Pointer to a buffer that will receive the results of this
    ///   operation. If the function returns a symbolic link path, it should not be
    ///   NULL terminated.
    /// - PSize - [in,out] Pointer to the buffer size. On input it contains the
    ///   size of the buffer. On output it will contain the actual size of data
    ///   copied.
    unsafe extern "C" fn get_reparse_point_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        file_context: PVOID,
        file_name: PWSTR,
        buffer: PVOID,
        p_size: PSIZE_T,
    ) -> NTSTATUS {
        let fs = &*(*file_system).UserContext.cast::<C>();
        let fctx = C::FileContext::access(file_context);
        let file_name = U16CStr::from_ptr_str(file_name);
        let buffer = std::slice::from_raw_parts_mut(buffer.cast(), *p_size as usize);

        match C::get_reparse_point(fs, fctx, file_name, buffer) {
            Err(e) => e,
            Ok(byte_transferred) => {
                p_size.write(byte_transferred as SIZE_T);
                STATUS_SUCCESS
            }
        }
    }

    /// Set reparse point.
    /// - FileSystem - The file system on which this request is posted.
    /// - FileContext - The file context of the reparse point.
    /// - FileName - The file name of the reparse point.
    /// - Buffer - Pointer to a buffer that contains the data for this operation.
    ///   If this buffer contains a symbolic link path, it should not be assumed to
    ///   be NULL terminated.
    /// - Size - Size of data to write.
    unsafe extern "C" fn set_reparse_point_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        file_context: PVOID,
        file_name: PWSTR,
        buffer: PVOID,
        size: SIZE_T,
    ) -> NTSTATUS {
        let fs = &*(*file_system).UserContext.cast::<C>();
        let fctx = C::FileContext::access(file_context);
        let file_name = U16CStr::from_ptr_str(file_name);
        let buffer = std::slice::from_raw_parts_mut(buffer.cast(), size as usize);

        match C::set_reparse_point(fs, fctx, file_name, buffer) {
            Err(e) => e,
            Ok(()) => STATUS_SUCCESS,
        }
    }

    /// Delete reparse point.
    /// - FileSystem - The file system on which this request is posted.
    /// - FileContext - The file context of the reparse point.
    /// - FileName - The file name of the reparse point.
    /// - Buffer - Pointer to a buffer that contains the data for this operation.
    /// - Size - Size of data to write.
    unsafe extern "C" fn delete_reparse_point_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        file_context: PVOID,
        file_name: PWSTR,
        buffer: PVOID,
        size: SIZE_T,
    ) -> NTSTATUS {
        let fs = &*(*file_system).UserContext.cast::<C>();
        let fctx = C::FileContext::access(file_context);
        let file_name = U16CStr::from_ptr_str(file_name);
        let buffer = std::slice::from_raw_parts_mut(buffer.cast(), size as usize);

        match C::delete_reparse_point(fs, fctx, file_name, buffer) {
            Err(e) => e,
            Ok(()) => STATUS_SUCCESS,
        }
    }

    /// Get named streams information.
    /// - FileSystem - The file system on which this request is posted.
    /// - FileContext - The file context of the file or directory to get stream
    ///   information for.
    /// - Buffer - Pointer to a buffer that will receive the stream information.
    /// - Length - Length of buffer.
    /// - PBytesTransferred - [out] Pointer to a memory location that will receive
    ///   the actual number of bytes stored.
    unsafe extern "C" fn get_stream_info_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        file_context: PVOID,
        buffer: PVOID,
        length: ULONG,
        p_bytes_transferred: PULONG,
    ) -> NTSTATUS {
        let fs = &*(*file_system).UserContext.cast::<C>();
        let fctx = C::FileContext::access(file_context);
        let buffer = std::slice::from_raw_parts_mut(buffer.cast(), length as usize);

        match C::get_stream_info(fs, fctx, buffer) {
            Err(e) => e,
            Ok(bytes_transferred) => {
                p_bytes_transferred.write(bytes_transferred as ULONG);
                STATUS_SUCCESS
            }
        }
    }

    /// Get directory information for a single file or directory within a parent
    /// directory.
    /// - FileSystem - The file system on which this request is posted.
    /// - FileContext - The file context of the parent directory.
    /// - FileName - The name of the file or directory to get information for. This
    ///   name is relative to the parent directory and is a single path component.
    /// - DirInfo - [out] Pointer to a structure that will receive the directory
    ///   information on successful return from this call. This information
    ///   includes the file name, but also file attributes, file times, etc.
    unsafe extern "C" fn get_dir_info_by_name_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        file_context: PVOID,
        file_name: PWSTR,
        dir_info: *mut FSP_FSCTL_DIR_INFO,
    ) -> NTSTATUS {
        let fs = &*(*file_system).UserContext.cast::<C>();
        let fctx = C::FileContext::access(file_context);
        let file_name = U16CStr::from_ptr_str(file_name);

        match C::get_dir_info_by_name(fs, fctx, file_name) {
            Err(e) => e,
            Ok(file_info) => {
                (*dir_info).Size =
                    (std::mem::size_of::<FSP_FSCTL_DIR_INFO>() + file_name.len() * 2) as u16;
                (*dir_info).FileInfo = file_info.0;
                std::ptr::copy(
                    file_name.as_ptr(),
                    (*dir_info).FileNameBuf.as_mut_ptr(),
                    file_name.len(),
                );
                STATUS_SUCCESS
            }
        }
    }

    /// Process control code.
    /// - FileSystem - The file system on which this request is posted.
    /// - FileContext - The file context of the file or directory to be controled.
    /// - ControlCode - The control code for the operation. This code must have a
    ///   DeviceType with bit 0x8000 set and must have a TransferType of
    ///   METHOD_BUFFERED.
    /// - InputBuffer - Pointer to a buffer that contains the input data.
    /// - InputBufferLength - Input data length.
    /// - OutputBuffer - Pointer to a buffer that will receive the output data.
    /// - OutputBufferLength - Output data length.
    /// - PBytesTransferred - [out] Pointer to a memory location that will receive
    ///   the actual number of bytes transferred.
    unsafe extern "C" fn control_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        file_context: PVOID,
        control_code: UINT32,
        input_buffer: PVOID,
        input_buffer_length: ULONG,
        output_buffer: PVOID,
        output_buffer_length: ULONG,
        p_bytes_transferred: PULONG,
    ) -> NTSTATUS {
        let fs = &*(*file_system).UserContext.cast::<C>();
        let fctx = C::FileContext::access(file_context);
        let input = std::slice::from_raw_parts(input_buffer.cast(), input_buffer_length as usize);
        let output =
            std::slice::from_raw_parts_mut(output_buffer.cast(), output_buffer_length as usize);

        match C::control(fs, fctx, control_code, input, output) {
            Err(e) => e,
            Ok(bytes_transferred) => {
                p_bytes_transferred.write(bytes_transferred as ULONG);
                STATUS_SUCCESS
            }
        }
    }

    /// Set the file delete flag.
    /// - FileSystem - The file system on which this request is posted.
    /// - FileContext - The file context of the file or directory to set the delete
    ///   flag for.
    /// - FileName - The name of the file or directory to set the delete flag for.
    /// - DeleteFile - If set to TRUE the FSD indicates that the file will be
    ///   deleted on Cleanup; otherwise it will not be deleted. It is legal to
    ///   receive multiple SetDelete calls for the same file with different
    ///   DeleteFile parameters.
    unsafe extern "C" fn set_delete_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        file_context: PVOID,
        file_name: PWSTR,
        delete_file_w: BOOLEAN,
    ) -> NTSTATUS {
        let fs = &*(*file_system).UserContext.cast::<C>();
        let fctx = C::FileContext::access(file_context);
        let file_name = U16CStr::from_ptr_str(file_name);

        match C::set_delete(fs, fctx, file_name, delete_file_w != 0) {
            Err(e) => e,
            Ok(()) => STATUS_SUCCESS,
        }
    }

    /// Create new file or directory.
    /// - FileSystem - The file system on which this request is posted.
    /// - FileName - The name of the file or directory to be created.
    /// - CreateOptions - Create options for this request. This parameter has the
    ///   same meaning as the CreateOptions parameter of the NtCreateFile API. User
    ///   mode file systems should typically only be concerned with the flag
    ///   FILE_DIRECTORY_FILE, which is an instruction to create a directory rather
    ///   than a file. Some file systems may also want to pay attention to the
    ///   FILE_NO_INTERMEDIATE_BUFFERING and FILE_WRITE_THROUGH flags, although
    ///   these are typically handled by the FSD component.
    /// - GrantedAccess - Determines the specific access rights that have been
    ///   granted for this request. Upon receiving this call all access checks have
    ///   been performed and the user mode file system need not perform any
    ///   additional checks. However this parameter may be useful to a user mode
    ///   file system; for example the WinFsp-FUSE layer uses this parameter to
    ///   determine which flags to use in its POSIX open() call.
    /// - FileAttributes - File attributes to apply to the newly created file or
    ///   directory.
    /// - SecurityDescriptor - Security descriptor to apply to the newly created
    ///   file or directory. This security descriptor will always be in
    ///   self-relative format. Its length can be retrieved using the Windows
    ///   GetSecurityDescriptorLength API. Will be NULL for named streams.
    /// - AllocationSize - Allocation size for the newly created file.
    /// - ExtraBuffer - Extended attributes or reparse point buffer.
    /// - ExtraLength - Extended attributes or reparse point buffer length.
    /// - ExtraBufferIsReparsePoint - FALSE: extra buffer is extended attributes;
    ///   TRUE: extra buffer is reparse point.
    /// - PFileContext - [out] Pointer that will receive the file context on
    ///   successful return from this call.
    /// - FileInfo - [out] Pointer to a structure that will receive the file
    ///   information on successful return from this call. This information
    ///   includes file attributes, file times, etc.
    unsafe extern "C" fn create_ex_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        file_name: PWSTR,
        create_options: UINT32,
        granted_access: UINT32,
        file_attributes: UINT32,
        security_descriptor: PSECURITY_DESCRIPTOR,
        allocation_size: UINT64,
        extra_buffer: PVOID,
        extra_length: ULONG,
        extra_buffer_is_reparse_point: BOOLEAN,
        p_file_context: *mut PVOID,
        file_info: *mut FSP_FSCTL_FILE_INFO,
    ) -> NTSTATUS {
        let fs = &*(*file_system).UserContext.cast::<C>();
        let file_name = U16CStr::from_ptr_str(file_name);
        let sd = SecurityDescriptor::from_ptr(security_descriptor);
        let buffer = std::slice::from_raw_parts(extra_buffer.cast(), extra_length as usize);

        match C::create(
            fs,
            file_name,
            CreateFileInfo {
                create_options: CreateOptions(create_options),
                granted_access: FileAccessRights(granted_access),
                file_attributes: FileAttributes(file_attributes),
                allocation_size,
            },
            sd,
            buffer,
            extra_buffer_is_reparse_point != 0,
        ) {
            Err(e) => e,
            Ok(fctx) => {
                C::FileContext::write(fctx, p_file_context);
                Self::get_file_info_ext::<C>(file_system, *p_file_context, file_info)
            }
        }
    }

    /// Overwrite a file.
    /// - FileSystem - The file system on which this request is posted.
    /// - FileContext - The file context of the file to overwrite.
    /// - FileAttributes - File attributes to apply to the overwritten file.
    /// - ReplaceFileAttributes - When TRUE the existing file attributes should be
    ///   replaced with the new ones. When FALSE the existing file attributes
    ///   should be merged (or'ed) with the new ones.
    /// - AllocationSize - Allocation size for the overwritten file.
    /// - Ea - Extended attributes buffer.
    /// - EaLength - Extended attributes buffer length.
    /// - FileInfo - [out] Pointer to a structure that will receive the file
    ///   information on successful return from this call. This information
    ///   includes file attributes, file times, etc.
    unsafe extern "C" fn overwrite_ex_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        file_context: PVOID,
        file_attributes: UINT32,
        replace_file_attributes: BOOLEAN,
        allocation_size: UINT64,
        ea: PFILE_FULL_EA_INFORMATION,
        ea_length: ULONG,
        file_info: *mut FSP_FSCTL_FILE_INFO,
    ) -> NTSTATUS {
        let fs = &*(*file_system).UserContext.cast::<C>();
        let fctx = C::FileContext::access(file_context);
        let buffer = std::slice::from_raw_parts(ea.cast(), ea_length as usize);

        match C::overwrite(
            fs,
            fctx,
            FileAttributes(file_attributes),
            replace_file_attributes != 0,
            allocation_size,
            buffer,
        ) {
            Err(e) => e,
            Ok(()) => Self::get_file_info_ext::<C>(file_system, file_context, file_info),
        }
    }

    /// Get extended attributes.
    /// - FileSystem - The file system on which this request is posted.
    /// - FileContext - The file context of the file to get extended attributes
    ///   for.
    /// - Ea - Extended attributes buffer.
    /// - EaLength - Extended attributes buffer length.
    /// - PBytesTransferred - [out] Pointer to a memory location that will receive
    ///   the actual number of bytes transferred.
    unsafe extern "C" fn get_ea_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        file_context: PVOID,
        ea: PFILE_FULL_EA_INFORMATION,
        ea_length: ULONG,
        p_bytes_transferred: PULONG,
    ) -> NTSTATUS {
        let fs = &*(*file_system).UserContext.cast::<C>();
        let fctx = C::FileContext::access(file_context);
        let buffer = std::slice::from_raw_parts(ea.cast(), ea_length as usize);

        match C::get_ea(fs, fctx, buffer) {
            Err(e) => e,
            Ok(bytes_transfered) => {
                p_bytes_transferred.write(bytes_transfered as ULONG);
                STATUS_SUCCESS
            }
        }
    }

    /// Set extended attributes.
    /// - FileSystem - The file system on which this request is posted.
    /// - FileContext - The file context of the file to set extended attributes
    ///   for.
    /// - Ea - Extended attributes buffer.
    /// - EaLength - Extended attributes buffer length.
    /// - FileInfo - [out] Pointer to a structure that will receive the file
    ///   information on successful return from this call. This information
    ///   includes file attributes, file times, etc.
    unsafe extern "C" fn set_ea_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        file_context: PVOID,
        ea: PFILE_FULL_EA_INFORMATION,
        ea_length: ULONG,
        file_info: *mut FSP_FSCTL_FILE_INFO,
    ) -> NTSTATUS {
        let fs = &*(*file_system).UserContext.cast::<C>();
        let fctx = C::FileContext::access(file_context);
        let buffer = std::slice::from_raw_parts(ea.cast(), ea_length as usize);

        match C::set_ea(fs, fctx, buffer) {
            Err(e) => e,
            Ok(info) => {
                file_info.write(info.0);
                STATUS_SUCCESS
            }
        }
    }

    unsafe extern "C" fn dispatcher_stopped_ext<C: FileSystemContext>(
        file_system: *mut FSP_FILE_SYSTEM,
        normally: BOOLEAN,
    ) {
        let fs = &*(*file_system).UserContext.cast::<C>();

        C::dispatcher_stopped(fs, normally != 0);

        crate::ext::FspFileSystemStopServiceIfNecessary(file_system, normally)
    }

    pub(crate) fn interface<Ctx: FileSystemContext>() -> FSP_FILE_SYSTEM_INTERFACE {
        FSP_FILE_SYSTEM_INTERFACE {
            CanDelete: Some(Self::can_delete_ext::<Ctx>),
            Cleanup: Some(Self::cleanup_ext::<Ctx>),
            Close: Some(Self::close_ext::<Ctx>),
            Control: Some(Self::control_ext::<Ctx>),
            CreateEx: Some(Self::create_ex_ext::<Ctx>),
            DeleteReparsePoint: Some(Self::delete_reparse_point_ext::<Ctx>),
            DispatcherStopped: Some(Self::dispatcher_stopped_ext::<Ctx>),
            Flush: Some(Self::flush_ext::<Ctx>),
            GetDirInfoByName: Some(Self::get_dir_info_by_name_ext::<Ctx>),
            GetEa: Some(Self::get_ea_ext::<Ctx>),
            GetFileInfo: Some(Self::get_file_info_ext::<Ctx>),
            GetReparsePoint: Some(Self::get_reparse_point_ext::<Ctx>),
            GetSecurity: Some(Self::get_security_ext::<Ctx>),
            GetSecurityByName: Some(Self::get_security_by_name_ext::<Ctx>),
            GetStreamInfo: Some(Self::get_stream_info_ext::<Ctx>),
            GetVolumeInfo: Some(Self::get_volume_info_ext::<Ctx>),
            Open: Some(Self::open_ext::<Ctx>),
            OverwriteEx: Some(Self::overwrite_ex_ext::<Ctx>),
            Read: Some(Self::read_ext::<Ctx>),
            ReadDirectory: Some(Self::read_directory_ext::<Ctx>),
            Rename: Some(Self::rename_ext::<Ctx>),
            ResolveReparsePoints: Some(Self::resolve_reparse_points_ext::<Ctx>),
            SetBasicInfo: Some(Self::set_basic_info_ext::<Ctx>),
            SetDelete: Some(Self::set_delete_ext::<Ctx>),
            SetEa: Some(Self::set_ea_ext::<Ctx>),
            SetFileSize: Some(Self::set_file_size_ext::<Ctx>),
            SetReparsePoint: Some(Self::set_reparse_point_ext::<Ctx>),
            SetSecurity: Some(Self::set_security_ext::<Ctx>),
            SetVolumeLabelW: Some(Self::set_volume_label_w_ext::<Ctx>),
            Write: Some(Self::write_ext::<Ctx>),
            ..Default::default()
        }
    }
}
