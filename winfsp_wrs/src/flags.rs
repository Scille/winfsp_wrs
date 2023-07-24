use std::ops::{BitOr, BitOrAssign};

use windows_sys::Win32::{
    Storage::FileSystem::{
        CREATE_ALWAYS, CREATE_NEW, DELETE, FILE_ACCESS_RIGHTS, FILE_ADD_FILE,
        FILE_ADD_SUBDIRECTORY, FILE_ALL_ACCESS, FILE_APPEND_DATA, FILE_ATTRIBUTE_ARCHIVE,
        FILE_ATTRIBUTE_COMPRESSED, FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_EA, FILE_ATTRIBUTE_ENCRYPTED, FILE_ATTRIBUTE_HIDDEN,
        FILE_ATTRIBUTE_INTEGRITY_STREAM, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
        FILE_ATTRIBUTE_NO_SCRUB_DATA, FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_PINNED,
        FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
        FILE_ATTRIBUTE_RECALL_ON_OPEN, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SPARSE_FILE,
        FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_TEMPORARY, FILE_ATTRIBUTE_UNPINNED,
        FILE_ATTRIBUTE_VIRTUAL, FILE_CREATE_PIPE_INSTANCE, FILE_DELETE_CHILD, FILE_EXECUTE,
        FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
        FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_READ_EA, FILE_SHARE_DELETE,
        FILE_SHARE_MODE, FILE_SHARE_NONE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
        FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, INVALID_FILE_ATTRIBUTES,
        OPEN_ALWAYS, OPEN_EXISTING, READ_CONTROL, SPECIFIC_RIGHTS_ALL, STANDARD_RIGHTS_ALL,
        STANDARD_RIGHTS_EXECUTE, STANDARD_RIGHTS_READ, STANDARD_RIGHTS_REQUIRED,
        STANDARD_RIGHTS_WRITE, SYNCHRONIZE, TRUNCATE_EXISTING, WRITE_DAC, WRITE_OWNER,
    },
    System::WindowsProgramming::{
        FILE_DIRECTORY_FILE, FILE_NO_INTERMEDIATE_BUFFERING, FILE_WRITE_THROUGH,
    },
};

use crate::ext::{
    FspCleanupDelete, FspCleanupSetAllocationSize, FspCleanupSetArchiveBit,
    FspCleanupSetChangeTime, FspCleanupSetLastAccessTime, FspCleanupSetLastWriteTime,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// File attributes are metadata values stored by the file system on disk and
/// are used by the system and are available to developers via various file I/O
/// APIs.
pub struct FileAttributes(pub FILE_FLAGS_AND_ATTRIBUTES);

impl FileAttributes {
    /// A file that is read-only. Applications can read the file, but cannot write
    /// to it or delete it. This attribute is not honored on directories. For more
    /// information, see You cannot view or change the Read-only or the System
    /// attributes of folders in Windows Server 2003, in Windows XP, in Windows
    /// Vista or in Windows 7.
    pub const fn readonly() -> Self {
        Self(FILE_ATTRIBUTE_READONLY)
    }

    /// The file or directory is hidden. It is not included in an ordinary
    /// directory listing.
    pub const fn hidden() -> Self {
        Self(FILE_ATTRIBUTE_HIDDEN)
    }

    /// A file or directory that the operating system uses a part of, or uses
    /// exclusively.
    pub const fn system() -> Self {
        Self(FILE_ATTRIBUTE_SYSTEM)
    }

    /// The handle that identifies a directory.
    pub const fn directory() -> Self {
        Self(FILE_ATTRIBUTE_DIRECTORY)
    }

    /// A file or directory that is an archive file or directory. Applications
    /// typically use this attribute to mark files for backup or removal.
    pub const fn archive() -> Self {
        Self(FILE_ATTRIBUTE_ARCHIVE)
    }

    /// This value is reserved for system use.
    pub const fn device() -> Self {
        Self(FILE_ATTRIBUTE_DEVICE)
    }

    /// A file that does not have other attributes set. This attribute is valid
    /// only when used alone.
    pub const fn normal() -> Self {
        Self(FILE_ATTRIBUTE_NORMAL)
    }

    /// A file that is being used for temporary storage. File systems avoid writing
    /// data back to mass storage if sufficient cache memory is available, because
    /// typically, an application deletes a temporary file after the handle is
    /// closed. In that scenario, the system can entirely avoid writing the data.
    /// Otherwise, the data is written after the handle is closed.
    pub const fn temporary() -> Self {
        Self(FILE_ATTRIBUTE_TEMPORARY)
    }

    /// A file that is a sparse file.
    pub const fn sparse_file() -> Self {
        Self(FILE_ATTRIBUTE_SPARSE_FILE)
    }

    /// A file or directory that has an associated reparse point, or a file that is
    /// a symbolic link.
    pub const fn reparse_point() -> Self {
        Self(FILE_ATTRIBUTE_REPARSE_POINT)
    }

    /// A file or directory that is compressed. For a file, all of the data in the
    /// file is compressed. For a directory, compression is the default for newly
    /// created files and subdirectories.
    pub const fn compressed() -> Self {
        Self(FILE_ATTRIBUTE_COMPRESSED)
    }

    /// The data of a file is not available immediately. This attribute indicates
    /// that the file data is physically moved to offline storage. This attribute
    /// is used by Remote Storage, which is the hierarchical storage management
    /// software. Applications should not arbitrarily change this attribute.
    pub const fn offline() -> Self {
        Self(FILE_ATTRIBUTE_OFFLINE)
    }

    /// The file or directory is not to be indexed by the content indexing service.
    pub const fn not_content_indexed() -> Self {
        Self(FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
    }

    /// A file or directory that is encrypted. For a file, all data streams in the
    /// file are encrypted. For a directory, encryption is the default for newly
    /// created files and subdirectories.
    pub const fn encrypted() -> Self {
        Self(FILE_ATTRIBUTE_ENCRYPTED)
    }

    /// The directory or user data stream is configured with integrity (only
    /// supported on ReFS volumes). It is not included in an ordinary directory
    /// listing. The integrity setting persists with the file if it's renamed. If a
    ///  file is copied the destination file will have integrity set if either the
    /// source file or destination directory have integrity set.
    /// Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista,
    /// Windows Server 2003 and Windows XP: This flag is not supported until
    /// Windows Server 2012.
    pub const fn integrity_stream() -> Self {
        Self(FILE_ATTRIBUTE_INTEGRITY_STREAM)
    }

    /// This value is reserved for system use.
    pub const fn r#virtual() -> Self {
        Self(FILE_ATTRIBUTE_VIRTUAL)
    }

    /// The user data stream not to be read by the background data integrity
    /// scanner (AKA scrubber). When set on a directory it only provides
    /// inheritance. This flag is only supported on Storage Spaces and ReFS
    /// volumes. It is not included in an ordinary directory listing.
    /// Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista,
    /// Windows Server 2003 and Windows XP: This flag is not supported until
    /// Windows 8 and Windows Server 2012.
    pub const fn no_scrub_data() -> Self {
        Self(FILE_ATTRIBUTE_NO_SCRUB_DATA)
    }

    /// A file or directory with extended attributes.
    pub const fn ea() -> Self {
        Self(FILE_ATTRIBUTE_EA)
    }

    /// This attribute indicates user intent that the file or directory should be
    /// kept fully present locally even when not being actively accessed. This
    /// attribute is for use with hierarchical storage management software.
    pub const fn pinned() -> Self {
        Self(FILE_ATTRIBUTE_PINNED)
    }

    /// This attribute indicates that the file or directory should not be kept
    /// fully present locally except when being actively accessed. This attribute
    /// is for use with hierarchical storage management software.
    pub const fn unpinned() -> Self {
        Self(FILE_ATTRIBUTE_UNPINNED)
    }

    /// This attribute only appears in directory enumeration classes
    /// (FILE_DIRECTORY_INFORMATION, FILE_BOTH_DIR_INFORMATION, etc.). When this
    /// attribute is set, it means that the file or directory has no physical
    /// representation on the local system; the item is virtual. Opening the item
    /// will be more expensive than normal, e.g. it will cause at least some of it
    /// to be fetched from a remote store.
    pub const fn recall_open() -> Self {
        Self(FILE_ATTRIBUTE_RECALL_ON_OPEN)
    }

    /// When this attribute is set, it means that the file or directory is not
    /// fully present locally. For a file that means that not all of its data is on
    /// local storage (e.g. it may be sparse with some data still in remote
    /// storage). For a directory it means that some of the directory contents are
    /// being virtualized from another location. Reading the file / enumerating the
    /// directory will be more expensive than normal, e.g. it will cause at least
    /// some of the file/directory content to be fetched from a remote store. Only
    /// kernel-mode callers can set this bit.
    ///
    /// File system mini filters below the 180000 – 189999 altitude range (FSFilter
    /// HSM Load Order Group) must not issue targeted cached reads or writes to
    /// files that have this attribute set. This could lead to cache pollution and
    /// potential file corruption. For more information, see Handling placeholders.
    pub const fn recall_on_data_access() -> Self {
        Self(FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)
    }

    pub const fn invalid() -> Self {
        Self(INVALID_FILE_ATTRIBUTES)
    }

    pub const fn is(self, rhs: Self) -> bool {
        self.0 & rhs.0 == rhs.0
    }
}

impl BitOr for FileAttributes {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for FileAttributes {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CreateOptions(pub u32);

impl CreateOptions {
    pub const fn file_directory_file() -> Self {
        Self(FILE_DIRECTORY_FILE)
    }

    pub const fn file_no_intermediate_buffering() -> Self {
        Self(FILE_NO_INTERMEDIATE_BUFFERING)
    }

    pub const fn file_write_through() -> Self {
        Self(FILE_WRITE_THROUGH)
    }

    pub const fn is(self, rhs: Self) -> bool {
        self.0 & rhs.0 != 0
    }
}

impl BitOr for CreateOptions {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for CreateOptions {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileAccessRights(pub FILE_ACCESS_RIGHTS);

impl FileAccessRights {
    /// For a file object, the right to read the corresponding file data. For a
    /// directory object, the right to read the corresponding directory data.
    pub const fn file_read_data() -> Self {
        Self(FILE_READ_DATA)
    }

    /// The right to read extended file attributes.
    pub const fn file_read_ea() -> Self {
        Self(FILE_READ_EA)
    }

    /// For a directory, the right to list the contents of the directory.
    pub const fn file_list_directory() -> Self {
        Self(FILE_LIST_DIRECTORY)
    }

    /// For a file object, the right to write data to the file. For a directory
    /// object, the right to create a file in the directory (FILE_ADD_FILE).
    pub const fn file_write_data() -> Self {
        Self(FILE_WRITE_DATA)
    }

    /// For a directory, the right to create a file in the directory.
    pub const fn file_add_file() -> Self {
        Self(FILE_ADD_FILE)
    }

    /// For a file object, the right to append data to the file. (For local files,
    /// write operations will not overwrite existing data if this flag is specified
    /// without FILE_WRITE_DATA.) For a directory object, the right to create a
    /// subdirectory (FILE_ADD_SUBDIRECTORY).
    pub const fn file_append_data() -> Self {
        Self(FILE_APPEND_DATA)
    }

    /// For a directory, the right to create a subdirectory.
    pub const fn file_add_subdirectory() -> Self {
        Self(FILE_ADD_SUBDIRECTORY)
    }

    /// For a named pipe, the right to create a pipe.
    pub const fn file_create_pipe_instance() -> Self {
        Self(FILE_CREATE_PIPE_INSTANCE)
    }

    /// The right to write extended file attributes.
    pub const fn file_write_ea() -> Self {
        Self(FILE_WRITE_EA)
    }

    /// For a native code file, the right to execute the file. This access right
    /// given to scripts may cause the script to be executable, depending on the
    /// script interpreter.
    pub const fn file_execute() -> Self {
        Self(FILE_EXECUTE)
    }

    /// For a directory, the right to traverse the directory. By default, users are
    /// assigned the BYPASS_TRAVERSE_CHECKING privilege, which ignores the
    /// FILE_TRAVERSE access right. See the remarks in File Security and Access
    /// Rights for more information.
    pub const fn file_traverse() -> Self {
        Self(FILE_TRAVERSE)
    }

    /// For a directory, the right to delete a directory and all the files it
    /// contains, including read-only files.
    pub const fn file_delete_child() -> Self {
        Self(FILE_DELETE_CHILD)
    }

    /// The right to read file attributes.
    pub const fn file_read_attributes() -> Self {
        Self(FILE_READ_ATTRIBUTES)
    }

    /// The right to write file attributes.
    pub const fn file_write_attributes() -> Self {
        Self(FILE_WRITE_ATTRIBUTES)
    }

    pub const fn delete() -> Self {
        Self(DELETE)
    }

    pub const fn read_control() -> Self {
        Self(READ_CONTROL)
    }

    pub const fn write_dac() -> Self {
        Self(WRITE_DAC)
    }

    pub const fn write_owner() -> Self {
        Self(WRITE_OWNER)
    }

    pub const fn synchronize() -> Self {
        Self(SYNCHRONIZE)
    }

    pub const fn standard_rights_required() -> Self {
        Self(STANDARD_RIGHTS_REQUIRED)
    }

    /// Includes READ_CONTROL, which is the right to read the information in the
    /// file or directory object's security descriptor. This does not include the
    /// information in the SACL.
    pub const fn standard_rights_read() -> Self {
        Self(STANDARD_RIGHTS_READ)
    }

    /// Same as STANDARD_RIGHTS_READ.
    pub const fn standard_rights_write() -> Self {
        Self(STANDARD_RIGHTS_WRITE)
    }

    /// Same as STANDARD_RIGHTS_READ.
    pub const fn standard_rights_execute() -> Self {
        Self(STANDARD_RIGHTS_EXECUTE)
    }

    pub const fn standard_rights_all() -> Self {
        Self(STANDARD_RIGHTS_ALL)
    }

    pub const fn specific_rights_all() -> Self {
        Self(SPECIFIC_RIGHTS_ALL)
    }

    /// All possible access rights for a file.
    pub const fn file_all_access() -> Self {
        Self(FILE_ALL_ACCESS)
    }

    pub const fn file_generic_read() -> Self {
        Self(FILE_GENERIC_READ)
    }

    pub const fn file_generic_write() -> Self {
        Self(FILE_GENERIC_WRITE)
    }

    pub const fn file_generic_execute() -> Self {
        Self(FILE_GENERIC_EXECUTE)
    }

    pub const fn is(self, rhs: Self) -> bool {
        self.0 & rhs.0 == rhs.0
    }
}

impl BitOr for FileAccessRights {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for FileAccessRights {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CleanupFlags(pub i32);

impl CleanupFlags {
    pub const fn delete() -> Self {
        Self(FspCleanupDelete)
    }

    pub const fn set_allocation_size() -> Self {
        Self(FspCleanupSetAllocationSize)
    }

    pub const fn set_archive_bit() -> Self {
        Self(FspCleanupSetArchiveBit)
    }

    pub const fn set_last_access_time() -> Self {
        Self(FspCleanupSetLastAccessTime)
    }

    pub const fn set_last_write_time() -> Self {
        Self(FspCleanupSetLastWriteTime)
    }

    pub const fn set_change_time() -> Self {
        Self(FspCleanupSetChangeTime)
    }

    pub const fn is(self, rhs: Self) -> bool {
        self.0 & rhs.0 != 0
    }
}

impl BitOr for CleanupFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for CleanupFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileShareMode(pub FILE_SHARE_MODE);

impl FileShareMode {
    pub const fn none() -> Self {
        Self(FILE_SHARE_NONE)
    }

    pub const fn delete() -> Self {
        Self(FILE_SHARE_DELETE)
    }

    pub const fn read() -> Self {
        Self(FILE_SHARE_READ)
    }

    pub const fn write() -> Self {
        Self(FILE_SHARE_WRITE)
    }

    pub const fn is(self, rhs: Self) -> bool {
        self.0 & rhs.0 == rhs.0
    }
}

impl BitOr for FileShareMode {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for FileShareMode {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0
    }
}

#[repr(u32)]
pub enum FileCreationDisposition {
    CreateNew = CREATE_NEW,
    CreateAlways = CREATE_ALWAYS,
    OpenExisting = OPEN_EXISTING,
    OpenAlways = OPEN_ALWAYS,
    TruncateExisting = TRUNCATE_EXISTING,
}
