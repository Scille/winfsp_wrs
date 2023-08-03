use serde_json::{json, Value};
use std::{
    cmp::Ordering,
    collections::HashMap,
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use winfsp_wrs::{
    filetime_now, u16cstr, CleanupFlags, CreateFileInfo, CreateOptions, FileAccessRights,
    FileAttributes, FileContextMode, FileInfo, FileSystem, FileSystemContext, PSecurityDescriptor,
    Params, SecurityDescriptor, U16CStr, U16CString, VolumeInfo, VolumeParams, NTSTATUS,
    STATUS_ACCESS_DENIED, STATUS_DIRECTORY_NOT_EMPTY, STATUS_END_OF_FILE,
    STATUS_MEDIA_WRITE_PROTECTED, STATUS_NOT_A_DIRECTORY, STATUS_OBJECT_NAME_COLLISION,
    STATUS_OBJECT_NAME_NOT_FOUND,
};

const ENTRY_INFO_EXTENSION: &str = "__parsec_entry_info__";

fn is_entry_info_path(path: &Path) -> bool {
    path.extension()
        .map(|ext| ext == ENTRY_INFO_EXTENSION)
        .unwrap_or_default()
}

enum Obj {
    Folder(FolderObj),
    File(FileObj),
    EntryInfo(EntryInfo),
}

impl std::fmt::Debug for Obj {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.path())
    }
}

impl Obj {
    fn path(&self) -> &Path {
        match self {
            Self::Folder(folder) => &folder.path,
            Self::File(file) => &file.path,
            Self::EntryInfo(entry) => &entry.path,
        }
    }
    fn set_path(&mut self, path: PathBuf) {
        match self {
            Self::Folder(folder) => folder.path = path,
            Self::File(file) => file.path = path,
            Self::EntryInfo(entry) => entry.path = path,
        }
    }
}

#[derive(Debug, Clone)]
struct FolderObj {
    path: PathBuf,
    security_descriptor: SecurityDescriptor,
    info: FileInfo,
}

#[derive(Debug, Clone)]
struct FileObj {
    path: PathBuf,
    security_descriptor: SecurityDescriptor,
    info: FileInfo,
    data: Vec<u8>,
}

struct EntryInfo {
    path: PathBuf,
    security_descriptor: SecurityDescriptor,
    encoded: String,
}

impl FolderObj {
    fn new(
        path: PathBuf,
        attributes: FileAttributes,
        security_descriptor: SecurityDescriptor,
    ) -> Self {
        let now = filetime_now();
        let mut info = FileInfo::default();

        info.set_file_attributes(attributes).set_time(now);

        assert!(attributes.is(FileAttributes::directory()));

        Self {
            path,
            security_descriptor,
            info,
        }
    }
}

impl FileObj {
    const ALLOCATION_UNIT: usize = 4096;

    fn new(
        path: PathBuf,
        attributes: FileAttributes,
        security_descriptor: SecurityDescriptor,
        allocation_size: u64,
    ) -> Self {
        let now = filetime_now();
        let mut info = FileInfo::default();

        info.set_allocation_size(allocation_size)
            .set_file_attributes(attributes | FileAttributes::archive())
            .set_time(now);

        assert!(!attributes.is(FileAttributes::directory()));

        Self {
            path,
            security_descriptor,
            info,
            data: vec![0; allocation_size as usize],
        }
    }

    fn allocation_size(&self) -> usize {
        self.data.len()
    }

    fn set_allocation_size(&mut self, allocation_size: usize) {
        match allocation_size.cmp(&self.allocation_size()) {
            Ordering::Less => self.data.truncate(allocation_size),
            Ordering::Greater => {
                self.data
                    .append(&mut vec![0; allocation_size - self.allocation_size()])
            }
            Ordering::Equal => (),
        }

        assert_eq!(self.allocation_size(), allocation_size);
        self.info
            .set_file_size(std::cmp::min(self.info.file_size(), allocation_size as u64));
        self.info.set_allocation_size(allocation_size as u64);
    }

    fn adapt_allocation_size(&mut self, file_size: usize) {
        let units = (file_size + Self::ALLOCATION_UNIT - 1) / Self::ALLOCATION_UNIT;
        self.set_allocation_size(units * Self::ALLOCATION_UNIT)
    }

    fn set_file_size(&mut self, file_size: usize) {
        if (file_size as u64) < self.info.file_size() {
            self.data[file_size..self.info.file_size() as usize].fill(0)
        }
        if file_size > self.allocation_size() {
            self.adapt_allocation_size(file_size)
        }
        self.info.set_file_size(file_size as u64);
    }

    fn read(&self, offset: usize, length: usize) -> &[u8] {
        let end_offset = std::cmp::min(self.info.file_size() as usize, offset + length);

        &self.data[offset..end_offset]
    }

    fn write(&mut self, buffer: &[u8], mut offset: usize, write_to_end_of_file: bool) -> usize {
        if write_to_end_of_file {
            offset = self.info.file_size() as usize
        }
        let end_offset = offset + buffer.len();
        if end_offset as u64 > self.info.file_size() {
            self.set_file_size(end_offset)
        }

        self.data[offset..end_offset].copy_from_slice(buffer);
        buffer.len()
    }

    fn constrained_write(&mut self, buffer: &[u8], offset: usize) -> usize {
        if offset as u64 >= self.info.file_size() {
            return 0;
        }

        let end_offset = std::cmp::min(self.info.file_size() as usize, offset + buffer.len());
        let transferred_length = end_offset - offset;

        self.data[offset..end_offset].copy_from_slice(&buffer[..transferred_length]);

        transferred_length
    }
}

impl EntryInfo {
    fn new(path: PathBuf, security_descriptor: SecurityDescriptor, value: &Value) -> Self {
        Self {
            path,
            security_descriptor,
            encoded: serde_json::to_string(value).unwrap(),
        }
    }

    fn read(&self, offset: usize, length: usize) -> Vec<u8> {
        let offset_end = std::cmp::min(self.encoded.len(), offset + length);

        self.encoded.as_bytes()[offset..offset_end].to_vec()
    }
}

impl From<&Obj> for FileInfo {
    fn from(value: &Obj) -> Self {
        match value {
            Obj::File(file_obj) => file_obj.info,
            Obj::Folder(folder_obj) => folder_obj.info,
            Obj::EntryInfo(_) => {
                let mut file_info = Self::default();
                file_info
                    .set_file_attributes(FileAttributes::hidden())
                    .set_file_size(1024)
                    .set_time(filetime_now());
                file_info
            }
        }
    }
}

impl Obj {
    fn new_file(
        path: PathBuf,
        attributes: FileAttributes,
        security_descriptor: SecurityDescriptor,
        allocation_size: u64,
    ) -> Self {
        Self::File(FileObj::new(
            path,
            attributes,
            security_descriptor,
            allocation_size,
        ))
    }

    fn new_folder(
        path: PathBuf,
        attributes: FileAttributes,
        security_descriptor: SecurityDescriptor,
    ) -> Self {
        Self::Folder(FolderObj::new(path, attributes, security_descriptor))
    }
}

#[derive(Debug)]
struct MemFs {
    entries: Arc<Mutex<HashMap<PathBuf, Arc<Mutex<Obj>>>>>,
    volume_info: Arc<Mutex<VolumeInfo>>,
    read_only: bool,
    root_path: PathBuf,
}

impl MemFs {
    const MAX_FILE_NODES: u64 = 1024;
    const MAX_FILE_SIZE: u64 = 16 * 1024 * 1024;
    const FILE_NODES: u64 = 1;

    fn new(volume_label: &U16CStr, read_only: bool) -> Self {
        let root_path = PathBuf::from("/");
        let mut entries = HashMap::new();

        let sd = SecurityDescriptor::from_wstr(u16cstr!(
            "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)"
        ))
        .unwrap();

        let entry = Obj::Folder(FolderObj::new(
            root_path.clone(),
            FileAttributes::directory(),
            sd.clone(),
        ));

        entries.insert(root_path.clone(), Arc::new(Mutex::new(entry)));

        let path = root_path.join("foo.txt");
        let entry = Obj::File(FileObj::new(
            path.clone(),
            FileAttributes::archive(),
            sd.clone(),
            0,
        ));

        entries.insert(path, Arc::new(Mutex::new(entry)));

        let path = root_path.join("foo.txt.__parsec_entry_info__");
        let entry = Obj::EntryInfo(EntryInfo::new(
            path.clone(),
            sd.clone(),
            &json!({
                "need_sync": true,
            }),
        ));

        entries.insert(path, Arc::new(Mutex::new(entry)));

        let path = root_path.join("bar.txt");
        let entry = Obj::File(FileObj::new(
            path.clone(),
            FileAttributes::archive(),
            sd.clone(),
            0,
        ));

        entries.insert(path, Arc::new(Mutex::new(entry)));

        let path = root_path.join("bar.txt.__parsec_entry_info__");
        let entry = Obj::EntryInfo(EntryInfo::new(
            path.clone(),
            sd.clone(),
            &json!({
                "need_sync": false,
            }),
        ));

        entries.insert(path, Arc::new(Mutex::new(entry)));

        let path = root_path.join("none.txt");
        let entry = Obj::File(FileObj::new(
            path.clone(),
            FileAttributes::archive(),
            sd.clone(),
            0,
        ));

        entries.insert(path, Arc::new(Mutex::new(entry)));

        Self {
            entries: Arc::new(Mutex::new(entries)),
            volume_info: Arc::new(Mutex::new(VolumeInfo::new(
                Self::MAX_FILE_NODES * Self::MAX_FILE_SIZE,
                (Self::MAX_FILE_NODES - Self::FILE_NODES) * Self::MAX_FILE_SIZE,
                volume_label,
            ))),
            read_only,
            root_path,
        }
    }
}

impl FileSystemContext for MemFs {
    type FileContext = Arc<Mutex<Obj>>;

    fn get_volume_info(&self) -> Result<VolumeInfo, NTSTATUS> {
        Ok(*self.volume_info.lock().unwrap())
    }

    fn set_volume_label(&self, volume_label: &U16CStr) -> Result<(), NTSTATUS> {
        self.volume_info
            .lock()
            .unwrap()
            .set_volume_label(volume_label);
        Ok(())
    }

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        _find_reparse_point: impl Fn() -> Option<FileAttributes>,
    ) -> Result<(FileAttributes, PSecurityDescriptor, bool), NTSTATUS> {
        let entries = self.entries.lock().unwrap();

        let file_name = PathBuf::from(file_name.to_os_string());

        if let Some(obj) = entries.get(&file_name) {
            match obj.lock().unwrap().deref() {
                Obj::File(file_obj) => Ok((
                    file_obj.info.file_attributes(),
                    file_obj.security_descriptor.as_ptr(),
                    false,
                )),
                Obj::Folder(folder_obj) => Ok((
                    folder_obj.info.file_attributes(),
                    folder_obj.security_descriptor.as_ptr(),
                    false,
                )),
                Obj::EntryInfo(entry) => Ok((
                    FileAttributes::hidden(),
                    entry.security_descriptor.as_ptr(),
                    false,
                )),
            }
        } else {
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        }
    }

    fn create(
        &self,
        file_name: &U16CStr,
        create_file_info: CreateFileInfo,
        security_descriptor: SecurityDescriptor,
        _buffer: &[u8],
        _extra_buffer_is_reparse_point: bool,
    ) -> Result<Self::FileContext, NTSTATUS> {
        let mut entries = self.entries.lock().unwrap();

        if self.read_only {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }

        let file_name = PathBuf::from(file_name.to_os_string());

        // Retrieve file
        if let Some(parent_file_obj) = file_name.parent().and_then(|parent| entries.get(parent)) {
            if let Obj::File { .. } = *parent_file_obj.lock().unwrap() {
                return Err(STATUS_NOT_A_DIRECTORY);
            }
        } else {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }

        // File/Folder already exists
        if entries.contains_key(&file_name) {
            return Err(STATUS_OBJECT_NAME_COLLISION);
        }

        let file_obj = Arc::new(Mutex::new(
            if create_file_info
                .create_options
                .is(CreateOptions::file_directory_file())
            {
                Obj::new_folder(
                    file_name.clone(),
                    create_file_info.file_attributes,
                    security_descriptor,
                )
            } else {
                Obj::new_file(
                    file_name.clone(),
                    create_file_info.file_attributes,
                    security_descriptor,
                    create_file_info.allocation_size,
                )
            },
        ));

        entries.insert(file_name, file_obj.clone());

        Ok(file_obj)
    }

    fn open(
        &self,
        file_name: &U16CStr,
        _create_options: CreateOptions,
        _granted_access: FileAccessRights,
    ) -> Result<Self::FileContext, NTSTATUS> {
        let file_name = PathBuf::from(file_name.to_os_string());

        match self.entries.lock().unwrap().get(&file_name) {
            Some(entry) => Ok(entry.clone()),
            None => Err(STATUS_OBJECT_NAME_NOT_FOUND),
        }
    }

    fn overwrite(
        &self,
        file_context: &Self::FileContext,
        mut file_attributes: FileAttributes,
        replace_file_attributes: bool,
        allocation_size: u64,
        _buffer: &[u8],
    ) -> Result<(), NTSTATUS> {
        if self.read_only {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }

        if let Obj::File(file_obj) = file_context.lock().unwrap().deref_mut() {
            // File attributes
            file_attributes |= FileAttributes::archive();
            if replace_file_attributes {
                file_obj.info.set_file_attributes(file_attributes);
            } else {
                file_obj
                    .info
                    .set_file_attributes(file_attributes | file_obj.info.file_attributes());
            }

            // Allocation size
            file_obj.set_allocation_size(allocation_size as usize);

            // Set times
            let now = filetime_now();
            file_obj.info.set_last_access_time(now);
            file_obj.info.set_last_write_time(now);
            file_obj.info.set_change_time(now);

            Ok(())
        } else {
            unreachable!()
        }
    }

    fn cleanup(
        &self,
        file_context: &Self::FileContext,
        file_name: Option<&U16CStr>,
        flags: CleanupFlags,
    ) {
        if self.read_only {
            return;
        }

        let mut entries = self.entries.lock().unwrap();

        if let Obj::File(file_obj) = file_context.lock().unwrap().deref_mut() {
            // Resize
            if flags.is(CleanupFlags::set_allocation_size()) {
                file_obj.adapt_allocation_size(file_obj.info.file_size() as usize)
            }

            // Set archive bit
            if flags.is(CleanupFlags::set_archive_bit()) {
                file_obj.info.set_file_attributes(
                    FileAttributes::archive() | file_obj.info.file_attributes(),
                );
            }

            let now = filetime_now();
            // Set last access time
            if flags.is(CleanupFlags::set_last_access_time()) {
                file_obj.info.set_last_access_time(now);
            }

            if flags.is(CleanupFlags::set_last_write_time()) {
                file_obj.info.set_last_write_time(now);
            }

            if flags.is(CleanupFlags::set_change_time()) {
                file_obj.info.set_change_time(now);
            }
        }

        // Delete
        if let Some(file_name) = file_name {
            assert!(flags.is(CleanupFlags::delete()));
            let file_name = PathBuf::from(file_name.to_os_string());

            // check for non-empty directory
            if entries
                .keys()
                .any(|entry| entry.parent() == Some(&file_name))
            {
                return;
            }

            entries.remove(&file_name);
        }
    }

    fn read(
        &self,
        file_context: &Self::FileContext,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, NTSTATUS> {
        match file_context.lock().unwrap().deref() {
            Obj::File(file_obj) => {
                if offset >= file_obj.info.file_size() {
                    return Err(STATUS_END_OF_FILE);
                }
                Ok(file_obj.read(offset as usize, length as usize).into())
            }
            Obj::EntryInfo(entry) => Ok(entry.read(offset as usize, length as usize)),
            Obj::Folder(_) => unreachable!(),
        }
    }

    fn write(
        &self,
        file_context: &Self::FileContext,
        buffer: &[u8],
        offset: u64,
        write_to_end_of_file: bool,
        constrained_io: bool,
    ) -> Result<usize, NTSTATUS> {
        if self.read_only {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }

        if let Obj::File(file_obj) = file_context.lock().unwrap().deref_mut() {
            if constrained_io {
                Ok(file_obj.constrained_write(buffer, offset as usize))
            } else {
                Ok(file_obj.write(buffer, offset as usize, write_to_end_of_file))
            }
        } else {
            unreachable!()
        }
    }

    fn flush(&self, _file_context: &Self::FileContext) -> Result<(), NTSTATUS> {
        Ok(())
    }

    fn get_file_info(&self, file_context: &Self::FileContext) -> Result<FileInfo, NTSTATUS> {
        Ok(file_context.lock().unwrap().deref().into())
    }

    fn set_basic_info(
        &self,
        file_context: &Self::FileContext,
        file_attributes: FileAttributes,
        creation_time: u64,
        last_access_time: u64,
        last_write_time: u64,
        change_time: u64,
    ) -> Result<(), NTSTATUS> {
        if self.read_only {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }

        match file_context.lock().unwrap().deref_mut() {
            Obj::File(file_obj) => {
                if !file_attributes.is(FileAttributes::invalid()) {
                    file_obj.info.set_file_attributes(file_attributes);
                }
                if creation_time != 0 {
                    file_obj.info.set_creation_time(creation_time);
                }
                if last_access_time != 0 {
                    file_obj.info.set_last_access_time(last_access_time);
                }
                if last_write_time != 0 {
                    file_obj.info.set_last_write_time(last_write_time);
                }
                if change_time != 0 {
                    file_obj.info.set_change_time(change_time);
                }
            }
            Obj::Folder(folder_obj) => {
                if !file_attributes.is(FileAttributes::invalid()) {
                    folder_obj.info.set_file_attributes(file_attributes);
                }
                if creation_time != 0 {
                    folder_obj.info.set_creation_time(creation_time);
                }
                if last_access_time != 0 {
                    folder_obj.info.set_last_access_time(last_access_time);
                }
                if last_write_time != 0 {
                    folder_obj.info.set_last_write_time(last_write_time);
                }
                if change_time != 0 {
                    folder_obj.info.set_change_time(change_time);
                }
            }
            Obj::EntryInfo(_) => unreachable!(),
        }

        Ok(())
    }

    fn set_file_size(
        &self,
        file_context: &Self::FileContext,
        new_size: u64,
        set_allocation_size: bool,
    ) -> Result<(), NTSTATUS> {
        if self.read_only {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }

        match file_context.lock().unwrap().deref_mut() {
            Obj::File(file_obj) => {
                if set_allocation_size {
                    file_obj.set_allocation_size(new_size as usize)
                } else {
                    file_obj.set_file_size(new_size as usize)
                }
            }
            Obj::Folder(_) => unreachable!(),
            Obj::EntryInfo(_) => unreachable!(),
        }

        Ok(())
    }

    fn rename(
        &self,
        _file_context: &Self::FileContext,
        file_name: &U16CStr,
        new_file_name: &U16CStr,
        replace_if_exists: bool,
    ) -> Result<(), NTSTATUS> {
        if self.read_only {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }

        let mut entries = self.entries.lock().unwrap();

        let file_name = PathBuf::from(file_name.to_os_string());
        let new_file_name = PathBuf::from(new_file_name.to_os_string());

        if entries.contains_key(&new_file_name) {
            if let Obj::Folder(_) = entries.get(&file_name).unwrap().lock().unwrap().deref() {
                return Err(STATUS_ACCESS_DENIED);
            }
            if replace_if_exists {
                entries.remove(&new_file_name);
            } else {
                return Err(STATUS_OBJECT_NAME_COLLISION);
            }
        }

        let iter_entries = entries
            .keys()
            .filter(|path| path.to_str().unwrap().contains(file_name.to_str().unwrap()))
            .cloned()
            .collect::<Vec<PathBuf>>();

        for entry_path in iter_entries {
            let new_entry_path = PathBuf::from(entry_path.to_str().unwrap().replacen(
                file_name.to_str().unwrap(),
                new_file_name.to_str().unwrap(),
                1,
            ));

            let entry = entries.remove(&entry_path).unwrap();
            entry.lock().unwrap().set_path(new_entry_path.clone());
            entries.insert(new_entry_path, entry);
        }

        Ok(())
    }

    fn get_security(
        &self,
        file_context: &Self::FileContext,
    ) -> Result<PSecurityDescriptor, NTSTATUS> {
        match file_context.lock().unwrap().deref() {
            Obj::File(file_obj) => Ok(file_obj.security_descriptor.as_ptr()),
            Obj::Folder(folder_obj) => Ok(folder_obj.security_descriptor.as_ptr()),
            Obj::EntryInfo(entry) => Ok(entry.security_descriptor.as_ptr()),
        }
    }

    fn set_security(
        &self,
        file_context: &Self::FileContext,
        security_information: u32,
        modification_descriptor: PSecurityDescriptor,
    ) -> Result<(), NTSTATUS> {
        if self.read_only {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }

        match file_context.lock().unwrap().deref_mut() {
            Obj::File(file_obj) => {
                let new_descriptor = file_obj
                    .security_descriptor
                    .set(security_information, modification_descriptor)?;
                file_obj.security_descriptor = new_descriptor;
            }
            Obj::Folder(folder_obj) => {
                let new_descriptor = folder_obj
                    .security_descriptor
                    .set(security_information, modification_descriptor)?;
                folder_obj.security_descriptor = new_descriptor;
            }
            Obj::EntryInfo(_) => unreachable!(),
        }

        Ok(())
    }

    fn read_directory(
        &self,
        file_context: &Self::FileContext,
        marker: Option<&U16CStr>,
    ) -> Result<Vec<(U16CString, FileInfo)>, NTSTATUS> {
        let entries = self.entries.lock().unwrap();

        match file_context.lock().unwrap().deref() {
            Obj::File(_) | Obj::EntryInfo(_) => Err(STATUS_NOT_A_DIRECTORY),
            Obj::Folder(folder_obj) => {
                let mut res_entries = vec![];

                if folder_obj.path != self.root_path {
                    let parent_path = folder_obj.path.parent().unwrap();
                    res_entries.push((u16cstr!(".").to_owned(), folder_obj.info));
                    let parent_obj = entries[parent_path].lock().unwrap();
                    res_entries.push((u16cstr!("..").into(), FileInfo::from(parent_obj.deref())));
                }

                for (entry_path, entry_obj) in entries.iter().filter(|(entry_path, _)| {
                    // - Filter out unrelated entries
                    // - Filter out ourself or our grandchildren
                    let entry_path_len = entry_path.components().count();
                    let folder_obj_path_len = folder_obj.path.components().count();

                    entry_path.starts_with(&folder_obj.path)
                        && entry_path_len == folder_obj_path_len + 1
                        && !is_entry_info_path(&entry_path)
                }) {
                    let entry_obj = entry_obj.lock().unwrap();
                    res_entries.push((
                        U16CString::from_os_str(entry_path.file_name().unwrap()).unwrap(),
                        FileInfo::from(entry_obj.deref()),
                    ))
                }

                res_entries.sort_by(|x, y| y.0.cmp(&x.0));

                if let Some(marker) = marker {
                    // # Filter out all results before the marker
                    if let Some(i) = res_entries.iter().position(|x| x.0 == marker) {
                        res_entries.truncate(i);
                    }
                }

                res_entries.reverse();

                Ok(res_entries)
            }
        }
    }

    fn set_delete(
        &self,
        _file_context: &Self::FileContext,
        file_name: &U16CStr,
        _delete_file: bool,
    ) -> Result<(), NTSTATUS> {
        if self.read_only {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }

        let entries = self.entries.lock().unwrap();
        let file_name = PathBuf::from(file_name.to_os_string());

        if entries
            .keys()
            .any(|entry| entry.parent() == Some(&file_name))
        {
            return Err(STATUS_DIRECTORY_NOT_EMPTY);
        }

        Ok(())
    }
}

fn create_memory_file_system(mountpoint: &U16CStr) -> FileSystem<MemFs> {
    let mut volume_params = VolumeParams::default();

    volume_params
        .set_sector_size(512)
        .set_sectors_per_allocation_unit(1)
        .set_volume_creation_time(filetime_now())
        .set_volume_serial_number(0)
        .set_file_info_timeout(1000)
        .set_case_sensitive_search(true)
        .set_case_preserved_names(true)
        .set_unicode_on_disk(true)
        .set_persistent_acls(true)
        .set_post_cleanup_when_modified_only(true)
        .set_file_context_mode(FileContextMode::Descriptor)
        .set_file_system_name(mountpoint)
        .set_prefix(u16cstr!(""));

    let params = Params {
        volume_params,
        ..Default::default()
    };

    FileSystem::new(
        params,
        Some(mountpoint),
        MemFs::new(u16cstr!("memfs"), false),
    )
    .unwrap()
}

fn main() {
    winfsp_wrs::init().unwrap();
    println!("Starting FS");
    let mut fs = create_memory_file_system(u16cstr!("Z:"));

    let mut input = String::new();

    loop {
        println!("read only ? (y, n, q)");
        input.clear();
        std::io::stdin().read_line(&mut input).unwrap();

        match input.trim() {
            "q" => break,
            "y" => {
                fs.volume_params_mut().set_read_only_volume(true);
                fs = fs.restart().unwrap();
            }
            "n" => {
                fs.volume_params_mut().set_read_only_volume(false);
                fs = fs.restart().unwrap();
            }
            _ => continue,
        }
    }

    println!("Stopping FS");
    fs.stop();
}