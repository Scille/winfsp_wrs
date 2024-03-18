use std::sync::Arc;

use winfsp_wrs::{
    filetime_now, u16cstr, u16str, CreateOptions, DirInfo, FileAccessRights, FileAttributes,
    FileInfo, FileSystem, FileSystemContext, PSecurityDescriptor, Params, SecurityDescriptor,
    U16CStr, U16Str, VolumeInfo, VolumeParams, NTSTATUS,
};

#[derive(Debug, Clone)]
struct Context {
    info: FileInfo,
    security_descriptor: SecurityDescriptor,
}

#[derive(Debug)]
struct MemFs {
    volume_info: VolumeInfo,
    file_context: Context,
}

impl MemFs {
    const MAX_FILE_NODES: u64 = 1024;
    const MAX_FILE_SIZE: u64 = 16 * 1024 * 1024;
    const FILE_NODES: u64 = 1;

    fn new(volume_label: &U16Str) -> Self {
        let now = filetime_now();
        let mut info = FileInfo::default();

        info.set_file_attributes(FileAttributes::DIRECTORY)
            .set_time(now);

        Self {
            volume_info: VolumeInfo::new(
                Self::MAX_FILE_NODES * Self::MAX_FILE_SIZE,
                (Self::MAX_FILE_NODES - Self::FILE_NODES) * Self::MAX_FILE_SIZE,
                volume_label,
            )
            .expect("volume label too long"),
            file_context: Context {
                info,
                security_descriptor: SecurityDescriptor::from_wstr(u16cstr!(
                    "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)"
                ))
                .unwrap(),
            },
        }
    }
}

impl FileSystemContext for MemFs {
    type FileContext = Arc<Context>;

    fn get_security_by_name(
        &self,
        _file_name: &U16CStr,
        _find_reparse_point: impl Fn() -> Option<FileAttributes>,
    ) -> Result<(FileAttributes, PSecurityDescriptor, bool), NTSTATUS> {
        Ok((
            self.file_context.info.file_attributes(),
            self.file_context.security_descriptor.as_ptr(),
            false,
        ))
    }

    fn open(
        &self,
        _file_name: &U16CStr,
        _create_options: CreateOptions,
        _granted_access: FileAccessRights,
    ) -> Result<(Self::FileContext, FileInfo), NTSTATUS> {
        let file_context = Arc::new(self.file_context.clone());
        let file_info = self.file_context.info;
        Ok((file_context, file_info))
    }

    fn get_file_info(&self, _file_context: Self::FileContext) -> Result<FileInfo, NTSTATUS> {
        Ok(self.file_context.info)
    }

    fn get_volume_info(&self) -> Result<VolumeInfo, NTSTATUS> {
        Ok(self.volume_info.clone())
    }

    fn read_directory(
        &self,
        _file_context: Self::FileContext,
        _marker: Option<&U16CStr>,
        _add_dir_info: impl FnMut(DirInfo) -> bool,
    ) -> Result<(), NTSTATUS> {
        Ok(())
    }
}

fn create_memory_file_system(mountpoint: &U16CStr) -> FileSystem<MemFs> {
    let mut volume_params = VolumeParams::default();

    volume_params
        .set_file_system_name(mountpoint)
        .unwrap()
        .set_prefix(u16cstr!(""))
        .unwrap();

    let params = Params {
        volume_params,
        ..Default::default()
    };

    FileSystem::new(params, Some(mountpoint), MemFs::new(u16str!("memfs"))).unwrap()
}

fn main() {
    winfsp_wrs::init().unwrap();
    println!("Starting FS");
    let fs = create_memory_file_system(u16cstr!("Z:"));

    let (tx, rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || tx.send(()).unwrap()).unwrap();
    rx.recv().unwrap();

    println!("Stopping FS");
    fs.stop();
}
