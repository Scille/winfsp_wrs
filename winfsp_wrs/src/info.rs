use widestring::U16CStr;

use crate::{
    ext::{FSP_FSCTL_FILE_INFO, FSP_FSCTL_VOLUME_INFO},
    CreateOptions, FileAccessRights, FileAttributes,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct FileInfo(pub(crate) FSP_FSCTL_FILE_INFO);

impl FileInfo {
    pub const fn file_attributes(&self) -> FileAttributes {
        FileAttributes(self.0.FileAttributes)
    }

    pub const fn reparse_tag(&self) -> u32 {
        self.0.ReparseTag
    }

    pub const fn allocation_size(&self) -> u64 {
        self.0.AllocationSize
    }

    pub const fn file_size(&self) -> u64 {
        self.0.FileSize
    }

    pub const fn creation_time(&self) -> u64 {
        self.0.CreationTime
    }

    pub const fn last_access_time(&self) -> u64 {
        self.0.LastAccessTime
    }

    pub const fn last_write_time(&self) -> u64 {
        self.0.LastWriteTime
    }

    pub const fn change_time(&self) -> u64 {
        self.0.ChangeTime
    }

    pub const fn index_number(&self) -> u64 {
        self.0.IndexNumber
    }

    pub const fn hard_links(&self) -> u32 {
        self.0.HardLinks
    }

    pub const fn ea_size(&self) -> u32 {
        self.0.EaSize
    }

    pub fn set_file_attributes(&mut self, val: FileAttributes) -> &mut Self {
        self.0.FileAttributes = val.0;
        self
    }

    pub fn set_reparse_tag(&mut self, val: u32) -> &mut Self {
        self.0.ReparseTag = val;
        self
    }

    pub fn set_allocation_size(&mut self, val: u64) -> &mut Self {
        self.0.AllocationSize = val;
        self
    }

    pub fn set_file_size(&mut self, val: u64) -> &mut Self {
        self.0.FileSize = val;
        self
    }

    pub fn set_creation_time(&mut self, val: u64) -> &mut Self {
        self.0.CreationTime = val;
        self
    }

    pub fn set_last_access_time(&mut self, val: u64) -> &mut Self {
        self.0.LastAccessTime = val;
        self
    }

    pub fn set_last_write_time(&mut self, val: u64) -> &mut Self {
        self.0.LastWriteTime = val;
        self
    }

    pub fn set_change_time(&mut self, val: u64) -> &mut Self {
        self.0.ChangeTime = val;
        self
    }

    pub fn set_time(&mut self, val: u64) -> &mut Self {
        self.0.CreationTime = val;
        self.0.LastAccessTime = val;
        self.0.LastWriteTime = val;
        self.0.ChangeTime = val;
        self
    }

    pub fn set_index_number(&mut self, val: u64) -> &mut Self {
        self.0.IndexNumber = val;
        self
    }

    pub fn set_hard_links(&mut self, val: u32) -> &mut Self {
        self.0.HardLinks = val;
        self
    }

    pub fn set_ea_size(&mut self, val: u32) -> &mut Self {
        self.0.EaSize = val;
        self
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub struct VolumeInfo(pub(crate) FSP_FSCTL_VOLUME_INFO);

impl VolumeInfo {
    const VOLUME_LABEL_MAX_LEN: usize = 31;

    pub fn new(total_size: u64, free_size: u64, volume_label: &U16CStr) -> Self {
        assert!(volume_label.len() <= Self::VOLUME_LABEL_MAX_LEN);

        let mut vl = [0; Self::VOLUME_LABEL_MAX_LEN + 1];
        vl[..volume_label.len()].copy_from_slice(volume_label.as_slice());

        Self(FSP_FSCTL_VOLUME_INFO {
            TotalSize: total_size,
            FreeSize: free_size,
            VolumeLabelLength: (volume_label.len() * std::mem::size_of::<u16>()) as u16,
            VolumeLabel: vl,
        })
    }

    pub fn total_size(&self) -> u64 {
        self.0.TotalSize
    }

    pub fn free_size(&self) -> u64 {
        self.0.FreeSize
    }

    pub fn volume_label(&self) -> &U16CStr {
        U16CStr::from_slice(&self.0.VolumeLabel[..self.0.VolumeLabelLength as usize]).unwrap()
    }

    pub fn set_volume_label(&mut self, volume_label: &U16CStr) {
        assert!(volume_label.len() <= Self::VOLUME_LABEL_MAX_LEN);

        self.0.VolumeLabelLength = volume_label.len() as u16;
        self.0.VolumeLabel[..volume_label.len()].copy_from_slice(volume_label.as_slice());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CreateFileInfo {
    pub create_options: CreateOptions,
    pub granted_access: FileAccessRights,
    pub file_attributes: FileAttributes,
    pub allocation_size: u64,
}
