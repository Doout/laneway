#![deny(unsafe_code)]
//! Access to private state containing device identities and password verifiers.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

fn permission_denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Laneway state must be owned by the current user and inaccessible to other users",
    )
}

fn parent(path: &Path) -> io::Result<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "state path has no directory"))
}

/// Create a new private directory, failing if it already exists.
pub fn create_directory(path: &Path) -> io::Result<()> {
    platform::make_directory(path)?;
    check_directory(path)
}

pub fn ensure_directory(path: &Path) -> io::Result<()> {
    match platform::make_directory(path) {
        Ok(()) => (),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => (),
        Err(err) => return Err(err),
    }
    check_directory(path)
}

pub fn check_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() {
        return Err(permission_denied());
    }
    platform::check(path, &metadata)
}

fn open_file(path: &Path, writable: bool) -> io::Result<File> {
    check_directory(parent(path)?)?;
    open_checked(path, writable)
}

/// Open an owner-only file, including token files outside a Laneway state directory.
pub fn open_private_file(path: &Path) -> io::Result<File> {
    open_checked(path, false)
}

fn open_checked(path: &Path, writable: bool) -> io::Result<File> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(permission_denied());
    }
    platform::check(path, &metadata)?;
    let mut options = OpenOptions::new();
    options.read(true).write(writable);
    platform::configure_open(&mut options);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(permission_denied());
    }
    platform::check(path, &metadata)?;
    Ok(file)
}

pub fn read(path: &Path) -> io::Result<Vec<u8>> {
    read_file(open_file(path, false)?)
}

pub use platform::StateStamp;

#[cfg(target_os = "linux")]
pub use platform::is_root;

pub fn read_if_changed(
    path: &Path,
    previous: Option<&StateStamp>,
) -> io::Result<Option<(StateStamp, Vec<u8>)>> {
    let file = open_file(path, false)?;
    let stamp = platform::stamp(&file)?;
    if previous == Some(&stamp) {
        return Ok(None);
    }
    let bytes = read_file(file)?;
    Ok(Some((stamp, bytes)))
}

fn read_file(file: File) -> io::Result<Vec<u8>> {
    // All state records written by this application are small.
    const MAX_STATE_BYTES: u64 = 1024 * 1024;
    let mut bytes = Vec::new();
    file.take(MAX_STATE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "state file is too large",
        ));
    }
    Ok(bytes)
}

pub fn write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    persist(path, bytes, true)
}

pub fn create(path: &Path, bytes: &[u8]) -> io::Result<()> {
    persist(path, bytes, false)
}

fn persist(path: &Path, bytes: &[u8], replace: bool) -> io::Result<()> {
    let directory = parent(path)?;
    check_directory(directory)?;
    if replace {
        match open_file(path, false) {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
    }
    let mut temporary = platform::temporary_file(directory)?;
    platform::check(temporary.path(), &temporary.as_file().metadata()?)?;
    temporary.as_file_mut().write_all(bytes)?;
    temporary.as_file().sync_all()?;
    if replace {
        temporary.persist(path)?;
    } else {
        temporary.persist_noclobber(path)?;
    }
    #[cfg(unix)]
    File::open(directory)?.sync_all()?;
    Ok(())
}

fn lock_file(path: &Path) -> io::Result<File> {
    match open_file(path, true) {
        Ok(file) => Ok(file),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            match create(path, &[]) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(err),
            }
            open_file(path, true)
        }
        Err(err) => Err(err),
    }
}

pub fn lock(path: &Path) -> io::Result<File> {
    let file = lock_file(path)?;
    fs2::FileExt::lock_exclusive(&file)?;
    Ok(file)
}

pub fn try_lock(path: &Path) -> io::Result<File> {
    let file = lock_file(path)?;
    fs2::FileExt::try_lock_exclusive(&file)?;
    Ok(file)
}

#[cfg(unix)]
#[allow(unsafe_code)] // Native owner and ACL checks use the operating system's C API.
mod platform {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};

    #[cfg(target_os = "linux")]
    pub fn is_root() -> bool {
        // The effective UID determines ownership of newly created state.
        unsafe { libc::geteuid() == 0 }
    }

    #[derive(PartialEq, Eq)]
    pub struct StateStamp {
        device: u64,
        inode: u64,
        size: u64,
        modified: (i64, i64),
        changed: (i64, i64),
    }

    pub(super) fn stamp(file: &File) -> io::Result<StateStamp> {
        let metadata = file.metadata()?;
        Ok(StateStamp {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }

    pub(super) fn make_directory(path: &Path) -> io::Result<()> {
        fs::DirBuilder::new().mode(0o700).create(path)
    }

    pub(super) fn temporary_file(directory: &Path) -> io::Result<tempfile::NamedTempFile> {
        tempfile::NamedTempFile::new_in(directory)
    }

    pub(super) fn configure_open(options: &mut OpenOptions) {
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }

    pub(super) fn check(path: &Path, metadata: &Metadata) -> io::Result<()> {
        // The effective UID is the identity under which files are opened.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(permission_denied());
        }
        #[cfg(target_os = "macos")]
        check_extended_acl(path)?;
        #[cfg(not(target_os = "macos"))]
        let _ = path;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn check_extended_acl(path: &Path) -> io::Result<()> {
        use std::ffi::{CString, c_void};
        use std::os::unix::ffi::OsStrExt;
        use std::ptr::null_mut;

        const ACL_TYPE_EXTENDED: libc::c_int = 0x100;
        const ACL_FIRST_ENTRY: libc::c_int = 0;
        const ACL_NEXT_ENTRY: libc::c_int = -1;
        const ACL_EXTENDED_DENY: libc::c_int = 2;
        unsafe extern "C" {
            fn acl_get_link_np(path: *const libc::c_char, kind: libc::c_int) -> *mut c_void;
            fn acl_get_entry(
                acl: *mut c_void,
                index: libc::c_int,
                entry: *mut *mut c_void,
            ) -> libc::c_int;
            fn acl_get_tag_type(entry: *mut c_void, tag: *mut libc::c_int) -> libc::c_int;
            fn acl_free(acl: *mut c_void) -> libc::c_int;
        }

        struct Acl(*mut c_void);

        impl Drop for Acl {
            fn drop(&mut self) {
                unsafe { acl_free(self.0) };
            }
        }

        // Darwin ACLs can grant access independently of Unix permission bits.
        let path = CString::new(path.as_os_str().as_bytes())?;
        let acl = unsafe { acl_get_link_np(path.as_ptr(), ACL_TYPE_EXTENDED) };
        if acl.is_null() {
            let err = io::Error::last_os_error();
            return match err.raw_os_error() {
                // Darwin reports ENOENT if the file has no extended ACL.
                Some(libc::ENOENT | libc::ENOTSUP) => Ok(()),
                _ => Err(err),
            };
        }
        let acl = Acl(acl);
        let mut index = ACL_FIRST_ENTRY;
        loop {
            let mut entry = null_mut();
            if unsafe { acl_get_entry(acl.0, index, &mut entry) } != 0 {
                let err = io::Error::last_os_error();
                return if err.raw_os_error() == Some(libc::EINVAL) {
                    Ok(())
                } else {
                    Err(err)
                };
            }
            let mut tag = 0;
            if unsafe { acl_get_tag_type(entry, &mut tag) } != 0 {
                return Err(io::Error::last_os_error());
            }
            if tag != ACL_EXTENDED_DENY {
                return Err(permission_denied());
            }
            index = ACL_NEXT_ENTRY;
        }
    }
}

#[cfg(windows)]
#[allow(unsafe_code)] // Token, file handle and DACL checks use the Windows security API.
mod platform {
    use super::*;
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
        GetTokenInformation, OWNER_SECURITY_INFORMATION, PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY,
        TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_ATTRIBUTE_TEMPORARY, FILE_BASIC_INFO, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileBasicInfo, FileIdInfo,
        GetFileInformationByHandleEx,
    };
    use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    #[derive(PartialEq, Eq)]
    pub struct StateStamp {
        volume: u64,
        id: [u8; 16],
        size: u64,
        modified: i64,
        changed: i64,
    }

    pub(super) fn stamp(file: &File) -> io::Result<StateStamp> {
        let handle = file.as_raw_handle();
        let mut id = FILE_ID_INFO::default();
        let mut basic = FILE_BASIC_INFO::default();
        unsafe {
            if GetFileInformationByHandleEx(
                handle,
                FileIdInfo,
                std::ptr::addr_of_mut!(id).cast(),
                size_of::<FILE_ID_INFO>() as u32,
            ) == 0
                || GetFileInformationByHandleEx(
                    handle,
                    FileBasicInfo,
                    std::ptr::addr_of_mut!(basic).cast(),
                    size_of::<FILE_BASIC_INFO>() as u32,
                ) == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(StateStamp {
            volume: id.VolumeSerialNumber,
            id: id.FileId.Identifier,
            size: file.metadata()?.len(),
            modified: basic.LastWriteTime,
            changed: basic.ChangeTime,
        })
    }

    struct LocalAllocation(*mut c_void);

    impl Drop for LocalAllocation {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { LocalFree(self.0) };
            }
        }
    }

    struct TokenHandle(HANDLE);

    impl Drop for TokenHandle {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    // Keep the aligned TOKEN_USER buffer alive so its embedded SID pointer remains valid.
    struct CurrentUser(Vec<usize>);

    impl CurrentUser {
        fn load() -> io::Result<Self> {
            unsafe {
                let mut token = null_mut();
                if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                    return Err(io::Error::last_os_error());
                }
                let token = TokenHandle(token);
                let mut bytes = 0;
                GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut bytes);
                if bytes == 0 {
                    return Err(io::Error::last_os_error());
                }
                let mut buffer = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())];
                if GetTokenInformation(
                    token.0,
                    TokenUser,
                    buffer.as_mut_ptr().cast(),
                    bytes,
                    &mut bytes,
                ) == 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(Self(buffer))
            }
        }

        fn sid(&self) -> PSID {
            unsafe { (*self.0.as_ptr().cast::<TOKEN_USER>()).User.Sid }
        }

        fn sid_string(&self) -> io::Result<String> {
            unsafe {
                let mut sid = null_mut();
                if ConvertSidToStringSidW(self.sid(), &mut sid) == 0 {
                    return Err(io::Error::last_os_error());
                }
                let _allocation = LocalAllocation(sid.cast());
                let length = (0..).take_while(|&index| *sid.add(index) != 0).count();
                Ok(String::from_utf16_lossy(std::slice::from_raw_parts(
                    sid, length,
                )))
            }
        }
    }

    fn path_to_wide(path: &Path) -> io::Result<Vec<u16>> {
        let path = std::path::absolute(path)?;
        let wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        if wide.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "state path contains NUL",
            ));
        }
        Ok(wide.into_iter().chain([0]).collect())
    }

    pub(super) fn make_directory(path: &Path) -> io::Result<()> {
        let path = path_to_wide(path)?;
        with_owner_security("OICI", |attributes| {
            if unsafe { CreateDirectoryW(path.as_ptr(), attributes) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })
    }

    pub(super) fn temporary_file(directory: &Path) -> io::Result<tempfile::NamedTempFile> {
        // Windows can default the file's owner to a group in the access token.
        with_owner_security("", |attributes| {
            tempfile::Builder::new().make_in(directory, |path| {
                let path = path_to_wide(path)?;
                let handle = unsafe {
                    CreateFileW(
                        path.as_ptr(),
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        attributes,
                        CREATE_NEW,
                        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_OPEN_REPARSE_POINT,
                        null_mut(),
                    )
                };
                if handle == INVALID_HANDLE_VALUE {
                    return Err(io::Error::last_os_error());
                }
                Ok(unsafe { File::from_raw_handle(handle) })
            })
        })
    }

    fn with_owner_security<T>(
        inheritance: &str,
        create: impl FnOnce(&SECURITY_ATTRIBUTES) -> io::Result<T>,
    ) -> io::Result<T> {
        let sid = CurrentUser::load()?.sid_string()?;
        let descriptor: Vec<u16> = format!("O:{sid}D:P(A;{inheritance};FA;;;{sid})")
            .encode_utf16()
            .chain([0])
            .collect();
        let mut allocation = LocalAllocation(null_mut());
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                descriptor.as_ptr(),
                SDDL_REVISION_1,
                &mut allocation.0,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        create(&SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: allocation.0,
            bInheritHandle: 0,
        })
    }

    pub(super) fn configure_open(options: &mut OpenOptions) {
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }

    pub(super) fn check(path: &Path, metadata: &Metadata) -> io::Result<()> {
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(permission_denied());
        }
        let path = path_to_wide(path)?;
        let current_user = CurrentUser::load()?;
        let mut owner = null_mut();
        let mut acl = null_mut();
        let mut descriptor = LocalAllocation(null_mut());
        unsafe {
            let status = GetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut acl,
                null_mut(),
                &mut descriptor.0,
            );
            if status != 0 {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            if owner.is_null() || EqualSid(owner, current_user.sid()) == 0 || acl.is_null() {
                return Err(permission_denied());
            }
            if (*acl).AceCount == 0 {
                return Err(permission_denied());
            }
            for index in 0..u32::from((*acl).AceCount) {
                let mut ace = null_mut();
                if GetAce(acl, index, &mut ace) == 0 || ace.is_null() {
                    return Err(permission_denied());
                }
                if u32::from((*ace.cast::<ACE_HEADER>()).AceType) != ACCESS_ALLOWED_ACE_TYPE {
                    return Err(permission_denied());
                }
                let sid = std::ptr::addr_of_mut!((*ace.cast::<ACCESS_ALLOWED_ACE>()).SidStart);
                if EqualSid(sid.cast(), current_user.sid()) == 0 {
                    return Err(permission_denied());
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_create_and_replace_are_distinct() {
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("state");
        ensure_directory(&directory).unwrap();
        let path = directory.join("file");

        create(&path, b"original").unwrap();
        assert_eq!(
            create(&path, b"duplicate").unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(read(&path).unwrap(), b"original");
        write(&path, b"replaced").unwrap();
        assert_eq!(read(&path).unwrap(), b"replaced");
    }

    #[test]
    fn unchanged_state_skips_reads_and_replacement_keeps_identity_distinct() {
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("state");
        ensure_directory(&directory).unwrap();
        let path = directory.join("file");
        create(&path, b"first").unwrap();

        let (first, bytes) = read_if_changed(&path, None).unwrap().unwrap();
        assert_eq!(bytes, b"first");
        assert!(read_if_changed(&path, Some(&first)).unwrap().is_none());

        write(&path, b"other").unwrap();
        let (other, bytes) = read_if_changed(&path, Some(&first)).unwrap().unwrap();
        assert_eq!(bytes, b"other");
        assert!(other != first);
        assert!(read_if_changed(&path, Some(&other)).unwrap().is_none());
    }

    #[test]
    fn lock_is_released_when_file_is_dropped() {
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("state");
        ensure_directory(&directory).unwrap();
        let path = directory.join("lock");

        let guard = lock(&path).unwrap();
        assert!(try_lock(&path).is_err());
        drop(guard);
        assert!(try_lock(&path).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn public_files_and_links_are_rejected() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("state");
        ensure_directory(&directory).unwrap();
        let public = directory.join("public");
        create(&public, b"public").unwrap();
        fs::set_permissions(&public, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            read(&public).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            write(&public, b"private").unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );

        let private = directory.join("private");
        create(&private, b"private").unwrap();
        let link = directory.join("link");
        symlink(&private, &link).unwrap();
        assert_eq!(
            read(&link).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            write(&link, b"replacement").unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(read(&private).unwrap(), b"private");
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn extended_acl_must_not_grant_access() {
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("state");
        ensure_directory(&directory).unwrap();
        let path = directory.join("file");
        create(&path, b"private").unwrap();

        assert!(
            std::process::Command::new("/bin/chmod")
                .args(["+a", "everyone allow read"])
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(
            read(&path).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
