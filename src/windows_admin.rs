use std::{
    env,
    ffi::{OsStr, c_void},
    io,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle},
    },
    ptr,
    sync::OnceLock,
};

const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_ELEVATION_CLASS: i32 = 20;
const ERROR_CANCELLED: i32 = 1223;
const SEE_MASK_NOASYNC: u32 = 0x0000_0100;
const SEE_MASK_FLAG_NO_UI: u32 = 0x0000_0400;
const SW_SHOWNORMAL: i32 = 1;
const COINIT_APARTMENTTHREADED: u32 = 0x2;
const COINIT_DISABLE_OLE1DDE: u32 = 0x4;
const RELAUNCH_ARGUMENT: &str = "--toolbox-elevation-attempted";

// Layout of SHELLEXECUTEINFOW. The unused hIcon/hMonitor union holds one handle.
#[repr(C)]
#[derive(Default)]
struct ShellExecuteInfo {
    size: u32,
    mask: u32,
    window: RawHandle,
    verb: *const u16,
    file: *const u16,
    parameters: *const u16,
    directory: *const u16,
    show: i32,
    instance: RawHandle,
    id_list: *mut c_void,
    class: *const u16,
    class_key: RawHandle,
    hot_key: u32,
    icon_or_monitor: RawHandle,
    process: RawHandle,
}

#[link(name = "shell32")]
unsafe extern "system" {
    fn ShellExecuteExW(info: *mut ShellExecuteInfo) -> i32;
}

#[link(name = "ole32")]
unsafe extern "system" {
    fn CoInitializeEx(reserved: *mut c_void, flags: u32) -> i32;
    fn CoUninitialize();
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> RawHandle;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process: RawHandle, access: u32, token: *mut RawHandle) -> i32;
    fn GetTokenInformation(
        token: RawHandle,
        information_class: i32,
        information: *mut c_void,
        information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

pub(crate) fn is_elevated() -> bool {
    static ELEVATED: OnceLock<bool> = OnceLock::new();
    *ELEVATED.get_or_init(|| query_elevation().unwrap_or(false))
}

/// Returns true once Windows has launched the replacement process.
pub(crate) fn relaunch_if_needed() -> io::Result<bool> {
    if env::args_os()
        .skip(1)
        .any(|argument| argument == RELAUNCH_ARGUMENT)
        || query_elevation()?
    {
        return Ok(false);
    }

    let executable = env::current_exe()?;
    let executable: Vec<u16> = executable.as_os_str().encode_wide().chain([0]).collect();
    let verb: Vec<u16> = OsStr::new("runas").encode_wide().chain([0]).collect();
    let parameters: Vec<u16> = OsStr::new(RELAUNCH_ARGUMENT)
        .encode_wide()
        .chain([0])
        .collect();
    let mut info = ShellExecuteInfo {
        size: size_of::<ShellExecuteInfo>() as u32,
        mask: SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
        verb: verb.as_ptr(),
        file: executable.as_ptr(),
        parameters: parameters.as_ptr(),
        show: SW_SHOWNORMAL,
        ..ShellExecuteInfo::default()
    };

    let _apartment = ComApartment::initialize()?;
    // SAFETY: The structure has Win32 layout and lives through the call, as
    // do all three NUL-terminated strings. No returned handle is requested.
    if unsafe { ShellExecuteExW(&mut info) } != 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(ERROR_CANCELLED) {
        Ok(false)
    } else {
        Err(error)
    }
}

struct ComApartment;

impl ComApartment {
    fn initialize() -> io::Result<Self> {
        // SAFETY: COM requires a null reserved pointer. This guard balances a
        // successful initialization on the same thread.
        let result = unsafe {
            CoInitializeEx(
                ptr::null_mut(),
                COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE,
            )
        };
        if result < 0 {
            Err(io::Error::other(format!(
                "COM initialization failed (HRESULT {result:#010x})"
            )))
        } else {
            Ok(Self)
        }
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        // SAFETY: This guard is created only after successful initialization.
        unsafe { CoUninitialize() };
    }
}

fn query_elevation() -> io::Result<bool> {
    let mut token = ptr::null_mut();
    // SAFETY: GetCurrentProcess yields a valid pseudo-handle. The output points
    // to writable handle storage for OpenProcessToken.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: On success OpenProcessToken provides a newly owned token handle.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };

    // TOKEN_ELEVATION contains a single DWORD, TokenIsElevated.
    let mut elevated = 0_u32;
    let mut returned = 0_u32;
    // SAFETY: The handle stays open and both output pointers refer to writable
    // DWORDs. The buffer length matches the requested TOKEN_ELEVATION layout.
    let success = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TOKEN_ELEVATION_CLASS,
            ptr::from_mut(&mut elevated).cast(),
            size_of::<u32>() as u32,
            &mut returned,
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(elevated != 0)
}
