use windows::Win32::Foundation::{HANDLE, BOOL, CloseHandle, GetLastError};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::Storage::FileSystem::{CreateFileA, FILE_SHARE_MODE,
    FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES};
use windows::core::PCSTR;
use std::ffi::CString;
use std::os::raw::c_void;

type Result<T> = std::result::Result<T, &'static str>;

/// Wrapper for Win32 `CloseHandle`
pub fn close_handle(handle: HANDLE) {
    unsafe {
        CloseHandle(handle);
    }
}

/// Wrapper for Win32 `CreateFileA` with default parameters:
/// - GENERIC_READ
/// - FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_NO_BUFFERING
pub unsafe fn create_file_read(file_path: &str) -> Result<HANDLE> {
    // this is bad and I feel bad
    let path = PCSTR::from_raw(
        CString::new(file_path)
        .unwrap()
        .into_raw() as *const u8);

    let template: HANDLE = HANDLE::default();
    let result = CreateFileA(
        path,
        0x80000000, // GENERIC_READ
        FILE_SHARE_MODE(0x1), // FILE_SHARE_READ
        None,
        FILE_CREATION_DISPOSITION(0x3), // OPEN_EXISTING
        // FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_NO_BUFFERING
        FILE_FLAGS_AND_ATTRIBUTES(0x80 | 0x08000000 | 0x20000000),
        template,
    );

    match result {
        Ok(handle) => Ok(handle),
        Err(_) => Err("CreateFileA failed!"),
    }
}

/// Wrapper for Win32 `DeviceIoControl`
pub unsafe fn device_io_control(
    device_handle: HANDLE, 
    control_code: u32, 
    in_buffer: &mut [u8],
    out_buffer: &mut [u8]) -> Result<()> {
    let mut bytes_returned = 0;

    let result = DeviceIoControl(
        device_handle,
        control_code,
        Some(in_buffer.as_mut_ptr() as *const c_void),
        in_buffer.len() as u32,
        Some(out_buffer.as_mut_ptr() as *mut c_void),
        out_buffer.len() as u32,
        Some(&mut bytes_returned),
        None,
    );

    match result {
        BOOL(0) => {
            println!("Error: {:#?}", GetLastError());
            Err("DeviceIoControl failed!")
        },
        _ => Ok(()),
    }
}