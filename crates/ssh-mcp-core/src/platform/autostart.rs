use std::path::Path;

use crate::error::{CoreError, CoreResult};

#[cfg(target_os = "windows")]
mod win {
    use super::*;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW,
        RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE,
        REG_SZ,
    };

    const RUN_SUBKEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    const VALUE_NAME: &str = "SshMcpConsole";

    fn to_wide_null(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    pub fn is_enabled() -> bool {
        let subkey = to_wide_null(RUN_SUBKEY);
        let value_name = to_wide_null(VALUE_NAME);
        let mut hkey: HKEY = null_mut();
        let open_status = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                KEY_READ,
                &mut hkey,
            )
        };
        if open_status != ERROR_SUCCESS {
            return false;
        }
        let mut data_len: u32 = 0;
        let query_status = unsafe {
            RegQueryValueExW(
                hkey,
                value_name.as_ptr(),
                null(),
                null_mut(),
                null_mut(),
                &mut data_len,
            )
        };
        unsafe {
            RegCloseKey(hkey);
        }
        query_status == ERROR_SUCCESS && data_len > 2
    }

    pub fn set_enabled(enabled: bool, exe_path: &Path) -> CoreResult<()> {
        let subkey = to_wide_null(RUN_SUBKEY);
        let value_name = to_wide_null(VALUE_NAME);
        let mut hkey: HKEY = null_mut();
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                null(),
                &mut hkey,
                null_mut(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(CoreError::Internal(format!(
                "无法打开 Windows 注册表启动项 (code={status})"
            )));
        }

        let res = if enabled {
            let cmd = format!("\"{}\" --minimized", exe_path.display());
            let wide = to_wide_null(&cmd);
            let bytes_len = (wide.len() * 2) as u32;
            let write_status = unsafe {
                RegSetValueExW(
                    hkey,
                    value_name.as_ptr(),
                    0,
                    REG_SZ,
                    wide.as_ptr() as *const u8,
                    bytes_len,
                )
            };
            if write_status != ERROR_SUCCESS {
                Err(CoreError::Internal(format!(
                    "写入开机自启注册表失败 (code={write_status})"
                )))
            } else {
                Ok(())
            }
        } else {
            let _ = unsafe { RegDeleteValueW(hkey, value_name.as_ptr()) };
            Ok(())
        };

        unsafe {
            RegCloseKey(hkey);
        }
        res
    }
}

pub fn is_autostart_enabled() -> bool {
    #[cfg(target_os = "windows")]
    {
        win::is_enabled()
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

pub fn set_autostart_enabled(enabled: bool, exe_path: &Path) -> CoreResult<()> {
    #[cfg(target_os = "windows")]
    {
        win::set_enabled(enabled, exe_path)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (enabled, exe_path);
        Ok(())
    }
}

pub fn sync_autostart_path_if_enabled(exe_path: &Path) {
    if is_autostart_enabled() {
        let _ = set_autostart_enabled(true, exe_path);
    }
}
