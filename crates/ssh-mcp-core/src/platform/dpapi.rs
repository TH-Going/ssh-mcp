use std::ptr::{null, null_mut};
use zeroize::Zeroizing;

use crate::error::{CoreError, CoreResult};

#[cfg(target_os = "windows")]
mod win {
    use super::*;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    const ENTROPY: &[u8] = b"ssh-mcp-master-key:v1";

    pub fn protect_current_user(plaintext: &[u8]) -> CoreResult<Vec<u8>> {
        let mut in_buf = plaintext.to_vec();
        let mut entropy_buf = ENTROPY.to_vec();
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: in_buf.len() as u32,
            pbData: in_buf.as_mut_ptr(),
        };
        let entropy_blob = CRYPT_INTEGER_BLOB {
            cbData: entropy_buf.len() as u32,
            pbData: entropy_buf.as_mut_ptr(),
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: null_mut(),
        };

        let ok = unsafe {
            CryptProtectData(
                &in_blob,
                null(),
                &entropy_blob,
                null(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };
        zeroize::Zeroize::zeroize(&mut in_buf);

        if ok == 0 || out_blob.pbData.is_null() {
            return Err(CoreError::Crypto(
                "Windows DPAPI 加密主密钥失败".to_string(),
            ));
        }

        let protected =
            unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec() };
        unsafe {
            LocalFree(out_blob.pbData as _);
        }
        Ok(protected)
    }

    pub fn unprotect_current_user(ciphertext: &[u8]) -> CoreResult<Zeroizing<Vec<u8>>> {
        let mut in_buf = ciphertext.to_vec();
        let mut entropy_buf = ENTROPY.to_vec();
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: in_buf.len() as u32,
            pbData: in_buf.as_mut_ptr(),
        };
        let entropy_blob = CRYPT_INTEGER_BLOB {
            cbData: entropy_buf.len() as u32,
            pbData: entropy_buf.as_mut_ptr(),
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: null_mut(),
        };

        let ok = unsafe {
            CryptUnprotectData(
                &in_blob,
                null_mut(),
                &entropy_blob,
                null(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };

        if ok == 0 || out_blob.pbData.is_null() {
            return Err(CoreError::Crypto(
                "Windows DPAPI 解密主密钥失败（可能当前登录用户与创建者不一致）".to_string(),
            ));
        }

        let slice = unsafe { std::slice::from_raw_parts_mut(out_blob.pbData, out_blob.cbData as usize) };
        let plain = Zeroizing::new(slice.to_vec());
        zeroize::Zeroize::zeroize(slice);
        unsafe {
            LocalFree(out_blob.pbData as _);
        }
        Ok(plain)
    }
}

pub fn dpapi_protect(plaintext: &[u8]) -> CoreResult<Vec<u8>> {
    #[cfg(target_os = "windows")]
    {
        win::protect_current_user(plaintext)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = plaintext;
        Err(CoreError::Internal("仅支持 Windows 10/11".to_string()))
    }
}

pub fn dpapi_unprotect(ciphertext: &[u8]) -> CoreResult<Zeroizing<Vec<u8>>> {
    #[cfg(target_os = "windows")]
    {
        win::unprotect_current_user(ciphertext)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = ciphertext;
        Err(CoreError::Internal("仅支持 Windows 10/11".to_string()))
    }
}
