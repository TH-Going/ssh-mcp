use std::path::Path;

use crate::error::CoreResult;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Creates `path` (if missing) and restricts NTFS ACLs to Current User + SYSTEM on Windows 10/11.
pub fn ensure_private_directory(path: &Path) -> CoreResult<()> {
    std::fs::create_dir_all(path)?;

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        use std::process::Command;

        if let Some(sid) = current_user_sid() {
            let user_grant = format!("*{sid}:(OI)(CI)F");
            let _ = Command::new("icacls.exe")
                .arg(path)
                .args(["/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", &user_grant])
                .creation_flags(CREATE_NO_WINDOW)
                .output();
        }
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn current_user_sid() -> Option<String> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    let out = Command::new("whoami.exe")
        .args(["/user", "/fo", "csv", "/nh"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // Format: "DOMAIN\User","S-1-5-21-..."
    let line = text.lines().find(|l| !l.trim().is_empty())?;
    let last_col = line.rsplit(',').next()?.trim().trim_matches('"');
    if last_col.starts_with("S-1-") {
        Some(last_col.to_string())
    } else {
        None
    }
}
