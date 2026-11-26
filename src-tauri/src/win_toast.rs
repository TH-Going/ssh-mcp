#[cfg(windows)]
mod imp {
    use std::collections::{HashMap, HashSet};
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::{null, null_mut};
    use std::sync::{Arc, OnceLock};

    use parking_lot::Mutex;
    use ssh_mcp_core::models::{Approval, ApprovalRiskLevel};
    use windows::core::{h, w, BOOL, GUID, HSTRING, IInspectable, Interface, Ref, PCWSTR};
    use windows::Data::Xml::Dom::XmlDocument;
    use windows::Foundation::TypedEventHandler;
    use windows::Win32::Foundation::{CLASS_E_NOAGGREGATION, E_NOINTERFACE, ERROR_SUCCESS};
    use windows::Win32::System::Com::{
        CoInitializeEx, CoRegisterClassObject, IClassFactory, IClassFactory_Impl,
        CLSCTX_LOCAL_SERVER, COINIT_MULTITHREADED, REGCLS_MULTIPLEUSE,
    };
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE,
        REG_OPTION_NON_VOLATILE, REG_SZ,
    };
    use windows::Win32::UI::Notifications::{
        INotificationActivationCallback, INotificationActivationCallback_Impl,
        NOTIFICATION_USER_INPUT_DATA,
    };
    use windows::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID;
    use windows::UI::Notifications::{
        ToastActivatedEventArgs, ToastDismissedEventArgs, ToastNotification,
        ToastNotificationManager,
    };

    pub const APP_USER_MODEL_ID: &str = "com.sshmcp.console";
    const APP_DISPLAY_NAME: &str = "服务器控制台";
    const POWERSHELL_FALLBACK_AUMID: &str =
        "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe";
    const APPROVAL_GROUP: &str = "approvals";

    // Fixed COM Activator CLSID for ssh-mcp interactive Windows Toast notifications
    const TOAST_ACTIVATOR_CLSID: GUID = GUID::from_u128(0xd8e4f6a2_9c3b_4e71_b5a0_3f1d8c9e2a47);
    const TOAST_ACTIVATOR_CLSID_STR: &str = "{D8E4F6A2-9C3B-4E71-B5A0-3F1D8C9E2A47}";

    const EMBEDDED_ICON_PNG: &[u8] = include_bytes!("../icons/128x128.png");

    #[derive(Debug, Clone)]
    pub enum ToastActionEvent {
        Approve { approval_id: String },
        Reject { approval_id: String },
        OpenApproval { approval_id: String },
        OpenConsole,
    }

    type ActionCallback = Arc<dyn Fn(ToastActionEvent) + Send + Sync + 'static>;

    static ACTION_CALLBACK: OnceLock<ActionCallback> = OnceLock::new();
    static ACTIVE_APPROVAL_TOASTS: OnceLock<Mutex<HashMap<String, ToastNotification>>> =
        OnceLock::new();
    static AUMID_REGISTERED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    fn active_toasts() -> &'static Mutex<HashMap<String, ToastNotification>> {
        ACTIVE_APPROVAL_TOASTS.get_or_init(|| Mutex::new(HashMap::new()))
    }

    fn to_wide_null(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn write_hkcu_sz(subkey: &str, value_name: Option<&str>, data: &str) -> Result<(), String> {
        let subkey_w = to_wide_null(subkey);
        let mut hkey: HKEY = HKEY::default();
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(subkey_w.as_ptr()),
                Some(0),
                PCWSTR(null()),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                None,
                &mut hkey,
                None,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!("RegCreateKeyExW({subkey}) failed: {:?}", status));
        }

        let name_w = value_name.map(to_wide_null);
        let name_ptr = name_w
            .as_ref()
            .map(|v| PCWSTR(v.as_ptr()))
            .unwrap_or(PCWSTR(null()));

        let data_w = to_wide_null(data);
        let bytes =
            unsafe { std::slice::from_raw_parts(data_w.as_ptr() as *const u8, data_w.len() * 2) };

        let write_status =
            unsafe { RegSetValueExW(hkey, name_ptr, Some(0), REG_SZ, Some(bytes)) };
        let _ = unsafe { RegCloseKey(hkey) };

        if write_status != ERROR_SUCCESS {
            return Err(format!("RegSetValueExW({subkey}) failed: {:?}", write_status));
        }
        Ok(())
    }

    fn register_aumid_and_com_server(data_dir: &Path) -> Result<(), String> {
        let icon_path = data_dir.join("toast-icon.png");
        let need_write_icon = match std::fs::metadata(&icon_path) {
            Ok(meta) => meta.len() != EMBEDDED_ICON_PNG.len() as u64,
            Err(_) => true,
        };
        if need_write_icon {
            let _ = std::fs::write(&icon_path, EMBEDDED_ICON_PNG);
        }

        let aumid_key = format!("Software\\Classes\\AppUserModelId\\{APP_USER_MODEL_ID}");
        write_hkcu_sz(&aumid_key, Some("DisplayName"), APP_DISPLAY_NAME)?;
        if icon_path.exists() {
            write_hkcu_sz(
                &aumid_key,
                Some("IconUri"),
                &icon_path.to_string_lossy(),
            )?;
        }
        write_hkcu_sz(&aumid_key, Some("CustomActivator"), TOAST_ACTIVATOR_CLSID_STR)?;

        if let Ok(exe) = std::env::current_exe() {
            let clsid_key =
                format!("Software\\Classes\\CLSID\\{TOAST_ACTIVATOR_CLSID_STR}\\LocalServer32");
            let launch_cmd = format!("\"{}\" --toast-activated", exe.display());
            write_hkcu_sz(&clsid_key, None, &launch_cmd)?;
        }

        Ok(())
    }

    #[windows_core::implement(INotificationActivationCallback)]
    struct ToastActivationHandler;

    impl INotificationActivationCallback_Impl for ToastActivationHandler_Impl {
        fn Activate(
            &self,
            _appusermodelid: &PCWSTR,
            invokedargs: &PCWSTR,
            _data: *const NOTIFICATION_USER_INPUT_DATA,
            _count: u32,
        ) -> windows_core::Result<()> {
            let args = if invokedargs.is_null() {
                String::new()
            } else {
                unsafe { invokedargs.to_string().unwrap_or_default() }
            };
            dispatch_raw_args(&args);
            Ok(())
        }
    }

    #[windows_core::implement(IClassFactory)]
    struct ToastActivatorFactory;

    impl IClassFactory_Impl for ToastActivatorFactory_Impl {
        fn CreateInstance(
            &self,
            punkouter: windows_core::Ref<windows_core::IUnknown>,
            riid: *const GUID,
            ppvobject: *mut *mut core::ffi::c_void,
        ) -> windows_core::Result<()> {
            if ppvobject.is_null() {
                return Err(windows_core::Error::from_hresult(E_NOINTERFACE));
            }
            unsafe {
                *ppvobject = null_mut();
            }
            if punkouter.is_some() {
                return Err(windows_core::Error::from_hresult(CLASS_E_NOAGGREGATION));
            }
            let handler: INotificationActivationCallback = ToastActivationHandler.into();
            unsafe { handler.query(riid, ppvobject).ok() }
        }

        fn LockServer(&self, _flock: BOOL) -> windows_core::Result<()> {
            Ok(())
        }
    }

    fn start_com_activator_worker() {
        let _ = std::thread::Builder::new()
            .name("win-toast-com-activator".to_string())
            .spawn(|| unsafe {
                let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
                let factory: IClassFactory = ToastActivatorFactory.into();
                match CoRegisterClassObject(
                    &TOAST_ACTIVATOR_CLSID,
                    &factory,
                    CLSCTX_LOCAL_SERVER,
                    REGCLS_MULTIPLEUSE,
                ) {
                    Ok(_cookie) => {
                        // Keep the MTA thread and COM registration alive for the lifetime of the app.
                        loop {
                            std::thread::park();
                        }
                    }
                    Err(err) => {
                        tracing::warn!("Failed to register COM Toast activator: {err}");
                    }
                }
            });
    }

    pub fn initialize<F>(data_dir: &Path, handler: F)
    where
        F: Fn(ToastActionEvent) + Send + Sync + 'static,
    {
        let _ = ACTION_CALLBACK.set(Arc::new(handler));

        unsafe {
            let _ = SetCurrentProcessExplicitAppUserModelID(w!("com.sshmcp.console"));
        }

        match register_aumid_and_com_server(data_dir) {
            Ok(()) => {
                AUMID_REGISTERED.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            Err(err) => {
                tracing::warn!("Failed to register Windows Toast AUMID: {err}");
            }
        }

        start_com_activator_worker();
    }

    fn parse_toast_args(raw: &str) -> ToastActionEvent {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return ToastActionEvent::OpenConsole;
        }

        let mut action: Option<&str> = None;
        let mut approval_id: Option<String> = None;

        for pair in trimmed.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                match k {
                    "action" => action = Some(v),
                    "approval_id" => approval_id = Some(v.to_string()),
                    _ => {}
                }
            }
        }

        match (action, approval_id) {
            (Some("approve"), Some(id)) if !id.is_empty() => {
                ToastActionEvent::Approve { approval_id: id }
            }
            (Some("reject"), Some(id)) if !id.is_empty() => {
                ToastActionEvent::Reject { approval_id: id }
            }
            (Some("open"), Some(id)) if !id.is_empty() => {
                ToastActionEvent::OpenApproval { approval_id: id }
            }
            _ => ToastActionEvent::OpenConsole,
        }
    }

    fn dispatch_raw_args(raw: &str) {
        let event = parse_toast_args(raw);
        if let Some(cb) = ACTION_CALLBACK.get() {
            cb(event);
        }
    }

    fn approval_toast_tag(approval_id: &str) -> String {
        let compact: String = approval_id.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if compact.len() >= 16 {
            compact[..16].to_string()
        } else if !compact.is_empty() {
            compact
        } else {
            approval_id.chars().take(16).collect()
        }
    }

    fn extract_activated_args(insp: Ref<'_, IInspectable>) -> String {
        if let Some(insp) = insp.as_ref() {
            if let Ok(args) = insp.cast::<ToastActivatedEventArgs>() {
                if let Ok(s) = args.Arguments() {
                    return s.to_string();
                }
            }
        }
        String::new()
    }

    fn active_aumid() -> &'static str {
        if AUMID_REGISTERED.load(std::sync::atomic::Ordering::SeqCst) {
            APP_USER_MODEL_ID
        } else {
            POWERSHELL_FALLBACK_AUMID
        }
    }

    fn show_xml_toast(
        doc: &XmlDocument,
        tag_group: Option<(&str, &str)>,
        approval_id_for_keepalive: Option<&str>,
        default_launch_args: &str,
    ) -> windows_core::Result<()> {
        let toast = ToastNotification::CreateToastNotification(doc)?;

        if let Some((tag, group)) = tag_group {
            let _ = toast.SetTag(&HSTRING::from(tag));
            let _ = toast.SetGroup(&HSTRING::from(group));
        }

        let fallback_args = default_launch_args.to_string();
        let keepalive_id_act = approval_id_for_keepalive.map(str::to_string);
        toast.Activated(&TypedEventHandler::<ToastNotification, IInspectable>::new(
            move |_, insp| {
                let raw = extract_activated_args(insp);
                if raw.is_empty() {
                    dispatch_raw_args(&fallback_args);
                } else {
                    dispatch_raw_args(&raw);
                }
                if let Some(id) = &keepalive_id_act {
                    active_toasts().lock().remove(id);
                }
                Ok(())
            },
        ))?;

        let keepalive_id_dis = approval_id_for_keepalive.map(str::to_string);
        toast.Dismissed(
            &TypedEventHandler::<ToastNotification, ToastDismissedEventArgs>::new(
                move |_, _| {
                    if let Some(id) = &keepalive_id_dis {
                        active_toasts().lock().remove(id);
                    }
                    Ok(())
                },
            ),
        )?;

        if let Some(id) = approval_id_for_keepalive {
            active_toasts().lock().insert(id.to_string(), toast.clone());
        }

        let primary_id = active_aumid();
        let primary_res = ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(
            primary_id,
        ))
        .and_then(|notifier| notifier.Show(&toast));

        if let Err(err) = primary_res {
            if primary_id != POWERSHELL_FALLBACK_AUMID {
                tracing::warn!(
                    "Toast show with custom AUMID failed ({err}), falling back to system AUMID"
                );
                let notifier = ToastNotificationManager::CreateToastNotifierWithId(
                    &HSTRING::from(POWERSHELL_FALLBACK_AUMID),
                )?;
                notifier.Show(&toast)?;
                return Ok(());
            }
            if let Some(id) = approval_id_for_keepalive {
                active_toasts().lock().remove(id);
            }
            return Err(err);
        }

        Ok(())
    }

    fn sanitize_xml_text(input: &str) -> String {
        let mut out = String::with_capacity(input.len() + 16);
        for ch in input.chars() {
            match ch {
                '&' => out.push_str("&amp;"),
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '"' => out.push_str("&quot;"),
                '\'' => out.push_str("&apos;"),
                '\n' | '\r' | '\t' => out.push(ch),
                c if c.is_control() => {}
                c => out.push(c),
            }
        }
        out
    }

    fn build_approval_toast_xml(approval: &Approval) -> (String, String) {
        let risk_text = match approval.risk {
            ApprovalRiskLevel::High => "高风险",
            _ => "中风险",
        };
        let title = format!("待审批（{risk_text}）· {}", approval.server_name);
        let sudo_suffix = if approval.sudo { "（sudo 提权）" } else { "" };
        let line1 = format!(
            "{} 发起 {}{}",
            approval.requester, approval.tool_label, sudo_suffix
        );
        let line2 = &approval.command_preview;

        let open_args = format!("action=open&approval_id={}", approval.id);
        let approve_args = format!("action=approve&approval_id={}", approval.id);
        let reject_args = format!("action=reject&approval_id={}", approval.id);

        let xml = format!(
            r#"<toast scenario="reminder" launch="{launch}"><visual><binding template="ToastGeneric"><text>{t1}</text><text>{t2}</text><text>{t3}</text></binding></visual><actions><action content="批准" arguments="{approve}"/><action content="拒绝" arguments="{reject}"/></actions></toast>"#,
            launch = sanitize_xml_text(&open_args),
            t1 = sanitize_xml_text(&title),
            t2 = sanitize_xml_text(&line1),
            t3 = sanitize_xml_text(line2),
            approve = sanitize_xml_text(&approve_args),
            reject = sanitize_xml_text(&reject_args),
        );
        (xml, open_args)
    }

    fn build_alert_toast_xml(title: &str, body: &str) -> String {
        format!(
            r#"<toast launch="action=open_console"><visual><binding template="ToastGeneric"><text>{t1}</text><text>{t2}</text></binding></visual></toast>"#,
            t1 = sanitize_xml_text(title),
            t2 = sanitize_xml_text(body),
        )
    }

    pub fn show_approval_toast(approval: &Approval) {
        if let Err(err) = try_show_approval_toast(approval) {
            tracing::warn!("Failed to display interactive approval toast: {err}");
        }
    }

    fn try_show_approval_toast(approval: &Approval) -> windows_core::Result<()> {
        let (xml, open_args) = build_approval_toast_xml(approval);
        let doc = XmlDocument::new()?;
        doc.LoadXml(&HSTRING::from(&xml))?;

        let tag = approval_toast_tag(&approval.id);
        show_xml_toast(
            &doc,
            Some((&tag, APPROVAL_GROUP)),
            Some(&approval.id),
            &open_args,
        )
    }

    pub fn show_alert_toast(title: &str, body: &str) {
        if let Err(err) = try_show_alert_toast(title, body) {
            tracing::warn!("Failed to display alert toast: {err}");
        }
    }

    fn try_show_alert_toast(title: &str, body: &str) -> windows_core::Result<()> {
        let xml = build_alert_toast_xml(title, body);
        let doc = XmlDocument::new()?;
        doc.LoadXml(&HSTRING::from(&xml))?;

        show_xml_toast(&doc, None, None, "action=open_console")
    }

    pub fn remove_approval_toast(approval_id: &str) {
        active_toasts().lock().remove(approval_id);
        let tag = HSTRING::from(approval_toast_tag(approval_id));
        let group = h!("approvals");
        if let Ok(history) = ToastNotificationManager::History() {
            let _ = history.RemoveGroupedTagWithId(&tag, group, &HSTRING::from(APP_USER_MODEL_ID));
            let _ = history.RemoveGroupedTagWithId(
                &tag,
                group,
                &HSTRING::from(POWERSHELL_FALLBACK_AUMID),
            );
        }
    }

    pub fn sync_pending_approvals(pending_ids: &HashSet<String>) {
        let stale_ids: Vec<String> = active_toasts()
            .lock()
            .keys()
            .filter(|id| !pending_ids.contains(*id))
            .cloned()
            .collect();
        for id in stale_ids {
            remove_approval_toast(&id);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parses_approve_and_reject_toast_arguments() {
            assert!(matches!(
                parse_toast_args("action=approve&approval_id=abc-123"),
                ToastActionEvent::Approve { approval_id } if approval_id == "abc-123"
            ));
            assert!(matches!(
                parse_toast_args("action=reject&approval_id=abc-123"),
                ToastActionEvent::Reject { approval_id } if approval_id == "abc-123"
            ));
            assert!(matches!(
                parse_toast_args("action=open&approval_id=abc-123"),
                ToastActionEvent::OpenApproval { approval_id } if approval_id == "abc-123"
            ));
            assert!(matches!(
                parse_toast_args(""),
                ToastActionEvent::OpenConsole
            ));
        }

        #[test]
        fn generates_bounded_16_char_toast_tag() {
            let tag = approval_toast_tag("550e8400-e29b-41d4-a716-446655440000");
            assert_eq!(tag, "550e8400e29b41d4");
            assert!(tag.len() <= 16);
        }

        #[test]
        fn builds_valid_winrt_toast_xml_with_buttons_and_text() {
            let approval = Approval {
                id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                job_id: "job-1".to_string(),
                target_id: "target-1".to_string(),
                server_id: "srv-1".to_string(),
                server_name: "公司linux".to_string(),
                tool_label: "Shell 命令".to_string(),
                command_preview: "echo \"approval & <test>\"".to_string(),
                requester: "antigravity-client".to_string(),
                caller_reason: None,
                operation: ssh_mcp_core::models::ToolOperation::ShellExecute {
                    command: "echo test".to_string(),
                    sudo: false,
                    timeout_seconds: None,
                    reason: None,
                },
                content_digest: None,
                request_digest: "sha256:123".to_string(),
                risk: ApprovalRiskLevel::High,
                risk_level: ApprovalRiskLevel::High,
                approval_reason: "需审批".to_string(),
                matched_policy: "default".to_string(),
                policy_summary: None,
                sudo: false,
                status: ssh_mcp_core::models::ApprovalStatus::Pending,
                created_at: "2026-11-26T03:00:00Z".to_string(),
                expires_at: "2026-11-26T03:15:00Z".to_string(),
                decided_at: None,
            };

            let (xml, _) = build_approval_toast_xml(&approval);
            let doc = XmlDocument::new().unwrap();
            doc.LoadXml(&HSTRING::from(&xml)).unwrap();
            let loaded = doc.GetXml().unwrap().to_string();
            assert!(loaded.contains("待审批（高风险）· 公司linux"));
            assert!(loaded.contains("content=\"批准\""));
            assert!(loaded.contains("content=\"拒绝\""));
        }
    }
}

#[cfg(windows)]
pub use imp::*;

#[cfg(not(windows))]
mod stub {
    use std::collections::HashSet;
    use std::path::Path;
    use ssh_mcp_core::models::Approval;

    #[derive(Debug, Clone)]
    pub enum ToastActionEvent {
        Approve { approval_id: String },
        Reject { approval_id: String },
        OpenApproval { approval_id: String },
        OpenConsole,
    }

    pub fn initialize<F>(_data_dir: &Path, _handler: F)
    where
        F: Fn(ToastActionEvent) + Send + Sync + 'static,
    {
    }

    pub fn show_approval_toast(_approval: &Approval) {}
    pub fn show_alert_toast(_title: &str, _body: &str) {}
    pub fn remove_approval_toast(_approval_id: &str) {}
    pub fn sync_pending_approvals(_pending_ids: &HashSet<String>) {}
}

#[cfg(not(windows))]
pub use stub::*;
