pub mod dashboard;
mod global_hotkey;
mod hosts;
mod port_forwarding;
mod pty_manager;
mod quick_terminal;
mod sftp;
mod sftp_transfer;
mod snippet_exec;
mod snippets;
mod ssh;
mod ssh_keys;
mod sync;
mod sync_auto;
mod tombstones;
mod vault;
use dashboard::DashboardManager;
use termifai_core::store;

use hosts::{
    Host, HostGroup, HostsVault, SaveHostGroupRequest, SaveHostRequest, TestHostConnectionRequest,
    TestHostConnectionResult,
};
use port_forwarding::{PortForwardRule, SavePortForwardRequest, TunnelManagerState, TunnelStatus};
use pty_manager::{PtyManager, TabInfo};
use serde::Serialize;
use sftp::{LocalFileEntry, RemoteFileEntry, SftpConnectRequest, SftpManager};
use sftp_transfer::{
    backoff_delay_secs, claim_transfer_slot, is_retryable_network_error, TransferStatusEvent,
    TransferStatusKind, MAX_RECONNECT_ATTEMPTS,
};

#[derive(Serialize, Clone)]
struct SftpConnectEvent {
    stage: String,
    message: String,
}

#[derive(Serialize, Clone)]
struct SftpConnectDone {
    ok: bool,
    remote_path: Option<String>,
    error: Option<String>,
}

#[derive(Serialize, Clone)]
struct SftpTransferDone {
    ok: bool,
    error: Option<String>,
}

#[derive(Clone)]
enum SftpTransferOp {
    Download {
        remote_path: String,
        local_path: String,
    },
    Upload {
        local_path: String,
        remote_path: String,
        overwrite: Option<bool>,
    },
}

#[derive(Clone, Copy)]
enum TransferResumeSignal {
    Resume,
    Abort,
}
use global_hotkey::{disable_global_hotkey, enable_global_hotkey, get_global_hotkey_status};
use quick_terminal::{
    get_quick_terminal_info, hide_quick_terminal, quick_terminal_frontend_ready,
    resize_quick_terminal, set_quick_terminal_edge, set_quick_terminal_enabled,
    set_quick_terminal_opacity, toggle_quick_terminal,
};
use snippets::{SaveSnippetRequest, Snippet, SnippetGroup};
use ssh_keys::{GenerateSshKeyRequest, ImportSshKeyRequest, SshKey};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tauri::menu::{Menu, MenuItem};
#[cfg(target_os = "macos")]
use tauri::menu::{MenuBuilder, MenuItemBuilder, PredefinedMenuItem, SubmenuBuilder};
use tauri::tray::TrayIconBuilder;
use tauri::{Emitter, Manager, State, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_autostart::MacosLauncher;
use tauri_plugin_window_state::StateFlags;

static WINDOW_COUNTER: AtomicU64 = AtomicU64::new(0);
static SHOULD_EXIT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

struct AppState {
    pty_manager: Mutex<PtyManager>,
    tunnel_manager: TunnelManagerState,
    sftp_manager: Mutex<SftpManager>,
    watch_handles: Mutex<std::collections::HashMap<String, tokio::sync::oneshot::Sender<()>>>,
    transfer_cancel_flags: Mutex<std::collections::HashMap<String, Arc<AtomicBool>>>,
    transfer_conflict_tx:
        Mutex<std::collections::HashMap<String, std::sync::mpsc::Sender<sftp::ConflictDecision>>>,
    /// وقتی بعد از ۵ تلاش paused شدیم، Resume/Abort از این کانال می‌آد
    transfer_resume_tx:
        Mutex<std::collections::HashMap<String, std::sync::mpsc::Sender<TransferResumeSignal>>>,
    dashboard_manager: Mutex<DashboardManager>,
    hosts_store: store::JsonStore<hosts::HostsVault>,
    port_forward_store: store::JsonStore<port_forwarding::PortForwardVault>,
    snippets_store: store::JsonStore<snippets::SnippetsVault>,
    vault_settings_store: store::JsonStore<vault::VaultSettings>,
    vault_crypto_store: store::JsonStore<vault::CryptoVault>,
    tombstones_store: store::JsonStore<tombstones::TombstonesVault>,
    sync_state_store: store::JsonStore<termifai_core::model::sync_state::SyncState>,
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn create_session(
    app: tauri::AppHandle,
    state: State<AppState>,
    session_id: String,
    cwd: String,
    initial_command: Option<String>,
    host_id: Option<String>,
    ready_marker: Option<String>,
    cols: Option<u16>,
    rows: Option<u16>,
) -> Result<TabInfo, String> {
    let password = if let Some(ref h_id) = host_id {
        let vault = hosts::list_hosts(&app)?;
        let host = vault
            .hosts
            .iter()
            .find(|h| h.id == *h_id)
            .ok_or_else(|| "Host not found".to_string())?;
        hosts::decrypt_host_password(host)
    } else {
        None
    };

    let manager = state.pty_manager.lock().unwrap();
    manager.create_session(
        &app,
        &session_id,
        &cwd,
        initial_command.as_deref(),
        password.as_deref(),
        ready_marker.as_deref(),
        host_id.as_deref(),
        cols.unwrap_or(80),
        rows.unwrap_or(24),
    )
}

#[tauri::command]
fn write_to_session(
    state: State<AppState>,
    session_id: String,
    data: String,
) -> Result<(), String> {
    let manager = state.pty_manager.lock().unwrap();
    manager.write_to_session(&session_id, &data)
}

#[tauri::command]
fn resize_session(
    state: State<AppState>,
    session_id: String,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    let manager = state.pty_manager.lock().unwrap();
    manager.resize_session(&session_id, cols, rows)
}

#[tauri::command]
fn close_session(state: State<AppState>, session_id: String) -> Result<(), String> {
    // اگه snippet-run یه SFTP کمکی با همین session_id باز کرده، با بستن تب باید بره
    if let Some(flag) = state.transfer_cancel_flags.lock().unwrap().get(&session_id) {
        flag.store(true, Ordering::Relaxed);
    }
    {
        let mut sftp_mgr = state.sftp_manager.lock().unwrap();
        let _ = sftp_mgr.disconnect(&session_id);
    }
    let manager = state.pty_manager.lock().unwrap();
    manager.close_session(&session_id)
}

/// Reports whether native DWM window effects (Acrylic/Blur/HudWindow) should
/// be applied on this Windows install. Windows 10's compositor recomputes
/// the blur-behind region on every frame while a transparent, undecorated
/// window is being dragged/resized — this is visibly janky there but cheap
/// on Windows 11's compositor. Rather than risk that stutter (and the
/// two-tone seam between the native blur layer and the app's own CSS
/// transparency it can produce while content resizes), skip the effects
/// entirely below the Windows 11 build number (22000) and fall back to the
/// app's CSS-only transparency.
#[cfg(target_os = "windows")]
fn windows_supports_smooth_effects() -> bool {
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ,
    };

    unsafe {
        let subkey: Vec<u16> = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\0"
            .encode_utf16()
            .collect();
        let mut hkey = std::ptr::null_mut();
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.as_ptr(), 0, KEY_READ, &mut hkey) != 0 {
            return true;
        }

        let value_name: Vec<u16> = "CurrentBuildNumber\0".encode_utf16().collect();
        let mut buf = [0u16; 32];
        let mut buf_len = (buf.len() * 2) as u32;
        let mut value_type = 0u32;
        let ok = RegQueryValueExW(
            hkey,
            value_name.as_ptr(),
            std::ptr::null_mut(),
            &mut value_type,
            buf.as_mut_ptr() as *mut u8,
            &mut buf_len,
        ) == 0
            && value_type == REG_SZ;
        RegCloseKey(hkey);

        if !ok {
            return true;
        }

        let len = (buf_len as usize / 2).saturating_sub(1).min(buf.len());
        String::from_utf16_lossy(&buf[..len])
            .trim()
            .parse::<u32>()
            .map(|build| build >= 22000)
            .unwrap_or(true)
    }
}

/// WebView2 launch args for release builds on Windows: Tauri's defaults
/// (which `additional_browser_args` replaces, so they must be repeated)
/// plus `--disable-dev-tools`, so F12/Ctrl+Shift+I can't open DevTools.
#[cfg(all(target_os = "windows", not(debug_assertions)))]
const WEBVIEW2_RELEASE_ARGS: &str =
    "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --disable-dev-tools";

/// Builds the "main" webview window. Used both at startup and to recreate
/// the window if a second launch is forwarded after the user fully closed
/// it (possible when the "run in background" setting is off).
fn build_main_window(app: &tauri::AppHandle, visible: bool) -> tauri::Result<tauri::WebviewWindow> {
    let mut main_builder =
        WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
            .title("Termifai")
            .inner_size(900.0, 600.0)
            .min_inner_size(900.0, 600.0)
            .resizable(true)
            .transparent(true)
            .visible(visible);

    #[cfg(target_os = "macos")]
    {
        main_builder = main_builder
            .decorations(true)
            .title_bar_style(tauri::TitleBarStyle::Overlay)
            .hidden_title(true)
            .traffic_light_position(tauri::LogicalPosition::new(12.0, 25.0));
    }

    #[cfg(not(target_os = "macos"))]
    {
        main_builder = main_builder.decorations(false);
    }

    #[cfg(all(target_os = "windows", not(debug_assertions)))]
    {
        main_builder = main_builder.additional_browser_args(WEBVIEW2_RELEASE_ARGS);
    }

    main_builder.build()
}

#[tauri::command]
fn new_window(app: tauri::AppHandle) -> Result<(), String> {
    let count = WINDOW_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;
    let label = format!("window-{}", count);

    let app_clone = app.clone();
    app.run_on_main_thread(move || {
        let mut builder =
            WebviewWindowBuilder::new(&app_clone, &label, WebviewUrl::App("index.html".into()))
                .title("Termifai")
                .inner_size(800.0, 600.0)
                .min_inner_size(800.0, 600.0);

        #[cfg(target_os = "macos")]
        {
            builder = builder
                .title_bar_style(tauri::TitleBarStyle::Overlay)
                .hidden_title(true)
                .traffic_light_position(tauri::Position::Logical(tauri::LogicalPosition::new(
                    12.0, 16.0,
                )));
        }

        #[cfg(any(target_os = "windows", target_os = "linux"))]
        {
            builder = builder.decorations(false);
        }

        #[cfg(all(target_os = "windows", not(debug_assertions)))]
        {
            builder = builder.additional_browser_args(WEBVIEW2_RELEASE_ARGS);
        }

        let _ = builder.build();
    })
    .map_err(|e| format!("Failed to dispatch to main thread: {:?}", e))?;

    Ok(())
}

#[tauri::command]
fn get_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    }
}

#[tauri::command]
fn open_settings_window(app: tauri::AppHandle) -> Result<(), String> {
    open_settings_window_inner(&app)
}

#[tauri::command]
fn list_ssh_keys(app: tauri::AppHandle) -> Result<Vec<SshKey>, String> {
    ssh_keys::list_ssh_keys(&app)
}

#[tauri::command]
fn generate_ssh_key(
    app: tauri::AppHandle,
    request: GenerateSshKeyRequest,
) -> Result<SshKey, String> {
    ssh_keys::generate_ssh_key(&app, request)
}

#[tauri::command]
fn import_ssh_key(app: tauri::AppHandle, request: ImportSshKeyRequest) -> Result<SshKey, String> {
    ssh_keys::import_ssh_key(&app, request)
}

#[tauri::command]
fn remove_ssh_keys(app: tauri::AppHandle, ids: Vec<String>) -> Result<(), String> {
    ssh_keys::remove_ssh_keys(&app, ids)
}

#[tauri::command]
fn remove_known_host(host_or_ip: String) -> Result<(), String> {
    ssh_keys::remove_known_host(&host_or_ip)
}

#[tauri::command]
fn list_hosts(app: tauri::AppHandle) -> Result<HostsVault, String> {
    hosts::list_hosts(&app)
}

#[tauri::command]
fn save_host(app: tauri::AppHandle, request: SaveHostRequest) -> Result<Host, String> {
    hosts::save_host(&app, request)
}

#[tauri::command]
fn remove_hosts(app: tauri::AppHandle, ids: Vec<String>) -> Result<(), String> {
    hosts::remove_hosts(&app, ids)
}

#[tauri::command]
fn get_host_password(app: tauri::AppHandle, id: String) -> Result<Option<String>, String> {
    hosts::get_host_password(&app, &id)
}

#[tauri::command]
fn save_host_group(
    app: tauri::AppHandle,
    request: SaveHostGroupRequest,
) -> Result<HostGroup, String> {
    hosts::save_host_group(&app, request)
}

#[tauri::command]
fn remove_host_group(app: tauri::AppHandle, id: String) -> Result<(), String> {
    hosts::remove_host_group(&app, id)
}

#[tauri::command]
fn vault_status(app: tauri::AppHandle) -> Result<vault::VaultStatus, String> {
    vault::op_status(&app)
}

#[tauri::command]
fn vault_init(app: tauri::AppHandle, master_password: String) -> Result<(), String> {
    vault::op_init(&app, &master_password)?;
    hosts::migrate_plaintext_passwords(&app)?;
    Ok(())
}

#[tauri::command]
fn vault_unlock(app: tauri::AppHandle, master_password: String) -> Result<(), String> {
    vault::op_unlock(&app, &master_password)?;
    hosts::migrate_plaintext_passwords(&app)?;
    sync_auto::request_sync_after_unlock();
    Ok(())
}

#[tauri::command]
fn vault_lock(app: tauri::AppHandle) {
    vault::op_lock();
    let _ = app.emit("vault-locked", ());
}

#[tauri::command]
fn vault_change_master_password(
    app: tauri::AppHandle,
    old_password: String,
    new_password: String,
) -> Result<(), String> {
    vault::op_change_master_password(&app, &old_password, &new_password)?;
    hosts::migrate_plaintext_passwords(&app)?;
    Ok(())
}

#[tauri::command]
fn get_vault_lock_policy(app: tauri::AppHandle) -> String {
    let policy = vault::get_lock_policy(&app);
    serde_json::to_string(&policy)
        .map(|s| s.trim_matches('"').to_string())
        .unwrap_or_else(|_| "on_restart".to_string())
}

#[tauri::command]
fn set_vault_lock_policy(app: tauri::AppHandle, policy: String) -> Result<(), String> {
    let p: vault::LockPolicy = serde_json::from_str(&format!("\"{}\"", policy))
        .map_err(|_| format!("Unknown lock policy: {policy}"))?;
    vault::set_lock_policy(&app, p)
}

#[tauri::command]
fn sync_get_config(app: tauri::AppHandle) -> Result<sync::SyncStatusDto, String> {
    sync::sync_get_config(&app)
}

#[tauri::command]
async fn sync_connect_provider(app: tauri::AppHandle, provider: String) -> Result<String, String> {
    sync::sync_connect_provider(app, provider).await
}

#[tauri::command]
fn sync_set_config(
    app: tauri::AppHandle,
    request: sync::SetSyncConfigRequest,
) -> Result<(), String> {
    sync::sync_set_config(&app, request)
}

#[tauri::command]
fn sync_status(app: tauri::AppHandle) -> Result<sync::SyncStatusDto, String> {
    sync::sync_status(&app)
}

#[tauri::command]
fn sync_disconnect(app: tauri::AppHandle, delete_remote: bool) -> Result<(), String> {
    sync::sync_disconnect(&app, delete_remote)
}

#[tauri::command]
fn sync_set_auto_sync(app: tauri::AppHandle, enabled: bool) -> Result<(), String> {
    sync::set_auto_sync(&app, enabled)
}

#[tauri::command]
fn sync_cache_settings(
    app: tauri::AppHandle,
    request: sync::CacheSettingsRequest,
) -> Result<(), String> {
    sync::cache_settings(&app, request)
}

#[tauri::command]
async fn sync_now(
    app: tauri::AppHandle,
    request: sync::SyncNowRequest,
) -> Result<sync::SyncNowResult, String> {
    tauri::async_runtime::spawn_blocking(move || sync::sync_now(&app, request))
        .await
        .map_err(|e| format!("Sync task error: {}", e))?
}

#[tauri::command]
async fn vault_init_from_sync(
    app: tauri::AppHandle,
    request: sync::VaultInitFromSyncRequest,
) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || sync::vault_init_from_sync(&app, request))
        .await
        .map_err(|e| format!("Sync task error: {}", e))?
}

#[tauri::command]
async fn sync_import_foreign(
    app: tauri::AppHandle,
    request: sync::SyncImportForeignRequest,
) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || sync::sync_import_foreign(&app, request))
        .await
        .map_err(|e| format!("Sync task error: {}", e))?
}

#[tauri::command]
async fn test_host_connection(
    app: tauri::AppHandle,
    request: TestHostConnectionRequest,
) -> Result<TestHostConnectionResult, String> {
    tauri::async_runtime::spawn_blocking(move || hosts::test_host_connection(&app, request))
        .await
        .map_err(|e| format!("Task error: {}", e))?
}

#[tauri::command]
fn list_port_forwards(app: tauri::AppHandle) -> Result<Vec<PortForwardRule>, String> {
    port_forwarding::list_port_forwards(&app)
}

#[tauri::command]
fn save_port_forward(
    app: tauri::AppHandle,
    request: SavePortForwardRequest,
) -> Result<PortForwardRule, String> {
    port_forwarding::save_port_forward(&app, request)
}

#[tauri::command]
fn remove_port_forwards(
    app: tauri::AppHandle,
    state: State<AppState>,
    ids: Vec<String>,
) -> Result<(), String> {
    port_forwarding::remove_port_forwards(&app, &state.tunnel_manager, ids)
}

#[tauri::command]
async fn start_tunnel(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    rule_id: String,
) -> Result<TunnelStatus, String> {
    port_forwarding::start_tunnel(&app, &state.tunnel_manager, rule_id).await
}

#[tauri::command]
fn stop_tunnel(state: State<AppState>, rule_id: String) -> Result<TunnelStatus, String> {
    port_forwarding::stop_tunnel(&state.tunnel_manager, rule_id)
}

#[tauri::command]
fn get_tunnel_statuses(state: State<AppState>, rule_ids: Vec<String>) -> Vec<TunnelStatus> {
    port_forwarding::get_tunnel_statuses(&state.tunnel_manager, rule_ids)
}

#[tauri::command]
fn list_snippets(app: tauri::AppHandle) -> Result<snippets::SnippetsListResult, String> {
    snippets::list_snippets(&app)
}

#[tauri::command]
fn save_snippet(app: tauri::AppHandle, request: SaveSnippetRequest) -> Result<Snippet, String> {
    snippets::save_snippet(&app, request)
}

#[tauri::command]
fn remove_snippets(app: tauri::AppHandle, ids: Vec<String>) -> Result<(), String> {
    snippets::remove_snippets(&app, ids)
}

#[tauri::command]
fn reorder_snippets(app: tauri::AppHandle, ids: Vec<String>) -> Result<(), String> {
    snippets::reorder_snippets(&app, ids)
}

#[tauri::command]
fn reorder_snippet_groups(app: tauri::AppHandle, ids: Vec<String>) -> Result<(), String> {
    snippets::reorder_snippet_groups(&app, ids)
}

#[tauri::command]
fn save_snippet_group(
    app: tauri::AppHandle,
    request: snippets::SaveSnippetGroupRequest,
) -> Result<SnippetGroup, String> {
    snippets::save_snippet_group(&app, request)
}

#[tauri::command]
fn remove_snippet_group(app: tauri::AppHandle, id: String) -> Result<(), String> {
    snippets::remove_snippet_group(&app, id)
}

#[tauri::command]
async fn run_snippet_script(
    app: tauri::AppHandle,
    session_id: String,
    title: String,
    script: String,
    run_as_sudo: bool,
) -> Result<(), String> {
    // Emit title message directly to xterm via event (bypasses PTY — user sees the title)
    let title_msg = format!(
        "\x1b[38;2;255;207;107m▶ {} script started...\x1b[0m\r\n",
        title
    );
    let event_name = format!("term:{}:output", session_id);
    let _ = app.emit(&event_name, title_msg);

    let script = snippet_exec::normalize_script(&script);

    // All PTY/SFTP work is blocking I/O (network for SSH sessions) — keep it
    // off the main thread so the UI never freezes while a connection is made.
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let host_id = {
            let manager = state.pty_manager.lock().unwrap();
            manager.get_host_id(&session_id)?
        };

        match host_id {
            Some(h_id) => run_script_over_ssh(&app, &session_id, &h_id, &script, run_as_sudo),
            None => run_script_locally(&app, &session_id, &script, run_as_sudo),
        }
    })
    .await
    .map_err(|e| format!("Script task failed: {}", e))?
}

/// SSH session: upload via SFTP and execute; fall back to a heredoc over the
/// PTY when SFTP is unavailable (subsystem disabled, auth not stored, etc.).
fn run_script_over_ssh(
    app: &tauri::AppHandle,
    session_id: &str,
    host_id: &str,
    script: &str,
    run_as_sudo: bool,
) -> Result<(), String> {
    match upload_script_via_sftp(app, session_id, host_id, script) {
        Ok(remote_path) => {
            let state = app.state::<AppState>();
            let payload = snippet_exec::remote_exec_payload(&remote_path, run_as_sudo);
            let manager = state.pty_manager.lock().unwrap();
            manager.write_to_session(session_id, &payload)
        }
        Err(sftp_err) => {
            // Surface the fallback reason: in the terminal (the heredoc path
            // is visibly noisier, so the user deserves to know why) and on
            // stderr for diagnostics.
            eprintln!(
                "run_snippet_script: SFTP upload failed for session {}: {}",
                session_id, sftp_err
            );
            let warn = format!(
                "\x1b[38;2;255;180;90m⚠ SFTP upload failed ({}) — falling back to inline execution\x1b[0m\r\n",
                sftp_err
            );
            let _ = app.emit(&format!("term:{}:output", session_id), warn);
            run_script_via_heredoc(app, session_id, script, run_as_sudo).map_err(|heredoc_err| {
                format!(
                    "SFTP upload failed ({}); heredoc fallback failed: {}",
                    sftp_err, heredoc_err
                )
            })
        }
    }
}

/// Ensure an SFTP session exists for `session_id`, upload the script to a
/// random /tmp path, and return that path. Errors carry the real cause
/// (connect/auth/subsystem/write) so callers can report or fall back.
fn upload_script_via_sftp(
    app: &tauri::AppHandle,
    session_id: &str,
    host_id: &str,
    script: &str,
) -> Result<String, String> {
    let state = app.state::<AppState>();

    let has_sftp = {
        let sftp_mgr = state.sftp_manager.lock().unwrap();
        sftp_mgr.get_session(session_id).is_ok()
    };

    if !has_sftp {
        let request = build_sftp_request_from_host(app, session_id, host_id)?;
        let mut sftp_mgr = state.sftp_manager.lock().unwrap();
        sftp_mgr
            .connect(request, |_, _| {})
            .map_err(|e| format!("SFTP connect failed: {}", e))?;
    }

    let sftp_entry_arc = {
        let sftp_mgr = state.sftp_manager.lock().unwrap();
        sftp_mgr.get_session(session_id)?
    };
    let sftp_entry = sftp_entry_arc.lock().unwrap();
    let sftp = sftp_entry
        .session
        .sftp()
        .map_err(|e| format!("SFTP subsystem: {}", e))?;

    let remote_path = format!("/tmp/termifai_run_{}.sh", snippet_exec::short_id());

    use ssh2::{OpenFlags, OpenType};
    let mut remote_file = sftp
        .open_mode(
            std::path::Path::new(&remote_path),
            OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
            0o600,
            OpenType::File,
        )
        .map_err(|e| format!("Failed to create remote temp file: {}", e))?;

    use std::io::Write;
    remote_file
        .write_all(script.as_bytes())
        .map_err(|e| format!("Failed to write remote script file: {}", e))?;
    // Close the SFTP handle before anything executes the file — close is what
    // makes the server flush; Drop-at-end-of-scope would race the PTY exec.
    drop(remote_file);

    Ok(remote_path)
}

/// Write the script into the PTY as a non-echoed heredoc — works on any host
/// the PTY is already connected to, with no SFTP or second connection needed.
fn run_script_via_heredoc(
    app: &tauri::AppHandle,
    session_id: &str,
    script: &str,
    run_as_sudo: bool,
) -> Result<(), String> {
    let state = app.state::<AppState>();
    let payload = snippet_exec::heredoc_payload(script, &snippet_exec::short_id(), run_as_sudo);
    let manager = state.pty_manager.lock().unwrap();
    manager.write_to_session(session_id, &payload)
}

/// Local session: write the script to a local temp file and execute via bash.
fn run_script_locally(
    app: &tauri::AppHandle,
    session_id: &str,
    script: &str,
    run_as_sudo: bool,
) -> Result<(), String> {
    let state = app.state::<AppState>();
    let local_temp_path =
        std::env::temp_dir().join(format!("termifai_run_{}.sh", snippet_exec::short_id()));
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        // از اول 0600 بساز تا بین write و chmod لو نره
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&local_temp_path)
            .map_err(|e| format!("Failed to write local temp script: {}", e))?;
        file.write_all(script.as_bytes())
            .map_err(|e| format!("Failed to write local temp script: {}", e))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&local_temp_path, script)
            .map_err(|e| format!("Failed to write local temp script: {}", e))?;
    }

    let payload = snippet_exec::local_exec_payload(&local_temp_path.to_string_lossy(), run_as_sudo);
    let manager = state.pty_manager.lock().unwrap();
    manager.write_to_session(session_id, &payload)
}

/// Resolve a host from the vault into a ready-to-use SFTP connect request
/// (host lookup, ssh-key path resolution, password decryption).
fn build_sftp_request_from_host(
    app: &tauri::AppHandle,
    session_id: &str,
    host_id: &str,
) -> Result<SftpConnectRequest, String> {
    let vault = hosts::list_hosts(app)?;
    let host = vault
        .hosts
        .into_iter()
        .find(|h| h.id == host_id)
        .ok_or_else(|| format!("Host '{}' not found", host_id))?;

    let private_key_path = if let Some(key_id) = &host.ssh_key_id {
        let keys = ssh_keys::list_ssh_keys(app)?;
        keys.into_iter()
            .find(|k| &k.id == key_id)
            .map(|k| k.private_key_path)
    } else {
        None
    };

    Ok(SftpConnectRequest {
        session_id: session_id.to_string(),
        hostname: host.hostname.clone(),
        port: host.port,
        username: host.user.clone(),
        password: hosts::decrypt_host_password(&host),
        private_key_path,
        default_remote_path: host.default_sftp_path.clone(),
    })
}

#[tauri::command]
async fn sftp_connect_from_host(
    app: tauri::AppHandle,
    host_id: String,
    session_id: String,
) -> Result<(), String> {
    // Resolve credentials synchronously (fast local file reads) before spawning
    let request = build_sftp_request_from_host(&app, &session_id, &host_id)?;

    // Spawn blocking work in background — command returns immediately so the
    // loading screen appears before any network round-trips begin.
    let app_bg = app.clone();
    tokio::spawn(async move {
        let app_inner = app_bg.clone();
        let sid = session_id.clone();

        let result = tokio::task::spawn_blocking(move || {
            let app_log = app_inner.clone();
            let sid_log = sid.clone();
            let log = move |stage: &str, msg: &str| {
                let _ = app_log.emit(
                    &format!("sftp:{}:connect", sid_log),
                    SftpConnectEvent {
                        stage: stage.to_string(),
                        message: msg.to_string(),
                    },
                );
            };
            let state = app_inner.state::<AppState>();
            let mut manager = state.sftp_manager.lock().unwrap();
            manager.connect(request, log)
        })
        .await;

        let done = match result {
            Ok(Ok(info)) => SftpConnectDone {
                ok: true,
                remote_path: Some(info.remote_path),
                error: None,
            },
            Ok(Err(e)) => SftpConnectDone {
                ok: false,
                remote_path: None,
                error: Some(e),
            },
            Err(e) => SftpConnectDone {
                ok: false,
                remote_path: None,
                error: Some(format!("Task panic: {e}")),
            },
        };
        let _ = app_bg.emit(&format!("sftp:{}:done", session_id), done);
    });

    Ok(())
}

#[tauri::command]
async fn sftp_list_local(path: String) -> Result<Vec<LocalFileEntry>, String> {
    tokio::task::spawn_blocking(move || sftp::list_local(&path))
        .await
        .map_err(|e| format!("Thread panic: {}", e))?
}

#[tauri::command]
fn get_home_dir() -> Result<String, String> {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| "Could not determine home directory".to_string())
}

#[tauri::command]
async fn sftp_list_remote(
    app: tauri::AppHandle,
    session_id: String,
    path: String,
) -> Result<Vec<RemoteFileEntry>, String> {
    tokio::task::spawn_blocking(move || {
        sftp_op_with_retry(&app, &session_id, |entry| entry.list_remote(&path))
    })
    .await
    .map_err(|e| format!("Thread panic: {}", e))?
}

/// Helper: run an SFTP operation once, and if it fails with a retryable network
/// error, silently reconnect the session and retry once. This covers the common
/// case where a session has gone stale (NAT/idle timeout, server reboot) between
/// user interactions — without this, every non-transfer operation (list, mkdir,
/// delete, rename, stat, …) would fail and the user would have to manually
/// disconnect and reconnect.
fn sftp_op_with_retry<T>(
    app: &tauri::AppHandle,
    session_id: &str,
    op: impl Fn(&sftp::SftpEntry) -> Result<T, String>,
) -> Result<T, String> {
    let state = app.state::<AppState>();
    let entry = {
        let manager = state.sftp_manager.lock().unwrap();
        manager.get_session(session_id)?
    };
    // First attempt
    let first_err = {
        let guard = entry.lock().unwrap();
        match op(&guard) {
            Ok(v) => return Ok(v),
            Err(e) => e,
        }
    };
    // Only retry on network errors — permission/path errors are permanent
    if !is_retryable_network_error(&first_err) {
        return Err(first_err);
    }
    // Reconnect and retry once
    sftp::reconnect_entry(&entry, session_id)?;
    let guard = entry.lock().unwrap();
    op(&guard)
}

fn emit_sftp_transfer_status(
    app: &tauri::AppHandle,
    session_id: &str,
    status: TransferStatusKind,
    message: impl Into<String>,
    attempt: Option<u32>,
) {
    let _ = app.emit(
        &format!("sftp:{}:transfer_status", session_id),
        TransferStatusEvent {
            status,
            message: message.into(),
            attempt,
            max_attempts: if attempt.is_some() {
                Some(MAX_RECONNECT_ATTEMPTS)
            } else {
                None
            },
        },
    );
}

fn make_conflict_prompt(
    app: tauri::AppHandle,
    session_id: String,
    cancel: Arc<AtomicBool>,
) -> impl FnMut(&sftp::ConflictInfo) -> sftp::ConflictDecision {
    move |info: &sftp::ConflictInfo| -> sftp::ConflictDecision {
        let (tx, rx) = std::sync::mpsc::channel();
        app.state::<AppState>()
            .transfer_conflict_tx
            .lock()
            .unwrap()
            .insert(session_id.clone(), tx);
        let _ = app.emit(&format!("sftp:{}:conflict", session_id), info.clone());
        let decision = loop {
            if cancel.load(Ordering::Relaxed) {
                break sftp::ConflictDecision::Cancel;
            }
            match rx.recv_timeout(std::time::Duration::from_millis(200)) {
                Ok(d) => break d,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    break sftp::ConflictDecision::Cancel
                }
            }
        };
        app.state::<AppState>()
            .transfer_conflict_tx
            .lock()
            .unwrap()
            .remove(&session_id);
        decision
    }
}

fn run_sftp_transfer_once(
    app: &tauri::AppHandle,
    session_id: &str,
    op: &SftpTransferOp,
    cancel: Arc<AtomicBool>,
) -> Result<(), String> {
    let state = app.state::<AppState>();
    let entry = {
        let manager = state.sftp_manager.lock().unwrap();
        manager.get_session(session_id)?
    };
    let app_prog = app.clone();
    let sid_prog = session_id.to_string();
    let mut conflicts = sftp::ConflictHandler::new(
        match op {
            SftpTransferOp::Upload {
                overwrite: Some(true),
                ..
            } => sftp::ConflictMode::OverwriteAll,
            _ => sftp::ConflictMode::Ask,
        },
        make_conflict_prompt(app.clone(), session_id.to_string(), Arc::clone(&cancel)),
    );
    let entry_guard = entry.lock().unwrap();
    match op {
        SftpTransferOp::Download {
            remote_path,
            local_path,
        } => entry_guard.download_path(
            session_id,
            remote_path,
            local_path,
            cancel,
            &mut conflicts,
            move |progress| {
                let _ = app_prog.emit(&format!("sftp:{}:progress", sid_prog), progress);
            },
        ),
        SftpTransferOp::Upload {
            local_path,
            remote_path,
            ..
        } => entry_guard.upload_path(
            session_id,
            local_path,
            remote_path,
            cancel,
            &mut conflicts,
            move |progress| {
                let _ = app_prog.emit(&format!("sftp:{}:progress", sid_prog), progress);
            },
        ),
    }
}

/// تلاش برای reconnect با backoff؛ Ok یعنی session آمادهٔ resume است.
fn try_reconnect_with_backoff(
    app: &tauri::AppHandle,
    session_id: &str,
    cancel: &AtomicBool,
) -> Result<(), String> {
    for attempt in 1..=MAX_RECONNECT_ATTEMPTS {
        if cancel.load(Ordering::Relaxed) {
            return Err("Cancelled".to_string());
        }
        emit_sftp_transfer_status(
            app,
            session_id,
            TransferStatusKind::Reconnecting,
            format!("Reconnecting… ({attempt}/{MAX_RECONNECT_ATTEMPTS})"),
            Some(attempt),
        );
        let delay = backoff_delay_secs(attempt);
        if delay > 0 {
            let mut slept = 0u64;
            while slept < delay {
                if cancel.load(Ordering::Relaxed) {
                    return Err("Cancelled".to_string());
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
                slept += 1;
            }
        }
        // فقط Arc سشن رو زیر قفل manager بگیر؛ handshake بیرون از قفل
        let entry = {
            let state = app.state::<AppState>();
            let manager = state.sftp_manager.lock().unwrap();
            manager.take_entry(session_id)?
        };
        let reconnect_result = sftp::reconnect_entry(&entry, session_id);
        match reconnect_result {
            Ok(()) => {
                emit_sftp_transfer_status(
                    app,
                    session_id,
                    TransferStatusKind::Resuming,
                    "Connection restored, resuming…",
                    None,
                );
                return Ok(());
            }
            Err(e) if attempt == MAX_RECONNECT_ATTEMPTS => {
                return Err(e);
            }
            Err(_) => continue,
        }
    }
    Err("Reconnect failed".to_string())
}

fn wait_for_manual_resume(
    app: &tauri::AppHandle,
    session_id: &str,
    cancel: &AtomicBool,
    last_error: &str,
) -> Result<(), String> {
    emit_sftp_transfer_status(
        app,
        session_id,
        TransferStatusKind::Paused,
        format!("Paused after connection loss: {last_error}"),
        None,
    );
    let (tx, rx) = std::sync::mpsc::channel();
    {
        let state = app.state::<AppState>();
        state
            .transfer_resume_tx
            .lock()
            .unwrap()
            .insert(session_id.to_string(), tx);
    }
    let signal = loop {
        if cancel.load(Ordering::Relaxed) {
            break TransferResumeSignal::Abort;
        }
        match rx.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok(s) => break s,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                break TransferResumeSignal::Abort
            }
        }
    };
    app.state::<AppState>()
        .transfer_resume_tx
        .lock()
        .unwrap()
        .remove(session_id);
    match signal {
        TransferResumeSignal::Resume => Ok(()),
        TransferResumeSignal::Abort => Err("Cancelled".to_string()),
    }
}

fn spawn_sftp_transfer(
    app: tauri::AppHandle,
    session_id: String,
    op: SftpTransferOp,
) -> Result<(), String> {
    // یه سشن فقط یه transfer فعال می‌تونه داشته باشه — وگرنه cancel/done قاطی می‌شن
    let cancel_flag = {
        let state = app.state::<AppState>();
        let mut flags = state.transfer_cancel_flags.lock().unwrap();
        claim_transfer_slot(&mut flags, &session_id)?
    };
    tokio::spawn(async move {
        let app_bg = app.clone();
        let sid = session_id.clone();
        let cancel = Arc::clone(&cancel_flag);
        let op_bg = op.clone();
        let result = tokio::task::spawn_blocking(move || {
            emit_sftp_transfer_status(
                &app_bg,
                &sid,
                TransferStatusKind::Transferring,
                "Transferring…",
                None,
            );
            loop {
                match run_sftp_transfer_once(&app_bg, &sid, &op_bg, Arc::clone(&cancel)) {
                    Ok(()) => {
                        emit_sftp_transfer_status(
                            &app_bg,
                            &sid,
                            TransferStatusKind::Idle,
                            "Done",
                            None,
                        );
                        return Ok(());
                    }
                    Err(e) if e == "Cancelled" || cancel.load(Ordering::Relaxed) => {
                        return Err("Cancelled".to_string());
                    }
                    Err(e) if !is_retryable_network_error(&e) => {
                        return Err(e);
                    }
                    Err(e) => {
                        // شبکه قطع شده — reconnect با backoff، بعد resume از offset
                        match try_reconnect_with_backoff(&app_bg, &sid, &cancel) {
                            Ok(()) => continue,
                            Err(re) if re == "Cancelled" || cancel.load(Ordering::Relaxed) => {
                                return Err("Cancelled".to_string());
                            }
                            Err(_) => {
                                // ۵ بار شکست — صبر برای Resume دستی
                                wait_for_manual_resume(&app_bg, &sid, &cancel, &e)?;
                                if cancel.load(Ordering::Relaxed) {
                                    return Err("Cancelled".to_string());
                                }
                                try_reconnect_with_backoff(&app_bg, &sid, &cancel)?;
                                continue;
                            }
                        }
                    }
                }
            }
        })
        .await;

        let state = app.state::<AppState>();
        state
            .transfer_cancel_flags
            .lock()
            .unwrap()
            .remove(&session_id);
        state
            .transfer_conflict_tx
            .lock()
            .unwrap()
            .remove(&session_id);
        state.transfer_resume_tx.lock().unwrap().remove(&session_id);

        let done = match result {
            Ok(Ok(())) => SftpTransferDone {
                ok: true,
                error: None,
            },
            Ok(Err(e)) => SftpTransferDone {
                ok: false,
                error: Some(e),
            },
            Err(e) => SftpTransferDone {
                ok: false,
                error: Some(format!("Task panic: {e}")),
            },
        };
        if !done.ok {
            emit_sftp_transfer_status(
                &app,
                &session_id,
                TransferStatusKind::Idle,
                done.error.clone().unwrap_or_default(),
                None,
            );
        }
        let _ = app.emit(&format!("sftp:{}:transfer-done", session_id), done);
    });
    Ok(())
}

#[tauri::command]
async fn sftp_download(
    app: tauri::AppHandle,
    session_id: String,
    remote_path: String,
    local_path: String,
) -> Result<(), String> {
    spawn_sftp_transfer(
        app,
        session_id,
        SftpTransferOp::Download {
            remote_path,
            local_path,
        },
    )
}

#[tauri::command]
async fn sftp_upload(
    app: tauri::AppHandle,
    session_id: String,
    local_path: String,
    remote_path: String,
    overwrite: Option<bool>,
) -> Result<(), String> {
    spawn_sftp_transfer(
        app,
        session_id,
        SftpTransferOp::Upload {
            local_path,
            remote_path,
            overwrite,
        },
    )
}

#[tauri::command]
fn sftp_resolve_conflict(
    state: State<AppState>,
    session_id: String,
    decision: String,
) -> Result<(), String> {
    let decision = match decision.as_str() {
        "overwrite" => sftp::ConflictDecision::Overwrite,
        "skip" => sftp::ConflictDecision::Skip,
        "overwrite_all" => sftp::ConflictDecision::OverwriteAll,
        "skip_all" => sftp::ConflictDecision::SkipAll,
        "cancel" => sftp::ConflictDecision::Cancel,
        other => return Err(format!("Unknown decision '{}'", other)),
    };
    let tx = state
        .transfer_conflict_tx
        .lock()
        .unwrap()
        .remove(&session_id);
    match tx {
        Some(tx) => {
            let _ = tx.send(decision);
            Ok(())
        }
        None => Err("No pending conflict for this session".to_string()),
    }
}

#[tauri::command]
async fn sftp_delete_remote(
    app: tauri::AppHandle,
    session_id: String,
    paths: Vec<String>,
) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        sftp_op_with_retry(&app, &session_id, |entry| entry.delete_remote(&paths))
    })
    .await
    .map_err(|e| format!("Thread panic: {}", e))?
}

#[tauri::command]
async fn sftp_rename_remote(
    app: tauri::AppHandle,
    session_id: String,
    from_path: String,
    to_path: String,
) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        sftp_op_with_retry(&app, &session_id, |entry| {
            entry.rename_remote(&from_path, &to_path)
        })
    })
    .await
    .map_err(|e| format!("Thread panic: {}", e))?
}

#[tauri::command]
async fn sftp_mkdir_remote(
    app: tauri::AppHandle,
    session_id: String,
    path: String,
) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        sftp_op_with_retry(&app, &session_id, |entry| entry.mkdir_remote(&path))
    })
    .await
    .map_err(|e| format!("Thread panic: {}", e))?
}

#[tauri::command]
fn sftp_disconnect(state: State<AppState>, session_id: String) -> Result<(), String> {
    let mut manager = state.sftp_manager.lock().unwrap();
    manager.disconnect(&session_id)
}

#[tauri::command]
fn sftp_cancel_transfer(state: State<AppState>, session_id: String) -> Result<(), String> {
    if let Some(flag) = state.transfer_cancel_flags.lock().unwrap().get(&session_id) {
        flag.store(true, Ordering::Relaxed);
    }
    if let Some(tx) = state.transfer_resume_tx.lock().unwrap().remove(&session_id) {
        let _ = tx.send(TransferResumeSignal::Abort);
    }
    Ok(())
}

#[tauri::command]
fn sftp_resume_transfer(state: State<AppState>, session_id: String) -> Result<(), String> {
    let tx = state.transfer_resume_tx.lock().unwrap().remove(&session_id);
    match tx {
        Some(tx) => {
            let _ = tx.send(TransferResumeSignal::Resume);
            Ok(())
        }
        None => Err("No paused transfer for this session".to_string()),
    }
}

#[tauri::command]
async fn sftp_stat_remote(
    app: tauri::AppHandle,
    session_id: String,
    path: String,
) -> Result<sftp::RemoteStatResult, String> {
    tokio::task::spawn_blocking(move || {
        sftp_op_with_retry(&app, &session_id, |entry| entry.stat_remote(&path))
    })
    .await
    .map_err(|e| format!("Thread panic: {}", e))?
}

#[tauri::command]
async fn sftp_rename_local(path: String, new_name: String) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        sftp::validate_path_segment(&new_name)?;
        let p = std::path::Path::new(&path);
        let dest = p.parent().ok_or("No parent dir")?.join(&new_name);
        // Belt-and-suspenders: joined dest must stay under the same parent.
        let parent = p.parent().ok_or("No parent dir")?;
        if dest.parent() != Some(parent) {
            return Err("Rename must stay in the same directory".to_string());
        }
        std::fs::rename(p, &dest).map_err(|e| format!("Rename: {}", e))
    })
    .await
    .map_err(|e| format!("Thread panic: {}", e))?
}

#[tauri::command]
async fn sftp_delete_local(paths: Vec<String>) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        for path in &paths {
            let p = std::path::Path::new(path);
            if p.is_dir() {
                std::fs::remove_dir_all(p).map_err(|e| format!("Delete dir '{}': {}", path, e))?;
            } else {
                std::fs::remove_file(p).map_err(|e| format!("Delete '{}': {}", path, e))?;
            }
        }
        Ok(())
    })
    .await
    .map_err(|e| format!("Thread panic: {}", e))?
}

#[tauri::command]
async fn sftp_mkdir_local(path: String) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        sftp::reject_parent_dir_components(&path)?;
        let name = std::path::Path::new(&path)
            .file_name()
            .ok_or_else(|| "mkdir path has no file name".to_string())?
            .to_string_lossy();
        sftp::validate_path_segment(&name)?;
        std::fs::create_dir_all(&path).map_err(|e| format!("Create dir '{}': {}", path, e))
    })
    .await
    .map_err(|e| format!("Thread panic: {}", e))?
}

#[tauri::command]
async fn sftp_copy_local(paths: Vec<String>, dest_dir: String) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        let dest = std::path::Path::new(&dest_dir);
        for path in &paths {
            let src = std::path::Path::new(path);
            let name = src.file_name().ok_or("No file name")?;
            let target = dest.join(name);
            if src.is_dir() {
                copy_dir_all(src, &target).map_err(|e| format!("Copy dir '{}': {}", path, e))?;
            } else {
                std::fs::copy(src, &target).map_err(|e| format!("Copy '{}': {}", path, e))?;
            }
        }
        Ok(())
    })
    .await
    .map_err(|e| format!("Thread panic: {}", e))?
}

fn copy_dir_all(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dst.join(entry.file_name()))?;
        } else {
            std::fs::copy(entry.path(), dst.join(entry.file_name()))?;
        }
    }
    Ok(())
}

/// روی ویندوز `cmd /c start` با آرگومان‌های خام، متاکاراکترهایی مثل `&` رو
/// به‌عنوان جداکننده فرمان می‌خونه — برای open از ShellExecute استفاده می‌کنیم.
#[cfg(target_os = "windows")]
fn windows_shell_open(file: &str, params: Option<&str>) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    fn wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    let file_w = wide(file);
    let params_w = params.map(wide);
    let status = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            std::ptr::null(),
            file_w.as_ptr(),
            params_w
                .as_ref()
                .map(|p| p.as_ptr())
                .unwrap_or(std::ptr::null()),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    // برگشتی ShellExecute اگه ≤32 باشه یعنی خطا
    if (status as isize) <= 32 {
        Err(format!(
            "Failed to open path (ShellExecute error {})",
            status as isize
        ))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn windows_quote_param(s: &str) -> String {
    format!("\"{}\"", s.replace('"', ""))
}

#[tauri::command]
fn sftp_open_local(path: String) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    std::process::Command::new("open")
        .arg(&path)
        .spawn()
        .map_err(|e| e.to_string())?;
    #[cfg(target_os = "linux")]
    std::process::Command::new("xdg-open")
        .arg(&path)
        .spawn()
        .map_err(|e| e.to_string())?;
    #[cfg(target_os = "windows")]
    windows_shell_open(&path, None)?;
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    return Err("Platform not supported for open_local".to_string());
    Ok(())
}

#[tauri::command]
fn sftp_open_with_local(path: String, app: String) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    std::process::Command::new("open")
        .args(["-a", &app, &path])
        .spawn()
        .map_err(|e| e.to_string())?;
    #[cfg(target_os = "linux")]
    std::process::Command::new(&app)
        .arg(&path)
        .spawn()
        .map_err(|e| e.to_string())?;
    #[cfg(target_os = "windows")]
    windows_shell_open(&app, Some(&windows_quote_param(&path)))?;
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    return Err("Platform not supported for open_with_local".to_string());
    Ok(())
}

#[derive(Serialize, Clone)]
struct SftpFileChangedEvent {
    tmp_path: String,
    remote_path: String,
}

#[tauri::command]
async fn sftp_open_remote(
    _app: tauri::AppHandle,
    state: State<'_, AppState>,
    session_id: String,
    remote_path: String,
) -> Result<String, String> {
    let tmp_path = {
        let entry = {
            let manager = state.sftp_manager.lock().unwrap();
            manager.get_session(&session_id)?
        };
        // First attempt
        let first_err = {
            let guard = entry.lock().unwrap();
            match guard.open_remote(&session_id, &remote_path) {
                Ok(v) => {
                    // open succeeded — skip retry path
                    drop(guard);
                    // open local app — روی ویندوز حتماً ShellExecute، نه cmd /c start
                    // (مسیر temp می‌تونه از session_id دستکاری‌شده بیاد)
                    #[cfg(target_os = "macos")]
                    let _ = std::process::Command::new("open").arg(&v).spawn();
                    #[cfg(target_os = "linux")]
                    let _ = std::process::Command::new("xdg-open").arg(&v).spawn();
                    #[cfg(target_os = "windows")]
                    windows_shell_open(&v, None)?;
                    return Ok(v);
                }
                Err(e) => e,
            }
        };
        if !is_retryable_network_error(&first_err) {
            return Err(first_err);
        }
        sftp::reconnect_entry(&entry, &session_id)?;
        let guard = entry.lock().unwrap();
        guard.open_remote(&session_id, &remote_path)?
    };
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(&tmp_path).spawn();
    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("xdg-open")
        .arg(&tmp_path)
        .spawn();
    #[cfg(target_os = "windows")]
    windows_shell_open(&tmp_path, None)?;
    Ok(tmp_path)
}

#[tauri::command]
async fn sftp_watch_remote(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    session_id: String,
    tmp_path: String,
    remote_path: String,
) -> Result<(), String> {
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    {
        let mut handles = state.watch_handles.lock().unwrap();
        // Cancel any existing watch for this tmp_path
        if let Some(old_tx) = handles.remove(&tmp_path) {
            let _ = old_tx.send(());
        }
        handles.insert(tmp_path.clone(), tx);
    }
    let app_bg = app.clone();
    let sid = session_id.clone();
    let tp = tmp_path.clone();
    let rp = remote_path.clone();
    tokio::spawn(async move {
        let initial_mtime = std::fs::metadata(&tp).and_then(|m| m.modified()).ok();
        let mut last_mtime = initial_mtime;
        let mut rx = rx;
        loop {
            tokio::select! {
                _ = &mut rx => break,
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {
                    let current = std::fs::metadata(&tp).and_then(|m| m.modified()).ok();
                    if current != last_mtime && current.is_some() {
                        last_mtime = current;
                        let _ = app_bg.emit(
                            &format!("sftp:{}:file-changed", sid),
                            SftpFileChangedEvent { tmp_path: tp.clone(), remote_path: rp.clone() },
                        );
                    }
                }
            }
        }
    });
    Ok(())
}

#[tauri::command]
fn sftp_stop_watch(state: State<AppState>, tmp_path: String) -> Result<(), String> {
    let mut handles = state.watch_handles.lock().unwrap();
    if let Some(tx) = handles.remove(&tmp_path) {
        let _ = tx.send(());
    }
    let _ = std::fs::remove_file(&tmp_path);
    Ok(())
}

#[tauri::command]
async fn sftp_chmod(
    app: tauri::AppHandle,
    session_id: String,
    path: String,
    mode: String,
    recursive: bool,
) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        sftp_op_with_retry(&app, &session_id, |entry| {
            entry.chmod(&path, &mode, recursive)
        })
    })
    .await
    .map_err(|e| format!("Thread panic: {}", e))?
}

#[tauri::command]
async fn sftp_chown(
    app: tauri::AppHandle,
    session_id: String,
    path: String,
    user: String,
    group: String,
    recursive: bool,
) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        sftp_op_with_retry(&app, &session_id, |entry| {
            entry.chown(&path, &user, &group, recursive)
        })
    })
    .await
    .map_err(|e| format!("Thread panic: {}", e))?
}

#[tauri::command]
async fn sftp_copy_remote(
    app: tauri::AppHandle,
    session_id: String,
    paths: Vec<String>,
    dest_dir: String,
) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        sftp_op_with_retry(&app, &session_id, |entry| {
            entry.copy_remote(&paths, &dest_dir)
        })
    })
    .await
    .map_err(|e| format!("Thread panic: {}", e))?
}

#[tauri::command]
async fn sftp_get_users_groups(
    app: tauri::AppHandle,
    session_id: String,
) -> Result<sftp::UsersGroups, String> {
    // چند round-trip بلاکینگ SSH داره؛ نباید thread کامند رو بلاک کنه
    tokio::task::spawn_blocking(move || {
        sftp_op_with_retry(&app, &session_id, |entry| entry.get_users_groups())
    })
    .await
    .map_err(|e| format!("Thread panic: {}", e))?
}

#[tauri::command]
async fn dashboard_connect(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    host_ids: Vec<String>,
) -> Result<(), String> {
    let vault = hosts::list_hosts(&app)?;
    let gate = { state.dashboard_manager.lock().unwrap().connect_gate() };

    for host in vault.hosts.iter().filter(|h| host_ids.contains(&h.id)) {
        let key_path = if let Some(key_id) = &host.ssh_key_id {
            let keys = crate::ssh_keys::list_ssh_keys(&app).unwrap_or_default();
            keys.into_iter()
                .find(|k| &k.id == key_id)
                .map(|k| std::path::PathBuf::from(k.private_key_path))
        } else {
            None
        };

        let actor = dashboard::spawn_host_actor(
            app.clone(),
            host.id.clone(),
            host.hostname.clone(),
            host.port,
            host.user.clone(),
            hosts::decrypt_host_password(host),
            key_path,
            gate.clone(),
        );

        let mut dm = state.dashboard_manager.lock().unwrap();
        dm.connect(host.id.clone(), actor);
    }
    Ok(())
}

#[tauri::command]
async fn dashboard_poll(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    want_processes: bool,
    want_containers: bool,
    host_id: Option<String>,
) -> Result<(), String> {
    let senders = {
        let dm = state.dashboard_manager.lock().unwrap();
        match &host_id {
            Some(id) => dm
                .sender(id)
                .map(|s| vec![(id.clone(), s)])
                .unwrap_or_default(),
            None => dm.senders(),
        }
    };

    let handles: Vec<_> = senders
        .into_iter()
        .map(|(_id, tx)| {
            let app = app.clone();
            tokio::spawn(async move {
                let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                let cmd = dashboard::ActorCmd::Poll {
                    want_processes,
                    want_containers,
                    reply: reply_tx,
                };

                if tx.try_send(cmd).is_err() {
                    return;
                }

                if let Ok(result) = reply_rx.await {
                    let _ = app.emit("dash:stat", result);
                }
            })
        })
        .collect();

    futures::future::join_all(handles).await;
    Ok(())
}

#[tauri::command]
fn dashboard_disconnect(
    state: tauri::State<'_, AppState>,
    host_ids: Vec<String>,
) -> Result<(), String> {
    let mut dm = state.dashboard_manager.lock().unwrap();
    for id in &host_ids {
        dm.disconnect(id);
    }
    Ok(())
}

/// Toggled by the frontend when a host's detail view opens/closes, so the actor can run a
/// short-lived `docker events` watcher only while someone is actually looking at that host.
#[tauri::command]
fn dashboard_watch_containers(
    state: tauri::State<'_, AppState>,
    host_id: String,
    watch: bool,
) -> Result<(), String> {
    let sender = { state.dashboard_manager.lock().unwrap().sender(&host_id) };
    if let Some(tx) = sender {
        let _ = tx.try_send(dashboard::ActorCmd::WatchContainers(watch));
    }
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GeneralSettings {
    pub run_in_background: bool,
    #[serde(default)]
    pub open_in_context_menu: bool,
    // User's explicit "Run at Startup" preference. The global-hotkey daemon
    // also drives the same OS autolaunch entry (it needs to run at login to
    // supervise hotkeys), so this flag lets it avoid overriding a user who
    // explicitly turned autostart off in Settings.
    #[serde(default = "default_true")]
    pub run_at_startup: bool,
}

fn default_true() -> bool {
    true
}

impl Default for GeneralSettings {
    fn default() -> Self {
        Self {
            run_in_background: true,
            open_in_context_menu: false,
            run_at_startup: true,
        }
    }
}

fn general_settings_path(app: &tauri::AppHandle) -> Option<std::path::PathBuf> {
    app.path()
        .app_data_dir()
        .ok()
        .map(|d| d.join("general_settings.json"))
}

pub(crate) fn load_general_settings(app: &tauri::AppHandle) -> GeneralSettings {
    general_settings_path(app)
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str::<GeneralSettings>(&s).ok())
        .unwrap_or_default()
}

fn save_general_settings(app: &tauri::AppHandle, settings: &GeneralSettings) {
    if let Some(path) = general_settings_path(app) {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(settings) {
            let _ = std::fs::write(path, json);
        }
    }
}

/// Folder paths received from the FinderSync extension (via the termifai://
/// URL scheme) that the frontend has not consumed yet. The frontend drains
/// this on mount and whenever the `open-folder-pending` event fires, so paths
/// arriving before the webview is ready are not lost.
#[derive(Default)]
struct PendingOpenFolders(std::sync::Mutex<Vec<String>>);

#[tauri::command]
fn take_pending_open_folders(state: State<PendingOpenFolders>) -> Vec<String> {
    std::mem::take(&mut *state.0.lock().unwrap())
}

/// Per-webview initial-load progress, fed by `on_page_load`.
///
/// Why this exists: after a force quit, termifaid's supervisor respawns the
/// app with `--background`, so every webview performs its initial load while
/// the app is an invisible Accessory agent. macOS may App Nap / suspend the
/// WebKit content process mid-navigation in that state; the load then never
/// finishes and the window would be shown as a permanently blank shell.
/// Every show path consults this map via `revive_webview_if_stuck` first.
enum WebviewLoadState {
    /// Navigation started at `since` and has not reported Finished yet.
    Loading {
        /// Read by `revive_webview_if_stuck` on macOS to detect stale loads.
        #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
        since: std::time::Instant,
    },
    Finished,
}

#[derive(Default)]
struct WebviewHealth(std::sync::Mutex<std::collections::HashMap<String, WebviewLoadState>>);

/// How long an in-flight load is given before a show path presumes it dead.
/// A healthy cold load takes a couple of seconds; a suspended one stays
/// "loading" forever.
#[cfg(target_os = "macos")]
const WEBVIEW_STALE_LOAD: std::time::Duration = std::time::Duration::from_secs(10);

/// Reloads `window`'s webview if its initial load looks dead (started long
/// ago and never finished, or never started at all). Call before showing a
/// window that may have been loaded while hidden. Returns `true` when a
/// reload was issued, i.e. the frontend was NOT alive; callers that depend on
/// frontend event listeners (quick terminal slide-in) must then defer their
/// action until the fresh page reports ready. Uses `WebviewWindow::reload`
/// rather than an eval of `location.reload()`: eval is silently dropped by a
/// dead WebKit content process, while a native reload respawns it.
pub(crate) fn revive_webview_if_stuck(window: &tauri::WebviewWindow) -> bool {
    #[cfg(target_os = "macos")]
    {
        let health = window.app_handle().state::<WebviewHealth>();
        let stuck = {
            let mut map = health.0.lock().unwrap();
            let stuck = match map.get(window.label()) {
                Some(WebviewLoadState::Finished) => false,
                Some(WebviewLoadState::Loading { since }) => since.elapsed() > WEBVIEW_STALE_LOAD,
                // No Started event was ever delivered: navigation never began.
                None => true,
            };
            if stuck {
                // Restart the clock so back-to-back shows don't reload the reload.
                map.insert(
                    window.label().to_string(),
                    WebviewLoadState::Loading {
                        since: std::time::Instant::now(),
                    },
                );
            }
            stuck
            // Lock dropped here: reload() can re-enter on_page_load synchronously.
        };
        if stuck {
            log::warn!(
                "webview '{}' looks dead (initial load never finished) — reloading",
                window.label()
            );
            let _ = window.reload();
        }
        stuck
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = window;
        false
    }
}

/// Holds an NSActivity for the duration of the startup webview loads of a
/// `--background` launch, so macOS does not App Nap the invisible agent
/// process mid-navigation (the root cause `revive_webview_if_stuck` guards
/// against). Begun in setup, ended by `on_page_load` once every startup
/// webview reports Finished. Ending is idempotent; a leaked token (a load
/// that truly never finishes) merely keeps the process nap-exempt, which is
/// the safe direction.
#[cfg(target_os = "macos")]
mod launch_activity {
    use objc2::rc::Retained;
    use objc2::runtime::AnyObject;
    use objc2::{class, msg_send};
    use std::sync::Mutex;

    /// NSActivityUserInitiatedAllowingIdleSystemSleep:
    /// NSActivityUserInitiated (0x00FFFFFF) minus
    /// NSActivityIdleSystemSleepDisabled (1 << 20) — prevents App Nap without
    /// keeping the machine awake.
    const OPTIONS: u64 = 0x00EF_FFFF;

    struct ActivityToken(Retained<AnyObject>);
    // NSProcessInfo activity tokens are opaque and may be ended from any
    // thread; the token itself is never mutated.
    unsafe impl Send for ActivityToken {}

    static TOKEN: Mutex<Option<ActivityToken>> = Mutex::new(None);

    pub fn begin() {
        let token: Retained<AnyObject> = unsafe {
            let info: Retained<AnyObject> = msg_send![class!(NSProcessInfo), processInfo];
            let reason: Retained<AnyObject> = msg_send![
                class!(NSString),
                stringWithUTF8String: c"Termifai initial webview load while hidden".as_ptr()
            ];
            msg_send![&*info, beginActivityWithOptions: OPTIONS, reason: &*reason]
        };
        *TOKEN.lock().unwrap() = Some(ActivityToken(token));
    }

    pub fn end() {
        let token = TOKEN.lock().unwrap().take();
        if let Some(token) = token {
            unsafe {
                let info: Retained<AnyObject> = msg_send![class!(NSProcessInfo), processInfo];
                let _: () = msg_send![&*info, endActivity: &*token.0];
            }
        }
    }
}

/// Best-effort directory for the panic log, resolved without an AppHandle so
/// it works no matter how early the panic happens.
fn panic_log_dir() -> Option<std::path::PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA").map(|d| std::path::PathBuf::from(d).join("com.termifai"))
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(|h| std::path::PathBuf::from(h).join("Library/Application Support/com.termifai"))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::env::var_os("HOME")
            .map(|h| std::path::PathBuf::from(h).join(".local/share/com.termifai"))
    }
}

/// Appends every panic (message + location + backtrace) to
/// `<app-data>/panic.log` and to the regular log file, then delegates to the
/// previous hook. Release builds on Windows are `windows_subsystem =
/// "windows"`, so a panic — including the `.expect` that wraps a failed
/// `setup` — is otherwise completely invisible: the window flashes open and
/// the process silently dies.
fn install_panic_logger() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let message = format!(
            "[{:?}] panic: {}\nbacktrace:\n{}\n",
            std::time::SystemTime::now(),
            info,
            std::backtrace::Backtrace::force_capture()
        );
        log::error!("{message}");
        if let Some(dir) = panic_log_dir() {
            let _ = std::fs::create_dir_all(&dir);
            use std::io::Write;
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.join("panic.log"))
            {
                let _ = file.write_all(message.as_bytes());
            }
        }
        previous(info);
    }));
}

#[cfg(target_os = "macos")]
fn handle_opened_urls(app: &tauri::AppHandle, urls: Vec<tauri::Url>) {
    for url in urls {
        if url.scheme() != "termifai" || url.host_str() != Some("open-folder") {
            continue;
        }
        let Some(path) = url
            .query_pairs()
            .find(|(key, _)| key == "path")
            .map(|(_, value)| value.into_owned())
        else {
            continue;
        };

        app.state::<PendingOpenFolders>()
            .0
            .lock()
            .unwrap()
            .push(path);

        if let Some(window) = app.get_webview_window("main") {
            revive_webview_if_stuck(&window);
            global_hotkey::set_dock_visible(app, true);
            let _ = window.show();
            let _ = window.set_focus();
        }
        let _ = app.emit("open-folder-pending", ());
    }
}

fn update_os_context_menu(_app: &tauri::AppHandle, _enabled: bool) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        // The context menu item comes from the bundled FinderSync extension
        // (PlugIns/TermifaiFinder.appex); pluginkit toggles the same switch as
        // System Settings > General > Login Items & Extensions > File Providers.
        let action = if _enabled { "use" } else { "ignore" };
        let status = std::process::Command::new("pluginkit")
            .args(["-e", action, "-i", "com.termifai.finder"])
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err("pluginkit failed to update the Finder extension".into());
        }
    }

    #[cfg(target_os = "windows")]
    {
        let current_exe = std::env::current_exe()
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .into_owned();

        let reg_exe = "reg.exe";
        if _enabled {
            // Add Directory shell
            let _ = std::process::Command::new(reg_exe)
                .args(&[
                    "add",
                    "HKCU\\Software\\Classes\\Directory\\shell\\Termifai",
                    "/ve",
                    "/d",
                    "Open in Termifai",
                    "/f",
                ])
                .status();

            // Add Directory shell Icon
            let _ = std::process::Command::new(reg_exe)
                .args(&[
                    "add",
                    "HKCU\\Software\\Classes\\Directory\\shell\\Termifai",
                    "/v",
                    "Icon",
                    "/d",
                    &current_exe,
                    "/f",
                ])
                .status();

            // Add Directory command
            let cmd_val = format!("\"{}\" \"%V\"", current_exe);
            let _ = std::process::Command::new(reg_exe)
                .args(&[
                    "add",
                    "HKCU\\Software\\Classes\\Directory\\shell\\Termifai\\command",
                    "/ve",
                    "/d",
                    &cmd_val,
                    "/f",
                ])
                .status();

            // Add Drive shell
            let _ = std::process::Command::new(reg_exe)
                .args(&[
                    "add",
                    "HKCU\\Software\\Classes\\Drive\\shell\\Termifai",
                    "/ve",
                    "/d",
                    "Open in Termifai",
                    "/f",
                ])
                .status();

            // Add Drive shell Icon
            let _ = std::process::Command::new(reg_exe)
                .args(&[
                    "add",
                    "HKCU\\Software\\Classes\\Drive\\shell\\Termifai",
                    "/v",
                    "Icon",
                    "/d",
                    &current_exe,
                    "/f",
                ])
                .status();

            // Add Drive command
            let _ = std::process::Command::new(reg_exe)
                .args(&[
                    "add",
                    "HKCU\\Software\\Classes\\Drive\\shell\\Termifai\\command",
                    "/ve",
                    "/d",
                    &cmd_val,
                    "/f",
                ])
                .status();

            // Add Background shell
            let _ = std::process::Command::new(reg_exe)
                .args(&[
                    "add",
                    "HKCU\\Software\\Classes\\Directory\\Background\\shell\\Termifai",
                    "/ve",
                    "/d",
                    "Open in Termifai",
                    "/f",
                ])
                .status();

            // Add Background shell Icon
            let _ = std::process::Command::new(reg_exe)
                .args(&[
                    "add",
                    "HKCU\\Software\\Classes\\Directory\\Background\\shell\\Termifai",
                    "/v",
                    "Icon",
                    "/d",
                    &current_exe,
                    "/f",
                ])
                .status();

            // Add Background command
            let _ = std::process::Command::new(reg_exe)
                .args(&[
                    "add",
                    "HKCU\\Software\\Classes\\Directory\\Background\\shell\\Termifai\\command",
                    "/ve",
                    "/d",
                    &cmd_val,
                    "/f",
                ])
                .status();
        } else {
            // Remove Directory
            let _ = std::process::Command::new(reg_exe)
                .args(&[
                    "delete",
                    "HKCU\\Software\\Classes\\Directory\\shell\\Termifai",
                    "/f",
                ])
                .status();

            // Remove Drive
            let _ = std::process::Command::new(reg_exe)
                .args(&[
                    "delete",
                    "HKCU\\Software\\Classes\\Drive\\shell\\Termifai",
                    "/f",
                ])
                .status();

            // Remove Background
            let _ = std::process::Command::new(reg_exe)
                .args(&[
                    "delete",
                    "HKCU\\Software\\Classes\\Directory\\Background\\shell\\Termifai",
                    "/f",
                ])
                .status();
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Linux context menu integration is disabled. Clean up any leftover integration files.
        let mut home = std::env::var("HOME").map(std::path::PathBuf::from).ok();
        if let Ok(sudo_user) = std::env::var("SUDO_USER") {
            if !sudo_user.is_empty() {
                let user_home = std::path::PathBuf::from(format!("/home/{}", sudo_user));
                if user_home.exists() {
                    home = Some(user_home);
                }
            }
        }
        if let Some(ref h) = home {
            let _ = std::fs::remove_file(h.join(".local/share/nautilus/scripts/Open in Termifai"));
            let _ =
                std::fs::remove_file(h.join(".local/share/nautilus-python/extensions/termifai.py"));
            let _ = std::fs::remove_file(h.join(".local/share/nemo/scripts/Open in Termifai"));
            let _ = std::fs::remove_file(h.join(".local/share/nemo/actions/termifai.nemo_action"));
            let _ = std::fs::remove_file(h.join(".local/share/caja/scripts/Open in Termifai"));
            let _ = std::fs::remove_file(
                h.join(".local/share/kservices5/ServiceMenus/termifai.desktop"),
            );
            let _ = std::fs::remove_file(
                h.join(".local/share/kservices6/ServiceMenus/termifai.desktop"),
            );
            // Gracefully restart any file managers to apply cleanup
            let _ = std::process::Command::new("pkill")
                .args(["-f", "nautilus"])
                .status();
            let _ = std::process::Command::new("pkill")
                .args(["-f", "nemo"])
                .status();
            let _ = std::process::Command::new("pkill")
                .args(["-f", "caja"])
                .status();
        }
    }

    Ok(())
}

#[tauri::command]
fn get_general_settings(app: tauri::AppHandle) -> GeneralSettings {
    load_general_settings(&app)
}

#[tauri::command]
fn set_general_settings(app: tauri::AppHandle, settings: GeneralSettings) {
    let old_settings = load_general_settings(&app);
    if old_settings.open_in_context_menu != settings.open_in_context_menu {
        let _ = update_os_context_menu(&app, settings.open_in_context_menu);
    }
    save_general_settings(&app, &settings);
}

#[tauri::command]
fn is_autostart_enabled(app: tauri::AppHandle) -> bool {
    use tauri_plugin_autostart::ManagerExt;
    app.autolaunch().is_enabled().unwrap_or(false)
}

#[tauri::command]
fn set_autostart_enabled(app: tauri::AppHandle, enabled: bool) -> Result<(), String> {
    use tauri_plugin_autostart::ManagerExt;
    // Persist the user's explicit choice so the hotkey daemon (which also
    // drives this same OS autolaunch entry) doesn't silently re-enable it.
    let mut settings = load_general_settings(&app);
    settings.run_at_startup = enabled;
    save_general_settings(&app, &settings);
    if enabled {
        app.autolaunch().enable().map_err(|e| e.to_string())
    } else {
        app.autolaunch().disable().map_err(|e| e.to_string())
    }
}

#[tauri::command]
fn force_quit_app(app: tauri::AppHandle) {
    // Without this flag the ExitRequested handler treats the exit as a
    // window close and hides the app instead of quitting it.
    SHOULD_EXIT.store(true, std::sync::atomic::Ordering::SeqCst);
    // supervise:false must hit disk BEFORE the daemon dies: a daemon tick
    // racing the pkill would otherwise see a dead app and resurrect it with
    // a --background instance (which would in turn respawn the daemon).
    global_hotkey::clean_quit(&app);
    global_hotkey::kill_daemon();
    app.exit(0);
}

#[tauri::command]
fn quit_app(app: tauri::AppHandle) {
    if load_general_settings(&app).run_in_background {
        quit_to_background(&app);
    } else {
        SHOULD_EXIT.store(true, std::sync::atomic::Ordering::SeqCst);
        global_hotkey::clean_quit(&app);
        app.exit(0);
    }
}

/// "Quit" while `run_in_background` is on: the process stays resident (tray,
/// global hotkeys, quick terminal) but everything else resets so the next
/// open is indistinguishable from a cold launch. Steps are best-effort — one
/// failing teardown must not abort the rest. Reload comes last so the UI is
/// never shown half-torn-down.
fn quit_to_background(app: &tauri::AppHandle) {
    let state = app.state::<AppState>();

    if let Ok(pty) = state.pty_manager.lock() {
        pty.kill_all();
    }
    if let Ok(mut tunnels) = state.tunnel_manager.lock() {
        tunnels.stop_all();
    }
    if let Ok(mut sftp) = state.sftp_manager.lock() {
        sftp.clear_all();
    }
    if let Ok(mut watchers) = state.watch_handles.lock() {
        for (_, stop) in watchers.drain() {
            let _ = stop.send(());
        }
    }
    if let Ok(mut flags) = state.transfer_cancel_flags.lock() {
        for (_, flag) in flags.drain() {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    if let Ok(mut dash) = state.dashboard_manager.lock() {
        dash.disconnect_all();
    }

    // Vault: exactly what a relaunch does. on_app_exit covers the OnAppClose
    // policy (forget keychain cache + lock). For every other policy a real
    // relaunch silently re-unlocks from the keychain cache in setup(), so
    // keeping the in-memory unlock is equivalent — do NOT call op_lock()
    // here: it wipes the keychain cache and session token, which would force
    // a master-password prompt even under the OnRestart policy.
    vault::on_app_exit(app);

    for window in app.webview_windows().values() {
        let _ = window.hide();
    }
    global_hotkey::set_dock_visible(app, false);

    // Fresh frontend boot. Each window loads index.html?window=…, so a
    // reload equals a cold start of that webview. Windows are never
    // destroyed/recreated: dynamic creation deadlocks WebView2 on Windows.
    // Native reload instead of eval("location.reload()"): eval is silently
    // dropped by a dead WebKit content process, reload() revives it.
    for window in app.webview_windows().values() {
        let _ = window.reload();
    }
}

/// Global AppHandle for the screen-lock notification callback.
/// Populated once in `start_screen_lock_monitor` before the observer is registered.
#[cfg(target_os = "macos")]
static SCREEN_LOCK_APP: std::sync::OnceLock<tauri::AppHandle> = std::sync::OnceLock::new();

/// CoreFoundation callback fired when macOS emits `com.apple.screenIsLocked`.
/// Runs on the main thread (the Cocoa run loop delivers it there).
#[cfg(target_os = "macos")]
unsafe extern "C" fn screen_locked_callback(
    _center: *mut std::ffi::c_void,
    _observer: *const std::ffi::c_void,
    _name: *mut std::ffi::c_void,
    _object: *const std::ffi::c_void,
    _user_info: *mut std::ffi::c_void,
) {
    eprintln!("[vault] screen lock notification received");
    if let Some(app) = SCREEN_LOCK_APP.get() {
        vault::on_screen_lock(app);
    }
}

/// Registers for the `com.apple.screenIsLocked` Darwin distributed notification
/// on the main thread so delivery uses the existing Cocoa run loop.
///
/// Unlike the old polling approach this fires only on a genuine lock transition,
/// never on transient display-sleep states or polling races at startup.
#[cfg(target_os = "macos")]
fn start_screen_lock_monitor(app: tauri::AppHandle) {
    use std::ffi::c_void;
    use std::ptr;

    let _ = SCREEN_LOCK_APP.set(app.clone());

    let _ = app.run_on_main_thread(|| unsafe {
        #[link(name = "CoreFoundation", kind = "framework")]
        extern "C" {
            fn CFNotificationCenterGetDistributedCenter() -> *mut c_void;
            fn CFNotificationCenterAddObserver(
                center: *mut c_void,
                observer: *const c_void,
                callback: unsafe extern "C" fn(
                    *mut c_void,
                    *const c_void,
                    *mut c_void,
                    *const c_void,
                    *mut c_void,
                ),
                name: *mut c_void,
                object: *const c_void,
                suspension_behavior: isize,
            );
            fn CFStringCreateWithCString(
                alloc: *const c_void,
                c_str: *const i8,
                encoding: u32,
            ) -> *mut c_void;
            fn CFRelease(cf: *const c_void);
        }

        let center = CFNotificationCenterGetDistributedCenter();
        let name_bytes = b"com.apple.screenIsLocked\0";
        let name = CFStringCreateWithCString(
            ptr::null(),
            name_bytes.as_ptr() as *const i8,
            0x0800_0100u32, // kCFStringEncodingUTF8
        );
        // kCFNotificationSuspensionBehaviorDeliverImmediately = 4
        CFNotificationCenterAddObserver(
            center,
            ptr::null(),
            screen_locked_callback,
            name,
            ptr::null(),
            4,
        );
        CFRelease(name as *const c_void); // AddObserver retains; we release our ref
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    install_panic_logger();
    tauri::Builder::default()
        // Managed at builder level (not in setup) so it exists even for
        // RunEvent::Opened URLs delivered during early launch.
        .manage(PendingOpenFolders::default())
        .manage(WebviewHealth::default())
        .on_page_load(|webview, payload| {
            let app = webview.app_handle();
            let health = app.state::<WebviewHealth>();
            let mut map = health.0.lock().unwrap();
            match payload.event() {
                tauri::webview::PageLoadEvent::Started => {
                    log::info!("webview '{}': load started", webview.label());
                    map.insert(
                        webview.label().to_string(),
                        WebviewLoadState::Loading {
                            since: std::time::Instant::now(),
                        },
                    );
                }
                tauri::webview::PageLoadEvent::Finished => {
                    log::info!("webview '{}': load finished", webview.label());
                    map.insert(webview.label().to_string(), WebviewLoadState::Finished);
                    // Once every startup webview has finished loading, the
                    // hidden --background instance no longer needs its App
                    // Nap exemption.
                    #[cfg(target_os = "macos")]
                    {
                        let all_finished = app.webview_windows().keys().all(|label| {
                            matches!(map.get(label), Some(WebviewLoadState::Finished))
                        });
                        if all_finished {
                            launch_activity::end();
                        }
                    }
                }
            }
        })
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            // The hotkey daemon launches us with --hotkey=<action>; when an
            // instance is already running the argument lands here and is
            // dispatched directly. Any other second launch (e.g. clicking the
            // app icon again) just surfaces the existing instance.
            log::info!("single-instance: second launch forwarded, argv={argv:?}");
            let mut found_folder = false;
            for arg in &argv {
                let mut clean_arg = arg.clone();
                if clean_arg.ends_with('"') {
                    clean_arg.pop();
                }
                let path = std::path::Path::new(&clean_arg);
                if path.is_dir() {
                    let path_str = path.to_string_lossy().into_owned();
                    let clean_path = path_str
                        .strip_prefix(r"\\?\")
                        .map(|s| s.to_string())
                        .unwrap_or(path_str);
                    app.state::<PendingOpenFolders>()
                        .0
                        .lock()
                        .unwrap()
                        .push(clean_path);
                    found_folder = true;
                }
            }

            if found_folder {
                let _ = app.emit("open-folder-pending", ());
            }

            if let Some(action) = global_hotkey::hotkey_arg(&argv) {
                global_hotkey::dispatch(app, &action);
            } else {
                // The "main" window may not exist yet (setup is still running
                // on the main thread, e.g. a --background launch racing with
                // this forward) or may have been fully closed (the user has
                // "run in background" disabled). Either way, rebuilding a
                // WebView2 window off the main thread deadlocks on Windows,
                // so hop onto it and re-check there instead of building here.
                let app_handle = app.clone();
                let _ = app.run_on_main_thread(move || {
                    match app_handle.get_webview_window("main") {
                        Some(window) => {
                            // The resident instance may be a post-force-quit
                            // --background respawn whose webview died while
                            // loading hidden; recover it before surfacing it.
                            // Only relevant for a window that already existed —
                            // reloading one we just built below would race its
                            // own first navigation and can hang WebView2 on
                            // Windows.
                            revive_webview_if_stuck(&window);
                            global_hotkey::set_dock_visible(&app_handle, true);
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                        None => {
                            if let Err(e) = build_main_window(&app_handle, true) {
                                log::error!("failed to rebuild main window: {e}");
                            } else {
                                global_hotkey::set_dock_visible(&app_handle, true);
                            }
                        }
                    }
                });
            }
        }))
        .plugin(
            tauri_plugin_window_state::Builder::new()
                .with_state_flags(StateFlags::all() & !StateFlags::VISIBLE)
                .with_filter(|label| label != "settings" && label != quick_terminal::WINDOW_LABEL)
                .build(),
        )
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        // Clipboard reads must go through the native pasteboard API: WebKit's
        // navigator.clipboard.readText() pops macOS's per-read "Paste" balloon.
        .plugin(tauri_plugin_clipboard_manager::init())
        .invoke_handler(tauri::generate_handler![
            take_pending_open_folders,
            create_session,
            write_to_session,
            resize_session,
            close_session,
            new_window,
            get_platform,
            open_settings_window,
            list_ssh_keys,
            generate_ssh_key,
            import_ssh_key,
            remove_ssh_keys,
            remove_known_host,
            list_hosts,
            save_host,
            remove_hosts,
            get_host_password,
            save_host_group,
            remove_host_group,
            vault_status,
            vault_init,
            vault_unlock,
            vault_lock,
            vault_change_master_password,
            get_vault_lock_policy,
            set_vault_lock_policy,
            sync_get_config,
            sync_connect_provider,
            sync_set_config,
            sync_status,
            sync_disconnect,
            sync_set_auto_sync,
            sync_cache_settings,
            sync_now,
            vault_init_from_sync,
            sync_import_foreign,
            test_host_connection,
            list_port_forwards,
            save_port_forward,
            remove_port_forwards,
            start_tunnel,
            stop_tunnel,
            get_tunnel_statuses,
            list_snippets,
            save_snippet,
            remove_snippets,
            reorder_snippets,
            reorder_snippet_groups,
            save_snippet_group,
            remove_snippet_group,
            run_snippet_script,
            sftp_connect_from_host,
            sftp_disconnect,
            sftp_cancel_transfer,
            sftp_resume_transfer,
            sftp_resolve_conflict,
            sftp_download,
            sftp_upload,
            sftp_list_local,
            get_home_dir,
            sftp_list_remote,
            sftp_delete_remote,
            sftp_rename_remote,
            sftp_mkdir_remote,
            sftp_stat_remote,
            sftp_chmod,
            sftp_chown,
            sftp_copy_remote,
            sftp_get_users_groups,
            sftp_rename_local,
            sftp_delete_local,
            sftp_mkdir_local,
            sftp_copy_local,
            sftp_open_local,
            sftp_open_with_local,
            sftp_open_remote,
            sftp_watch_remote,
            sftp_stop_watch,
            dashboard_connect,
            dashboard_poll,
            dashboard_disconnect,
            dashboard_watch_containers,
            quit_app,
            get_general_settings,
            set_general_settings,
            is_autostart_enabled,
            set_autostart_enabled,
            force_quit_app,
            enable_global_hotkey,
            disable_global_hotkey,
            get_global_hotkey_status,
            toggle_quick_terminal,
            hide_quick_terminal,
            resize_quick_terminal,
            get_quick_terminal_info,
            set_quick_terminal_edge,
            set_quick_terminal_enabled,
            set_quick_terminal_opacity,
            quick_terminal_frontend_ready,
        ])
        .on_window_event(|window, event| {
            // Closing the main/extra windows hides them rather than exiting the
            // process on every platform: the tray icon + optional global hotkey
            // only make sense if the app keeps running in the background. The
            // tray's "Quit" item (or the menu/shortcut equivalent) is the real exit.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let label = window.label();
                log::info!("window '{label}': close requested");
                // The settings window is built once at startup and reopened
                // by showing it — the native close button must hide it, not
                // destroy it.
                if label == "settings" {
                    let _ = window.hide();
                    api.prevent_close();
                    return;
                }
                if label == "main"
                    || label.starts_with("window-")
                    || label == quick_terminal::WINDOW_LABEL
                {
                    let app = window.app_handle();
                    let settings = load_general_settings(app);
                    if settings.run_in_background {
                        let _ = window.hide();
                        api.prevent_close();
                    } else {
                        log::info!("run_in_background is false: quitting app");
                        // supervise:false before killing the daemon — see
                        // force_quit_app.
                        global_hotkey::clean_quit(app);
                        global_hotkey::kill_daemon();
                        app.exit(0);
                    }
                }
            }
        })
        .setup(|app| {
            #[cfg(debug_assertions)]
            app.handle().plugin(
                tauri_plugin_log::Builder::default()
                    .level(log::LevelFilter::Info)
                    .build(),
            )?;

            // Cold launch triggered by the termifaid hotkey service?
            // This must be decided FIRST: Tauri pumps the event loop while
            // building the webviews below, which fires didFinishLaunching and
            // locks in the activation policy — setting Accessory any later
            // leaves the app registered as a regular (Dock-visible) app.
            let launch_args: Vec<String> = std::env::args().collect();
            log::info!("setup: begin, args={launch_args:?}");
            let is_background_flag = launch_args.iter().any(|arg| arg == "--background");
            let hotkey_action = global_hotkey::hotkey_arg(&launch_args);
            let is_hotkey_launch = hotkey_action.is_some();
            let background_launch = is_background_flag || is_hotkey_launch;

            #[cfg(target_os = "macos")]
            if background_launch {
                app.set_activation_policy(tauri::ActivationPolicy::Accessory);
                // An invisible Accessory agent is exactly what macOS App
                // Naps; napping the WebKit content process mid-load is what
                // leaves the webviews permanently blank (the
                // blank-window-after-force-quit bug). Stay nap-exempt until
                // on_page_load sees every startup webview finish.
                launch_activity::begin();
            }

            let app_data_dir = app
                .path()
                .app_data_dir()
                .map_err(|e| format!("Failed to resolve app data dir: {}", e))?;

            // One-time, idempotent move of pre-multi-vault top-level files into
            // vaults/default/. Every store below reads from vault_dir, never
            // app_data_dir directly, so this runs before any store is opened.
            termifai_core::layout::migrate_legacy_layout(&app_data_dir)
                .map_err(|e| format!("Failed to migrate to vault layout: {}", e))?;
            let vault_dir = termifai_core::layout::vault_dir(
                &app_data_dir,
                termifai_core::layout::DEFAULT_VAULT_ID,
            );

            app.manage(AppState {
                pty_manager: Mutex::new(PtyManager::new()),
                tunnel_manager: port_forwarding::new_tunnel_manager(),
                sftp_manager: Mutex::new(SftpManager::new()),
                watch_handles: Mutex::new(std::collections::HashMap::new()),
                transfer_cancel_flags: Mutex::new(std::collections::HashMap::new()),
                transfer_conflict_tx: Mutex::new(std::collections::HashMap::new()),
                transfer_resume_tx: Mutex::new(std::collections::HashMap::new()),
                dashboard_manager: Mutex::new(DashboardManager::new()),
                hosts_store: store::JsonStore::new(vault_dir.join("hosts.json")),
                port_forward_store: store::JsonStore::new(vault_dir.join("port_forwards.json")),
                snippets_store: store::JsonStore::new(vault_dir.join("snippets.json")),
                vault_settings_store: store::JsonStore::new(vault_dir.join("vault_settings.json")),
                vault_crypto_store: store::JsonStore::new(vault_dir.join("vault.json")),
                tombstones_store: store::JsonStore::new(vault_dir.join("tombstones.json")),
                sync_state_store: store::JsonStore::new(vault_dir.join("sync_state.json")),
            });
            // One-time move of legacy inline snippet scripts into .sh files.
            // Non-fatal: a failure keeps scripts inline (still readable).
            if let Err(e) = snippets::migrate_inline_scripts(app.handle()) {
                eprintln!("Snippet script migration failed: {}", e);
            }
            // On Windows: pre-allocate a hidden console so that ConPTY session creation
            // doesn't flash a black console window each time a terminal tab is opened.
            // Also set UTF-8 (codepage 65001) so ConPTY correctly interprets multi-byte
            // Unicode sequences — fixes garbled Arabic/Persian text in RTL sessions.
            #[cfg(target_os = "windows")]
            unsafe {
                use windows_sys::Win32::System::Console::{
                    AllocConsole, GetConsoleWindow, SetConsoleCP, SetConsoleOutputCP,
                };
                use windows_sys::Win32::UI::WindowsAndMessaging::{ShowWindow, SW_HIDE};
                AllocConsole();
                SetConsoleCP(65001);
                SetConsoleOutputCP(65001);
                let hwnd = GetConsoleWindow();
                if !hwnd.is_null() {
                    ShowWindow(hwnd, SW_HIDE);
                }
            }

            // On Linux and Windows, remove native decorations so the custom frontend titlebar takes over
            // Build the main window programmatically.
            // On macOS: with decorations and Overlay title bar style for traffic lights.
            // On Windows/Linux: without decorations to avoid two-toned title bar.
            // Process folder arguments on startup:
            for arg in &launch_args {
                let mut clean_arg = arg.clone();
                if clean_arg.ends_with('"') {
                    clean_arg.pop();
                }
                let path = std::path::Path::new(&clean_arg);
                if path.is_dir() {
                    let path_str = path.to_string_lossy().into_owned();
                    let clean_path = path_str
                        .strip_prefix(r"\\?\")
                        .map(|s| s.to_string())
                        .unwrap_or(path_str);
                    app.state::<PendingOpenFolders>()
                        .0
                        .lock()
                        .unwrap()
                        .push(clean_path);
                }
            }

            let _main_win = build_main_window(app.handle(), !background_launch)?;

            // Create the settings window hidden at startup — creating it dynamically after
            // the event loop starts deadlocks on Windows because WebView2 initialization
            // requires the event loop to be free.
            #[allow(unused_mut)]
            let mut settings_builder = WebviewWindowBuilder::new(
                app,
                "settings",
                WebviewUrl::App("index.html?window=settings".into()),
            )
            .title("Settings")
            .inner_size(800.0, 600.0)
            .min_inner_size(800.0, 600.0)
            .resizable(false)
            .minimizable(false)
            .maximizable(false)
            .visible(false);
            #[cfg(all(target_os = "windows", not(debug_assertions)))]
            {
                settings_builder = settings_builder.additional_browser_args(WEBVIEW2_RELEASE_ARGS);
            }
            #[allow(unused_variables)]
            let settings_win = settings_builder.build()?;
            // minimizable/maximizable(false) only greys out the traffic-light
            // buttons on macOS; remove them from the title bar entirely.
            #[cfg(target_os = "macos")]
            if let Ok(ns_window) = settings_win.ns_window() {
                use objc2::rc::Retained;
                use objc2::runtime::AnyObject;
                unsafe {
                    let ns_window = ns_window as *mut AnyObject;
                    // NSWindowButton: 1 = Miniaturize, 2 = Zoom.
                    for kind in [1u64, 2u64] {
                        let button: Option<Retained<AnyObject>> =
                            objc2::msg_send![ns_window, standardWindowButton: kind];
                        if let Some(button) = button {
                            let _: () = objc2::msg_send![&*button, setHidden: true];
                        }
                    }
                }
            }

            // Quick Terminal panel — same create-hidden-at-startup pattern as the
            // settings window (dynamic creation deadlocks WebView2 on Windows).
            // Not draggable (no drag region in its HTML) and not natively
            // resizable: sizing happens only via the in-panel drag handle.
            #[cfg(target_os = "windows")]
            let apply_native_effects = windows_supports_smooth_effects();
            #[cfg(not(target_os = "windows"))]
            let apply_native_effects = true;

            let mut qt_builder = WebviewWindowBuilder::new(
                app,
                quick_terminal::WINDOW_LABEL,
                WebviewUrl::App("index.html?window=quick-terminal".into()),
            )
            .title("Quick Terminal")
            .decorations(false)
            .resizable(false)
            .always_on_top(true)
            .skip_taskbar(true)
            .minimizable(false)
            .maximizable(false)
            // Transparent + shadowless so the native window itself is invisible:
            // what the user sees sliding in is the panel div inside the webview.
            .transparent(true)
            .shadow(false);
            #[cfg(all(target_os = "windows", not(debug_assertions)))]
            {
                qt_builder = qt_builder.additional_browser_args(WEBVIEW2_RELEASE_ARGS);
            }
            // Native backdrop blur for the glass look: the first effect the
            // platform supports is applied (HudWindow → macOS vibrancy,
            // Acrylic/Blur → Windows; no-op on Linux). Only visible where the
            // frontend makes its backgrounds translucent (panel transparency
            // setting below 100%). Skipped on Windows 10 and below — DWM
            // there recomputes the blur-behind region every frame while the
            // window is dragged/resized, which is janky, and can desync from
            // the app's own CSS transparency as content resizes, producing a
            // visible seam. The app's CSS-only transparency is used instead.
            if apply_native_effects {
                qt_builder = qt_builder.effects(
                    tauri::window::EffectsBuilder::new()
                        .effect(tauri::window::Effect::HudWindow)
                        .effect(tauri::window::Effect::Acrylic)
                        .effect(tauri::window::Effect::Blur)
                        // Pin the effect to its active look — by default macOS
                        // vibrancy follows window focus and dims when the panel
                        // loses key status, which reads as the panel "darkening".
                        .state(tauri::window::EffectState::Active)
                        .build(),
                );
            }
            qt_builder.visible(false).build()?;

            let app_handle = app.handle().clone();
            if let Some(main_win) = app.get_webview_window("main") {
                if apply_native_effects {
                    let _ = main_win.set_effects(
                        tauri::window::EffectsBuilder::new()
                            .effect(tauri::window::Effect::HudWindow)
                            .effect(tauri::window::Effect::Acrylic)
                            .effect(tauri::window::Effect::Blur)
                            .state(tauri::window::EffectState::Active)
                            .build(),
                    );
                }

                main_win.on_window_event(move |event| {
                    if let tauri::WindowEvent::CloseRequested { .. } = event {
                        // Closing "main" now only hides it on every platform (the app
                        // keeps running via the tray), so the settings window — created
                        // once at startup — must survive too, or it becomes unopenable
                        // for the rest of the session.
                        if let Some(settings_win) = app_handle.get_webview_window("settings") {
                            let _ = settings_win.hide();
                        }
                    }
                });
            }

            // On Linux and Windows the native menubar is replaced by a frontend hamburger menu
            #[cfg(target_os = "macos")]
            {
                let new_terminal = MenuItemBuilder::with_id("new-terminal", "New Terminal")
                    .accelerator("CmdOrCtrl+T")
                    .build(app)?;
                let settings = MenuItemBuilder::with_id("open-settings", "Settings...")
                    .accelerator("CmdOrCtrl+,")
                    .build(app)?;
                let lock_vault = MenuItemBuilder::with_id("lock-vault", "Lock Vault")
                    .accelerator("CmdOrCtrl+Shift+L")
                    .build(app)?;
                let custom_quit = MenuItemBuilder::with_id("custom-quit", "Quit Termifai")
                    .accelerator("CmdOrCtrl+Q")
                    .build(app)?;
                let custom_force_quit = MenuItemBuilder::with_id("custom-force-quit", "Force Quit")
                    .accelerator("CmdOrCtrl+Alt+Q")
                    .build(app)?;

                let file_menu = SubmenuBuilder::new(app, "File")
                    .item(&new_terminal)
                    .item(&settings)
                    .separator()
                    .item(&lock_vault)
                    .separator()
                    .item(&PredefinedMenuItem::close_window(app, None)?)
                    .separator()
                    .item(&custom_quit)
                    .item(&custom_force_quit)
                    .build()?;

                let edit_menu = SubmenuBuilder::new(app, "Edit")
                    .undo()
                    .redo()
                    .separator()
                    .cut()
                    .copy()
                    .paste()
                    .select_all()
                    .build()?;

                let window_menu = SubmenuBuilder::new(app, "Window")
                    .minimize()
                    .maximize()
                    .separator()
                    .fullscreen()
                    .build()?;

                let menu = MenuBuilder::new(app)
                    .item(&file_menu)
                    .item(&edit_menu)
                    .item(&window_menu)
                    .build()?;

                app.set_menu(menu)?;

                let handle = app.handle().clone();
                app.on_menu_event(move |_app_handle, event| match event.id().as_ref() {
                    "new-terminal" => {
                        let _ = handle.emit("menu-new-terminal", ());
                    }
                    "open-settings" => {
                        let _ = open_settings_window_inner(&handle);
                    }
                    "lock-vault" => {
                        vault::op_lock();
                        let _ = handle.emit("vault-locked", ());
                    }
                    "custom-quit" => {
                        if load_general_settings(&handle).run_in_background {
                            quit_to_background(&handle);
                        } else {
                            SHOULD_EXIT.store(true, std::sync::atomic::Ordering::SeqCst);
                            global_hotkey::clean_quit(&handle);
                            handle.exit(0);
                        }
                    }
                    "custom-force-quit" => {
                        SHOULD_EXIT.store(true, std::sync::atomic::Ordering::SeqCst);
                        // supervise:false before killing the daemon — see
                        // force_quit_app.
                        global_hotkey::clean_quit(&handle);
                        global_hotkey::kill_daemon();
                        handle.exit(0);
                    }
                    _ => {}
                });
            }

            app.handle().plugin(tauri_plugin_autostart::init(
                MacosLauncher::LaunchAgent,
                Some(vec!["--background"]),
            ))?;
            // Try to unlock the vault silently using the keychain-cached master password,
            // so a returning user on this device isn't prompted again. This bypasses the
            // vault_unlock command, so — same as that command — it must also trigger the
            // legacy-plaintext-password migration; otherwise a user whose vault always
            // auto-unlocks (the default OnRestart policy) would never get migrated.
            if let Ok(true) = vault::op_try_cached_unlock(app.handle()) {
                let _ = hosts::migrate_plaintext_passwords(app.handle());
                sync_auto::request_sync_after_unlock();
            }

            // Background sync: debounce after dirty + periodic pull.
            sync_auto::start(app.handle().clone());

            // Start background screen-lock monitor (macOS only).
            #[cfg(target_os = "macos")]
            start_screen_lock_monitor(app.handle().clone());

            // Tray icon so the app can keep running in the background (required
            // for the optional global hotkey to mean anything) with an explicit
            // way to show the window or quit.
            let show_item =
                MenuItem::with_id(app, "tray-show", "Show Termifai", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "tray-quit", "Quit", true, None::<&str>)?;
            let force_quit_item =
                MenuItem::with_id(app, "tray-force-quit", "Force Quit", true, None::<&str>)?;
            let tray_menu = Menu::with_items(app, &[&show_item, &quit_item, &force_quit_item])?;
            TrayIconBuilder::new()
                .icon(
                    app.default_window_icon()
                        .cloned()
                        .ok_or("Missing default window icon")?,
                )
                .menu(&tray_menu)
                .show_menu_on_left_click(true)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "tray-show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            revive_webview_if_stuck(&window);
                            global_hotkey::set_dock_visible(app, true);
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "tray-quit" => {
                        if load_general_settings(app).run_in_background {
                            quit_to_background(app);
                        } else {
                            SHOULD_EXIT.store(true, std::sync::atomic::Ordering::SeqCst);
                            global_hotkey::clean_quit(app);
                            app.exit(0);
                        }
                    }
                    "tray-force-quit" => {
                        SHOULD_EXIT.store(true, std::sync::atomic::Ordering::SeqCst);
                        // supervise:false before killing the daemon — see
                        // force_quit_app.
                        global_hotkey::clean_quit(app);
                        global_hotkey::kill_daemon();
                        app.exit(0);
                    }
                    _ => {}
                })
                .build(app)?;

            // Record our exe path for the hotkey daemon and make sure the
            // daemon is running if any hotkey is enabled.
            global_hotkey::restore_on_startup(&app.handle().clone());

            // Cold launch triggered by the hotkey daemon (--hotkey=<action>).
            // main-window needs nothing: the main window shows by default.
            // quick-terminal: the user asked for the panel, not the app — hide
            // the main window and slide the panel in once its webview reports
            // ready (see quick_terminal_frontend_ready).
            app.manage(quick_terminal::PendingToggle::default());
            // Finish the cold-launch handling decided at the top of setup:
            // the panel slides in once its webview reports ready. The bundle
            // is marked LSUIElement (agent) to cover the instant before
            // didFinishLaunching; normal launches opt back into being a
            // regular app here, which is what shows the Dock icon.
            if hotkey_action.as_deref() == Some(global_hotkey::ACTION_QUICK_TERMINAL) {
                app.state::<quick_terminal::PendingToggle>()
                    .0
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            } else if hotkey_action.as_deref() == Some(global_hotkey::ACTION_MAIN_WINDOW) {
                if let Some(main_win) = app.get_webview_window("main") {
                    global_hotkey::set_dock_visible(app.handle(), true);
                    let _ = main_win.show();
                    let _ = main_win.set_focus();
                }
            } else if !background_launch {
                global_hotkey::set_dock_visible(app.handle(), true);
            }

            log::info!("setup: complete");
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| match event {
            tauri::RunEvent::ExitRequested { api, .. } => {
                let run_in_background = load_general_settings(app_handle).run_in_background;
                log::info!(
                    "exit requested (run_in_background={run_in_background}, should_exit={})",
                    SHOULD_EXIT.load(std::sync::atomic::Ordering::SeqCst)
                );
                if !run_in_background {
                    // Backstop for any exit path (e.g. Cmd+Q): stop the
                    // daemon from resurrecting the app — see force_quit_app.
                    global_hotkey::clean_quit(app_handle);
                    global_hotkey::kill_daemon();
                } else if !SHOULD_EXIT.load(std::sync::atomic::Ordering::SeqCst) {
                    api.prevent_exit();
                    for window in app_handle.webview_windows().values() {
                        let _ = window.hide();
                    }
                    global_hotkey::set_dock_visible(app_handle, false);
                }
            }
            tauri::RunEvent::Exit => {
                log::info!("exiting");
                vault::on_app_exit(app_handle);
            }
            #[cfg(target_os = "macos")]
            tauri::RunEvent::Opened { urls } => {
                handle_opened_urls(app_handle, urls);
            }
            #[cfg(target_os = "macos")]
            tauri::RunEvent::Reopen {
                has_visible_windows: false,
                ..
            } => {
                if let Some(window) = app_handle.get_webview_window("main") {
                    revive_webview_if_stuck(&window);
                    global_hotkey::set_dock_visible(app_handle, true);
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            _ => {}
        });
}

/// Shared logic for opening the settings window (used by both command and menu event).
fn open_settings_window_inner(app: &tauri::AppHandle) -> Result<(), String> {
    let window = app
        .get_webview_window("settings")
        .ok_or_else(|| "Settings window not found".to_string())?;

    // The settings window is a normal window (not always-on-top), so it would
    // end up *behind* the always-on-top Quick Terminal panel. Collapse the
    // panel instead — it's a transient overlay, and this keeps the settings
    // window from having to sit above other apps' windows.
    if let Some(quick) = app.get_webview_window(quick_terminal::WINDOW_LABEL) {
        if quick.is_visible().unwrap_or(false) {
            let _ = app.emit("quick-terminal:hide", ());
        }
    }

    // Center on the main window using *logical* coordinates: physical
    // coordinates are interpreted with the scale factor of the monitor the
    // settings window currently sits on, so when the main window is on a
    // monitor with a different scale factor the position lands on the wrong
    // screen. Logical coordinates are global across monitors.
    let center_on_main = |window: &tauri::WebviewWindow| {
        if let Some(main_window) = app.get_webview_window("main") {
            if let (Ok(main_pos), Ok(main_size), Ok(scale_factor)) = (
                main_window.outer_position(),
                main_window.outer_size(),
                main_window.scale_factor(),
            ) {
                let main_pos = main_pos.to_logical::<f64>(scale_factor);
                let main_size = main_size.to_logical::<f64>(scale_factor);
                let x = main_pos.x + (main_size.width - 800.0) / 2.0;
                let y = main_pos.y + (main_size.height - 600.0) / 2.0;
                let _ = window
                    .set_position(tauri::Position::Logical(tauri::LogicalPosition::new(x, y)));
            }
        }
    };

    // The settings webview loads once at startup and then sits hidden — the
    // same suspended-while-hidden risk as the main window.
    revive_webview_if_stuck(&window);

    // Position before showing so the window doesn't flash at its old spot.
    center_on_main(&window);

    window
        .show()
        .map_err(|e| format!("Failed to show settings window: {}", e))?;

    // Re-apply after show: on Windows the window's DPI is only updated once it
    // actually moves to the other monitor, so the first pass can be slightly off.
    center_on_main(&window);

    window
        .set_focus()
        .map_err(|e| format!("Failed to focus settings window: {}", e))?;

    Ok(())
}
