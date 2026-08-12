use crate::AppState;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use tauri::{AppHandle, Emitter, Manager};
use termifai_core::model::sync_state::{
    migrate_sync_state, CachedSettingsBlob, SettingsCache, SyncBackendConfig, SyncState,
};
use termifai_core::sync::{
    self, CollectionKind, LocalDirBackend, LocalSnapshot, Manifest, SettingsBlob, SettingsPayload,
    SyncBackend, SyncError, SyncOutcome, TokenStore,
};

fn sync_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

static SYNCING: AtomicBool = AtomicBool::new(false);

pub fn is_syncing() -> bool {
    SYNCING.load(Ordering::SeqCst)
}

// ── Request / response DTOs (Tauri command boundary) ──────────────────────────

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SyncNowRequest {
    /// Falls back to the keychain-cached master password when omitted.
    pub master_password: Option<String>,
    #[serde(default)]
    pub app_theme: Option<SettingsBlob>,
    #[serde(default)]
    pub terminal_appearance: Option<SettingsBlob>,
    #[serde(default)]
    pub shortcuts: Option<SettingsBlob>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncNowResult {
    pub blob_version: u64,
    /// True when a new remote blob was written (version bumped).
    pub uploaded: bool,
    /// True when local stores were rewritten from the merge result.
    pub applied: bool,
    pub collections_uploaded: Vec<String>,
    pub collections_downloaded: Vec<String>,
    pub app_theme: SettingsBlob,
    pub terminal_appearance: SettingsBlob,
    pub shortcuts: SettingsBlob,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatusDto {
    pub backend: Option<SyncBackendConfig>,
    pub last_synced_blob_version: u64,
    pub last_sync_at: Option<String>,
    pub sync_ssh_keys: bool,
    pub dirty: bool,
    pub device_id: Option<String>,
    pub auto_sync: bool,
    pub last_error: Option<String>,
    pub syncing: bool,
    pub last_sync_stats: Option<termifai_core::model::sync_state::SyncStats>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CacheSettingsRequest {
    #[serde(default)]
    pub app_theme: Option<SettingsBlob>,
    #[serde(default)]
    pub terminal_appearance: Option<SettingsBlob>,
    #[serde(default)]
    pub shortcuts: Option<SettingsBlob>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetSyncConfigRequest {
    pub backend: SyncBackendConfig,
    #[serde(default)]
    #[allow(dead_code)]
    pub sync_ssh_keys: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultInitFromSyncRequest {
    pub backend: SyncBackendConfig,
    pub master_password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncImportForeignRequest {
    pub backend: SyncBackendConfig,
    pub remote_master_password: String,
    /// Falls back to the keychain-cached master password when omitted.
    pub current_master_password: Option<String>,
    #[serde(default)]
    pub replace_remote: bool,
}

// ── Commands (thin coordinators — real logic below) ───────────────────────────

pub fn sync_get_config(app: &AppHandle) -> Result<SyncStatusDto, String> {
    let state = load_state(app)?;
    Ok(to_status_dto(&state))
}

fn open_url(url: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(url).spawn();
    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    #[cfg(target_os = "windows")]
    {
        // قبلاً فقط `&` رو با `^&` فرار می‌دادیم؛ بقیه متاکاراکترهای cmd
        // هنوز خطرناک بودن. ShellExecute مسیر امن‌تریه.
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::UI::Shell::ShellExecuteW;
        use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

        let wide: Vec<u16> = std::ffi::OsStr::new(url)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let status = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                std::ptr::null(),
                wide.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            )
        };
        if (status as isize) <= 32 {
            return Err(format!(
                "Failed to open URL (ShellExecute error {})",
                status as isize
            ));
        }
    }
    Ok(())
}

pub async fn sync_connect_provider(_app: AppHandle, provider: String) -> Result<String, String> {
    use oauth2::basic::BasicClient;
    use oauth2::{
        AuthUrl, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl, TokenResponse,
        TokenUrl,
    };

    let client_id = sync::oauth::client_id(&provider)?;
    let client_secret = sync::oauth::client_secret(&provider);

    let (auth_url, token_url) = match provider.as_str() {
        "google" => (
            "https://accounts.google.com/o/oauth2/v2/auth",
            "https://oauth2.googleapis.com/token",
        ),
        "dropbox" => (
            "https://www.dropbox.com/oauth2/authorize",
            "https://api.dropboxapi.com/oauth2/token",
        ),
        _ => unreachable!(),
    };

    // Bind loopback listener. Google's "Desktop app" client type accepts any
    // loopback port automatically, so we let the OS pick one. Dropbox (like
    // most providers) requires the redirect_uri to exactly match one
    // pre-registered in the app's dashboard, so it needs a fixed port that
    // you register once — see `DROPBOX_REDIRECT_PORT` below.
    let bind_addr = if provider == "dropbox" {
        format!("127.0.0.1:{}", sync::oauth::DROPBOX_REDIRECT_PORT)
    } else {
        "127.0.0.1:0".to_string()
    };
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| {
            if provider == "dropbox" {
                format!(
                    "Failed to bind 127.0.0.1:{} for the Dropbox OAuth callback — is another \
                 program using that port? ({e})",
                    sync::oauth::DROPBOX_REDIRECT_PORT
                )
            } else {
                format!("Failed to bind loopback address: {}", e)
            }
        })?;
    let port = listener.local_addr().unwrap().port();

    let client = BasicClient::new(
        ClientId::new(client_id.to_string()),
        client_secret.map(|s| ClientSecret::new(s.to_string())),
        AuthUrl::new(auth_url.to_string()).unwrap(),
        Some(TokenUrl::new(token_url.to_string()).unwrap()),
    )
    .set_redirect_uri(RedirectUrl::new(format!("http://127.0.0.1:{}/callback", port)).unwrap());

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let state = CsrfToken::new_random();

    let mut auth_request = client.authorize_url(|| state.clone());

    if provider == "google" {
        auth_request = auth_request
            .add_scope(oauth2::Scope::new(
                "https://www.googleapis.com/auth/drive.appdata".to_string(),
            ))
            .add_extra_param("prompt", "consent")
            .add_extra_param("access_type", "offline");
    } else if provider == "dropbox" {
        auth_request = auth_request
            .add_scope(oauth2::Scope::new("files.content.read".to_string()))
            .add_scope(oauth2::Scope::new("files.content.write".to_string()))
            .add_extra_param("token_access_type", "offline");
    }

    let (auth_url, csrf_token) = auth_request.set_pkce_challenge(pkce_challenge).url();

    // Open consent page in system browser
    open_url(auth_url.as_str())?;

    // Wait for callback redirection (timeout after 5 minutes)
    let timeout = tokio::time::sleep(tokio::time::Duration::from_secs(300));
    tokio::pin!(timeout);

    let accept_fut = listener.accept();
    tokio::pin!(accept_fut);

    let (mut stream, _) = tokio::select! {
        res = &mut accept_fut => {
            res.map_err(|e| format!("Failed to accept callback connection: {}", e))?
        }
        _ = &mut timeout => {
            return Err("Authorization timed out".to_string());
        }
    };

    // Read HTTP GET redirect request
    let mut buf = [0u8; 1024];
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let n = stream.read(&mut buf).await.map_err(|e| e.to_string())?;
    let request_str = String::from_utf8_lossy(&buf[..n]);
    let first_line = request_str.lines().next().unwrap_or("");

    let mut code = None;
    let mut incoming_state = None;

    if let Some(query_start) = first_line.find("?") {
        let query_end = first_line[query_start..]
            .find(" ")
            .unwrap_or(first_line[query_start..].len());
        let query_str = &first_line[query_start + 1..query_start + query_end];
        for pair in query_str.split("&") {
            let mut parts = pair.split("=");
            if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
                if k == "code" {
                    code = Some(v.to_string());
                } else if k == "state" {
                    incoming_state = Some(v.to_string());
                }
            }
        }
    }

    let code = code.ok_or_else(|| "No authorization code found".to_string())?;
    let incoming_state = incoming_state.ok_or_else(|| "No state parameter found".to_string())?;

    if &incoming_state != csrf_token.secret() {
        return Err("State parameter mismatch (CSRF protection)".to_string());
    }

    // Respond back to browser
    let response_html = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n\
        <html>\
        <head><title>Authorization Successful</title></head>\
        <body style=\"font-family: sans-serif; text-align: center; padding-top: 50px; background: #0f0f13; color: #e2e8f0;\">\
          <h1 style=\"color: #10b981;\">Authorization Successful!</h1>\
          <p>You can now close this browser tab and return to Termifai.</p>\
        </body>\
        </html>";
    let _ = stream.write_all(response_html.as_bytes()).await;
    let _ = stream.flush().await;

    // Exchange authorization code for tokens
    let token_result = client
        .exchange_code(oauth2::AuthorizationCode::new(code))
        .set_pkce_verifier(pkce_verifier)
        .request_async(oauth2::reqwest::async_http_client)
        .await
        .map_err(|e| format!("Token exchange failed: {:?}", e))?;

    let access_token = token_result.access_token().secret().to_string();
    let refresh_token = token_result
        .refresh_token()
        .ok_or_else(|| "No refresh token returned".to_string())?
        .secret()
        .to_string();

    let expires_in = token_result
        .expires_in()
        .map(|d| d.as_secs())
        .unwrap_or(3600);
    let expires_at = time::OffsetDateTime::now_utc() + time::Duration::seconds(expires_in as i64);
    let expires_at_rfc3339 = expires_at
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| e.to_string())?;

    let oauth_tokens = termifai_core::sync::oauth::OAuthTokens {
        access_token,
        refresh_token,
        expires_at_rfc3339,
    };

    let token_str = serde_json::to_string(&oauth_tokens).map_err(|e| e.to_string())?;
    let account = format!("sync-oauth-{}", provider);
    KeyringTokenStore.save(&account, &token_str)?;

    Ok(account)
}

pub fn sync_set_config(app: &AppHandle, request: SetSyncConfigRequest) -> Result<(), String> {
    // Switching away from (or between) SFTP targets should drop the badge on
    // whichever host previously wore it — the new config may not be SFTP.
    if !matches!(request.backend, SyncBackendConfig::Sftp { .. }) {
        clear_sync_server_flags(app)?;
    }
    let state = app.state::<AppState>();
    state
        .sync_state_store
        .update_with_migration(migrate_sync_state, |s| {
            s.backend = Some(request.backend.clone());
            s.sync_ssh_keys = false;
            // A backend switch targets a different remote — start it fresh.
            s.last_synced_blob_version = 0;
            s.last_sync_at = None;
            s.dirty = true;
            s.last_error = None;
        })
        .map_err(|e| e.to_string())?;
    crate::sync_auto::note_dirty();
    if crate::vault::is_unlocked() {
        crate::sync_auto::request_sync_after_unlock();
    }
    Ok(())
}

pub fn sync_status(app: &AppHandle) -> Result<SyncStatusDto, String> {
    sync_get_config(app)
}

pub fn sync_disconnect(app: &AppHandle, delete_remote: bool) -> Result<(), String> {
    let current = load_state(app)?;
    if delete_remote {
        if let Some(backend_config) = &current.backend {
            wipe_remote(app, backend_config)?;
        }
    }
    // Badge روی هاست sync server بعد از قطع باید برداشته بشه
    clear_sync_server_flags(app)?;
    let state = app.state::<AppState>();
    state
        .sync_state_store
        .update_with_migration(migrate_sync_state, |s| {
            s.backend = None;
            s.last_synced_blob_version = 0;
            s.last_sync_at = None;
            s.dirty = false;
        })
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Marks the vault dirty so the next sync cycle knows local mutations exist.
/// Safe to call even when sync is not configured — the flag is simply ignored.
pub fn mark_dirty(app: &AppHandle) {
    let state = app.state::<AppState>();
    let mut marked = false;
    let _ = state
        .sync_state_store
        .update_with_migration(migrate_sync_state, |s| {
            if s.backend.is_some() {
                s.dirty = true;
                marked = true;
            }
        });
    if marked {
        crate::sync_auto::note_dirty();
    }
}

pub fn set_auto_sync(app: &AppHandle, enabled: bool) -> Result<(), String> {
    let state = app.state::<AppState>();
    state
        .sync_state_store
        .update_with_migration(migrate_sync_state, |s| {
            s.auto_sync = enabled;
        })
        .map_err(|e| e.to_string())?;
    if enabled {
        crate::sync_auto::request_sync_after_unlock();
    }
    Ok(())
}

pub fn cache_settings(app: &AppHandle, request: CacheSettingsRequest) -> Result<(), String> {
    let state = app.state::<AppState>();
    let mut touched = false;
    state
        .sync_state_store
        .update_with_migration(migrate_sync_state, |s| {
            if let Some(blob) = request.app_theme {
                let next = to_cached_blob(blob);
                if next != s.settings_cache.app_theme {
                    s.settings_cache.app_theme = next;
                    touched = true;
                }
            }
            if let Some(blob) = request.terminal_appearance {
                let next = to_cached_blob(blob);
                if next != s.settings_cache.terminal_appearance {
                    s.settings_cache.terminal_appearance = next;
                    touched = true;
                }
            }
            if let Some(blob) = request.shortcuts {
                let next = to_cached_blob(blob);
                if next != s.settings_cache.shortcuts {
                    s.settings_cache.shortcuts = next;
                    touched = true;
                }
            }
            if touched && s.backend.is_some() {
                s.dirty = true;
            }
        })
        .map_err(|e| e.to_string())?;
    if touched {
        crate::sync_auto::note_dirty();
    }
    Ok(())
}

pub fn set_last_error(app: &AppHandle, error: Option<String>) -> Result<(), String> {
    let state = app.state::<AppState>();
    state
        .sync_state_store
        .update_with_migration(migrate_sync_state, |s| {
            s.last_error = error;
        })
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn to_cached_blob(blob: SettingsBlob) -> CachedSettingsBlob {
    CachedSettingsBlob {
        value: blob.value,
        updated_at: blob.updated_at,
    }
}

fn persist_settings_cache(app: &AppHandle, settings: &SettingsPayload) -> Result<(), String> {
    let state = app.state::<AppState>();
    state
        .sync_state_store
        .update_with_migration(migrate_sync_state, |s| {
            s.settings_cache = SettingsCache {
                app_theme: to_cached_blob(settings.app_theme.clone()),
                terminal_appearance: to_cached_blob(settings.terminal_appearance.clone()),
                shortcuts: to_cached_blob(settings.shortcuts.clone()),
            };
        })
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn sync_now(app: &AppHandle, request: SyncNowRequest) -> Result<SyncNowResult, String> {
    let _guard = sync_mutex()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    SYNCING.store(true, Ordering::SeqCst);
    let result = sync_now_inner(app, request);
    SYNCING.store(false, Ordering::SeqCst);
    emit_sync_finished(app, &result);
    result
}

/// Like `sync_now`, but returns `None` immediately if another sync holds the lock
/// (used by the background loop so ticks don't pile up behind a long upload).
pub fn try_sync_now(
    app: &AppHandle,
    request: SyncNowRequest,
) -> Option<Result<SyncNowResult, String>> {
    let Ok(_guard) = sync_mutex().try_lock() else {
        return None;
    };
    SYNCING.store(true, Ordering::SeqCst);
    let result = sync_now_inner(app, request);
    SYNCING.store(false, Ordering::SeqCst);
    emit_sync_finished(app, &result);
    Some(result)
}

fn emit_sync_finished(app: &AppHandle, result: &Result<SyncNowResult, String>) {
    let status = load_state(app).ok();
    match result {
        Ok(outcome) => {
            let _ = app.emit(
                "sync:activity",
                crate::sync_auto::SyncActivityEvent {
                    phase: "ok",
                    uploaded: outcome.uploaded,
                    applied: outcome.applied,
                    blob_version: outcome.blob_version,
                    last_sync_at: status.as_ref().and_then(|s| s.last_sync_at.clone()),
                    error: None,
                    dirty: status.as_ref().map(|s| s.dirty).unwrap_or(false),
                    auto_sync: status.as_ref().map(|s| s.auto_sync).unwrap_or(true),
                },
            );
        }
        Err(err) => {
            let _ = set_last_error(app, Some(err.clone()));
            let _ = app.emit(
                "sync:activity",
                crate::sync_auto::SyncActivityEvent {
                    phase: "error",
                    uploaded: false,
                    applied: false,
                    blob_version: status
                        .as_ref()
                        .map(|s| s.last_synced_blob_version)
                        .unwrap_or(0),
                    last_sync_at: status.as_ref().and_then(|s| s.last_sync_at.clone()),
                    error: Some(err.clone()),
                    dirty: status.as_ref().map(|s| s.dirty).unwrap_or(false),
                    auto_sync: status.as_ref().map(|s| s.auto_sync).unwrap_or(true),
                },
            );
        }
    }
}

fn sync_now_inner(app: &AppHandle, request: SyncNowRequest) -> Result<SyncNowResult, String> {
    let _ = app.emit(
        "sync:activity",
        crate::sync_auto::SyncActivityEvent {
            phase: "syncing",
            uploaded: false,
            applied: false,
            blob_version: 0,
            last_sync_at: None,
            error: None,
            dirty: true,
            auto_sync: true,
        },
    );

    let sync_state = load_state(app)?;
    let backend_config = sync_state
        .backend
        .clone()
        .ok_or_else(|| "No sync backend configured".to_string())?;
    let master_password = resolve_master_password(request.master_password)?;
    // بدون vault unlocked، decrypt_host_password می‌شه None و merge ممکنه
    // پسوردهای ریموت رو با host بدون پسورد بازنویسی کنه — قبل از gather آنلاک کن
    if !crate::vault::is_unlocked() {
        crate::vault::op_unlock(app, &master_password)?;
    }
    let device_id = ensure_device_id(app)?;

    // اگه فرانت تنظیمات نفرستاده، از کش دیسک استفاده کن (مسیر auto-sync)
    let settings = SettingsPayload {
        app_theme: request.app_theme.unwrap_or_else(|| SettingsBlob {
            value: sync_state.settings_cache.app_theme.value.clone(),
            updated_at: sync_state.settings_cache.app_theme.updated_at.clone(),
        }),
        terminal_appearance: request.terminal_appearance.unwrap_or_else(|| SettingsBlob {
            value: sync_state.settings_cache.terminal_appearance.value.clone(),
            updated_at: sync_state
                .settings_cache
                .terminal_appearance
                .updated_at
                .clone(),
        }),
        shortcuts: request.shortcuts.unwrap_or_else(|| SettingsBlob {
            value: sync_state.settings_cache.shortcuts.value.clone(),
            updated_at: sync_state.settings_cache.shortcuts.updated_at.clone(),
        }),
    };
    let _ = persist_settings_cache(app, &settings);

    // Snapshot dirty gen قبل از gather تا ویرایش‌های وسط sync رو از دست ندیم
    let dirty_gen_at_gather = crate::sync_auto::dirty_generation();
    let local = gather_local_snapshot(
        app,
        sync_state.sync_ssh_keys,
        settings.clone(),
        device_id.clone(),
        sync_state.device_name.clone(),
    )?;

    let backend = build_backend(app, &backend_config)?;
    let mut outcome = sync::run_sync(
        backend.as_ref(),
        local,
        &master_password,
        termifai_core::layout::DEFAULT_VAULT_ID,
    )
    .map_err(|e| e.to_string())?;

    let applied = if outcome.local_changed {
        // Rebase when dirty moved during run_sync. apply_outcome LWW-merges into
        // the live JsonStore under lock so a save racing the write is not wiped.
        if crate::sync_auto::dirty_generation() != dirty_gen_at_gather {
            outcome = rebase_outcome_on_current_local(
                app,
                &outcome,
                sync_state.sync_ssh_keys,
                settings.clone(),
                device_id.clone(),
                sync_state.device_name.clone(),
            )?;
        }
        apply_outcome(app, &outcome, sync_state.sync_ssh_keys)?;
        true
    } else {
        false
    };

    let blob_version = outcome.blob_version;
    let result = SyncNowResult {
        blob_version,
        uploaded: outcome.uploaded,
        applied,
        collections_uploaded: outcome.collections_uploaded.clone(),
        collections_downloaded: outcome.collections_downloaded.clone(),
        app_theme: outcome.settings.app_theme.clone(),
        terminal_appearance: outcome.settings.terminal_appearance.clone(),
        shortcuts: outcome.settings.shortcuts.clone(),
    };

    let synced_at = now_iso();
    let stats = termifai_core::model::sync_state::SyncStats {
        uploaded: outcome.uploaded,
        applied,
        collections_uploaded: outcome.collections_uploaded,
        collections_downloaded: outcome.collections_downloaded,
        at: synced_at.clone(),
    };

    // فقط وقتی dirty رو پاک کن که از gather تا حالا ویرایش جدیدی نیومده باشه.
    let still_dirty = crate::sync_auto::dirty_generation() != dirty_gen_at_gather;
    let state = app.state::<AppState>();
    state
        .sync_state_store
        .update_with_migration(migrate_sync_state, |s| {
            s.last_synced_blob_version = blob_version;
            s.last_sync_at = Some(synced_at);
            s.dirty = still_dirty;
            s.last_error = None;
            s.last_sync_stats = Some(stats);
            s.settings_cache = SettingsCache {
                app_theme: to_cached_blob(result.app_theme.clone()),
                terminal_appearance: to_cached_blob(result.terminal_appearance.clone()),
                shortcuts: to_cached_blob(result.shortcuts.clone()),
            };
        })
        .map_err(|e| e.to_string())?;

    if still_dirty {
        crate::sync_auto::note_dirty();
    }

    Ok(result)
}

/// Restore flow (1.7-A): a fresh device with no local vault, linking to an
/// existing synced vault. Nothing is written locally until the remote blob
/// decrypts successfully with the supplied master password.
pub fn vault_init_from_sync(
    app: &AppHandle,
    request: VaultInitFromSyncRequest,
) -> Result<(), String> {
    if crate::vault::read_crypto_meta(app)?.is_some() {
        return Err("Vault is already initialized".to_string());
    }

    let backend = build_backend(app, &request.backend)?;
    let (manifest, payload) =
        sync::fetch_remote_payload(backend.as_ref(), &request.master_password)
            .map_err(|e| e.to_string())?;

    // Decrypt succeeded — safe to start writing local state now.
    crate::vault::op_init(app, &request.master_password)?;

    write_payload_to_local_stores(app, &payload)?;

    let device_id = ensure_device_id(app)?;
    let state = app.state::<AppState>();
    state
        .sync_state_store
        .update_with_migration(migrate_sync_state, |s| {
            s.backend = Some(request.backend.clone());
            s.sync_ssh_keys = false;
            s.last_synced_blob_version = manifest.blob_version;
            s.last_sync_at = Some(now_iso());
            s.dirty = false;
        })
        .map_err(|e| e.to_string())?;
    let _ = device_id;

    Ok(())
}

/// Foreign-vault-merge flow (1.7-B): the local vault is already unlocked,
/// and the configured backend turns out to hold data encrypted under a
/// different master password. Decrypts with the caller-supplied remote
/// password, merges into local state, then re-uploads under the *local*
/// device's own master password with a fresh sync salt.
pub fn sync_import_foreign(
    app: &AppHandle,
    request: SyncImportForeignRequest,
) -> Result<(), String> {
    if !crate::vault::is_unlocked() {
        return Err("Vault is locked".to_string());
    }
    // هم‌زمانی با sync_now باعث apply/store موازی و state پاره‌پاره می‌شه
    let _guard = sync_mutex()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let current_master_password = resolve_master_password(request.current_master_password)?;

    let backend = build_backend(app, &request.backend)?;
    let (manifest, foreign_payload) =
        sync::fetch_remote_payload(backend.as_ref(), &request.remote_master_password)
            .map_err(|e| e.to_string())?;

    let sync_state = load_state(app)?;
    let device_id = ensure_device_id(app)?;
    let device_name = sync_state.device_name.clone();
    // مثل sync_now از کش واقعی استفاده کن — default خالی تم/شورتکات بقیه دستگاه‌ها رو پاک می‌کنه
    let settings = crate::sync_auto::cache_to_settings(&sync_state.settings_cache);

    // Track dirty gen so an edit during the (slow) foreign fetch/store is not
    // wiped by apply, and so we don't clear dirty while local still diverges.
    let dirty_gen_at_gather = crate::sync_auto::dirty_generation();
    let mut outcome = if request.replace_remote {
        // Overwrite remote with this device's own state — no merge.
        let local = gather_local_snapshot(
            app,
            sync_state.sync_ssh_keys,
            settings.clone(),
            device_id.clone(),
            device_name.clone(),
        )?;
        sync::merge_snapshot(&local, None)
    } else {
        let local = gather_local_snapshot(
            app,
            sync_state.sync_ssh_keys,
            settings.clone(),
            device_id.clone(),
            device_name.clone(),
        )?;
        sync::merge_snapshot(&local, Some(foreign_payload))
    };

    // اول remote رو بنویس، بعد local — اگه store بخوره local دست‌نخورده می‌مونه
    let new_salt = sync::random_sync_salt();
    let key = sync::derive_sync_key(&current_master_password, &new_salt)
        .map_err(|e| format!("Failed to derive sync key: {:?}", e))?;
    let merged_payload = termifai_core::sync::SyncPayload {
        format_version: sync::PAYLOAD_FORMAT_VERSION,
        exported_at: now_iso(),
        device_id: device_id.clone(),
        hosts: outcome.hosts.clone(),
        groups: outcome.groups.clone(),
        snippets: outcome.snippets.clone(),
        snippet_groups: outcome.snippet_groups.clone(),
        port_forwards: outcome.port_forwards.clone(),
        ssh_keys: outcome.ssh_keys.clone(),
        settings: outcome.settings.clone(),
        tombstones: outcome.tombstones.clone(),
    };
    let blob_str = sync::encrypt_payload(&key, &merged_payload)
        .map_err(|e| format!("Failed to encrypt sync payload: {:?}", e))?;
    let blob_bytes = blob_str.into_bytes();
    let new_manifest = Manifest {
        format_version: sync::PAYLOAD_FORMAT_VERSION,
        vault_id: termifai_core::layout::DEFAULT_VAULT_ID.to_string(),
        blob_version: manifest.blob_version + 1,
        updated_at: now_iso(),
        device_id: device_id.clone(),
        device_name: device_name.clone(),
        kdf: sync::default_kdf_params(),
        sync_salt: sync::b64_encode(&new_salt),
        blob_sha256: sync::sha256_hex(&blob_bytes),
        content_hash: Some(sync::payload_content_hash(&merged_payload)),
        collections: Default::default(),
    };
    backend
        .store(&new_manifest, &blob_bytes, Some(manifest.blob_version))
        .map_err(|e| e.to_string())?;

    if crate::sync_auto::dirty_generation() != dirty_gen_at_gather {
        outcome = rebase_outcome_on_current_local(
            app,
            &outcome,
            sync_state.sync_ssh_keys,
            settings,
            device_id,
            device_name,
        )?;
    }
    apply_outcome(app, &outcome, sync_state.sync_ssh_keys)?;

    let still_dirty = crate::sync_auto::dirty_generation() != dirty_gen_at_gather;
    let state = app.state::<AppState>();
    state
        .sync_state_store
        .update_with_migration(migrate_sync_state, |s| {
            s.backend = Some(request.backend.clone());
            s.last_synced_blob_version = new_manifest.blob_version;
            s.last_sync_at = Some(now_iso());
            s.dirty = still_dirty;
            s.settings_cache = SettingsCache {
                app_theme: to_cached_blob(outcome.settings.app_theme.clone()),
                terminal_appearance: to_cached_blob(outcome.settings.terminal_appearance.clone()),
                shortcuts: to_cached_blob(outcome.settings.shortcuts.clone()),
            };
        })
        .map_err(|e| e.to_string())?;

    if still_dirty {
        crate::sync_auto::note_dirty();
    }

    Ok(())
}

// ── Internals ──────────────────────────────────────────────────────────────────

pub(crate) fn load_state(app: &AppHandle) -> Result<SyncState, String> {
    let state = app.state::<AppState>();
    let mut s = state
        .sync_state_store
        .load_with_migration(migrate_sync_state)
        .map_err(|e| e.to_string())?;
    s.sync_ssh_keys = false;
    Ok(s)
}

fn to_status_dto(state: &SyncState) -> SyncStatusDto {
    SyncStatusDto {
        backend: state.backend.clone(),
        last_synced_blob_version: state.last_synced_blob_version,
        last_sync_at: state.last_sync_at.clone(),
        sync_ssh_keys: state.sync_ssh_keys,
        dirty: state.dirty,
        device_id: state.device_id.clone(),
        auto_sync: state.auto_sync,
        last_error: state.last_error.clone(),
        syncing: is_syncing(),
        last_sync_stats: state.last_sync_stats.clone(),
    }
}

fn ensure_device_id(app: &AppHandle) -> Result<String, String> {
    let existing = load_state(app)?.device_id;
    if let Some(id) = existing {
        return Ok(id);
    }
    let id = format!("dev-{}", uuid::Uuid::new_v4());
    let state = app.state::<AppState>();
    state
        .sync_state_store
        .update_with_migration(migrate_sync_state, |s| {
            s.device_id = Some(id.clone());
        })
        .map_err(|e| e.to_string())?;
    Ok(id)
}

/// Falls back to the OS-keychain-cached master password (already used for
/// silent unlock) so background/automatic syncs don't need to prompt.
fn resolve_master_password(explicit: Option<String>) -> Result<String, String> {
    if let Some(pw) = explicit.filter(|p| !p.is_empty()) {
        return Ok(pw);
    }
    crate::vault::cached_master_password().ok_or_else(|| "master_password_required".to_string())
}

struct KeyringTokenStore;

impl termifai_core::sync::TokenStore for KeyringTokenStore {
    fn load(&self, account: &str) -> Result<Option<String>, String> {
        let entry = keyring::Entry::new("termifai", account)
            .map_err(|e| format!("Keychain unavailable: {e}"))?;
        match entry.get_password() {
            Ok(pw) => Ok(Some(pw)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    fn save(&self, account: &str, value: &str) -> Result<(), String> {
        let entry = keyring::Entry::new("termifai", account)
            .map_err(|e| format!("Keychain unavailable: {e}"))?;
        entry.set_password(value).map_err(|e| e.to_string())
    }

    fn delete(&self, account: &str) -> Result<(), String> {
        let entry = keyring::Entry::new("termifai", account)
            .map_err(|e| format!("Keychain unavailable: {e}"))?;
        let _ = entry.delete_credential();
        Ok(())
    }
}

/// `fs::create_dir_all("~/foo")` creates a literal directory named `~` next
/// to the app's working directory — the filesystem never expands `~`, only
/// shells do. Expand it ourselves so a path typed in Settings behaves the
/// way the user expects.
fn expand_home(path: &str) -> std::path::PathBuf {
    if let Some(rest) = path
        .strip_prefix("~/")
        .or_else(|| (path == "~").then_some(""))
    {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            return std::path::PathBuf::from(home).join(rest);
        }
    }
    std::path::PathBuf::from(path)
}

fn build_backend(
    app: &AppHandle,
    config: &SyncBackendConfig,
) -> Result<Box<dyn SyncBackend>, String> {
    use std::sync::Arc;
    match config {
        SyncBackendConfig::LocalDir { path } => {
            Ok(Box::new(LocalDirBackend::new(expand_home(path))))
        }
        SyncBackendConfig::GoogleDrive => Ok(Box::new(
            termifai_core::sync::GoogleDriveBackend::new(Arc::new(KeyringTokenStore)),
        )),
        SyncBackendConfig::Dropbox => Ok(Box::new(termifai_core::sync::DropboxBackend::new(
            Arc::new(KeyringTokenStore),
        ))),
        SyncBackendConfig::Sftp {
            host_id,
            remote_path,
        } => {
            let hosts_vault = crate::hosts::list_hosts(app)?;
            let host = hosts_vault
                .hosts
                .iter()
                .find(|h| &h.id == host_id)
                .ok_or_else(|| format!("Sync server host '{}' not found", host_id))?;

            let password = crate::hosts::decrypt_host_password(host);

            let key_path = if let Some(ref key_id) = host.ssh_key_id {
                if !key_id.trim().is_empty() {
                    crate::ssh_keys::private_key_path(app, key_id)
                        .ok()
                        .map(std::path::PathBuf::from)
                } else {
                    None
                }
            } else {
                None
            };

            let backend = SftpSyncBackend::new(
                host.hostname.clone(),
                host.port,
                host.user.clone(),
                password,
                key_path,
                remote_path.clone(),
            );
            Ok(Box::new(backend))
        }
    }
}

/// Re-merge a sync outcome against the live local vault so saves that landed
/// while `run_sync` was in flight are not wiped by a full-store replace.
fn rebase_outcome_on_current_local(
    app: &AppHandle,
    outcome: &SyncOutcome,
    sync_ssh_keys: bool,
    settings: SettingsPayload,
    device_id: String,
    device_name: Option<String>,
) -> Result<SyncOutcome, String> {
    let current = gather_local_snapshot(app, sync_ssh_keys, settings, device_id, device_name)?;
    let remote = termifai_core::sync::SyncPayload {
        format_version: sync::PAYLOAD_FORMAT_VERSION,
        exported_at: now_iso(),
        device_id: String::new(),
        hosts: outcome.hosts.clone(),
        groups: outcome.groups.clone(),
        snippets: outcome.snippets.clone(),
        snippet_groups: outcome.snippet_groups.clone(),
        port_forwards: outcome.port_forwards.clone(),
        ssh_keys: outcome.ssh_keys.clone(),
        settings: outcome.settings.clone(),
        tombstones: outcome.tombstones.clone(),
    };
    let mut rebased = sync::merge_snapshot(&current, Some(remote));
    rebased.blob_version = outcome.blob_version;
    rebased.uploaded = outcome.uploaded;
    rebased.local_changed = true;
    rebased.collections_uploaded = outcome.collections_uploaded.clone();
    rebased.collections_downloaded = outcome.collections_downloaded.clone();
    Ok(rebased)
}

fn gather_local_snapshot(
    app: &AppHandle,
    sync_ssh_keys: bool,
    settings: SettingsPayload,
    device_id: String,
    device_name: Option<String>,
) -> Result<LocalSnapshot, String> {
    let hosts_vault = crate::hosts::list_hosts(app)?;
    let mut hosts = hosts_vault.hosts;
    for host in hosts.iter_mut() {
        let had_encrypted = host
            .password
            .as_deref()
            .is_some_and(|p| p.starts_with("v1:"));
        host.password = crate::hosts::decrypt_host_password(host);
        // اگه ciphertext هست ولی decrypt نشد (vault قفل)، sync رو قطع کن تا
        // یه snapshot بدون پسورد آپلود/merge نشه و دیتای ریموت پاک نشه
        if had_encrypted && host.password.is_none() {
            return Err("vault_locked".to_string());
        }
    }

    let ssh_keys = if sync_ssh_keys {
        let mut keys = crate::ssh_keys::list_ssh_keys(app)?;
        for key in keys.iter_mut() {
            // Must not upload metadata without PEM: equal created_at + same
            // device_id makes LWW prefer local None over a remote key that still
            // has private material, permanently wiping the sync backup.
            key.private_key_pem = Some(crate::ssh_keys::read_private_key_pem(key)?);
        }
        Some(keys)
    } else {
        None
    };

    let snippets_result = crate::snippets::list_snippets(app)?;

    Ok(LocalSnapshot {
        hosts,
        groups: hosts_vault.groups,
        snippets: snippets_result.snippets,
        snippet_groups: snippets_result.groups,
        port_forwards: crate::port_forwarding::list_port_forwards(app)?,
        ssh_keys,
        settings,
        tombstones: crate::tombstones::list(app)?,
        device_id,
        device_name,
    })
}

/// Writes a merged result back to every local store: hosts (re-encrypting
/// plaintext passwords with the local DEK only when the secret changed),
/// groups, snippets (including `.sh` bodies), port forwards, SSH keys
/// (opt-in only), and the merged tombstone list.
///
/// Hosts/groups/port-forwards/snippets are LWW-merged into the *live* store
/// under each `JsonStore` lock (not a blind replace), so a concurrent save
/// that lands after the sync snapshot was taken cannot be clobbered by stale
/// apply data. Tombstones from the outcome still delete records sync removed.
fn apply_outcome(
    app: &AppHandle,
    outcome: &SyncOutcome,
    sync_ssh_keys: bool,
) -> Result<(), String> {
    let existing_hosts = crate::hosts::list_hosts(app)?.hosts;
    let mut hosts = outcome.hosts.clone();
    for host in hosts.iter_mut() {
        if let Some(plaintext) = host.password.take() {
            if plaintext.is_empty() {
                continue;
            }
            // اگه پسورد منطقی عوض نشده، همون ciphertext قبلی رو نگه می‌داریم
            // تا هر sync بی‌خودی vault محلی رو کثیف نکنه.
            if let Some(existing) = existing_hosts.iter().find(|h| h.id == host.id) {
                if crate::hosts::decrypt_host_password(existing).as_deref()
                    == Some(plaintext.as_str())
                {
                    host.password = existing.password.clone();
                    continue;
                }
            }
            // take() قبلاً پسورد رو برداشته؛ اگه اینجا encrypt نشه و None بنویسیم،
            // پسورد هاست برای همیشه پاک می‌شه. قفل بودن vault یا خطای encrypt باید
            // کل apply رو abort کنه، نه اینکه بی‌سر و صدا passwordless ذخیره بشه.
            let guard = crate::vault::current_key();
            let key = guard.as_ref().ok_or_else(|| {
                "Vault is locked — cannot apply synced host passwords".to_string()
            })?;
            host.password = Some(
                termifai_core::crypto::encrypt_field(key, &plaintext)
                    .map_err(|e| format!("Failed to encrypt synced host password: {e:?}"))?,
            );
        }
    }

    let state = app.state::<AppState>();
    let groups = outcome.groups.clone();
    let tombstones = outcome.tombstones.clone();
    // Prefer live local on equal timestamps (local_device_id >= remote_device_id).
    const APPLY_LOCAL: &str = "apply-local";
    const APPLY_OUTCOME: &str = "apply-from-sync";
    state
        .hosts_store
        .update_with_migration(termifai_core::model::hosts::migrate_hosts_vault, |vault| {
            let live_hosts = std::mem::take(&mut vault.hosts);
            let live_groups = std::mem::take(&mut vault.groups);
            vault.hosts = sync::merge::merge_entities(
                live_hosts,
                hosts.clone(),
                &tombstones,
                termifai_core::model::tombstones::EntityKind::Host,
                APPLY_LOCAL,
                APPLY_OUTCOME,
            );
            vault.groups = sync::merge::merge_entities(
                live_groups,
                groups.clone(),
                &tombstones,
                termifai_core::model::tombstones::EntityKind::Group,
                APPLY_LOCAL,
                APPLY_OUTCOME,
            );
        })
        .map_err(|e| e.to_string())?;

    crate::snippets::apply_synced_snippets(
        app,
        outcome.snippets.clone(),
        outcome.snippet_groups.clone(),
        outcome.tombstones.clone(),
    )?;

    let port_forwards = outcome.port_forwards.clone();
    state
        .port_forward_store
        .update_with_migration(
            termifai_core::model::forwards::migrate_port_forward_vault,
            |vault| {
                let live = std::mem::take(&mut vault.rules);
                vault.rules = sync::merge::merge_entities(
                    live,
                    port_forwards.clone(),
                    &tombstones,
                    termifai_core::model::tombstones::EntityKind::PortForward,
                    APPLY_LOCAL,
                    APPLY_OUTCOME,
                );
            },
        )
        .map_err(|e| e.to_string())?;

    if sync_ssh_keys {
        if let Some(merged_keys) = &outcome.ssh_keys {
            let local_keys = crate::ssh_keys::list_ssh_keys(app)?;
            let merged_ids: std::collections::HashSet<&str> =
                merged_keys.iter().map(|k| k.id.as_str()).collect();

            // New keys this device doesn't have yet.
            for key in merged_keys {
                if !local_keys.iter().any(|k| k.id == key.id) {
                    crate::ssh_keys::import_synced_key(app, key)?;
                }
            }
            // Keys removed elsewhere — tombstone-driven deletion propagates here.
            let removed: Vec<String> = local_keys
                .iter()
                .filter(|k| !merged_ids.contains(k.id.as_str()))
                .map(|k| k.id.clone())
                .collect();
            if !removed.is_empty() {
                crate::ssh_keys::remove_ssh_keys(app, removed)?;
            }
        }
    }

    crate::tombstones::replace_and_prune(app, outcome.tombstones.clone())?;
    Ok(())
}

/// Clears the `syncServer` badge from every host. Used on disconnect / when
/// switching to a non-SFTP backend. Does **not** mark the vault dirty — the
/// badge is a local UI flag for the active sync target, not user content.
fn clear_sync_server_flags(app: &AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();
    state
        .hosts_store
        .update_with_migration(termifai_core::model::hosts::migrate_hosts_vault, |vault| {
            for host in vault.hosts.iter_mut() {
                host.sync_server = None;
            }
        })
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn write_payload_to_local_stores(
    app: &AppHandle,
    payload: &termifai_core::sync::SyncPayload,
) -> Result<(), String> {
    let outcome = SyncOutcome {
        hosts: payload.hosts.clone(),
        groups: payload.groups.clone(),
        snippets: payload.snippets.clone(),
        snippet_groups: payload.snippet_groups.clone(),
        port_forwards: payload.port_forwards.clone(),
        ssh_keys: payload.ssh_keys.clone(),
        settings: payload.settings.clone(),
        tombstones: payload.tombstones.clone(),
        blob_version: 0,
        uploaded: false,
        local_changed: true,
        collections_downloaded: vec![],
        collections_uploaded: vec![],
    };
    apply_outcome(app, &outcome, false)
}

fn now_iso() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// Deletes the remote blob + manifest. Cloud/SFTP backends (phases 2/3) will
/// need their own delete semantics when those variants are added.
fn wipe_remote(app: &AppHandle, config: &SyncBackendConfig) -> Result<(), String> {
    let backend = build_backend(app, config)?;
    backend.wipe().map_err(|e| e.to_string())
}

pub struct SftpSyncBackend {
    hostname: String,
    port: u16,
    username: String,
    password: Option<String>,
    key_path: Option<std::path::PathBuf>,
    remote_path: String,
}

impl SftpSyncBackend {
    pub fn new(
        hostname: String,
        port: u16,
        username: String,
        password: Option<String>,
        key_path: Option<std::path::PathBuf>,
        remote_path: String,
    ) -> Self {
        Self {
            hostname,
            port,
            username,
            password,
            key_path,
            remote_path,
        }
    }

    fn connect(&self) -> Result<ssh2::Session, String> {
        let ssh_cfg = crate::ssh::SshConfig {
            hostname: &self.hostname,
            port: self.port,
            username: &self.username,
            password: self.password.as_deref(),
            key_path: self.key_path.as_deref(),
        };
        crate::ssh::connect(&ssh_cfg, |_, _| {})
            .map_err(|e| format!("Failed to connect to sync server: {}", e))
    }

    /// SFTP never expands `~` — a configured path like `~/.termifai/sync` would
    /// be taken literally (a directory named `~`). Resolve it against the
    /// server-side home directory (`realpath(".")`).
    fn resolve_remote_dir(&self, sftp: &ssh2::Sftp) -> Result<std::path::PathBuf, SyncError> {
        let raw = self.remote_path.trim();
        if raw == "~" || raw.starts_with("~/") {
            let home = sftp.realpath(std::path::Path::new(".")).map_err(|e| {
                SyncError::Backend(format!("Failed to resolve remote home directory: {}", e))
            })?;
            Ok(if raw == "~" {
                home
            } else {
                home.join(&raw[2..])
            })
        } else {
            Ok(std::path::PathBuf::from(raw))
        }
    }

    /// Resolves the remote directory and creates it (with any missing parents —
    /// SFTP mkdir is not recursive) so first sync against a fresh server works.
    fn ensure_remote_dir(&self, sftp: &ssh2::Sftp) -> Result<std::path::PathBuf, SyncError> {
        let dir = self.resolve_remote_dir(sftp)?;
        let mut current = std::path::PathBuf::new();
        for component in dir.components() {
            current.push(component);
            if sftp.stat(&current).is_err() {
                sftp.mkdir(&current, 0o755).map_err(|e| {
                    SyncError::Backend(format!(
                        "Failed to create remote directory {}: {}",
                        current.display(),
                        e
                    ))
                })?;
            }
        }
        Ok(dir)
    }

    fn acquire_lock(
        &self,
        sftp: &ssh2::Sftp,
        lock_path: &std::path::Path,
    ) -> Result<(), SyncError> {
        use ssh2::{OpenFlags, OpenType};
        let mut attempts = 0;
        loop {
            match sftp.open_mode(
                lock_path,
                OpenFlags::CREATE | OpenFlags::EXCLUSIVE | OpenFlags::WRITE,
                0o644,
                OpenType::File,
            ) {
                Ok(_) => return Ok(()),
                Err(open_err) => {
                    match sftp.stat(lock_path) {
                        Ok(stat) => {
                            if let Some(mtime) = stat.mtime {
                                let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
                                if now > mtime && now - mtime > 120 {
                                    let _ = sftp.unlink(lock_path);
                                    continue;
                                }
                            }
                        }
                        // The lock file doesn't exist, so the open failure wasn't
                        // contention — report the real error instead of retrying
                        // into a misleading "remote changed concurrently".
                        Err(_) => {
                            return Err(SyncError::Backend(format!(
                                "Failed to create sync lock file {}: {}",
                                lock_path.display(),
                                open_err
                            )))
                        }
                    }

                    attempts += 1;
                    if attempts > 5 {
                        return Err(SyncError::Conflict);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            }
        }
    }
}

impl SyncBackend for SftpSyncBackend {
    fn fetch_manifest(&self) -> Result<Option<Manifest>, SyncError> {
        let session = self.connect().map_err(SyncError::Backend)?;
        let sftp = session
            .sftp()
            .map_err(|e| SyncError::Backend(e.to_string()))?;

        let remote_dir = self.ensure_remote_dir(&sftp)?;

        let manifest_path = remote_dir.join("manifest.json");
        let mut file = match sftp.open(&manifest_path) {
            Ok(f) => f,
            Err(_) => return Ok(None),
        };

        use std::io::Read;
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|e| SyncError::Io(e.to_string()))?;

        let manifest: Manifest = serde_json::from_str(&contents)?;
        Ok(Some(manifest))
    }

    fn fetch_blob(&self) -> Result<Vec<u8>, SyncError> {
        let session = self.connect().map_err(SyncError::Backend)?;
        let sftp = session
            .sftp()
            .map_err(|e| SyncError::Backend(e.to_string()))?;

        let remote_dir = self.resolve_remote_dir(&sftp)?;
        let blob_path = remote_dir.join("vault.blob");

        let mut file = sftp.open(&blob_path).map_err(|_| SyncError::NotFound)?;

        use std::io::Read;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)
            .map_err(|e| SyncError::Io(e.to_string()))?;
        Ok(contents)
    }

    fn fetch_collection(
        &self,
        name: &str,
        expected_sha256: Option<&str>,
    ) -> Result<Vec<u8>, SyncError> {
        let session = self.connect().map_err(SyncError::Backend)?;
        let sftp = session
            .sftp()
            .map_err(|e| SyncError::Backend(e.to_string()))?;
        let remote_dir = self.resolve_remote_dir(&sftp)?;
        use std::io::Read;
        if let Some(sha) = expected_sha256.filter(|s| !s.is_empty()) {
            let addressed = sync::collections::collection_file_name(name, Some(sha));
            let path = remote_dir.join(addressed);
            if let Ok(mut file) = sftp.open(&path) {
                let mut contents = Vec::new();
                file.read_to_end(&mut contents)
                    .map_err(|e| SyncError::Io(e.to_string()))?;
                return Ok(contents);
            }
        }
        let file_name = CollectionKind::from_str(name)
            .map(|k| k.file_name())
            .unwrap_or_else(|| format!("col-{name}.blob"));
        let path = remote_dir.join(file_name);
        let mut file = sftp.open(&path).map_err(|_| SyncError::NotFound)?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)
            .map_err(|e| SyncError::Io(e.to_string()))?;
        Ok(contents)
    }

    fn store(
        &self,
        manifest: &Manifest,
        blob: &[u8],
        expected_blob_version: Option<u64>,
    ) -> Result<(), SyncError> {
        let session = self.connect().map_err(SyncError::Backend)?;
        let sftp = session
            .sftp()
            .map_err(|e| SyncError::Backend(e.to_string()))?;

        let remote_dir = self.ensure_remote_dir(&sftp)?;

        let lock_path = remote_dir.join(".lock");
        let manifest_path = remote_dir.join("manifest.json");

        // 1. Acquire exclusive lock
        self.acquire_lock(&sftp, &lock_path)?;

        // 2. CAS check
        let mut conflict = false;
        let current_manifest = sftp.open(&manifest_path).ok().and_then(|mut f| {
            use std::io::Read;
            let mut contents = String::new();
            f.read_to_string(&mut contents).ok()?;
            serde_json::from_str::<Manifest>(&contents).ok()
        });

        match (expected_blob_version, current_manifest.as_ref()) {
            (None, None) => {}
            (None, Some(_)) => conflict = true,
            (Some(expected), Some(current)) if current.blob_version != expected => conflict = true,
            (Some(_), None) => conflict = true,
            _ => {}
        }

        if conflict {
            let _ = sftp.unlink(&lock_path);
            return Err(SyncError::Conflict);
        }

        // 3. Write temp files
        let blob_tmp = remote_dir.join("vault.blob.tmp");
        let manifest_tmp = remote_dir.join("manifest.json.tmp");

        {
            use std::io::Write;
            let mut f_blob = sftp
                .create(&blob_tmp)
                .map_err(|e| SyncError::Backend(e.to_string()))?;
            f_blob
                .write_all(blob)
                .map_err(|e| SyncError::Io(e.to_string()))?;
        }

        {
            use std::io::Write;
            let manifest_bytes = serde_json::to_vec_pretty(manifest)?;
            let mut f_manifest = sftp
                .create(&manifest_tmp)
                .map_err(|e| SyncError::Backend(e.to_string()))?;
            f_manifest
                .write_all(&manifest_bytes)
                .map_err(|e| SyncError::Io(e.to_string()))?;
        }

        // 4. Rename temp to final (atomic per file)
        let blob_path = remote_dir.join("vault.blob");
        let _ = sftp.unlink(&blob_path);
        sftp.rename(&blob_tmp, &blob_path, None)
            .map_err(|e| SyncError::Backend(e.to_string()))?;

        let _ = sftp.unlink(&manifest_path);
        sftp.rename(&manifest_tmp, &manifest_path, None)
            .map_err(|e| SyncError::Backend(e.to_string()))?;

        // 5. Release lock
        let _ = sftp.unlink(&lock_path);

        Ok(())
    }

    fn store_delta(
        &self,
        manifest: &Manifest,
        changed: &[(String, Vec<u8>)],
        expected_blob_version: Option<u64>,
    ) -> Result<(), SyncError> {
        let session = self.connect().map_err(SyncError::Backend)?;
        let sftp = session
            .sftp()
            .map_err(|e| SyncError::Backend(e.to_string()))?;

        let remote_dir = self.ensure_remote_dir(&sftp)?;
        let lock_path = remote_dir.join(".lock");
        let manifest_path = remote_dir.join("manifest.json");

        self.acquire_lock(&sftp, &lock_path)?;

        let mut conflict = false;
        let current_manifest = sftp.open(&manifest_path).ok().and_then(|mut f| {
            use std::io::Read;
            let mut contents = String::new();
            f.read_to_string(&mut contents).ok()?;
            serde_json::from_str::<Manifest>(&contents).ok()
        });

        match (expected_blob_version, current_manifest.as_ref()) {
            (None, None) => {}
            (None, Some(_)) => conflict = true,
            (Some(expected), Some(current)) if current.blob_version != expected => conflict = true,
            (Some(_), None) => conflict = true,
            _ => {}
        }

        if conflict {
            let _ = sftp.unlink(&lock_path);
            return Err(SyncError::Conflict);
        }

        use std::io::Write;
        for (name, bytes) in changed {
            let sha = sync::sha256_hex(bytes);
            let addressed_name = sync::collections::collection_file_name(name, Some(&sha));
            let addressed_path = remote_dir.join(&addressed_name);
            let addressed_tmp = remote_dir.join(format!("{addressed_name}.tmp"));
            {
                let mut f = sftp
                    .create(&addressed_tmp)
                    .map_err(|e| SyncError::Backend(e.to_string()))?;
                f.write_all(bytes)
                    .map_err(|e| SyncError::Io(e.to_string()))?;
            }
            let _ = sftp.unlink(&addressed_path);
            sftp.rename(&addressed_tmp, &addressed_path, None)
                .map_err(|e| SyncError::Backend(e.to_string()))?;

            // alias پایدار برای کلاینت قدیمی
            let file_name = CollectionKind::from_str(name)
                .map(|k| k.file_name())
                .unwrap_or_else(|| format!("col-{name}.blob"));
            let path = remote_dir.join(&file_name);
            let tmp = remote_dir.join(format!("{file_name}.tmp"));
            {
                let mut f = sftp
                    .create(&tmp)
                    .map_err(|e| SyncError::Backend(e.to_string()))?;
                f.write_all(bytes)
                    .map_err(|e| SyncError::Io(e.to_string()))?;
            }
            let _ = sftp.unlink(&path);
            sftp.rename(&tmp, &path, None)
                .map_err(|e| SyncError::Backend(e.to_string()))?;
        }

        let manifest_tmp = remote_dir.join("manifest.json.tmp");
        {
            let manifest_bytes = serde_json::to_vec_pretty(manifest)?;
            let mut f = sftp
                .create(&manifest_tmp)
                .map_err(|e| SyncError::Backend(e.to_string()))?;
            f.write_all(&manifest_bytes)
                .map_err(|e| SyncError::Io(e.to_string()))?;
        }
        let _ = sftp.unlink(&manifest_path);
        sftp.rename(&manifest_tmp, &manifest_path, None)
            .map_err(|e| SyncError::Backend(e.to_string()))?;

        let _ = sftp.unlink(&remote_dir.join("vault.blob"));
        let _ = sftp.unlink(&lock_path);
        Ok(())
    }

    fn wipe(&self) -> Result<(), SyncError> {
        let session = self.connect().map_err(SyncError::Backend)?;
        let sftp = session
            .sftp()
            .map_err(|e| SyncError::Backend(e.to_string()))?;

        let remote_dir = self.resolve_remote_dir(&sftp)?;
        let _ = sftp.unlink(&remote_dir.join("manifest.json"));
        let _ = sftp.unlink(&remote_dir.join("vault.blob"));
        let _ = sftp.unlink(&remote_dir.join(".lock"));
        for kind in CollectionKind::ALL {
            let _ = sftp.unlink(&remote_dir.join(kind.file_name()));
        }
        Ok(())
    }
}
