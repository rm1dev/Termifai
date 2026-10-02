use crate::AppState;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::ToSocketAddrs;
use std::thread;
use std::time::Duration;
use tauri::{AppHandle, Manager};
use termifai_core::model::hosts::migrate_hosts_vault;
pub use termifai_core::model::hosts::{
    group_deletion_includes_host, AuthMethod, Host, HostGroup, HostsVault, OsKind,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveHostRequest {
    pub id: Option<String>,
    pub name: String,
    pub user: String,
    pub hostname: String,
    pub port: u16,
    pub os: OsKind,
    #[serde(default)]
    pub tags: Vec<String>,
    pub group_id: Option<String>,
    pub auth_method: Option<AuthMethod>,
    pub password: Option<String>,
    pub ssh_key_id: Option<String>,
    pub show_status_in_dashboard: Option<bool>,
    pub working_directory: Option<String>,
    pub default_sftp_path: Option<String>,
    #[serde(default)]
    pub sync_server: Option<bool>,
    #[serde(default)]
    pub resilient_session: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveHostGroupRequest {
    pub id: Option<String>,
    pub name: String,
    pub parent_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestHostConnectionRequest {
    pub hostname: String,
    pub user: String,
    pub port: u16,
    pub password: Option<String>,
    pub ssh_key_id: Option<String>,
    pub timeout_secs: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestHostConnectionResult {
    pub ok: bool,
    pub message: String,
}

pub fn list_hosts(app: &AppHandle) -> Result<HostsVault, String> {
    let state = app.state::<AppState>();
    let vault = state
        .hosts_store
        .load_with_migration(migrate_hosts_vault)
        .map_err(|e| e.to_string())?;

    if vault.crypto.is_none() {
        return Ok(vault);
    }

    // Rare, one-time path: legacy hosts.json still has the crypto meta embedded.
    // Re-check and strip it atomically under the store's lock (a single
    // update_with_migration call) instead of a separate load + save, so a
    // concurrent save_host/remove_hosts write can't be silently clobbered by the
    // stale snapshot read above. The vault_crypto_store write happens *inside*
    // the critical section, before the strip is persisted, so a crash mid-migration
    // (or a failed write) leaves the crypto meta present in both places rather
    // than lost from both.
    let mut migrate_err = None;
    let vault = state
        .hosts_store
        .update_with_migration(migrate_hosts_vault, |v| {
            if let Some(crypto_meta) = v.crypto.take() {
                if let Err(e) =
                    crate::vault::migrate_crypto_meta_from_hosts(app, crypto_meta.clone())
                {
                    migrate_err = Some(e);
                    v.crypto = Some(crypto_meta);
                }
            }
        })
        .map_err(|e| e.to_string())?;

    if let Some(e) = migrate_err {
        return Err(e);
    }

    Ok(vault)
}

/// Returns the plaintext password for a host:
/// - legacy plaintext (no "v1:" prefix) is returned as-is;
/// - "v1:" tokens are decrypted with the unlocked vault key;
/// - returns None if there is no password, or the vault is locked, or decryption fails.
pub fn decrypt_host_password(host: &Host) -> Option<String> {
    let stored = host.password.as_ref().filter(|p| !p.is_empty())?;
    if !stored.starts_with("v1:") {
        return Some(stored.clone());
    }
    let guard = crate::vault::current_key();
    let key = guard.as_ref()?;
    decrypt_token(key, stored)
}

/// Decrypts a "v1:" token, unwrapping values that were double-encrypted by the
/// former edit round-trip bug (the token shown in the edit form got re-encrypted
/// on save). A decrypted value that starts with "v1:" but fails to decrypt again
/// is treated as the actual password.
fn decrypt_token(key: &termifai_core::crypto::VaultKey, token: &str) -> Option<String> {
    let mut value = termifai_core::crypto::decrypt_field(key, token).ok()?;
    for _ in 0..4 {
        if !value.starts_with("v1:") {
            break;
        }
        match termifai_core::crypto::decrypt_field(key, &value) {
            Ok(inner) => value = inner,
            Err(_) => break,
        }
    }
    Some(value)
}

/// Plaintext password of a stored host, for display in the edit form.
/// `None` when the host has no password or the vault is locked.
pub fn get_host_password(app: &AppHandle, id: &str) -> Result<Option<String>, String> {
    let vault = list_hosts(app)?;
    let host = vault
        .hosts
        .iter()
        .find(|h| h.id == id)
        .ok_or_else(|| format!("Host '{}' not found", id))?;
    Ok(decrypt_host_password(host))
}

/// Re-encrypt any legacy plaintext password fields using the unlocked vault key.
/// Returns how many hosts were migrated. No-op if the vault is locked.
pub fn migrate_plaintext_passwords(app: &AppHandle) -> Result<usize, String> {
    let guard = crate::vault::current_key();
    let key = match guard.as_ref() {
        Some(k) => k,
        None => return Ok(0),
    };

    let state = app.state::<AppState>();
    let mut migrated = 0usize;

    state
        .hosts_store
        .update_with_migration(migrate_hosts_vault, |vault| {
            for host in vault.hosts.iter_mut() {
                if let Some(pw) = host.password.as_ref() {
                    if !pw.is_empty() && !pw.starts_with("v1:") {
                        if let Ok(token) = termifai_core::crypto::encrypt_field(key, pw) {
                            host.password = Some(token);
                            migrated += 1;
                        }
                    }
                }
            }
        })
        .map_err(|e| e.to_string())?;

    Ok(migrated)
}

pub fn save_host(app: &AppHandle, request: SaveHostRequest) -> Result<Host, String> {
    validate_host(&request)?;

    let id = request
        .id
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("h-{}", uuid::Uuid::new_v4()));
    let now = now_iso();
    let encrypted_password = encrypt_password_for_save(request.password)?;

    let state = app.state::<AppState>();
    let mut error = None;
    let mut saved_host = None;

    state
        .hosts_store
        .update_with_migration(migrate_hosts_vault, |vault| {
            if let Err(e) = validate_group_exists(vault, request.group_id.as_deref()) {
                error = Some(e);
                return;
            }

            // Enforce at-most-one sync_server rule: clear the flag on all other hosts
            // before setting it on this one.
            let is_sync_server = request.sync_server == Some(true);
            if is_sync_server {
                for other in vault.hosts.iter_mut() {
                    if other.id != id {
                        other.sync_server = None;
                    }
                }
            }

            let existing_last_used = vault
                .hosts
                .iter()
                .find(|host| host.id == id)
                .and_then(|host| host.last_used.clone());
            let host = Host {
                id: id.clone(),
                name: request.name.trim().to_string(),
                user: request.user.trim().to_string(),
                hostname: request.hostname.trim().to_string(),
                port: request.port,
                os: request.os,
                tags: request
                    .tags
                    .into_iter()
                    .map(|tag| tag.trim().to_string())
                    .filter(|tag| !tag.is_empty())
                    .collect(),
                last_used: existing_last_used.or(Some(now.clone())),
                group_id: request.group_id.filter(|value| !value.trim().is_empty()),
                auth_method: request.auth_method,
                password: encrypted_password,
                ssh_key_id: request.ssh_key_id.filter(|value| !value.trim().is_empty()),
                show_status_in_dashboard: request.show_status_in_dashboard,
                working_directory: request
                    .working_directory
                    .filter(|value| !value.trim().is_empty()),
                default_sftp_path: request
                    .default_sftp_path
                    .filter(|value| !value.trim().is_empty()),
                updated_at: Some(now),
                sync_server: if is_sync_server { Some(true) } else { None },
                // فقط وقتی روشنه ذخیره‌ش کن که فایل JSON شلوغ نشه
                resilient_session: request.resilient_session.filter(|v| *v),
            };

            upsert_by_id(&mut vault.hosts, host.clone(), |item| &item.id);
            saved_host = Some(host);
        })
        .map_err(|e| e.to_string())?;

    if let Some(err_msg) = error {
        return Err(err_msg);
    }

    crate::sync::mark_dirty(app);
    saved_host.ok_or_else(|| "Failed to save host".to_string())
}

pub fn remove_hosts(app: &AppHandle, ids: Vec<String>) -> Result<(), String> {
    // Guard: block removal of a host that is currently configured as the sync server.
    let sync_state = crate::sync::load_state(app)?;
    if let Some(termifai_core::model::sync_state::SyncBackendConfig::Sftp { host_id, .. }) =
        &sync_state.backend
    {
        if ids.contains(host_id) {
            return Err(
                "Cannot delete this host — it is configured as the sync server. \
                 Disconnect sync first."
                    .to_string(),
            );
        }
    }

    let state = app.state::<AppState>();
    state
        .hosts_store
        .update_with_migration(migrate_hosts_vault, |vault| {
            vault.hosts.retain(|host| !ids.contains(&host.id));
        })
        .map_err(|e| e.to_string())?;
    crate::tombstones::record(app, crate::tombstones::EntityKind::Host, &ids)?;
    crate::sync::mark_dirty(app);
    Ok(())
}

pub fn save_host_group(
    app: &AppHandle,
    request: SaveHostGroupRequest,
) -> Result<HostGroup, String> {
    let name = request.name.trim();
    if name.is_empty() {
        return Err("Group name is required".to_string());
    }

    let id = request
        .id
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("g-{}", uuid::Uuid::new_v4()));

    if request.parent_id.as_deref() == Some(&id) {
        return Err("Group cannot be its own parent".to_string());
    }

    let parent_id = request
        .parent_id
        .as_ref()
        .filter(|value| !value.trim().is_empty())
        .cloned();

    let group = HostGroup {
        id: id.clone(),
        name: name.to_string(),
        parent_id: parent_id.clone(),
        updated_at: Some(now_iso()),
    };

    let state = app.state::<AppState>();
    let mut error = None;

    state
        .hosts_store
        .update_with_migration(migrate_hosts_vault, |vault| {
            if let Err(e) = validate_group_exists(vault, parent_id.as_deref()) {
                error = Some(e);
                return;
            }
            if would_create_group_cycle(&vault.groups, &id, parent_id.as_deref()) {
                error = Some("Group cannot be nested under its own descendant".to_string());
                return;
            }
            upsert_by_id(&mut vault.groups, group.clone(), |item| &item.id);
        })
        .map_err(|e| e.to_string())?;

    if let Some(err_msg) = error {
        return Err(err_msg);
    }

    crate::sync::mark_dirty(app);
    Ok(group)
}

pub fn remove_host_group(app: &AppHandle, id: String) -> Result<(), String> {
    // همون گارد remove_hosts: هاست sync server نباید با حذف گروه پاک بشه
    let sync_state = crate::sync::load_state(app)?;
    let sync_host_id = match &sync_state.backend {
        Some(termifai_core::model::sync_state::SyncBackendConfig::Sftp { host_id, .. }) => {
            Some(host_id.clone())
        }
        _ => None,
    };

    let state = app.state::<AppState>();
    let mut removed_group_ids: Vec<String> = Vec::new();
    let mut removed_host_ids: Vec<String> = Vec::new();
    let mut blocked_sync_host = false;
    state
        .hosts_store
        .update_with_migration(migrate_hosts_vault, |vault| {
            let descendants = sftp_descendant_group_ids(&vault.groups, &id);
            let candidate_host_ids: Vec<String> = vault
                .hosts
                .iter()
                .filter(|host| {
                    host.group_id
                        .as_ref()
                        .map(|group_id| group_id == &id || descendants.contains(group_id))
                        .unwrap_or(false)
                })
                .map(|host| host.id.clone())
                .collect();

            if let Some(sync_id) = &sync_host_id {
                if group_deletion_includes_host(vault, &id, sync_id) {
                    blocked_sync_host = true;
                    return;
                }
            }

            removed_group_ids = std::iter::once(id.clone())
                .chain(descendants.iter().cloned())
                .collect();
            removed_host_ids = candidate_host_ids;

            vault
                .groups
                .retain(|group| group.id != id && !descendants.contains(&group.id));
            vault.hosts.retain(|host| {
                host.group_id
                    .as_ref()
                    .map(|group_id| group_id != &id && !descendants.contains(group_id))
                    .unwrap_or(true)
            });
        })
        .map_err(|e| e.to_string())?;

    if blocked_sync_host {
        return Err(
            "Cannot delete this group — it contains the host configured as the sync server. \
             Disconnect sync first."
                .to_string(),
        );
    }

    crate::tombstones::record(
        app,
        crate::tombstones::EntityKind::Group,
        &removed_group_ids,
    )?;
    crate::tombstones::record(app, crate::tombstones::EntityKind::Host, &removed_host_ids)?;
    crate::sync::mark_dirty(app);
    Ok(())
}

pub fn test_host_connection(
    app: &AppHandle,
    request: TestHostConnectionRequest,
) -> Result<TestHostConnectionResult, String> {
    let hostname = request.hostname.trim();
    let user = request.user.trim();
    if hostname.is_empty() {
        return Err("Hostname is required".to_string());
    }
    if user.is_empty() {
        return Err("Username is required".to_string());
    }
    if request.port == 0 {
        return Err("Port must be between 1 and 65535".to_string());
    }

    (hostname, request.port)
        .to_socket_addrs()
        .map_err(|e| format!("Failed to resolve host: {}", e))?;

    let timeout_secs = request.timeout_secs.unwrap_or(8).clamp(2, 30);
    // جلوگیری از تزریق آپشن OpenSSH از طریق user/hostname (مثل -oProxyCommand=…)
    validate_ssh_cli_identity(user, hostname)?;
    let mut command = portable_pty::CommandBuilder::new("ssh");
    command.arg("-o");
    command.arg("BatchMode=no");
    // accept-new: trust a host's key on first contact (TOFU) and record it in the
    // user's known_hosts, but hard-fail if a previously recorded key changes —
    // unlike StrictHostKeyChecking=no + /dev/null known_hosts, which trusted every
    // connection unconditionally and made this test blind to MITM.
    command.arg("-o");
    command.arg("StrictHostKeyChecking=accept-new");
    command.arg("-o");
    command.arg(format!("ConnectTimeout={}", timeout_secs));
    command.arg("-p");
    command.arg(request.port.to_string());

    if let Some(ssh_key_id) = request
        .ssh_key_id
        .as_deref()
        .filter(|id| !id.trim().is_empty())
    {
        let key_path = crate::ssh_keys::private_key_path(app, ssh_key_id)?;
        command.arg("-i");
        command.arg(key_path);
    }

    push_ssh_cli_destination(&mut command, user, hostname);
    command.arg("echo");
    command.arg("termifai-ssh-ok");

    // The edit form sends the stored "v1:" token when the user didn't retype the
    // password — decrypt it before handing it to ssh.
    let password = match request.password.filter(|p| !p.is_empty()) {
        Some(pw) if pw.starts_with("v1:") => {
            let guard = crate::vault::current_key();
            let key = guard
                .as_ref()
                .ok_or("Vault is locked — unlock it to use the saved password")?;
            decrypt_token(key, &pw)
                .ok_or("Failed to decrypt the saved password — re-enter it and try again")?
        }
        Some(pw) => pw,
        None => String::new(),
    };
    run_ssh_test(command, password, timeout_secs)
}

fn run_ssh_test(
    command: portable_pty::CommandBuilder,
    password: String,
    timeout_secs: u64,
) -> Result<TestHostConnectionResult, String> {
    let pty_system = portable_pty::native_pty_system();
    let pair = pty_system
        .openpty(portable_pty::PtySize {
            rows: 24,
            cols: 100,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| format!("Failed to open PTY for SSH test: {}", e))?;
    let mut child = pair
        .slave
        .spawn_command(command)
        .map_err(|e| format!("Failed to run ssh: {}", e))?;
    let mut reader = pair
        .master
        .try_clone_reader()
        .map_err(|e| format!("Failed to read SSH test output: {}", e))?;
    let mut writer = pair
        .master
        .take_writer()
        .map_err(|e| format!("Failed to write SSH test input: {}", e))?;
    let mut killer = child.clone_killer();
    let timeout = Duration::from_secs(timeout_secs);

    // Run the blocking read loop in a dedicated thread and communicate via channel.
    // This lets us enforce a hard timeout without blocking on reader.read() forever,
    // which on Linux can hang indefinitely even after the child process is killed.
    let (tx, rx) = std::sync::mpsc::channel::<Result<TestHostConnectionResult, String>>();

    thread::spawn(move || {
        let mut output = String::new();
        let mut password_sent = false;
        let mut buffer = [0_u8; 512];

        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    let chunk = String::from_utf8_lossy(&buffer[..n]);
                    output.push_str(&chunk);
                    let lower = output.to_lowercase();

                    if lower.contains("termifai-ssh-ok") {
                        let _ = child.kill();
                        let _ = tx.send(Ok(TestHostConnectionResult {
                            ok: true,
                            message: "SSH authentication succeeded".to_string(),
                        }));
                        return;
                    }

                    if !password_sent && lower.contains("password:") {
                        if password.is_empty() {
                            let _ = child.kill();
                            let _ = tx.send(Ok(TestHostConnectionResult {
                                ok: false,
                                message: "SSH password is required for this host".to_string(),
                            }));
                            return;
                        }
                        if writer
                            .write_all(format!("{}\r", password).as_bytes())
                            .is_err()
                        {
                            break;
                        }
                        password_sent = true;
                    }
                }
                Err(_) => break,
            }

            if let Ok(Some(_)) = child.try_wait() {
                break;
            }
        }

        let _ = child.wait();
        let _ = tx.send(Ok(TestHostConnectionResult {
            ok: false,
            message: ssh_failure_message(&output),
        }));
    });

    // Wait for the result with a hard timeout; kill the child if it expires
    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(_) => {
            let _ = killer.kill();
            Ok(TestHostConnectionResult {
                ok: false,
                message: "SSH connection test timed out".to_string(),
            })
        }
    }
}

fn ssh_failure_message(output: &str) -> String {
    let lower = output.to_lowercase();
    if lower.contains("permission denied") {
        "SSH authentication failed".to_string()
    } else if lower.contains("connection refused") {
        "SSH connection refused".to_string()
    } else if lower.contains("operation timed out") || lower.contains("connection timed out") {
        "SSH connection timed out".to_string()
    } else if lower.contains("could not resolve hostname")
        || lower.contains("name or service not known")
    {
        "SSH hostname could not be resolved".to_string()
    } else if lower.contains("no route to host") {
        "No route to SSH host".to_string()
    } else {
        "SSH test failed".to_string()
    }
}

fn validate_host(request: &SaveHostRequest) -> Result<(), String> {
    if request.name.trim().is_empty() {
        return Err("Host name is required".to_string());
    }
    validate_ssh_cli_identity(request.user.trim(), request.hostname.trim())?;
    if request.port == 0 {
        return Err("Port must be between 1 and 65535".to_string());
    }
    Ok(())
}

/// OpenSSH treats a destination that begins with `-` as another option. A crafted
/// username like `-oProxyCommand=…` therefore becomes local command execution when
/// we spawn `ssh user@host`. Same for a leading-dash hostname if ever passed alone.
/// Reject those shapes at save/test time and always pass `--` before the destination.
pub(crate) fn validate_ssh_cli_identity(user: &str, hostname: &str) -> Result<(), String> {
    validate_ssh_cli_user(user)?;
    validate_ssh_cli_hostname(hostname)?;
    Ok(())
}

fn validate_ssh_cli_user(user: &str) -> Result<(), String> {
    if user.is_empty() {
        return Err("Username is required".to_string());
    }
    if user.starts_with('-') {
        return Err("Username must not start with '-'".to_string());
    }
    if user.contains('@') {
        return Err("Username must not contain '@'".to_string());
    }
    if user
        .chars()
        .any(|ch| ch.is_whitespace() || ch.is_control() || ch == '\0')
    {
        return Err("Username contains invalid characters".to_string());
    }
    Ok(())
}

fn validate_ssh_cli_hostname(hostname: &str) -> Result<(), String> {
    if hostname.is_empty() {
        return Err("Hostname is required".to_string());
    }
    if hostname.starts_with('-') {
        return Err("Hostname must not start with '-'".to_string());
    }
    if hostname
        .chars()
        .any(|ch| ch.is_whitespace() || ch.is_control() || ch == '\0')
    {
        return Err("Hostname contains invalid characters".to_string());
    }
    Ok(())
}

pub(crate) fn push_ssh_cli_destination(
    command: &mut portable_pty::CommandBuilder,
    user: &str,
    hostname: &str,
) {
    command.arg("--");
    command.arg(format!("{user}@{hostname}"));
}

/// Keep only hosts whose SSH identity is safe to pass to the system `ssh`
/// binary. When an incoming sync record fails validation, prefer the existing
/// local copy (if that copy is itself valid) over installing an injection
/// payload; otherwise drop the host.
pub(crate) fn filter_synced_ssh_hosts(incoming: &[Host], existing: &[Host]) -> Vec<Host> {
    incoming
        .iter()
        .filter_map(|host| {
            if validate_ssh_cli_identity(host.user.trim(), host.hostname.trim()).is_ok() {
                return Some(host.clone());
            }
            existing.iter().find_map(|prior| {
                if prior.id != host.id {
                    return None;
                }
                if validate_ssh_cli_identity(prior.user.trim(), prior.hostname.trim()).is_ok() {
                    Some(prior.clone())
                } else {
                    None
                }
            })
        })
        .collect()
}

fn validate_group_exists(vault: &HostsVault, group_id: Option<&str>) -> Result<(), String> {
    if let Some(group_id) = group_id {
        if !vault.groups.iter().any(|group| group.id == group_id) {
            return Err("Selected group does not exist".to_string());
        }
    }
    Ok(())
}

fn upsert_by_id<T, F>(items: &mut Vec<T>, item: T, id: F)
where
    F: Fn(&T) -> &String,
{
    if let Some(index) = items.iter().position(|existing| id(existing) == id(&item)) {
        items[index] = item;
    } else {
        items.insert(0, item);
    }
}

fn would_create_group_cycle(groups: &[HostGroup], id: &str, parent_id: Option<&str>) -> bool {
    let mut current = parent_id;
    let mut seen = std::collections::HashSet::new();
    while let Some(pid) = current {
        if pid == id {
            return true;
        }
        if !seen.insert(pid) {
            return true;
        }
        current = groups
            .iter()
            .find(|g| g.id == pid)
            .and_then(|g| g.parent_id.as_deref());
    }
    false
}

fn sftp_descendant_group_ids(groups: &[HostGroup], id: &str) -> Vec<String> {
    let mut descendants = Vec::new();
    let mut stack = vec![id.to_string()];
    let mut visited = std::collections::HashSet::new();

    while let Some(parent_id) = stack.pop() {
        if !visited.insert(parent_id.clone()) {
            continue;
        }
        for group in groups.iter().filter(|group| {
            group
                .parent_id
                .as_ref()
                .map(|current| current == &parent_id)
                .unwrap_or(false)
        }) {
            descendants.push(group.id.clone());
            stack.push(group.id.clone());
        }
    }

    descendants
}

/// Encrypt a to-be-saved password with the unlocked vault key. If the value is
/// empty it becomes None. If the vault is locked, we return an error.
/// A value that is already a "v1:" token is stored as-is: the edit form round-trips
/// the stored token when the user leaves the password unchanged, and re-encrypting
/// it would double-encrypt the password.
fn encrypt_password_for_save(password: Option<String>) -> Result<Option<String>, String> {
    let pw = match password.filter(|value| !value.is_empty()) {
        Some(pw) => pw,
        None => return Ok(None),
    };
    if pw.starts_with("v1:") {
        return Ok(Some(pw));
    }
    let guard = crate::vault::current_key();
    match guard.as_ref() {
        Some(key) => termifai_core::crypto::encrypt_field(key, &pw)
            .map(Some)
            .map_err(|e| format!("Encryption failed: {:?}", e)),
        None => Err("Vault is locked — unlock it to save a password".to_string()),
    }
}

fn now_iso() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypt_host_password_passes_through_legacy_plaintext() {
        let host = Host {
            id: "h1".into(),
            name: "n".into(),
            user: "u".into(),
            hostname: "h".into(),
            port: 22,
            os: OsKind::Other,
            tags: vec![],
            last_used: None,
            group_id: None,
            auth_method: None,
            password: Some("plainpw".into()),
            ssh_key_id: None,
            show_status_in_dashboard: None,
            working_directory: None,
            default_sftp_path: None,
            updated_at: None,
            sync_server: None,
            resilient_session: None,
        };
        assert_eq!(decrypt_host_password(&host), Some("plainpw".to_string()));
    }

    #[test]
    fn decrypt_host_password_none_when_no_password() {
        let host = Host {
            id: "h1".into(),
            name: "n".into(),
            user: "u".into(),
            hostname: "h".into(),
            port: 22,
            os: OsKind::Other,
            tags: vec![],
            last_used: None,
            group_id: None,
            auth_method: None,
            password: None,
            ssh_key_id: None,
            show_status_in_dashboard: None,
            working_directory: None,
            default_sftp_path: None,
            updated_at: None,
            sync_server: None,
            resilient_session: None,
        };
        assert_eq!(decrypt_host_password(&host), None);
    }

    #[test]
    fn encrypt_password_fails_when_locked_but_succeeds_when_none() {
        // Vault is locked by default in test environment
        let res = encrypt_password_for_save(Some("secret".to_string()));
        assert!(res.is_err(), "Expected error when vault is locked");
        assert_eq!(
            res.unwrap_err(),
            "Vault is locked — unlock it to save a password"
        );

        let res_none = encrypt_password_for_save(None);
        assert!(res_none.is_ok(), "Expected Ok(None) when password is None");
        assert_eq!(res_none.unwrap(), None);

        let res_empty = encrypt_password_for_save(Some("".to_string()));
        assert!(
            res_empty.is_ok(),
            "Expected Ok(None) when password is empty"
        );
        assert_eq!(res_empty.unwrap(), None);
    }

    #[test]
    fn rejects_ssh_option_injection_via_username() {
        let err = validate_ssh_cli_identity("-oProxyCommand=touch /tmp/pwned #", "127.0.0.1")
            .unwrap_err();
        assert!(
            err.contains("must not start with '-'"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_at_sign_and_whitespace_in_ssh_identity() {
        assert!(validate_ssh_cli_identity("user@evil", "host").is_err());
        assert!(validate_ssh_cli_identity("user name", "host").is_err());
        assert!(validate_ssh_cli_identity("user", "-evilhost").is_err());
        assert!(validate_ssh_cli_identity("user", "host name").is_err());
        assert!(validate_ssh_cli_identity("ubuntu", "example.com").is_ok());
        assert!(validate_ssh_cli_identity("ubuntu", "127.0.0.1").is_ok());
    }

    fn sample_host(id: &str, user: &str, hostname: &str) -> Host {
        Host {
            id: id.into(),
            name: id.into(),
            user: user.into(),
            hostname: hostname.into(),
            port: 22,
            os: OsKind::Other,
            tags: vec![],
            last_used: None,
            group_id: None,
            auth_method: None,
            password: None,
            ssh_key_id: None,
            show_status_in_dashboard: None,
            working_directory: None,
            default_sftp_path: None,
            updated_at: None,
            sync_server: None,
            resilient_session: None,
        }
    }

    #[test]
    fn filter_synced_ssh_hosts_drops_option_injection_payload() {
        let incoming = vec![sample_host(
            "h1",
            "-oProxyCommand=touch /tmp/pwned",
            "127.0.0.1",
        )];
        let kept = filter_synced_ssh_hosts(&incoming, &[]);
        assert!(
            kept.is_empty(),
            "injection username must not be installed via sync"
        );
    }

    #[test]
    fn filter_synced_ssh_hosts_keeps_prior_when_incoming_is_malicious() {
        let existing = vec![sample_host("h1", "ubuntu", "example.com")];
        let incoming = vec![sample_host(
            "h1",
            "-oProxyCommand=touch /tmp/pwned",
            "example.com",
        )];
        let kept = filter_synced_ssh_hosts(&incoming, &existing);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].user, "ubuntu");
    }

    #[test]
    fn filter_synced_ssh_hosts_keeps_valid_incoming() {
        let incoming = vec![sample_host("h1", "ubuntu", "example.com")];
        let kept = filter_synced_ssh_hosts(&incoming, &[]);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].user, "ubuntu");
    }
}
