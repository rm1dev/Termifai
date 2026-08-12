use crate::model::forwards::PortForwardRule;
use crate::model::hosts::{Host, HostGroup};
use crate::model::snippets::{Snippet, SnippetGroup};
use crate::model::ssh_keys::SshKey;
use crate::model::tombstones::{EntityKind, Tombstone};
use crate::sync::backend::{SyncBackend, SyncError};
use crate::sync::collections::{
    assemble_payload, build_collection_hashes, decrypt_collection, encrypt_collection,
    index_integrity_hash, CollectionKind, CollectionMeta, MANIFEST_FORMAT_V2,
};
use crate::sync::merge::{merge_entities, merge_settings, union_tombstones};
use crate::sync::payload::{
    b64_decode, b64_encode, decrypt_payload, default_kdf_params, derive_sync_key,
    payload_content_hash, random_sync_salt, sha256_hex, Manifest, SettingsPayload, SyncPayload,
    PAYLOAD_FORMAT_VERSION,
};
use std::collections::BTreeMap;

const MAX_CONFLICT_RETRIES: u32 = 3;

/// Everything this device knows locally, going into a sync cycle.
#[derive(Clone, Default)]
pub struct LocalSnapshot {
    pub hosts: Vec<Host>,
    pub groups: Vec<HostGroup>,
    pub snippets: Vec<Snippet>,
    pub snippet_groups: Vec<SnippetGroup>,
    pub port_forwards: Vec<PortForwardRule>,
    /// `None` when this device has SSH-key sync turned off.
    pub ssh_keys: Option<Vec<SshKey>>,
    pub settings: SettingsPayload,
    pub tombstones: Vec<Tombstone>,
    pub device_id: String,
    pub device_name: Option<String>,
}

/// The result of one sync cycle: what should be written back to local
/// storage, and the blob version now live on the remote.
pub struct SyncOutcome {
    pub hosts: Vec<Host>,
    pub groups: Vec<HostGroup>,
    pub snippets: Vec<Snippet>,
    pub snippet_groups: Vec<SnippetGroup>,
    pub port_forwards: Vec<PortForwardRule>,
    pub ssh_keys: Option<Vec<SshKey>>,
    pub settings: SettingsPayload,
    pub tombstones: Vec<Tombstone>,
    pub blob_version: u64,
    /// True when a new ciphertext was uploaded (version bumped).
    pub uploaded: bool,
    /// True when merged state differs from the local snapshot that went in —
    /// callers should rewrite local stores only when this is set.
    pub local_changed: bool,
    /// Collection names downloaded this cycle (Phase C diagnostics).
    pub collections_downloaded: Vec<String>,
    /// Collection names uploaded this cycle (Phase C diagnostics).
    pub collections_uploaded: Vec<String>,
}

/// Pure merge step, exposed for the foreign-vault-merge flow (1.7-B) which
/// needs to merge against a payload decrypted with a different password than
/// the one it will re-encrypt and re-upload with.
pub fn merge_snapshot(local: &LocalSnapshot, remote: Option<SyncPayload>) -> SyncOutcome {
    let remote = remote.unwrap_or_default();
    let remote_device_id = if remote.device_id.is_empty() {
        local.device_id.clone()
    } else {
        remote.device_id.clone()
    };

    let tombstones = union_tombstones(&local.tombstones, &remote.tombstones);

    let hosts = merge_entities(
        local.hosts.clone(),
        remote.hosts,
        &tombstones,
        EntityKind::Host,
        &local.device_id,
        &remote_device_id,
    );
    let groups = merge_entities(
        local.groups.clone(),
        remote.groups,
        &tombstones,
        EntityKind::Group,
        &local.device_id,
        &remote_device_id,
    );
    let snippets = merge_entities(
        local.snippets.clone(),
        remote.snippets,
        &tombstones,
        EntityKind::Snippet,
        &local.device_id,
        &remote_device_id,
    );
    let snippet_groups = merge_entities(
        local.snippet_groups.clone(),
        remote.snippet_groups,
        &tombstones,
        EntityKind::SnippetGroup,
        &local.device_id,
        &remote_device_id,
    );
    let port_forwards = merge_entities(
        local.port_forwards.clone(),
        remote.port_forwards,
        &tombstones,
        EntityKind::PortForward,
        &local.device_id,
        &remote_device_id,
    );
    let ssh_keys = match (&local.ssh_keys, remote.ssh_keys) {
        (Some(l), Some(r)) => Some(merge_entities(
            l.clone(),
            r,
            &tombstones,
            EntityKind::SshKey,
            &local.device_id,
            &remote_device_id,
        )),
        (Some(l), None) => Some(l.clone()),
        (None, _) => None,
    };

    let settings = merge_settings(&local.settings, &remote.settings);

    SyncOutcome {
        hosts,
        groups,
        snippets,
        snippet_groups,
        port_forwards,
        ssh_keys,
        settings,
        tombstones,
        blob_version: 0, // filled in by run_sync once the store succeeds
        uploaded: false,
        local_changed: false,
        collections_downloaded: vec![],
        collections_uploaded: vec![],
    }
}

fn now_iso() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn snapshot_as_payload(local: &LocalSnapshot) -> SyncPayload {
    SyncPayload {
        format_version: PAYLOAD_FORMAT_VERSION,
        exported_at: String::new(),
        device_id: String::new(),
        hosts: local.hosts.clone(),
        groups: local.groups.clone(),
        snippets: local.snippets.clone(),
        snippet_groups: local.snippet_groups.clone(),
        port_forwards: local.port_forwards.clone(),
        ssh_keys: local.ssh_keys.clone(),
        settings: local.settings.clone(),
        tombstones: local.tombstones.clone(),
    }
}

fn outcome_as_payload(outcome: &SyncOutcome) -> SyncPayload {
    SyncPayload {
        format_version: PAYLOAD_FORMAT_VERSION,
        exported_at: String::new(),
        device_id: String::new(),
        hosts: outcome.hosts.clone(),
        groups: outcome.groups.clone(),
        snippets: outcome.snippets.clone(),
        snippet_groups: outcome.snippet_groups.clone(),
        port_forwards: outcome.port_forwards.clone(),
        ssh_keys: outcome.ssh_keys.clone(),
        settings: outcome.settings.clone(),
        tombstones: outcome.tombstones.clone(),
    }
}

/// Sort entity vectors the same way `merge_entities` does so a local gather
/// and a post-merge outcome hash the same when content matches.
fn normalize_payload_for_hash(payload: &mut SyncPayload) {
    payload.hosts.sort_by(|a, b| a.id.cmp(&b.id));
    payload.groups.sort_by(|a, b| a.id.cmp(&b.id));
    payload.snippets.sort_by(|a, b| a.id.cmp(&b.id));
    payload.snippet_groups.sort_by(|a, b| a.id.cmp(&b.id));
    payload.port_forwards.sort_by(|a, b| a.id.cmp(&b.id));
    if let Some(keys) = payload.ssh_keys.as_mut() {
        keys.sort_by(|a, b| a.id.cmp(&b.id));
    }
    payload.tombstones.sort_by(|a, b| a.id.cmp(&b.id));
}

fn content_hash_of(mut payload: SyncPayload) -> String {
    normalize_payload_for_hash(&mut payload);
    payload_content_hash(&payload)
}

/// Runs one full sync cycle: fetch → delta-download changed collections →
/// merge → delta-upload only dirty collections. Retries on CAS conflict.
pub fn run_sync(
    backend: &dyn SyncBackend,
    local: LocalSnapshot,
    master_password: &str,
    vault_id: &str,
) -> Result<SyncOutcome, SyncError> {
    let local_payload = snapshot_as_payload(&local);
    let local_hash = content_hash_of(local_payload.clone());
    let local_col_hashes = build_collection_hashes(&local_payload)?;

    // Fast path: whole-vault content hash already matches.
    if let Some(manifest) = backend.fetch_manifest()? {
        if manifest
            .content_hash
            .as_deref()
            .is_some_and(|h| h == local_hash)
        {
            let mut outcome = merge_snapshot(&local, None);
            outcome.hosts = local.hosts;
            outcome.groups = local.groups;
            outcome.snippets = local.snippets;
            outcome.snippet_groups = local.snippet_groups;
            outcome.port_forwards = local.port_forwards;
            outcome.ssh_keys = local.ssh_keys;
            outcome.settings = local.settings;
            outcome.tombstones = local.tombstones;
            outcome.blob_version = manifest.blob_version;
            outcome.uploaded = false;
            outcome.local_changed = false;
            return Ok(outcome);
        }
    }

    let mut attempt = 0;
    loop {
        attempt += 1;
        let remote_manifest = backend.fetch_manifest()?;

        let sync_salt_b64 = match &remote_manifest {
            Some(m) => m.sync_salt.clone(),
            None => b64_encode(&random_sync_salt()),
        };
        let sync_salt = b64_decode(&sync_salt_b64)?;
        let key = derive_sync_key(master_password, &sync_salt)?;

        let (remote_payload, downloaded) =
            load_remote_payload(backend, &key, remote_manifest.as_ref(), &local_payload, &local_col_hashes)?;

        let remote_hash = remote_payload.as_ref().map(|p| content_hash_of(p.clone()));

        let mut outcome = merge_snapshot(&local, remote_payload);
        outcome.collections_downloaded = downloaded;
        let merged_payload = outcome_as_payload(&outcome);
        let merged_hash = content_hash_of(merged_payload.clone());
        outcome.local_changed = merged_hash != local_hash;

        if remote_hash.as_deref() == Some(merged_hash.as_str()) {
            if let Some(m) = &remote_manifest {
                outcome.blob_version = m.blob_version;
                outcome.uploaded = false;
                return Ok(outcome);
            }
        }

        let mut upload_payload = merged_payload;
        upload_payload.format_version = PAYLOAD_FORMAT_VERSION;
        upload_payload.exported_at = now_iso();
        upload_payload.device_id = local.device_id.clone();

        let expected_version = remote_manifest.as_ref().map(|m| m.blob_version);
        let new_version = expected_version.unwrap_or(0) + 1;

        let (changed, index) = prepare_delta_upload(
            &key,
            &upload_payload,
            remote_manifest.as_ref(),
        )?;

        let manifest = Manifest {
            format_version: MANIFEST_FORMAT_V2,
            vault_id: vault_id.to_string(),
            blob_version: new_version,
            updated_at: now_iso(),
            device_id: local.device_id.clone(),
            device_name: local.device_name.clone(),
            kdf: default_kdf_params(),
            sync_salt: sync_salt_b64,
            blob_sha256: index_integrity_hash(&index),
            content_hash: Some(merged_hash),
            collections: index,
        };

        let uploaded_names: Vec<String> = changed.iter().map(|(n, _)| n.clone()).collect();

        match backend.store_delta(&manifest, &changed, expected_version) {
            Ok(()) => {
                outcome.blob_version = new_version;
                outcome.uploaded = !uploaded_names.is_empty();
                outcome.collections_uploaded = uploaded_names;
                return Ok(outcome);
            }
            Err(SyncError::Conflict) if attempt < MAX_CONFLICT_RETRIES => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Load remote state: prefer collection delta; fall back to legacy `vault.blob`.
fn load_remote_payload(
    backend: &dyn SyncBackend,
    key: &crate::crypto::VaultKey,
    remote_manifest: Option<&Manifest>,
    local_payload: &SyncPayload,
    local_col_hashes: &BTreeMap<CollectionKind, String>,
) -> Result<(Option<SyncPayload>, Vec<String>), SyncError> {
    let Some(manifest) = remote_manifest else {
        return Ok((None, vec![]));
    };

    if !manifest.collections.is_empty() {
        let mut pieces = BTreeMap::new();
        let mut downloaded = Vec::new();
        for kind in CollectionKind::ALL {
            let name = kind.as_str();
            let remote_hash = manifest
                .collections
                .get(name)
                .map(|m| m.content_hash.as_str());
            let local_hash = local_col_hashes.get(&kind).map(|s| s.as_str());

            if kind == CollectionKind::SshKeys && local_payload.ssh_keys.is_none() {
                // این دستگاه کلیدها رو سینک نمی‌کنه — remote رو هم نادیده بگیر
                continue;
            }

            if remote_hash.is_some() && remote_hash == local_hash {
                // اسلایس یکسانه — از local به‌عنوان remote استفاده کن (دانلود لازم نیست)
                let mut piece = SyncPayload::default();
                crate::sync::collections::merge_collection_into(
                    &mut piece,
                    kind,
                    local_payload.clone(),
                );
                if kind == CollectionKind::SshKeys {
                    piece.ssh_keys = local_payload.ssh_keys.clone();
                }
                pieces.insert(kind, piece);
                continue;
            }

            if remote_hash.is_none() {
                continue;
            }

            let expected_sha = manifest
                .collections
                .get(name)
                .map(|m| m.blob_sha256.as_str());
            match backend.fetch_collection(name, expected_sha) {
                Ok(bytes) => {
                    // اگه blob با hash منیفست نخونه، یعنی یه writer وسط race
                    // فایل پایدار رو خراب کرده — merge نکن، خطا بده
                    if let Some(meta) = manifest.collections.get(name) {
                        let actual = sha256_hex(&bytes);
                        if actual != meta.blob_sha256 {
                            return Err(SyncError::Backend(format!(
                                "collection '{name}' failed integrity check (expected {}, got {})",
                                meta.blob_sha256, actual
                            )));
                        }
                    }
                    let piece = decrypt_collection(key, kind, &bytes)?;
                    pieces.insert(kind, piece);
                    downloaded.push(name.to_string());
                }
                // مانیفست می‌گه این collection هست؛ NotFound یعنی partial upload /
                // lag بک‌اند — خالی فرض کردنش tombstone/host رو غلط merge می‌کنه.
                Err(SyncError::NotFound) => {
                    return Err(SyncError::Backend(format!(
                        "collection '{name}' listed in manifest but blob is missing"
                    )));
                }
                Err(e) => return Err(e),
            }
        }
        let assembled = assemble_payload(pieces, manifest.device_id.clone());
        return Ok((Some(assembled), downloaded));
    }

    // Legacy monolith
    let blob = backend.fetch_blob()?;
    let blob_str = String::from_utf8(blob)
        .map_err(|_| SyncError::Backend("blob was not valid UTF-8".to_string()))?;
    let payload = decrypt_payload(key, &blob_str)?;
    Ok((Some(payload), vec!["vault".to_string()]))
}

#[allow(clippy::type_complexity)]
fn prepare_delta_upload(
    key: &crate::crypto::VaultKey,
    merged: &SyncPayload,
    remote_manifest: Option<&Manifest>,
) -> Result<(Vec<(String, Vec<u8>)>, BTreeMap<String, CollectionMeta>), SyncError> {
    let mut changed = Vec::new();
    let mut index = BTreeMap::new();
    let remote_index = remote_manifest.map(|m| &m.collections);

    for kind in CollectionKind::ALL {
        if kind == CollectionKind::SshKeys && merged.ssh_keys.is_none() {
            // کلیدها رو دست نزن — ایندکس remote رو حفظ کن
            if let Some(remote) = remote_index {
                if let Some(meta) = remote.get(kind.as_str()) {
                    index.insert(kind.as_str().to_string(), meta.clone());
                }
            }
            continue;
        }

        let content_hash = crate::sync::collections::collection_content_hash(kind, merged)?;
        let remote_hash = remote_index
            .and_then(|idx| idx.get(kind.as_str()))
            .map(|m| m.content_hash.as_str());

        if remote_hash == Some(content_hash.as_str()) {
            if let Some(meta) = remote_index.and_then(|idx| idx.get(kind.as_str())) {
                index.insert(kind.as_str().to_string(), meta.clone());
            }
            continue;
        }

        let bytes = encrypt_collection(key, kind, merged)?;
        let meta = CollectionMeta {
            content_hash: content_hash.clone(),
            blob_sha256: sha256_hex(&bytes),
        };
        index.insert(kind.as_str().to_string(), meta);
        changed.push((kind.as_str().to_string(), bytes));
    }

    Ok((changed, index))
}

/// Used by the restore/link flows (1.7): decrypt whatever's on the remote
/// using a caller-supplied master password, without merging against any
/// local state. Callers still need to derive their own local DEK afterwards
/// to re-encrypt secrets — this function only deals with the sync layer.
pub fn fetch_remote_payload(
    backend: &dyn SyncBackend,
    master_password: &str,
) -> Result<(Manifest, SyncPayload), SyncError> {
    let manifest = backend.fetch_manifest()?.ok_or(SyncError::NotFound)?;
    let sync_salt = b64_decode(&manifest.sync_salt)?;
    let key = derive_sync_key(master_password, &sync_salt)?;

    if !manifest.collections.is_empty() {
        let mut pieces = BTreeMap::new();
        for kind in CollectionKind::ALL {
            let name = kind.as_str();
            if !manifest.collections.contains_key(name) {
                continue;
            }
            let expected_sha = manifest
                .collections
                .get(name)
                .map(|m| m.blob_sha256.as_str());
            match backend.fetch_collection(name, expected_sha) {
                Ok(bytes) => {
                    if let Some(meta) = manifest.collections.get(name) {
                        let actual = sha256_hex(&bytes);
                        if actual != meta.blob_sha256 {
                            return Err(SyncError::Backend(format!(
                                "collection '{name}' failed integrity check (expected {}, got {})",
                                meta.blob_sha256, actual
                            )));
                        }
                    }
                    pieces.insert(kind, decrypt_collection(&key, kind, &bytes)?);
                }
                Err(SyncError::NotFound) => {
                    return Err(SyncError::Backend(format!(
                        "collection '{name}' listed in manifest but blob is missing"
                    )));
                }
                Err(e) => return Err(e),
            }
        }
        let payload = assemble_payload(pieces, manifest.device_id.clone());
        return Ok((manifest, payload));
    }

    let blob = backend.fetch_blob()?;
    let blob_str =
        String::from_utf8(blob).map_err(|_| SyncError::Backend("blob was not valid UTF-8".to_string()))?;
    let payload = decrypt_payload(&key, &blob_str)?;
    Ok((manifest, payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::hosts::OsKind;
    use crate::sync::local_backend::LocalDirBackend;

    fn tmp_dir(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "termifai-engine-test-{name}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn host(id: &str, name: &str, updated_at: &str) -> Host {
        Host {
            id: id.to_string(),
            name: name.to_string(),
            user: "root".to_string(),
            hostname: "example.com".to_string(),
            port: 22,
            os: OsKind::Ubuntu,
            tags: vec![],
            last_used: None,
            group_id: None,
            auth_method: None,
            password: Some("s3cret".to_string()),
            ssh_key_id: None,
            show_status_in_dashboard: None,
            working_directory: None,
            default_sftp_path: None,
            updated_at: Some(updated_at.to_string()),
            sync_server: None,
            resilient_session: None,
        }
    }

    fn snapshot(device_id: &str, hosts: Vec<Host>) -> LocalSnapshot {
        LocalSnapshot {
            hosts,
            device_id: device_id.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn first_sync_from_empty_remote_uploads_local_state() {
        let dir = tmp_dir("first-sync");
        let backend = LocalDirBackend::new(&dir);
        let local = snapshot("dev-a", vec![host("h1", "prod", "2026-01-01T00:00:00Z")]);

        let outcome = run_sync(&backend, local, "hunter2", "default").unwrap();
        assert_eq!(outcome.blob_version, 1);
        assert!(outcome.uploaded);
        assert_eq!(outcome.hosts.len(), 1);
        assert_eq!(outcome.hosts[0].id, "h1");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn noop_resync_does_not_bump_blob_version() {
        let dir = tmp_dir("noop");
        let backend = LocalDirBackend::new(&dir);
        let local = snapshot("dev-a", vec![host("h1", "prod", "2026-01-01T00:00:00Z")]);

        let first = run_sync(&backend, local.clone(), "hunter2", "default").unwrap();
        assert_eq!(first.blob_version, 1);
        assert!(first.uploaded);

        // ده بار پشت سر هم بدون تغییر — نسخه باید همون ۱ بمونه
        for _ in 0..10 {
            let again = run_sync(&backend, local.clone(), "hunter2", "default").unwrap();
            assert_eq!(again.blob_version, 1);
            assert!(!again.uploaded);
            assert!(!again.local_changed);
        }

        let manifest = backend.fetch_manifest().unwrap().unwrap();
        assert_eq!(manifest.blob_version, 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn delta_upload_only_touches_changed_collections() {
        let dir = tmp_dir("delta-only");
        let backend = LocalDirBackend::new(&dir);

        let first = run_sync(
            &backend,
            snapshot("dev-a", vec![host("h1", "prod", "2026-01-01T00:00:00Z")]),
            "hunter2",
            "default",
        )
        .unwrap();
        assert!(first.collections_uploaded.contains(&"hosts".to_string()));
        let hosts_bytes = backend.fetch_collection("hosts", None).unwrap();

        // فقط settings عوض شده — hosts نباید دوباره آپلود بشه
        let mut local = snapshot("dev-a", vec![host("h1", "prod", "2026-01-01T00:00:00Z")]);
        local.settings.app_theme = crate::sync::payload::SettingsBlob {
            value: Some(serde_json::json!("dark")),
            updated_at: Some("2026-07-01T00:00:00Z".into()),
        };
        let second = run_sync(&backend, local, "hunter2", "default").unwrap();
        assert_eq!(second.blob_version, 2);
        assert!(second.collections_uploaded.contains(&"settings".to_string()));
        assert!(!second.collections_uploaded.contains(&"hosts".to_string()));
        assert_eq!(backend.fetch_collection("hosts", None).unwrap(), hosts_bytes);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn two_devices_converge_through_one_local_dir_backend() {
        let dir = tmp_dir("two-device");
        let backend = LocalDirBackend::new(&dir);

        // Device A creates a host and syncs first.
        let device_a = snapshot("dev-a", vec![host("h1", "prod", "2026-01-01T00:00:00Z")]);
        run_sync(&backend, device_a, "hunter2", "default").unwrap();

        // Device B, starting empty, syncs against the same folder and should
        // adopt device A's host — content matches remote after merge, so no
        // upload / version bump is needed.
        let device_b = snapshot("dev-b", vec![]);
        let outcome_b = run_sync(&backend, device_b, "hunter2", "default").unwrap();
        assert_eq!(outcome_b.hosts.len(), 1);
        assert_eq!(outcome_b.hosts[0].id, "h1");
        assert_eq!(outcome_b.blob_version, 1);
        assert!(!outcome_b.uploaded);
        assert!(outcome_b.local_changed);

        // Device B adds a second host and syncs again.
        let mut device_b_hosts = outcome_b.hosts.clone();
        device_b_hosts.push(host("h2", "staging", "2026-01-02T00:00:00Z"));
        let device_b_again = LocalSnapshot {
            hosts: device_b_hosts,
            device_id: "dev-b".to_string(),
            ..Default::default()
        };
        let upload_b = run_sync(&backend, device_b_again, "hunter2", "default").unwrap();
        assert_eq!(upload_b.blob_version, 2);
        assert!(upload_b.uploaded);

        // Device A syncs again and should now see both hosts (pull-only).
        let device_a_again = snapshot("dev-a", vec![host("h1", "prod", "2026-01-01T00:00:00Z")]);
        let outcome_a = run_sync(&backend, device_a_again, "hunter2", "default").unwrap();
        let mut ids: Vec<&str> = outcome_a.hosts.iter().map(|h| h.id.as_str()).collect();
        ids.sort();
        assert_eq!(ids, vec!["h1", "h2"]);
        assert_eq!(outcome_a.blob_version, 2);
        assert!(!outcome_a.uploaded);
        assert!(outcome_a.local_changed);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn wrong_master_password_fails_to_decrypt_existing_remote() {
        let dir = tmp_dir("wrong-pw");
        let backend = LocalDirBackend::new(&dir);
        let device_a = snapshot("dev-a", vec![host("h1", "prod", "2026-01-01T00:00:00Z")]);
        run_sync(&backend, device_a, "correct-horse", "default").unwrap();

        // Different local content forces the decrypt path (fast-path hash miss).
        let device_b = snapshot("dev-b", vec![host("h2", "other", "2026-01-02T00:00:00Z")]);
        let result = run_sync(&backend, device_b, "wrong-password", "default");
        assert!(matches!(result, Err(SyncError::Crypto(_))));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn deleted_host_stays_deleted_after_remote_sync() {
        let dir = tmp_dir("delete-propagates");
        let backend = LocalDirBackend::new(&dir);

        let device_a = snapshot("dev-a", vec![host("h1", "prod", "2026-01-01T00:00:00Z")]);
        run_sync(&backend, device_a, "hunter2", "default").unwrap();

        // Device B pulls it down, then deletes it locally (tombstone, no more host).
        let device_b = snapshot("dev-b", vec![]);
        let outcome_b = run_sync(&backend, device_b, "hunter2", "default").unwrap();
        assert_eq!(outcome_b.hosts.len(), 1);

        let device_b_deleted = LocalSnapshot {
            hosts: vec![],
            tombstones: vec![Tombstone {
                entity: EntityKind::Host,
                id: "h1".to_string(),
                deleted_at: "2026-06-01T00:00:00Z".to_string(),
            }],
            device_id: "dev-b".to_string(),
            ..Default::default()
        };
        run_sync(&backend, device_b_deleted, "hunter2", "default").unwrap();

        // Device A syncs again with its stale copy of h1 (older updated_at than the delete).
        let device_a_again = snapshot("dev-a", vec![host("h1", "prod", "2026-01-01T00:00:00Z")]);
        let outcome_a = run_sync(&backend, device_a_again, "hunter2", "default").unwrap();
        assert!(outcome_a.hosts.is_empty(), "delete must win over an older, unedited copy");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fetch_remote_payload_reads_without_merging() {
        let dir = tmp_dir("restore-flow");
        let backend = LocalDirBackend::new(&dir);
        let device_a = snapshot("dev-a", vec![host("h1", "prod", "2026-01-01T00:00:00Z")]);
        run_sync(&backend, device_a, "hunter2", "default").unwrap();

        let (manifest, payload) = fetch_remote_payload(&backend, "hunter2").unwrap();
        assert_eq!(manifest.blob_version, 1);
        assert_eq!(payload.hosts.len(), 1);
        assert_eq!(payload.hosts[0].password.as_deref(), Some("s3cret"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_collection_blob_listed_in_manifest_aborts_sync() {
        let dir = tmp_dir("missing-col-blob");
        let backend = LocalDirBackend::new(&dir);
        let device_a = snapshot("dev-a", vec![host("h1", "prod", "2026-01-01T00:00:00Z")]);
        run_sync(&backend, device_a, "hunter2", "default").unwrap();

        // مانیفست هنوز hosts رو لیست می‌کنه ولی blob نیست — نباید empty merge بشه
        // content-addressed objects + stable alias must both go, or fetch still succeeds
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("col-hosts") && name.ends_with(".blob") {
                std::fs::remove_file(entry.path()).unwrap();
            }
        }

        let device_b = snapshot("dev-b", vec![host("h2", "other", "2026-01-02T00:00:00Z")]);
        let result = run_sync(&backend, device_b, "hunter2", "default");
        assert!(
            matches!(&result, Err(SyncError::Backend(msg)) if msg.contains("listed in manifest")),
            "expected Backend error for missing collection blob"
        );

        let restore = fetch_remote_payload(&backend, "hunter2");
        assert!(
            matches!(&restore, Err(SyncError::Backend(msg)) if msg.contains("listed in manifest")),
            "restore path must also refuse a partial remote"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn corrupted_stable_alias_still_reads_addressed_object() {
        let dir = tmp_dir("corrupt-alias");
        let backend = LocalDirBackend::new(&dir);
        run_sync(
            &backend,
            snapshot("dev-a", vec![host("h1", "prod", "2026-01-01T00:00:00Z")]),
            "hunter2",
            "default",
        )
        .unwrap();

        // alias پایدار رو خراب کن — شبیه بازندهٔ race که col-hosts.blob رو overwrite کرده
        std::fs::write(dir.join("col-hosts.blob"), b"clobbered-by-loser").unwrap();

        let device_b = snapshot("dev-b", vec![host("h2", "other", "2026-01-02T00:00:00Z")]);
        let outcome = run_sync(&backend, device_b, "hunter2", "default").unwrap();
        let mut ids: Vec<&str> = outcome.hosts.iter().map(|h| h.id.as_str()).collect();
        ids.sort();
        assert_eq!(
            ids,
            vec!["h1", "h2"],
            "addressed blob must win over a clobbered stable alias"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn integrity_check_rejects_mismatched_collection_bytes() {
        let dir = tmp_dir("integrity-fail");
        let backend = LocalDirBackend::new(&dir);
        run_sync(
            &backend,
            snapshot("dev-a", vec![host("h1", "prod", "2026-01-01T00:00:00Z")]),
            "hunter2",
            "default",
        )
        .unwrap();

        let manifest = backend.fetch_manifest().unwrap().unwrap();
        let sha = manifest
            .collections
            .get("hosts")
            .expect("hosts meta")
            .blob_sha256
            .clone();
        let addressed = dir.join(crate::sync::collections::collection_file_name(
            "hosts",
            Some(&sha),
        ));
        // هم addressed هم alias رو خراب کن تا integrity واقعاً بجنگه
        std::fs::write(&addressed, b"not-the-ciphertext").unwrap();
        std::fs::write(dir.join("col-hosts.blob"), b"not-the-ciphertext").unwrap();

        let device_b = snapshot("dev-b", vec![host("h2", "other", "2026-01-02T00:00:00Z")]);
        let result = run_sync(&backend, device_b, "hunter2", "default");
        match result {
            Err(SyncError::Backend(msg)) => {
                assert!(
                    msg.contains("integrity check"),
                    "unexpected backend error: {msg}"
                );
            }
            Ok(_) => panic!("expected integrity Backend error, got Ok"),
            Err(other) => panic!("expected integrity Backend error, got {other}"),
        }

        std::fs::remove_dir_all(&dir).ok();
    }
}
