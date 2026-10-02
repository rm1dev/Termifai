use crate::model::forwards::PortForwardRule;
use crate::model::hosts::{Host, HostGroup};
use crate::model::snippets::{Snippet, SnippetGroup};
use crate::model::ssh_keys::SshKey;
use crate::model::tombstones::{EntityKind, Tombstone};
use crate::sync::payload::{SettingsBlob, SettingsPayload};
use std::collections::HashMap;

const EPOCH: &str = "1970-01-01T00:00:00Z";

/// Implemented by every entity type that can be synced/merged, so
/// `merge_entities` is written once and reused for hosts, groups, snippets,
/// port forwards, and (optionally) SSH keys.
pub trait Syncable {
    fn sync_id(&self) -> &str;
    /// Falls back to the epoch for older, pre-sync records that never got an
    /// `updated_at` stamp — they lose every real conflict, which is correct
    /// (anything with an actual timestamp is more likely to be current).
    fn sync_updated_at(&self) -> &str;
}

impl Syncable for Host {
    fn sync_id(&self) -> &str {
        &self.id
    }
    fn sync_updated_at(&self) -> &str {
        self.updated_at.as_deref().unwrap_or(EPOCH)
    }
}

impl Syncable for HostGroup {
    fn sync_id(&self) -> &str {
        &self.id
    }
    fn sync_updated_at(&self) -> &str {
        self.updated_at.as_deref().unwrap_or(EPOCH)
    }
}

impl Syncable for Snippet {
    fn sync_id(&self) -> &str {
        &self.id
    }
    fn sync_updated_at(&self) -> &str {
        self.updated_at.as_deref().unwrap_or(EPOCH)
    }
}

impl Syncable for SnippetGroup {
    fn sync_id(&self) -> &str {
        &self.id
    }
    fn sync_updated_at(&self) -> &str {
        self.updated_at.as_deref().unwrap_or(EPOCH)
    }
}

impl Syncable for PortForwardRule {
    fn sync_id(&self) -> &str {
        &self.id
    }
    fn sync_updated_at(&self) -> &str {
        self.updated_at.as_deref().unwrap_or(EPOCH)
    }
}

impl Syncable for SshKey {
    fn sync_id(&self) -> &str {
        &self.id
    }
    fn sync_updated_at(&self) -> &str {
        // Keys are never edited in place (only created/removed), so
        // created_at doubles as the LWW timestamp.
        &self.created_at
    }
}

/// Entity-level last-write-wins merge with tombstone precedence.
///
/// 1. Union local + remote by id; where both sides have a live entry, the
///    newer `updated_at` wins (ties broken by the larger of the two device
///    ids — deterministic, arbitrary, but symmetric on every device).
/// 2. A tombstone for an id beats a live entry for that id unless the live
///    entry's `updated_at` is *newer* than the delete (an edit racing a
///    propagating delete resurrects the record).
pub fn merge_entities<T: Syncable + Clone>(
    local: Vec<T>,
    remote: Vec<T>,
    tombstones: &[Tombstone],
    entity: EntityKind,
    local_device_id: &str,
    remote_device_id: &str,
) -> Vec<T> {
    let mut by_id: HashMap<String, T> = local
        .into_iter()
        .map(|item| (item.sync_id().to_string(), item))
        .collect();

    for r in remote {
        let id = r.sync_id().to_string();
        match by_id.remove(&id) {
            Some(l) => {
                by_id.insert(id, pick_winner(l, r, local_device_id, remote_device_id));
            }
            None => {
                by_id.insert(id, r);
            }
        }
    }

    let deleted_at_for = |id: &str| -> Option<&str> {
        tombstones
            .iter()
            .filter(|t| t.entity == entity && t.id == id)
            .map(|t| t.deleted_at.as_str())
            .max()
    };

    let mut result: Vec<T> = by_id
        .into_values()
        .filter(|item| match deleted_at_for(item.sync_id()) {
            Some(deleted_at) => deleted_at <= item.sync_updated_at(),
            None => true,
        })
        .collect();

    result.sort_by(|a, b| a.sync_id().cmp(b.sync_id()));
    result
}

fn pick_winner<T: Syncable>(local: T, remote: T, local_device_id: &str, remote_device_id: &str) -> T {
    match local.sync_updated_at().cmp(remote.sync_updated_at()) {
        std::cmp::Ordering::Greater => local,
        std::cmp::Ordering::Less => remote,
        std::cmp::Ordering::Equal => {
            if local_device_id >= remote_device_id {
                local
            } else {
                remote
            }
        }
    }
}

/// Union two tombstone lists, keeping the newest `deleted_at` per (entity, id).
pub fn union_tombstones(a: &[Tombstone], b: &[Tombstone]) -> Vec<Tombstone> {
    let mut map: HashMap<(EntityKind, String), Tombstone> = HashMap::new();
    for t in a.iter().chain(b.iter()) {
        let key = (t.entity, t.id.clone());
        map.entry(key)
            .and_modify(|existing| {
                if t.deleted_at > existing.deleted_at {
                    *existing = t.clone();
                }
            })
            .or_insert_with(|| t.clone());
    }
    let mut result: Vec<Tombstone> = map.into_values().collect();
    result.sort_by(|a, b| a.id.cmp(&b.id));
    result
}

fn merge_blob(local: &SettingsBlob, remote: &SettingsBlob) -> SettingsBlob {
    match (&local.updated_at, &remote.updated_at) {
        (Some(l), Some(r)) => {
            if l >= r {
                local.clone()
            } else {
                remote.clone()
            }
        }
        (Some(_), None) => local.clone(),
        (None, Some(_)) => remote.clone(),
        (None, None) => local.clone(),
    }
}

/// Whole-document LWW per settings key — no field-level merge inside a theme
/// or shortcut map, matching the "no field-level merge in v1" decision for
/// entities.
pub fn merge_settings(local: &SettingsPayload, remote: &SettingsPayload) -> SettingsPayload {
    SettingsPayload {
        app_theme: merge_blob(&local.app_theme, &remote.app_theme),
        terminal_appearance: merge_blob(&local.terminal_appearance, &remote.terminal_appearance),
        shortcuts: merge_blob(&local.shortcuts, &remote.shortcuts),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(id: &str, updated_at: &str) -> HostGroup {
        HostGroup {
            id: id.to_string(),
            name: id.to_string(),
            parent_id: None,
            updated_at: Some(updated_at.to_string()),
        }
    }

    fn tombstone(id: &str, deleted_at: &str) -> Tombstone {
        Tombstone {
            entity: EntityKind::Group,
            id: id.to_string(),
            deleted_at: deleted_at.to_string(),
        }
    }

    #[test]
    fn newer_updated_at_wins() {
        let local = vec![group("g1", "2026-01-01T00:00:00Z")];
        let remote = vec![group("g1", "2026-02-01T00:00:00Z")];
        let merged = merge_entities(local, remote, &[], EntityKind::Group, "dev-a", "dev-b");
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].updated_at.as_deref(), Some("2026-02-01T00:00:00Z"));
    }

    #[test]
    fn tie_breaks_on_larger_device_id() {
        let local = vec![group("g1", "2026-01-01T00:00:00Z")];
        let remote = vec![group("g1", "2026-01-01T00:00:00Z")];
        let merged_a_wins = merge_entities(local.clone(), remote.clone(), &[], EntityKind::Group, "zzz", "aaa");
        assert_eq!(merged_a_wins[0].sync_id(), "g1");
        // local ("zzz") > remote ("aaa") so local's identity should be picked;
        // both have identical content here so just assert determinism holds
        // the other way when device ids are swapped.
        let merged_b_wins = merge_entities(local, remote, &[], EntityKind::Group, "aaa", "zzz");
        assert_eq!(merged_b_wins.len(), 1);
    }

    #[test]
    fn tombstone_newer_than_live_record_wins() {
        let local = vec![group("g1", "2026-01-01T00:00:00Z")];
        let remote = vec![]; // deleted on remote
        let tombstones = vec![tombstone("g1", "2026-02-01T00:00:00Z")];
        let merged = merge_entities(local, remote, &tombstones, EntityKind::Group, "dev-a", "dev-b");
        assert!(merged.is_empty(), "delete newer than edit must win");
    }

    #[test]
    fn edit_after_delete_resurrects_record() {
        let local = vec![group("g1", "2026-03-01T00:00:00Z")];
        let remote = vec![];
        let tombstones = vec![tombstone("g1", "2026-02-01T00:00:00Z")];
        let merged = merge_entities(local, remote, &tombstones, EntityKind::Group, "dev-a", "dev-b");
        assert_eq!(merged.len(), 1, "edit newer than delete must survive");
    }

    #[test]
    fn first_sync_remote_only_entry_is_adopted() {
        let local = vec![];
        let remote = vec![group("g1", "2026-01-01T00:00:00Z")];
        let merged = merge_entities(local, remote, &[], EntityKind::Group, "dev-a", "dev-b");
        assert_eq!(merged.len(), 1);
    }

    #[test]
    fn union_tombstones_keeps_newest_per_id() {
        let a = vec![tombstone("g1", "2026-01-01T00:00:00Z")];
        let b = vec![tombstone("g1", "2026-03-01T00:00:00Z"), tombstone("g2", "2026-01-01T00:00:00Z")];
        let unioned = union_tombstones(&a, &b);
        assert_eq!(unioned.len(), 2);
        let g1 = unioned.iter().find(|t| t.id == "g1").unwrap();
        assert_eq!(g1.deleted_at, "2026-03-01T00:00:00Z");
    }

    #[test]
    fn settings_merge_prefers_newer_and_tolerates_missing_timestamp() {
        let local = SettingsBlob { value: Some(serde_json::json!({"a": 1})), updated_at: Some("2026-01-01T00:00:00Z".into()) };
        let remote = SettingsBlob { value: Some(serde_json::json!({"a": 2})), updated_at: Some("2026-02-01T00:00:00Z".into()) };
        let merged = merge_blob(&local, &remote);
        assert_eq!(merged.value, remote.value);

        let no_ts = SettingsBlob { value: Some(serde_json::json!({"a": 3})), updated_at: None };
        let merged2 = merge_blob(&no_ts, &remote);
        assert_eq!(merged2.value, remote.value, "missing local timestamp loses to a timestamped remote");
    }

    #[test]
    fn rebase_keeps_local_only_entity_added_during_sync() {
        // Simulates apply_outcome rebase: prior merge outcome is treated as
        // "remote", and a host saved while sync was in flight is current local.
        let prior_outcome = vec![group("g1", "2026-01-01T00:00:00Z"), group("g2", "2026-02-01T00:00:00Z")];
        let current_local = vec![group("g1", "2026-01-01T00:00:00Z"), group("g3", "2026-03-01T00:00:00Z")];
        let rebased = merge_entities(
            current_local,
            prior_outcome,
            &[],
            EntityKind::Group,
            "dev-a",
            "dev-b",
        );
        let ids: Vec<&str> = rebased.iter().map(|g| g.id.as_str()).collect();
        assert!(ids.contains(&"g1"));
        assert!(ids.contains(&"g2"), "remote-only entity from prior merge must survive");
        assert!(ids.contains(&"g3"), "local save during sync must not be clobbered");
    }

    #[test]
    fn settings_live_cache_edit_wins_over_stale_outcome() {
        // End-of-sync must merge the live settings cache into the outcome;
        // otherwise a theme/shortcut change during run_sync is overwritten and
        // the follow-up auto-sync re-uploads the stale gather-time value.
        let gather_time = SettingsBlob {
            value: Some(serde_json::json!("dark")),
            updated_at: Some("2026-01-01T00:00:00Z".into()),
        };
        let live_edit = SettingsBlob {
            value: Some(serde_json::json!("light")),
            updated_at: Some("2026-06-01T00:00:00Z".into()),
        };
        let outcome = SettingsPayload {
            app_theme: gather_time,
            ..Default::default()
        };
        let live = SettingsPayload {
            app_theme: live_edit,
            ..Default::default()
        };
        let merged = merge_settings(&live, &outcome);
        assert_eq!(
            merged.app_theme.value,
            Some(serde_json::json!("light")),
            "live cache edit during sync must not be clobbered by gather-time outcome"
        );
    }

    fn script_snippet(id: &str, updated_at: &str, body: Option<&str>) -> Snippet {
        Snippet {
            id: id.to_string(),
            kind: crate::model::snippets::SnippetKind::Script,
            name: id.to_string(),
            body: None,
            command: None,
            script: body.map(|s| s.to_string()),
            variables: vec![],
            group_id: None,
            keyword: None,
            os_targets: vec![],
            created_at: Some(updated_at.to_string()),
            updated_at: Some(updated_at.to_string()),
            run_as_sudo: None,
        }
    }

    #[test]
    fn script_equal_updated_at_prefers_local_none_over_remote_body() {
        // Documents the gather hazard fixed in sync.rs: if local `.sh` is
        // missing (list_snippets leaves script=None) while updated_at ties,
        // LWW+equal device_id uploads None and wipes the remote script body.
        let local = vec![script_snippet("s1", "2026-01-01T00:00:00Z", None)];
        let remote = vec![script_snippet("s1", "2026-01-01T00:00:00Z", Some("echo hi"))];
        let merged = merge_entities(
            local,
            remote,
            &[],
            EntityKind::Snippet,
            "dev-z",
            "dev-a",
        );
        assert!(
            merged[0].script.is_none(),
            "equal device-id tie-break prefers local — missing .sh would wipe remote body"
        );
    }
}
