use crate::AppState;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};
use termifai_core::model::snippets::migrate_snippets_vault;
pub use termifai_core::model::snippets::{
    Snippet, SnippetGroup, SnippetKind, SnippetOsTarget, SnippetVariable, SnippetVariableType,
    SnippetsVault,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveSnippetRequest {
    pub id: Option<String>,
    pub kind: SnippetKind,
    pub name: String,
    pub body: Option<String>,
    pub command: Option<String>,
    pub script: Option<String>,
    #[serde(default)]
    pub variables: Vec<SnippetVariable>,
    #[serde(default)]
    pub group_id: Option<String>,
    #[serde(default)]
    pub keyword: Option<String>,
    #[serde(default)]
    pub os_targets: Vec<SnippetOsTarget>,
    #[serde(default)]
    pub run_as_sudo: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveSnippetGroupRequest {
    pub id: Option<String>,
    pub name: String,
    pub parent_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnippetsListResult {
    pub snippets: Vec<Snippet>,
    pub groups: Vec<SnippetGroup>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────────────────────

fn get_snippets_dir(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to get app data dir: {}", e))?;
    let vault_dir =
        termifai_core::layout::vault_dir(&app_data_dir, termifai_core::layout::DEFAULT_VAULT_ID);
    let snippets_dir = vault_dir.join("snippets");
    if !snippets_dir.exists() {
        std::fs::create_dir_all(&snippets_dir)
            .map_err(|e| format!("Failed to create snippets dir: {}", e))?;
    }
    Ok(snippets_dir)
}

fn script_path(dir: &std::path::Path, id: &str) -> Result<std::path::PathBuf, String> {
    validate_snippet_id(id)?;
    Ok(dir.join(format!("{}.sh", id)))
}

/// Snippet ids become on-disk `.sh` filenames — allow only a safe charset so
/// sync/apply cannot write outside the snippets directory via `../` ids.
fn validate_snippet_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("Snippet id cannot be empty".to_string());
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(format!("Invalid snippet id '{}'", id));
    }
    Ok(())
}

fn read_script_file(dir: &std::path::Path, id: &str) -> Option<String> {
    let path = script_path(dir, id).ok()?;
    std::fs::read_to_string(path).ok()
}

fn write_script_file(dir: &std::path::Path, id: &str, content: &str) -> Result<(), String> {
    let path = script_path(dir, id)?;
    std::fs::write(path, content).map_err(|e| format!("Failed to write script file: {}", e))
}

fn delete_script_file(dir: &std::path::Path, id: &str) {
    if let Ok(path) = script_path(dir, id) {
        let _ = std::fs::remove_file(path);
    }
}

/// Writes/updates `.sh` bodies for Script snippets and clears inline script
/// fields for vault storage. Returns the set of script ids that must stay on
/// disk after the vault commit succeeds. Does **not** delete anything — orphans
/// are purged only after metadata is durable (see [`apply_synced_snippets`]).
#[cfg(test)]
fn write_synced_script_bodies(
    dir: &std::path::Path,
    snippets: Vec<Snippet>,
) -> Result<(Vec<Snippet>, std::collections::HashSet<String>), String> {
    for snippet in &snippets {
        validate_snippet_id(&snippet.id)?;
    }
    let mut keep_script_ids = std::collections::HashSet::new();
    let mut vault_snippets = Vec::with_capacity(snippets.len());
    for mut snippet in snippets {
        if matches!(snippet.kind, SnippetKind::Script) {
            if let Some(content) = snippet.script.take() {
                write_script_file(dir, &snippet.id, &content)?;
            }
            keep_script_ids.insert(snippet.id.clone());
        } else {
            snippet.script = None;
        }
        // مثل save_snippet — محتوای اسکریپت تو DB نمی‌مونه
        snippet.script = None;
        vault_snippets.push(snippet);
    }
    Ok((vault_snippets, keep_script_ids))
}

/// Deletes `.sh` files that are no longer Script snippets in the committed vault.
fn purge_orphan_script_files(
    dir: &std::path::Path,
    keep_script_ids: &std::collections::HashSet<String>,
) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("sh") {
                continue;
            }
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                if !keep_script_ids.contains(stem) {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }
}

/// Applies a merged snippet set from sync: LWW-merges vault metadata with the
/// live store under lock (so a concurrent `save_snippet` is not clobbered),
/// writes winning `.sh` bodies, then drops orphaned script files.
/// Orphan deletes happen **after** a successful vault write so a failed sync
/// apply cannot wipe script bodies while the local vault still references them.
pub fn apply_synced_snippets(
    app: &AppHandle,
    snippets: Vec<Snippet>,
    groups: Vec<SnippetGroup>,
    tombstones: Vec<crate::tombstones::Tombstone>,
) -> Result<(), String> {
    let dir = get_snippets_dir(app)?;
    for snippet in &snippets {
        validate_snippet_id(&snippet.id)?;
    }

    // Keep inline script bodies on the incoming set for LWW — do not write
    // `.sh` files yet or a concurrent local edit's file would be overwritten
    // before merge can prefer it.
    let mut incoming_snippets = snippets;
    clear_orphan_group_ids(&mut incoming_snippets, &groups);

    // Prefer live local on equal timestamps (local_device_id >= remote_device_id).
    const APPLY_LOCAL: &str = "apply-local";
    const APPLY_OUTCOME: &str = "apply-from-sync";
    let state = app.state::<AppState>();
    let mut keep_script_ids = std::collections::HashSet::new();
    let mut pending_writes: Vec<(String, String)> = Vec::new();
    state
        .snippets_store
        .update_with_migration(migrate_snippets_vault, |vault| {
            let live_snippets = std::mem::take(&mut vault.snippets);
            let live_groups = std::mem::take(&mut vault.groups);
            let live_with_scripts: Vec<Snippet> = live_snippets
                .into_iter()
                .map(|mut s| {
                    if matches!(s.kind, SnippetKind::Script) {
                        if let Some(content) = read_script_file(&dir, &s.id) {
                            s.script = Some(content);
                        }
                    }
                    s
                })
                .collect();
            let mut merged_snippets = termifai_core::sync::merge::merge_entities(
                live_with_scripts,
                incoming_snippets.clone(),
                &tombstones,
                crate::tombstones::EntityKind::Snippet,
                APPLY_LOCAL,
                APPLY_OUTCOME,
            );
            let merged_groups = termifai_core::sync::merge::merge_entities(
                live_groups,
                groups.clone(),
                &tombstones,
                crate::tombstones::EntityKind::SnippetGroup,
                APPLY_LOCAL,
                APPLY_OUTCOME,
            );
            clear_orphan_group_ids(&mut merged_snippets, &merged_groups);

            for snippet in &mut merged_snippets {
                if matches!(snippet.kind, SnippetKind::Script) {
                    keep_script_ids.insert(snippet.id.clone());
                    if let Some(content) = snippet.script.take() {
                        pending_writes.push((snippet.id.clone(), content));
                    }
                }
                snippet.script = None;
            }

            vault.snippets = merged_snippets;
            vault.groups = merged_groups;
        })
        .map_err(|e| e.to_string())?;

    for (id, content) in &pending_writes {
        write_script_file(&dir, id, content)?;
    }

    // فقط بعد از commit موفق پاک می‌کنیم — وگرنه با failure، دیتای لوکال می‌پره
    purge_orphan_script_files(&dir, &keep_script_ids);
    Ok(())
}

pub fn list_snippets(app: &AppHandle) -> Result<SnippetsListResult, String> {
    let state = app.state::<AppState>();
    let vault = state
        .snippets_store
        .load_with_migration(migrate_snippets_vault)
        .map_err(|e| e.to_string())?;

    let dir = get_snippets_dir(app)?;
    let mut snippets = vault.snippets;
    for snippet in &mut snippets {
        if matches!(snippet.kind, SnippetKind::Script) {
            // Prefer the .sh file; keep any inline copy that hasn't been
            // migrated yet (never downgrade Some(inline) to None here).
            if let Some(content) = read_script_file(&dir, &snippet.id) {
                snippet.script = Some(content);
            }
        }
    }
    Ok(SnippetsListResult {
        snippets,
        groups: vault.groups,
    })
}

/// One-time startup migration: move inline script bodies from the DB vault
/// into per-snippet .sh files. The inline copy is cleared ONLY for snippets
/// whose file write succeeded, so a failed write can never lose the script.
/// The write is unconditional (even if a .sh file already exists) because
/// synced inline content may be newer than whatever is on disk locally.
pub fn migrate_inline_scripts(app: &AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();
    let vault = state
        .snippets_store
        .load_with_migration(migrate_snippets_vault)
        .map_err(|e| e.to_string())?;

    let dir = get_snippets_dir(app)?;
    let mut migrated_ids: Vec<String> = Vec::new();
    for s in &vault.snippets {
        if matches!(s.kind, SnippetKind::Script) {
            if let Some(ref content) = s.script {
                if write_script_file(&dir, &s.id, content).is_ok() {
                    migrated_ids.push(s.id.clone());
                }
            }
        }
    }

    if !migrated_ids.is_empty() {
        state
            .snippets_store
            .update_with_migration(migrate_snippets_vault, |v| {
                for s in &mut v.snippets {
                    if migrated_ids.contains(&s.id) {
                        s.script = None;
                    }
                }
            })
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub fn save_snippet(app: &AppHandle, request: SaveSnippetRequest) -> Result<Snippet, String> {
    validate_snippet(&request)?;

    let id = request
        .id
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| format!("s-{}", uuid::Uuid::new_v4()));
    validate_snippet_id(&id)?;

    let dir = get_snippets_dir(app)?;
    if matches!(request.kind, SnippetKind::Script) {
        if let Some(ref script_content) = request.script {
            write_script_file(&dir, &id, script_content)?;
        }
    }

    let state = app.state::<AppState>();
    let mut saved_snippet = None;

    state
        .snippets_store
        .update_with_migration(migrate_snippets_vault, |vault| {
            let existing_created_at = vault
                .snippets
                .iter()
                .find(|s| s.id == id)
                .and_then(|s| s.created_at.clone());

            let keyword = if matches!(request.kind, SnippetKind::Text) {
                request.keyword.clone().filter(|v| !v.trim().is_empty())
            } else {
                None
            };

            let snippet_db = Snippet {
                id: id.clone(),
                kind: request.kind.clone(),
                name: request.name.trim().to_string(),
                body: request.body.filter(|v| !v.trim().is_empty()),
                command: request.command.filter(|v| !v.trim().is_empty()),
                script: None, // Do not store script content inline in DB
                variables: request.variables.clone(),
                group_id: request.group_id.clone().filter(|v| !v.trim().is_empty()),
                keyword,
                os_targets: request.os_targets.clone(),
                created_at: existing_created_at.or_else(|| Some(now_iso())),
                updated_at: Some(now_iso()),
                run_as_sudo: request.run_as_sudo,
            };

            upsert_by_id(&mut vault.snippets, snippet_db.clone());

            let mut returned = snippet_db;
            if matches!(request.kind, SnippetKind::Script) {
                returned.script = request.script.clone();
            }
            saved_snippet = Some(returned);
        })
        .map_err(|e| e.to_string())?;

    if !matches!(request.kind, SnippetKind::Script) {
        // Editing an existing Script snippet to another kind orphans its file.
        // Deleted only after the DB update succeeds, so a failure never loses
        // the script while also removing the snippet's Script-kind record.
        delete_script_file(&dir, &id);
    }

    crate::sync::mark_dirty(app);
    saved_snippet.ok_or_else(|| "Failed to save snippet".to_string())
}

pub fn remove_snippets(app: &AppHandle, ids: Vec<String>) -> Result<(), String> {
    let state = app.state::<AppState>();

    state
        .snippets_store
        .update_with_migration(migrate_snippets_vault, |vault| {
            vault.snippets.retain(|s| !ids.contains(&s.id));
        })
        .map_err(|e| e.to_string())?;
    crate::tombstones::record(app, crate::tombstones::EntityKind::Snippet, &ids)?;

    if let Ok(dir) = get_snippets_dir(app) {
        for id in &ids {
            delete_script_file(&dir, id);
        }
    }
    crate::sync::mark_dirty(app);
    Ok(())
}

/// Reorders `vault.snippets` to match `ids` (front-to-back). Any snippet not
/// referenced in `ids` keeps its original relative position, appended after
/// the reordered ones — defensive against a stale/partial id list.
pub fn reorder_snippets(app: &AppHandle, ids: Vec<String>) -> Result<(), String> {
    let state = app.state::<AppState>();
    state
        .snippets_store
        .update_with_migration(migrate_snippets_vault, |vault| {
            let mut reordered: Vec<Snippet> = Vec::with_capacity(vault.snippets.len());
            for id in &ids {
                if let Some(pos) = vault.snippets.iter().position(|s| &s.id == id) {
                    reordered.push(vault.snippets.remove(pos));
                }
            }
            reordered.append(&mut vault.snippets);
            vault.snippets = reordered;
        })
        .map_err(|e| e.to_string())?;
    crate::sync::mark_dirty(app);
    Ok(())
}

/// Replaces group slots with submitted group order, preserving hierarchy
/// and validating all input before mutating the vault.
pub fn reorder_snippet_groups(app: &AppHandle, ids: Vec<String>) -> Result<(), String> {
    let state = app.state::<AppState>();
    let mut validation_error = None;
    state
        .snippets_store
        .update_with_migration(migrate_snippets_vault, |vault| {
            let mut reordered = vault.groups.clone();
            match reorder_group_vector(&mut reordered, &ids) {
                Ok(()) => vault.groups = reordered,
                Err(error) => validation_error = Some(error),
            }
        })
        .map_err(|e| e.to_string())?;
    if let Some(error) = validation_error {
        return Err(error);
    }
    crate::sync::mark_dirty(app);
    Ok(())
}

fn reorder_group_vector(groups: &mut [SnippetGroup], ids: &[String]) -> Result<(), String> {
    if ids.is_empty() {
        return Ok(());
    }

    let mut seen = std::collections::HashSet::with_capacity(ids.len());
    for id in ids {
        if !seen.insert(id.as_str()) {
            return Err(format!("Invalid group order: duplicate group ID '{id}'"));
        }
        if !groups.iter().any(|group| group.id == *id) {
            return Err(format!("Snippet group '{id}' does not exist"));
        }
    }

    let first_group = groups.iter().find(|group| group.id == ids[0]).unwrap();
    let target_parent_id = first_group.parent_id.clone();

    for id in ids {
        let group = groups.iter().find(|group| group.id == *id).unwrap();
        if group.parent_id != target_parent_id {
            return Err(format!(
                "Invalid group order: group '{id}' does not share the same parent as group '{}'",
                ids[0]
            ));
        }
    }

    let sibling_ids: Vec<&str> = groups
        .iter()
        .filter(|group| group.parent_id == target_parent_id)
        .map(|group| group.id.as_str())
        .collect();

    if ids.len() != sibling_ids.len() {
        return Err(format!(
            "Invalid group order: expected {} group IDs for parent, received {}",
            sibling_ids.len(),
            ids.len()
        ));
    }

    if let Some(missing_id) = sibling_ids.iter().find(|id| !seen.contains(**id)) {
        return Err(format!(
            "Invalid group order: missing group ID '{missing_id}'"
        ));
    }

    let reordered_siblings: Vec<SnippetGroup> = ids
        .iter()
        .map(|id| {
            groups
                .iter()
                .find(|group| group.id == *id)
                .expect("validated group ID")
                .clone()
        })
        .collect();

    for (slot, source) in groups
        .iter_mut()
        .filter(|group| group.parent_id == target_parent_id)
        .zip(reordered_siblings)
    {
        *slot = source;
    }
    Ok(())
}

pub fn save_snippet_group(
    app: &AppHandle,
    request: SaveSnippetGroupRequest,
) -> Result<SnippetGroup, String> {
    let name = request.name.trim();
    if name.is_empty() {
        return Err("Group name is required".to_string());
    }

    let id = request
        .id
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("sg-{}", uuid::Uuid::new_v4()));

    if request.parent_id.as_deref() == Some(&id) {
        return Err("Group cannot be its own parent".to_string());
    }

    let parent_id = request
        .parent_id
        .as_ref()
        .filter(|value| !value.trim().is_empty())
        .cloned();

    let group = SnippetGroup {
        id: id.clone(),
        name: name.to_string(),
        parent_id: parent_id.clone(),
        updated_at: Some(now_iso()),
    };

    let state = app.state::<AppState>();
    let mut error = None;

    state
        .snippets_store
        .update_with_migration(migrate_snippets_vault, |vault| {
            if let Some(parent_id) = parent_id.as_deref() {
                if !vault.groups.iter().any(|g| g.id == parent_id) {
                    error = Some("Selected group does not exist".to_string());
                    return;
                }
                // نذار گروه بره زیر نوه‌ش — چرخه می‌سازه و delete گیر می‌کنه
                if would_create_group_cycle(&vault.groups, &id, Some(parent_id)) {
                    error = Some("Group cannot be nested under its own descendant".to_string());
                    return;
                }
            }
            upsert_group_by_id(&mut vault.groups, group.clone());
        })
        .map_err(|e| e.to_string())?;

    if let Some(err_msg) = error {
        return Err(err_msg);
    }

    crate::sync::mark_dirty(app);
    Ok(group)
}

pub fn remove_snippet_group(app: &AppHandle, id: String) -> Result<(), String> {
    let state = app.state::<AppState>();
    let mut removed_group_ids: Vec<String> = Vec::new();

    state
        .snippets_store
        .update_with_migration(migrate_snippets_vault, |vault| {
            let descendants = descendant_group_ids(&vault.groups, &id);
            removed_group_ids = std::iter::once(id.clone())
                .chain(descendants.iter().cloned())
                .collect();

            vault
                .groups
                .retain(|group| group.id != id && !descendants.contains(&group.id));
            for snippet in vault.snippets.iter_mut() {
                if snippet
                    .group_id
                    .as_ref()
                    .map(|group_id| group_id == &id || descendants.contains(group_id))
                    .unwrap_or(false)
                {
                    snippet.group_id = None;
                    // بدون bump، LWW موقع sync ممکنه نسخهٔ قدیمی با group_id حذف‌شده برنده بشه
                    snippet.updated_at = Some(now_iso());
                }
            }
        })
        .map_err(|e| e.to_string())?;
    crate::tombstones::record(
        app,
        crate::tombstones::EntityKind::SnippetGroup,
        &removed_group_ids,
    )?;
    crate::sync::mark_dirty(app);
    Ok(())
}

fn would_create_group_cycle(groups: &[SnippetGroup], id: &str, parent_id: Option<&str>) -> bool {
    let mut current = parent_id;
    let mut seen = std::collections::HashSet::new();
    while let Some(pid) = current {
        if pid == id {
            return true;
        }
        if !seen.insert(pid) {
            // زنجیرهٔ والد از قبل چرخه داره
            return true;
        }
        current = groups
            .iter()
            .find(|g| g.id == pid)
            .and_then(|g| g.parent_id.as_deref());
    }
    false
}

fn descendant_group_ids(groups: &[SnippetGroup], id: &str) -> Vec<String> {
    let mut descendants = Vec::new();
    let mut stack = vec![id.to_string()];
    let mut visited = std::collections::HashSet::new();

    while let Some(parent_id) = stack.pop() {
        if !visited.insert(parent_id.clone()) {
            // چرخهٔ sync‌شده — قطع کن تا hang نشه
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

/// Snippets whose `group_id` points at a deleted/missing group vanish from the
/// normal tree (neither root nor under any folder). Clear those pointers so
/// they surface at root after sync races.
fn clear_orphan_group_ids(snippets: &mut [Snippet], groups: &[SnippetGroup]) {
    let known: std::collections::HashSet<&str> = groups.iter().map(|g| g.id.as_str()).collect();
    for snippet in snippets.iter_mut() {
        if let Some(group_id) = snippet.group_id.as_deref() {
            if !known.contains(group_id) {
                snippet.group_id = None;
            }
        }
    }
}

fn upsert_group_by_id(items: &mut Vec<SnippetGroup>, item: SnippetGroup) {
    if let Some(index) = items.iter().position(|existing| existing.id == item.id) {
        items[index] = item;
    } else {
        items.insert(0, item);
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Internals
// ──────────────────────────────────────────────────────────────────────────────

fn validate_snippet(request: &SaveSnippetRequest) -> Result<(), String> {
    if request.name.trim().is_empty() {
        return Err("Snippet name is required".to_string());
    }

    match request.kind {
        SnippetKind::Text => {
            if request
                .body
                .as_ref()
                .map(|v| v.trim().is_empty())
                .unwrap_or(true)
            {
                return Err("Body is required for text snippets".to_string());
            }
        }
        SnippetKind::Command => {
            if request
                .command
                .as_ref()
                .map(|v| v.trim().is_empty())
                .unwrap_or(true)
            {
                return Err("Command is required for command snippets".to_string());
            }
        }
        SnippetKind::Script => {
            if request
                .script
                .as_ref()
                .map(|v| v.trim().is_empty())
                .unwrap_or(true)
            {
                return Err("Script is required for script snippets".to_string());
            }
        }
    }

    if let Some(keyword) = request.keyword.as_ref() {
        let trimmed = keyword.trim();
        if !trimmed.is_empty() && trimmed.split_whitespace().count() > 1 {
            return Err("Snippet keyword must be a single word".to_string());
        }
    }

    // Validate variables
    for var in &request.variables {
        if var.name.trim().is_empty() {
            return Err("Variable name is required".to_string());
        }
        if matches!(var.var_type, SnippetVariableType::Enum) && var.options.is_empty() {
            return Err(format!(
                "Variable '{}' is enum type but has no options",
                var.name
            ));
        }
    }

    Ok(())
}

fn upsert_by_id(items: &mut Vec<Snippet>, item: Snippet) {
    if let Some(index) = items.iter().position(|existing| existing.id == item.id) {
        items[index] = item;
    } else {
        items.insert(0, item);
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

    fn temp_dir() -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("termifai_snippets_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn script_file_roundtrip() {
        let dir = temp_dir();
        write_script_file(&dir, "abc", "echo hi").unwrap();
        assert_eq!(read_script_file(&dir, "abc").as_deref(), Some("echo hi"));
        delete_script_file(&dir, "abc");
        assert!(read_script_file(&dir, "abc").is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn script_path_uses_id_and_sh_extension() {
        let dir = temp_dir();
        assert_eq!(script_path(&dir, "s-1").unwrap(), dir.join("s-1.sh"));
        assert!(script_path(&dir, "../etc/passwd").is_err());
        assert!(script_path(&dir, "s/evil").is_err());
        assert!(validate_snippet_id("s-123_abc").is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_to_missing_dir_fails_without_panicking() {
        let dir = std::env::temp_dir().join("termifai_missing_dir_test/never_created");
        assert!(write_script_file(&dir, "abc", "x").is_err());
    }

    #[test]
    fn write_script_file_overwrites_stale_file_on_disk() {
        // Regression test for the migrate_inline_scripts short-circuit bug:
        // a .sh file already on disk must not block a write-through of newer
        // (e.g. synced) inline content.
        let dir = temp_dir();
        write_script_file(&dir, "abc", "OLD content").unwrap();
        assert_eq!(
            read_script_file(&dir, "abc").as_deref(),
            Some("OLD content")
        );

        write_script_file(&dir, "abc", "NEW content").unwrap();
        assert_eq!(
            read_script_file(&dir, "abc").as_deref(),
            Some("NEW content")
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reorder_group_vector_supports_subgroups() {
        let mut groups = vec![
            SnippetGroup {
                id: "root1".to_string(),
                name: "Root 1".to_string(),
                parent_id: None,
                updated_at: Some("2026-01-01T00:00:00Z".to_string()),
            },
            SnippetGroup {
                id: "sub1".to_string(),
                name: "Sub 1".to_string(),
                parent_id: Some("root1".to_string()),
                updated_at: Some("2026-01-01T00:00:00Z".to_string()),
            },
            SnippetGroup {
                id: "sub2".to_string(),
                name: "Sub 2".to_string(),
                parent_id: Some("root1".to_string()),
                updated_at: Some("2026-01-01T00:00:00Z".to_string()),
            },
        ];

        // Reorder subgroups under root1
        let res = reorder_group_vector(&mut groups, &["sub2".to_string(), "sub1".to_string()]);
        assert!(res.is_ok());
        assert_eq!(groups[1].id, "sub2");
        assert_eq!(groups[2].id, "sub1");
    }

    #[test]
    fn write_synced_script_bodies_keeps_disk_until_purge() {
        // اگه vault commit بترکه، نباید از قبل orphan پاک شده باشه
        let dir = temp_dir();
        write_script_file(&dir, "keep-me", "echo keep").unwrap();
        write_script_file(&dir, "orphan", "echo orphan").unwrap();

        let snippets = vec![Snippet {
            id: "keep-me".to_string(),
            kind: SnippetKind::Script,
            name: "Keep".to_string(),
            body: None,
            command: None,
            script: Some("echo keep-v2".to_string()),
            variables: vec![],
            group_id: None,
            keyword: None,
            os_targets: vec![],
            run_as_sudo: None,
            created_at: None,
            updated_at: Some("2026-01-01T00:00:00Z".to_string()),
        }];

        let (vault_snippets, keep_ids) = write_synced_script_bodies(&dir, snippets).unwrap();
        assert_eq!(vault_snippets.len(), 1);
        assert!(vault_snippets[0].script.is_none());
        assert!(keep_ids.contains("keep-me"));
        assert_eq!(
            read_script_file(&dir, "keep-me").as_deref(),
            Some("echo keep-v2")
        );
        // orphan هنوز روی دیسک هست تا بعد از commit موفق purge بشه
        assert_eq!(
            read_script_file(&dir, "orphan").as_deref(),
            Some("echo orphan")
        );

        purge_orphan_script_files(&dir, &keep_ids);
        assert!(read_script_file(&dir, "keep-me").is_some());
        assert!(read_script_file(&dir, "orphan").is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn purge_orphan_script_files_removes_former_scripts() {
        let dir = temp_dir();
        write_script_file(&dir, "was-script", "echo hi").unwrap();
        let keep = std::collections::HashSet::new();
        purge_orphan_script_files(&dir, &keep);
        assert!(read_script_file(&dir, "was-script").is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn would_create_group_cycle_rejects_nesting_under_descendant() {
        let groups = vec![
            SnippetGroup {
                id: "a".to_string(),
                name: "A".to_string(),
                parent_id: None,
                updated_at: Some("2026-01-01T00:00:00Z".to_string()),
            },
            SnippetGroup {
                id: "b".to_string(),
                name: "B".to_string(),
                parent_id: Some("a".to_string()),
                updated_at: Some("2026-01-01T00:00:00Z".to_string()),
            },
        ];
        assert!(would_create_group_cycle(&groups, "a", Some("b")));
        assert!(!would_create_group_cycle(&groups, "b", Some("a")));
        assert!(!would_create_group_cycle(&groups, "a", None));
    }

    #[test]
    fn descendant_group_ids_terminates_on_parent_cycle() {
        let groups = vec![
            SnippetGroup {
                id: "a".to_string(),
                name: "A".to_string(),
                parent_id: Some("b".to_string()),
                updated_at: Some("2026-01-01T00:00:00Z".to_string()),
            },
            SnippetGroup {
                id: "b".to_string(),
                name: "B".to_string(),
                parent_id: Some("a".to_string()),
                updated_at: Some("2026-01-01T00:00:00Z".to_string()),
            },
        ];
        let descendants = descendant_group_ids(&groups, "a");
        assert!(descendants.contains(&"b".to_string()));
        // Must not hang / grow forever on a mutual parent cycle.
        assert!(descendants.len() <= 2);
    }
    #[test]
    fn clear_orphan_group_ids_moves_snippets_to_root() {
        let groups = vec![SnippetGroup {
            id: "alive".to_string(),
            name: "Alive".to_string(),
            parent_id: None,
            updated_at: Some("2026-01-01T00:00:00Z".to_string()),
        }];
        let mut snippets = vec![
            Snippet {
                id: "s1".to_string(),
                kind: SnippetKind::Text,
                name: "orphan".to_string(),
                body: Some("x".to_string()),
                command: None,
                script: None,
                variables: vec![],
                group_id: Some("deleted".to_string()),
                keyword: None,
                os_targets: vec![],
                run_as_sudo: None,
                created_at: Some("2026-01-01T00:00:00Z".to_string()),
                updated_at: Some("2026-01-01T00:00:00Z".to_string()),
            },
            Snippet {
                id: "s2".to_string(),
                kind: SnippetKind::Text,
                name: "ok".to_string(),
                body: Some("y".to_string()),
                command: None,
                script: None,
                variables: vec![],
                group_id: Some("alive".to_string()),
                keyword: None,
                os_targets: vec![],
                run_as_sudo: None,
                created_at: Some("2026-01-01T00:00:00Z".to_string()),
                updated_at: Some("2026-01-01T00:00:00Z".to_string()),
            },
        ];

        clear_orphan_group_ids(&mut snippets, &groups);
        assert!(snippets[0].group_id.is_none());
        assert_eq!(snippets[1].group_id.as_deref(), Some("alive"));
    }
}
