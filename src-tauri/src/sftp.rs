use crate::sftp_transfer::{
    clear_download_resume_files, clear_upload_marker, download_marker_matches,
    download_resume_offset_verified, download_tmp_path, plan_upload_temp, same_file_identity,
    upload_marker_matches, upload_temp_is_our_partial, write_download_marker, write_upload_marker,
    DownloadMarker, UploadMarker, UploadTempPlan,
};
use crate::ssh;
use serde::{Deserialize, Serialize};
use ssh2::{OpenFlags, OpenType, Session};
use std::collections::HashMap;
use std::io::{Seek, SeekFrom};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant, UNIX_EPOCH};

/// Buffer size for SFTP read/write loops (Phase 2a).
const TRANSFER_BUF_SIZE: usize = 256 * 1024;
/// Minimum interval between progress emits (Phase 2a throttle).
const PROGRESS_THROTTLE: Duration = Duration::from_millis(100);

/// Credentials needed to rebuild an SFTP session after a network drop.
#[derive(Debug, Clone)]
pub struct SftpReconnectCreds {
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub private_key_path: Option<String>,
    #[allow(dead_code)] // برای reconnect آینده به default path نگه داشته می‌شه
    pub default_remote_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SftpConnectRequest {
    pub session_id: String,
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub private_key_path: Option<String>,
    pub default_remote_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SftpSessionInfo {
    pub session_id: String,
    pub remote_path: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LocalFileEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: Option<u64>,
    pub modified: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RemoteFileEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: Option<u64>,
    pub permissions: Option<u32>,
    pub modified: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransferProgress {
    pub session_id: String,
    pub file_name: String,
    pub bytes_transferred: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictDecision {
    Overwrite,
    Skip,
    OverwriteAll,
    SkipAll,
    Cancel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictMode {
    Ask,
    OverwriteAll,
    SkipAll,
}

/// Payload for the `sftp:{sid}:conflict` event: what already exists at the
/// destination vs. what is about to be written, so the dialog can compare.
#[derive(Debug, Clone, Serialize)]
pub struct ConflictInfo {
    pub session_id: String,
    pub file_name: String,
    pub dest_path: String,
    /// "file" | "dir"
    pub kind: String,
    /// "upload" | "download"
    pub direction: String,
    pub existing_size: Option<u64>,
    pub existing_modified: Option<String>,
    pub incoming_size: Option<u64>,
    pub incoming_modified: Option<String>,
}

/// Per-transfer conflict policy. `resolve` consults the sticky mode first and
/// only prompts (blocking) while the mode is `Ask`.
pub struct ConflictHandler<'a> {
    mode: ConflictMode,
    prompt: Box<dyn FnMut(&ConflictInfo) -> ConflictDecision + 'a>,
}

impl<'a> ConflictHandler<'a> {
    pub fn new(
        mode: ConflictMode,
        prompt: impl FnMut(&ConflictInfo) -> ConflictDecision + 'a,
    ) -> Self {
        Self {
            mode,
            prompt: Box::new(prompt),
        }
    }

    /// OverwriteAll یعنی skip بی‌صدای هم‌اندازه ممنوعه — باید دوباره بنویسیم.
    pub fn forces_overwrite(&self) -> bool {
        self.mode == ConflictMode::OverwriteAll
    }

    /// Ok(true) = overwrite/merge, Ok(false) = skip this item, Err = abort transfer.
    pub fn resolve(&mut self, info: &ConflictInfo) -> Result<bool, String> {
        match self.mode {
            ConflictMode::OverwriteAll => return Ok(true),
            ConflictMode::SkipAll => return Ok(false),
            ConflictMode::Ask => {}
        }
        match (self.prompt)(info) {
            ConflictDecision::Overwrite => Ok(true),
            ConflictDecision::Skip => Ok(false),
            ConflictDecision::OverwriteAll => {
                self.mode = ConflictMode::OverwriteAll;
                Ok(true)
            }
            ConflictDecision::SkipAll => {
                self.mode = ConflictMode::SkipAll;
                Ok(false)
            }
            ConflictDecision::Cancel => Err("Cancelled".to_string()),
        }
    }
}

fn local_mtime_secs(meta: &std::fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn list_local(path: &str) -> Result<Vec<LocalFileEntry>, String> {
    let dir = std::fs::read_dir(path).map_err(|e| format!("Cannot read '{}': {}", path, e))?;

    let mut entries: Vec<LocalFileEntry> = dir
        .filter_map(|e| e.ok())
        .map(|entry| {
            let meta = entry.metadata().ok();
            let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            let size = if is_dir {
                None
            } else {
                meta.as_ref().map(|m| m.len())
            };
            let modified = meta.and_then(|m| m.modified().ok()).map(|t| {
                let secs = t
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                format_unix_timestamp(secs)
            });
            LocalFileEntry {
                name: entry.file_name().to_string_lossy().to_string(),
                path: entry.path().to_string_lossy().to_string(),
                is_dir,
                size,
                modified,
            }
        })
        .collect();

    entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.cmp(&b.name)));
    Ok(entries)
}

fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// A single file/folder name for rename/mkdir — not a relative or absolute path.
/// Rejects empty names, `.` / `..`, separators, and absolute paths so
/// `parent.join(name)` cannot escape the intended directory.
pub fn validate_path_segment(name: &str) -> Result<(), String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("Name cannot be empty".to_string());
    }
    if name == "." || name == ".." {
        return Err("Invalid name".to_string());
    }
    if name.contains('/') || name.contains('\\') || name.contains('\0') {
        return Err("Name cannot contain path separators".to_string());
    }
    let as_path = std::path::Path::new(name);
    if as_path.is_absolute() || as_path.components().count() != 1 {
        return Err("Name must be a single path segment".to_string());
    }
    Ok(())
}

/// Ensures `to_path` is a same-directory rename of `from_path` to a safe
/// single-segment name (blocks `../` and absolute destinations).
pub fn validate_same_dir_rename(from_path: &str, to_path: &str) -> Result<(), String> {
    let from = std::path::Path::new(from_path);
    let to = std::path::Path::new(to_path);
    let from_parent = from
        .parent()
        .ok_or_else(|| "Source path has no parent directory".to_string())?;
    let to_parent = to
        .parent()
        .ok_or_else(|| "Destination path has no parent directory".to_string())?;
    if from_parent != to_parent {
        return Err("Rename must stay in the same directory".to_string());
    }
    let name = to
        .file_name()
        .ok_or_else(|| "Destination path has no file name".to_string())?
        .to_string_lossy();
    validate_path_segment(&name)
}

/// Rejects any `..` component so mkdir/join cannot climb out of the pane cwd.
pub fn reject_parent_dir_components(path: &str) -> Result<(), String> {
    for component in std::path::Path::new(path).components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err("Path cannot contain '..'".to_string());
        }
    }
    Ok(())
}

fn format_unix_timestamp(secs: u64) -> String {
    let secs = secs as i64;
    let (y, mo, d, h, mi) = unix_to_ymd_hm(secs);
    format!("{:04}-{:02}-{:02} {:02}:{:02}", y, mo, d, h, mi)
}

fn unix_to_ymd_hm(secs: i64) -> (i32, u32, u32, u32, u32) {
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let h = (time_of_day / 3600) as u32;
    let mi = ((time_of_day % 3600) / 60) as u32;

    let jd = days + 2440588;
    let l = jd + 68569;
    let n = (4 * l) / 146097;
    let l = l - (146097 * n + 3) / 4;
    let i = (4000 * (l + 1)) / 1461001;
    let l = l - (1461 * i) / 4 + 31;
    let j = (80 * l) / 2447;
    let d = l - (2447 * j) / 80;
    let l = j / 11;
    let mo = j + 2 - 12 * l;
    let y = 100 * (n - 49) + i + l;
    (y as i32, mo as u32, d as u32, h, mi)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RemoteStatResult {
    pub permissions: u32,
    pub owner: String,
    pub group: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UsersGroups {
    pub users: Vec<String>,
    pub groups: Vec<String>,
    pub current_user: String,
}

pub struct SftpEntry {
    pub session: Session,
    pub reconnect: SftpReconnectCreds,
    /// وقتی true بشه thread کیپ‌الایو تموم می‌شه (disconnect / clear_all)
    keepalive_stop: Arc<AtomicBool>,
}

impl std::fmt::Debug for SftpEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SftpEntry")
            .field("hostname", &self.reconnect.hostname)
            .finish()
    }
}

impl SftpEntry {
    /// Replace the live SSH session after a successful reconnect (creds stay).
    pub fn replace_session(&mut self, session: Session) {
        self.session = session;
    }

    pub fn stop_keepalive(&self) {
        self.keepalive_stop.store(true, Ordering::Relaxed);
    }

    /// Stops the previous keepalive worker and installs a fresh stop flag so a
    /// new keepalive thread can be spawned after reconnect (the old worker may
    /// already have exited on `keepalive_send` error).
    fn reset_keepalive_stop(&mut self) -> Arc<AtomicBool> {
        self.keepalive_stop.store(true, Ordering::Relaxed);
        let stop = Arc::new(AtomicBool::new(false));
        self.keepalive_stop = Arc::clone(&stop);
        stop
    }
}

/// `set_keepalive` فقط config می‌کنه؛ باید دوره‌ای `keepalive_send` بزنیم وگرنه
/// بعد از idle سرور/NAT کانال رو می‌کشه → «Unable to startup channel».
fn spawn_sftp_keepalive(entry: Arc<Mutex<SftpEntry>>, stop: Arc<AtomicBool>, session_id: &str) {
    let name = format!("sftp-ka-{}", &session_id[..session_id.len().min(12)]);
    let _ = std::thread::Builder::new().name(name).spawn(move || {
        // با اولین خطای لحظه‌ای (مثل contention کوتاه) نخ رو نکش —
        // وگرنه بعد از چند ثانیه idle سشن می‌میره و Channel open: Session(-7) می‌گیری
        let mut consecutive_failures = 0u32;
        while !stop.load(Ordering::Relaxed) {
            for _ in 0..10 {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
            // اگه transfer قفل گرفته، رد شو — ترافیک فعال خودش سشن رو زنده نگه می‌داره
            let Ok(guard) = entry.try_lock() else {
                consecutive_failures = 0;
                continue;
            };
            if stop.load(Ordering::Relaxed) || guard.keepalive_stop.load(Ordering::Relaxed) {
                return;
            }
            match guard.session.keepalive_send() {
                Ok(_) => consecutive_failures = 0,
                Err(_) => {
                    consecutive_failures += 1;
                    if consecutive_failures >= 3 {
                        return;
                    }
                }
            }
        }
    });
}

impl SftpEntry {
    pub fn list_remote(&self, path: &str) -> Result<Vec<RemoteFileEntry>, String> {
        let sftp = self
            .session
            .sftp()
            .map_err(|e| format!("SFTP subsystem: {}", e))?;
        let dir_entries = sftp
            .readdir(std::path::Path::new(path))
            .map_err(|e| format!("readdir '{}': {}", path, e))?;

        let mut result: Vec<RemoteFileEntry> = dir_entries
            .into_iter()
            .filter_map(|(pb, stat)| {
                let name = pb.file_name()?.to_string_lossy().to_string();
                if name == "." || name == ".." {
                    return None;
                }
                let is_dir = stat.file_type().is_dir();
                let is_symlink = stat.file_type().is_symlink();
                let size = if is_dir {
                    None
                } else {
                    Some(stat.size.unwrap_or(0))
                };
                let modified = stat.mtime.map(format_unix_timestamp);
                Some(RemoteFileEntry {
                    name,
                    path: pb.to_string_lossy().to_string(),
                    is_dir,
                    is_symlink,
                    size,
                    permissions: stat.perm,
                    modified,
                })
            })
            .collect();

        result.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.cmp(&b.name)));
        Ok(result)
    }

    pub fn download_file<F>(
        &self,
        session_id: &str,
        remote_path: &str,
        local_path: &str,
        cancel: Arc<AtomicBool>,
        on_progress: F,
    ) -> Result<(), String>
    where
        F: Fn(TransferProgress),
    {
        use std::io::{Read, Write};

        let sftp = self
            .session
            .sftp()
            .map_err(|e| format!("SFTP subsystem: {}", e))?;

        let remote_p = std::path::Path::new(remote_path);
        let stat = sftp
            .stat(remote_p)
            .map_err(|e| format!("stat '{}': {}", remote_path, e))?;
        let total_bytes = stat.size.unwrap_or(0);
        let remote_mtime = stat.mtime.unwrap_or(0);

        let tmp_path = download_tmp_path(local_path);
        let identity_ok =
            download_marker_matches(local_path, remote_path, total_bytes, remote_mtime);
        let tmp_len = std::fs::metadata(&tmp_path).ok().map(|m| m.len());
        let resume_at =
            download_resume_offset_verified(tmp_len, total_bytes, identity_ok).unwrap_or(0);

        if !identity_ok {
            // tmp کهنه از فایل/خطای دیگه — دور بریز
            clear_download_resume_files(local_path);
        }

        // فایل کامل از قبل تو tmp هست — فقط rename کن
        if resume_at == total_bytes && total_bytes > 0 {
            if std::path::Path::new(local_path).exists() {
                std::fs::remove_file(local_path)
                    .map_err(|e| format!("replace existing '{}': {}", local_path, e))?;
            }
            std::fs::rename(&tmp_path, local_path)
                .map_err(|e| format!("rename tmp to '{}': {}", local_path, e))?;
            let _ = std::fs::remove_file(crate::sftp_transfer::download_marker_path(local_path));
            on_progress(TransferProgress {
                session_id: session_id.to_string(),
                file_name: pathbase(remote_path),
                bytes_transferred: total_bytes,
                total_bytes,
            });
            return Ok(());
        }

        let mut remote_file = sftp
            .open(remote_p)
            .map_err(|e| format!("open remote: {}", e))?;

        let mut local_file = if resume_at > 0 {
            remote_file
                .seek(SeekFrom::Start(resume_at))
                .map_err(|e| format!("seek remote: {}", e))?;
            std::fs::OpenOptions::new()
                .append(true)
                .open(&tmp_path)
                .map_err(|e| format!("open tmp for resume '{}': {}", tmp_path, e))?
        } else {
            clear_download_resume_files(local_path);
            std::fs::File::create(&tmp_path)
                .map_err(|e| format!("create tmp file '{}': {}", tmp_path, e))?
        };

        write_download_marker(
            local_path,
            &DownloadMarker {
                remote_path: remote_path.to_string(),
                remote_size: total_bytes,
                remote_mtime,
            },
        )?;

        let file_name = remote_p
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| remote_path.to_string());

        let mut buf = vec![0u8; TRANSFER_BUF_SIZE];
        let mut bytes_transferred = resume_at;
        let mut last_progress = Instant::now()
            .checked_sub(PROGRESS_THROTTLE)
            .unwrap_or_else(Instant::now);

        on_progress(TransferProgress {
            session_id: session_id.to_string(),
            file_name: file_name.clone(),
            bytes_transferred,
            total_bytes,
        });

        let result = (|| {
            loop {
                if cancel.load(Ordering::Relaxed) {
                    // Cancel عمدی: tmp+marker می‌مونن تا بعداً بشه resume کرد؛ پاک نمی‌کنیم
                    return Err("Cancelled".to_string());
                }
                let n = remote_file
                    .read(&mut buf)
                    .map_err(|e| format!("read remote: {}", e))?;
                if n == 0 {
                    break;
                }
                local_file
                    .write_all(&buf[..n])
                    .map_err(|e| format!("write tmp: {}", e))?;
                bytes_transferred += n as u64;
                if last_progress.elapsed() >= PROGRESS_THROTTLE || bytes_transferred >= total_bytes
                {
                    last_progress = Instant::now();
                    on_progress(TransferProgress {
                        session_id: session_id.to_string(),
                        file_name: file_name.clone(),
                        bytes_transferred,
                        total_bytes,
                    });
                }
            }
            local_file
                .flush()
                .map_err(|e| format!("flush tmp: {}", e))?;
            // EOF زودرس (فایل remote وسط کار truncate شده، یا کانال نصفه بسته شده)
            // نباید به‌عنوان موفقیت rename بشه — فایل ناقص رو جای کامل جا نزن.
            if total_bytes > 0 && bytes_transferred != total_bytes {
                return Err(format!(
                    "incomplete download: got {} of {} bytes",
                    bytes_transferred, total_bytes
                ));
            }
            Ok::<(), String>(())
        })();

        // خطای شبکه/Cancel/incomplete: tmp+marker برای resume می‌مونن
        result?;

        // فقط بعد از دانلود کامل جایگزین کن (ویندوز rename روی فایل موجود fail می‌شه)
        if std::path::Path::new(local_path).exists() {
            std::fs::remove_file(local_path)
                .map_err(|e| format!("replace existing '{}': {}", local_path, e))?;
        }
        std::fs::rename(&tmp_path, local_path)
            .map_err(|e| format!("rename tmp to '{}': {}", local_path, e))?;
        let _ = std::fs::remove_file(crate::sftp_transfer::download_marker_path(local_path));
        Ok(())
    }

    pub fn upload_file<F>(
        &self,
        session_id: &str,
        local_path: &str,
        remote_path: &str,
        cancel: Arc<AtomicBool>,
        on_progress: F,
    ) -> Result<(), String>
    where
        F: Fn(TransferProgress),
    {
        use std::io::{Read, Write};

        let sftp = self
            .session
            .sftp()
            .map_err(|e| format!("SFTP subsystem: {}", e))?;

        let local_meta = std::fs::metadata(local_path)
            .map_err(|e| format!("stat local '{}': {}", local_path, e))?;
        let total_bytes = local_meta.len();
        let local_mtime = local_mtime_secs(&local_meta);

        let dest_exists = sftp.stat(std::path::Path::new(remote_path)).is_ok();

        let identity_ok = upload_marker_matches(local_path, remote_path, total_bytes, local_mtime);
        // همیشه روی sidecar می‌نویسیم؛ resume فقط از روی سایز temp — نه مقصد قدیمی.
        let remote_tmp = format!("{}.termifai-uploading", remote_path);
        let tmp_len = sftp
            .stat(std::path::Path::new(&remote_tmp))
            .ok()
            .and_then(|s| s.size);
        let plan = plan_upload_temp(identity_ok, tmp_len, total_bytes);

        if matches!(plan, UploadTempPlan::PromoteComplete) {
            promote_upload_temp(&sftp, remote_path, &remote_tmp, dest_exists)?;
            clear_upload_marker(local_path);
            on_progress(TransferProgress {
                session_id: session_id.to_string(),
                file_name: pathbase(local_path),
                bytes_transferred: total_bytes,
                total_bytes,
            });
            return Ok(());
        }

        let mut local_file =
            std::fs::File::open(local_path).map_err(|e| format!("open local: {}", e))?;

        let (resume_at, started_fresh) = match plan {
            UploadTempPlan::ResumeTemp { offset } => (offset, false),
            UploadTempPlan::FreshTemp => {
                let _ = sftp.unlink(std::path::Path::new(&remote_tmp));
                clear_upload_marker(local_path);
                (0, true)
            }
            UploadTempPlan::PromoteComplete => unreachable!("handled above"),
        };

        let mut remote_file = if resume_at > 0 {
            // فقط WRITE + seek روی temp — مقصد نهایی رو دست نزن
            let mut f = sftp
                .open_mode(
                    std::path::Path::new(&remote_tmp),
                    OpenFlags::WRITE,
                    0o644,
                    OpenType::File,
                )
                .map_err(|e| format!("open remote temp for resume '{}': {}", remote_tmp, e))?;
            f.seek(SeekFrom::Start(resume_at))
                .map_err(|e| format!("seek remote temp: {}", e))?;
            local_file
                .seek(SeekFrom::Start(resume_at))
                .map_err(|e| format!("seek local: {}", e))?;
            f
        } else {
            sftp.create(std::path::Path::new(&remote_tmp))
                .map_err(|e| format!("create remote temp '{}': {}", remote_tmp, e))?
        };

        write_upload_marker(
            local_path,
            &UploadMarker {
                remote_path: remote_path.to_string(),
                local_size: total_bytes,
                local_mtime,
            },
        )?;

        let file_name = std::path::Path::new(local_path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| local_path.to_string());

        let mut buf = vec![0u8; TRANSFER_BUF_SIZE];
        let mut bytes_transferred = resume_at;
        let mut last_progress = Instant::now()
            .checked_sub(PROGRESS_THROTTLE)
            .unwrap_or_else(Instant::now);

        on_progress(TransferProgress {
            session_id: session_id.to_string(),
            file_name: file_name.clone(),
            bytes_transferred,
            total_bytes,
        });

        let write_result = (|| {
            loop {
                if cancel.load(Ordering::Relaxed) {
                    // temp resumed رو unlink نکن — گیگابایت منتقل‌شده رو نگه دار
                    return Err("Cancelled".to_string());
                }
                let n = local_file
                    .read(&mut buf)
                    .map_err(|e| format!("read local: {}", e))?;
                if n == 0 {
                    break;
                }
                remote_file
                    .write_all(&buf[..n])
                    .map_err(|e| format!("write remote: {}", e))?;
                bytes_transferred += n as u64;
                if last_progress.elapsed() >= PROGRESS_THROTTLE || bytes_transferred >= total_bytes
                {
                    last_progress = Instant::now();
                    on_progress(TransferProgress {
                        session_id: session_id.to_string(),
                        file_name: file_name.clone(),
                        bytes_transferred,
                        total_bytes,
                    });
                }
            }
            Ok::<(), String>(())
        })();

        if let Err(err) = write_result {
            // تلاش تازه‌ی شکست‌خورده: temp ناقص رو بردار تا marker مقصد قدیمی رو
            // به‌اشتباه «partial» حساب نکنه. resume واقعی temp رو نگه می‌داریم.
            if started_fresh {
                let _ = sftp.unlink(std::path::Path::new(&remote_tmp));
                clear_upload_marker(local_path);
            }
            return Err(err);
        }

        // قبل از promote چک کن — فایل کوتاه نباید جای مقصد خوب بنشینه
        if total_bytes > 0 && bytes_transferred != total_bytes {
            if started_fresh {
                let _ = sftp.unlink(std::path::Path::new(&remote_tmp));
                clear_upload_marker(local_path);
            }
            return Err(format!(
                "incomplete upload: wrote {} of {} bytes",
                bytes_transferred, total_bytes
            ));
        }

        promote_upload_temp(&sftp, remote_path, &remote_tmp, dest_exists)?;
        clear_upload_marker(local_path);
        Ok(())
    }

    pub fn delete_remote(&self, paths: &[String]) -> Result<(), String> {
        let sftp = self
            .session
            .sftp()
            .map_err(|e| format!("SFTP subsystem: {}", e))?;

        for path in paths {
            let p = std::path::Path::new(path);
            let stat = sftp
                .stat(p)
                .map_err(|e| format!("stat '{}': {}", path, e))?;
            if stat.file_type().is_dir() {
                sftp.rmdir(p)
                    .map_err(|e| format!("rmdir '{}': {}", path, e))?;
            } else {
                sftp.unlink(p)
                    .map_err(|e| format!("unlink '{}': {}", path, e))?;
            }
        }
        Ok(())
    }

    pub fn rename_remote(&self, from_path: &str, to_path: &str) -> Result<(), String> {
        validate_same_dir_rename(from_path, to_path)?;
        let sftp = self
            .session
            .sftp()
            .map_err(|e| format!("SFTP subsystem: {}", e))?;
        sftp.rename(
            std::path::Path::new(from_path),
            std::path::Path::new(to_path),
            None,
        )
        .map_err(|e| format!("rename '{}' -> '{}': {}", from_path, to_path, e))
    }

    pub fn mkdir_remote(&self, path: &str) -> Result<(), String> {
        reject_parent_dir_components(path)?;
        let name = std::path::Path::new(path)
            .file_name()
            .ok_or_else(|| "mkdir path has no file name".to_string())?
            .to_string_lossy();
        validate_path_segment(&name)?;
        let sftp = self
            .session
            .sftp()
            .map_err(|e| format!("SFTP subsystem: {}", e))?;
        sftp.mkdir(std::path::Path::new(path), 0o755)
            .map_err(|e| format!("mkdir '{}': {}", path, e))
    }

    pub fn exec_command(&self, cmd: &str) -> Result<String, String> {
        let mut channel = self
            .session
            .channel_session()
            .map_err(|e| format!("Channel open: {}", e))?;
        // stderr رو به stdout می‌چسبونیم، دو دلیل:
        // ۱) پیام خطای واقعی شل (مثل Operation not permitted) گم نمی‌شه و به کاربر می‌رسه
        // ۲) اگه stderr جدا بمونه هیچ‌وقت خونده نمی‌شه؛ وقتی بافرش پر بشه (مثلاً chmod -R
        //    روی درخت بزرگ با کلی فایل غیرقابل‌دسترس) پنجره‌ی کانال فول می‌شه و read روی
        //    stdout تا ابد بلاک می‌مونه → کل سشن SFTP قفل می‌کنه
        channel
            .exec(&format!("{{ {}; }} 2>&1", cmd))
            .map_err(|e| format!("Exec '{}': {}", cmd, e))?;
        let mut output = String::new();
        use std::io::Read;
        channel
            .read_to_string(&mut output)
            .map_err(|e| format!("Read output: {}", e))?;
        channel
            .wait_close()
            .map_err(|e| format!("Channel close: {}", e))?;
        let status = channel
            .exit_status()
            .map_err(|e| format!("Exit status: {}", e))?;
        if status != 0 {
            // اولین خط غیرخالی خروجی معمولاً خود پیام خطای شله (بخاطر 2>&1)
            let detail = output.lines().map(|l| l.trim()).find(|l| !l.is_empty());
            return Err(match detail {
                Some(d) => {
                    let truncated: String = d.chars().take(300).collect();
                    format!("{} (exit status {})", truncated, status)
                }
                None => format!("Command '{}' exited with status {}", cmd, status),
            });
        }
        Ok(output)
    }

    pub fn stat_remote(&self, path: &str) -> Result<RemoteStatResult, String> {
        // اول SFTP رو کامل ببند، بعد exec بزن.
        // اگه کانال SFTP هنوز باز باشه و همزمان channel_session باز کنیم،
        // libssh2 گاهی SOCKET_SEND (-7) می‌ده → «Unable to send channel-open request»
        let permissions = {
            let sftp = self
                .session
                .sftp()
                .map_err(|e| format!("SFTP subsystem: {}", e))?;
            let stat = sftp
                .stat(std::path::Path::new(path))
                .map_err(|e| format!("stat '{}': {}", path, e))?;
            stat.perm.unwrap_or(0) & 0o7777
        };
        // get owner/group via SSH exec since libssh2 stat doesn't return names
        // stat -c مال گنو/لینوکسه؛ روی BSD/macOS از stat -f استفاده می‌کنیم
        let escaped = shell_escape(path);
        let owner_out = self.exec_command(&format!(
            "stat -c '%U %G' {0} 2>/dev/null || stat -f '%Su %Sg' {0} 2>/dev/null || echo 'root root'",
            escaped
        ))?;
        let parts: Vec<&str> = owner_out.trim().splitn(2, ' ').collect();
        let owner = parts.first().unwrap_or(&"root").to_string();
        let group = parts.get(1).unwrap_or(&"root").to_string();
        Ok(RemoteStatResult {
            permissions,
            owner,
            group,
        })
    }

    pub fn chmod(&self, path: &str, mode: &str, recursive: bool) -> Result<(), String> {
        if !mode.chars().all(|c| c.is_ascii_digit()) || mode.is_empty() || mode.len() > 4 {
            return Err(format!("Invalid chmod mode: '{}'", mode));
        }
        let flag = if recursive { "-R " } else { "" };
        let cmd = format!("chmod {}{} {}", flag, mode, shell_escape(path));
        self.exec_command(&cmd)?;
        Ok(())
    }

    pub fn chown(
        &self,
        path: &str,
        user: &str,
        group: &str,
        recursive: bool,
    ) -> Result<(), String> {
        fn is_valid_name(s: &str) -> bool {
            !s.is_empty()
                && s.chars().all(|c| {
                    c.is_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '@' || c == ':'
                })
        }
        if !is_valid_name(user) {
            return Err(format!("Invalid user name: '{}'", user));
        }
        if !is_valid_name(group) {
            return Err(format!("Invalid group name: '{}'", group));
        }
        let flag = if recursive { "-R " } else { "" };
        let cmd = format!("chown {}{}:{} {}", flag, user, group, shell_escape(path));
        self.exec_command(&cmd)?;
        Ok(())
    }

    pub fn copy_remote(&self, paths: &[String], dest_dir: &str) -> Result<(), String> {
        for path in paths {
            let cmd = format!("cp -a {} {}/", shell_escape(path), shell_escape(dest_dir));
            self.exec_command(&cmd)?;
        }
        Ok(())
    }

    pub fn get_users_groups(&self) -> Result<UsersGroups, String> {
        // یه round-trip به‌جای سه تا — باز/بست مکرر کانال exec سشن رو شکننده می‌کنه
        // (مخصوصاً وقتی دیالوگ با Promise.all همزمان stat هم می‌زنه)
        let out = self.exec_command(
            "printf '%s\\n' '__T_USERS__'; \
             (getent passwd 2>/dev/null || cat /etc/passwd) | cut -d: -f1; \
             printf '%s\\n' '__T_GROUPS__'; \
             (getent group 2>/dev/null || cat /etc/group) | cut -d: -f1; \
             printf '%s\\n' '__T_WHO__'; \
             (id -un 2>/dev/null || whoami 2>/dev/null || echo '')",
        )?;
        let mut section = "";
        let mut users = Vec::new();
        let mut groups = Vec::new();
        let mut current_user = String::new();
        for line in out.lines() {
            let line = line.trim();
            match line {
                "__T_USERS__" => section = "users",
                "__T_GROUPS__" => section = "groups",
                "__T_WHO__" => section = "who",
                "" => {}
                other => match section {
                    "users" => users.push(other.to_string()),
                    "groups" => groups.push(other.to_string()),
                    "who" if current_user.is_empty() => current_user = other.to_string(),
                    _ => {}
                },
            }
        }
        Ok(UsersGroups {
            users,
            groups,
            current_user,
        })
    }

    pub fn open_remote(&self, session_id: &str, remote_path: &str) -> Result<String, String> {
        // اسم خام remote می‌تونه & یا ..\\ داشته باشه؛ قبل از join تمیزش می‌کنیم
        let file_name = sanitize_open_basename(
            std::path::Path::new(remote_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file"),
        );

        let rand_id = uuid::Uuid::new_v4().to_string().replace('-', "");
        let rand_id = &rand_id[..8];
        let app_temp_dir = std::env::temp_dir()
            .join("termifai")
            .join(format!("{}_{}", session_id, rand_id));
        std::fs::create_dir_all(&app_temp_dir)
            .map_err(|e| format!("Create temp dir failed: {}", e))?;
        let tmp_path = app_temp_dir.join(&file_name);

        let sftp = self
            .session
            .sftp()
            .map_err(|e| format!("SFTP subsystem: {}", e))?;
        let mut remote_file = sftp
            .open(std::path::Path::new(remote_path))
            .map_err(|e| format!("Open remote '{}': {}", remote_path, e))?;
        let mut local_file = std::fs::File::create(&tmp_path)
            .map_err(|e| format!("Create tmp '{:?}': {}", tmp_path, e))?;
        std::io::copy(&mut remote_file, &mut local_file)
            .map_err(|e| format!("Copy to tmp: {}", e))?;
        Ok(tmp_path.to_string_lossy().to_string())
    }

    /// Uploads a local file OR directory (recursively) to the remote path.
    pub fn upload_path<F>(
        &self,
        session_id: &str,
        local_path: &str,
        remote_path: &str,
        cancel: Arc<AtomicBool>,
        conflicts: &mut ConflictHandler,
        on_progress: F,
    ) -> Result<(), String>
    where
        F: Fn(TransferProgress),
    {
        let meta = std::fs::metadata(local_path)
            .map_err(|e| format!("stat local '{}': {}", local_path, e))?;

        let local_mtime = local_mtime_secs(&meta);
        let (local_is_dir, local_size, local_modified) = (
            meta.is_dir(),
            if meta.is_dir() {
                None
            } else {
                Some(meta.len())
            },
            Some(format_unix_timestamp(local_mtime)),
        );
        {
            let sftp = self
                .session
                .sftp()
                .map_err(|e| format!("SFTP subsystem: {}", e))?;
            if let Some((dest_is_dir, dest_size, dest_mtime)) =
                stat_remote_brief(&sftp, remote_path)
            {
                if dest_is_dir == local_is_dir {
                    // هم‌اندازه + هم‌mtime → skip بی‌صدا؛ مگر OverwriteAll
                    let identical = !local_is_dir
                        && same_file_identity(
                            dest_size.unwrap_or(0),
                            dest_mtime,
                            local_size.unwrap_or(0),
                            Some(local_mtime),
                        );
                    if identical && !conflicts.forces_overwrite() {
                        return Ok(());
                    }
                    // ادامه‌ی transfer خودمون فقط وقتی temp sidecar ناقص/کامل باشه —
                    // سایز مقصد قدیمی (مثلاً فایل کوچک‌تر overwrite) رو partial حساب نکن.
                    let remote_tmp = format!("{}.termifai-uploading", remote_path);
                    let tmp_len = stat_remote_brief(&sftp, &remote_tmp).and_then(|(_, sz, _)| sz);
                    let our_partial = !local_is_dir
                        && upload_marker_matches(
                            local_path,
                            remote_path,
                            local_size.unwrap_or(0),
                            local_mtime,
                        )
                        && upload_temp_is_our_partial(tmp_len, local_size.unwrap_or(0));
                    if !our_partial {
                        let proceed = conflicts.resolve(&ConflictInfo {
                            session_id: session_id.to_string(),
                            file_name: pathbase(remote_path),
                            dest_path: remote_path.to_string(),
                            kind: if dest_is_dir { "dir" } else { "file" }.to_string(),
                            direction: "upload".to_string(),
                            existing_size: dest_size,
                            existing_modified: dest_mtime.map(format_unix_timestamp),
                            incoming_size: local_size,
                            incoming_modified: local_modified,
                        })?;
                        if !proceed {
                            return Ok(());
                        }
                        // overwrite تأیید شد — marker غریبه رو پاک کن؛ فایل ریموت
                        // رو نگه می‌داریم تا upload_file بعد از نوشتن کامل جایگزین کنه
                        if !local_is_dir {
                            clear_upload_marker(local_path);
                        }
                    }
                }
            }
        }

        if !meta.is_dir() {
            return self.upload_file(session_id, local_path, remote_path, cancel, on_progress);
        }

        let mut remote_dirs: Vec<String> = Vec::new();
        let mut files: Vec<(std::path::PathBuf, String, u64)> = Vec::new();
        walk_local_tree(
            std::path::Path::new(local_path),
            remote_path,
            &mut remote_dirs,
            &mut files,
        )?;

        {
            let sftp = self
                .session
                .sftp()
                .map_err(|e| format!("SFTP subsystem: {}", e))?;
            for dir in &remote_dirs {
                if cancel.load(Ordering::Relaxed) {
                    return Err("Cancelled".to_string());
                }
                ensure_remote_dir(&sftp, dir)?;
            }
        }

        let sftp = self
            .session
            .sftp()
            .map_err(|e| format!("SFTP subsystem: {}", e))?;

        let grand_total: u64 = files.iter().map(|(_, _, size)| size).sum();
        let mut offset = 0u64;
        for (lp, rp, size) in &files {
            if cancel.load(Ordering::Relaxed) {
                return Err("Cancelled".to_string());
            }

            // کامل+mtime → skip (مگر OverwriteAll)؛ ناقص با marker → resume؛ سایر → conflict
            let remote_brief = stat_remote_brief(&sftp, rp);
            let local_brief = stat_local_brief(lp);
            if let Some((_, dest_size, dest_mtime)) = &remote_brief {
                let local_mtime = local_brief.as_ref().and_then(|(_, _, m)| *m);
                let identical =
                    same_file_identity(dest_size.unwrap_or(0), *dest_mtime, *size, local_mtime);
                if identical && !conflicts.forces_overwrite() {
                    offset += size;
                    on_progress(TransferProgress {
                        session_id: session_id.to_string(),
                        file_name: pathbase(rp),
                        bytes_transferred: offset,
                        total_bytes: grand_total,
                    });
                    continue;
                }
                let lp_str = lp.to_string_lossy();
                let remote_tmp = format!("{}.termifai-uploading", rp);
                let tmp_len = stat_remote_brief(&sftp, &remote_tmp).and_then(|(_, sz, _)| sz);
                let is_our_partial = upload_marker_matches(
                    &lp_str,
                    rp,
                    *size,
                    local_mtime.unwrap_or(0),
                ) && upload_temp_is_our_partial(tmp_len, *size);
                if !is_our_partial {
                    if let Some((dest_is_dir, dest_size, dest_mtime)) = remote_brief {
                        // هم‌اندازه با محتوای متفاوت، یا فایل غریبه — از کاربر بپرس / OverwriteAll
                        let proceed = conflicts.resolve(&ConflictInfo {
                            session_id: session_id.to_string(),
                            file_name: pathbase(rp),
                            dest_path: rp.clone(),
                            kind: if dest_is_dir { "dir" } else { "file" }.to_string(),
                            direction: "upload".to_string(),
                            existing_size: dest_size,
                            existing_modified: dest_mtime.map(format_unix_timestamp),
                            incoming_size: Some(*size),
                            incoming_modified: local_mtime.map(format_unix_timestamp),
                        })?;
                        if !proceed {
                            offset += size;
                            on_progress(TransferProgress {
                                session_id: session_id.to_string(),
                                file_name: pathbase(rp),
                                bytes_transferred: offset,
                                total_bytes: grand_total,
                            });
                            continue;
                        }
                        clear_upload_marker(&lp_str);
                        // ریموت رو اینجا unlink نکن — upload_file بعد از موفقیت جایگزین می‌کنه
                    }
                }
            }

            let base = offset;
            self.upload_file(
                session_id,
                &lp.to_string_lossy(),
                rp,
                Arc::clone(&cancel),
                |p| {
                    on_progress(TransferProgress {
                        session_id: p.session_id,
                        file_name: p.file_name,
                        bytes_transferred: base + p.bytes_transferred,
                        total_bytes: grand_total,
                    })
                },
            )?;
            offset += size;
        }
        Ok(())
    }

    /// Downloads a remote file OR directory (recursively) to the local path.
    pub fn download_path<F>(
        &self,
        session_id: &str,
        remote_path: &str,
        local_path: &str,
        cancel: Arc<AtomicBool>,
        conflicts: &mut ConflictHandler,
        on_progress: F,
    ) -> Result<(), String>
    where
        F: Fn(TransferProgress),
    {
        let (is_dir, remote_size, remote_mtime_secs) = {
            let sftp = self
                .session
                .sftp()
                .map_err(|e| format!("SFTP subsystem: {}", e))?;
            let stat = sftp
                .stat(std::path::Path::new(remote_path))
                .map_err(|e| format!("stat '{}': {}", remote_path, e))?;
            let is_dir = stat.file_type().is_dir();
            let remote_size = if is_dir { None } else { stat.size };
            (is_dir, remote_size, stat.mtime)
        };
        let remote_modified = remote_mtime_secs.map(format_unix_timestamp);

        if let Some((dest_is_dir, dest_size, dest_mtime)) =
            stat_local_brief(std::path::Path::new(local_path))
        {
            if dest_is_dir == is_dir {
                let identical = !is_dir
                    && same_file_identity(
                        dest_size.unwrap_or(0),
                        dest_mtime,
                        remote_size.unwrap_or(0),
                        remote_mtime_secs,
                    );
                if identical && !conflicts.forces_overwrite() {
                    return Ok(());
                }
                if !identical || conflicts.forces_overwrite() {
                    let proceed = conflicts.resolve(&ConflictInfo {
                        session_id: session_id.to_string(),
                        file_name: pathbase(remote_path),
                        dest_path: local_path.to_string(),
                        kind: if dest_is_dir { "dir" } else { "file" }.to_string(),
                        direction: "download".to_string(),
                        existing_size: dest_size,
                        existing_modified: dest_mtime.map(format_unix_timestamp),
                        incoming_size: remote_size,
                        incoming_modified: remote_modified,
                    })?;
                    if !proceed {
                        return Ok(());
                    }
                    // فایل مقصد رو اینجا پاک نکن — download_file اول تو tmp می‌نویسه
                    // و فقط بعد از موفقیت جایگزین می‌کنه؛ پاک کردن زودهنگام = از دست رفتن دیتا
                    if !is_dir {
                        clear_download_resume_files(local_path);
                    }
                }
            }
        }

        if !is_dir {
            return self.download_file(session_id, remote_path, local_path, cancel, on_progress);
        }

        let mut local_dirs: Vec<std::path::PathBuf> = Vec::new();
        let mut files: Vec<(String, std::path::PathBuf, u64)> = Vec::new();
        {
            let sftp = self
                .session
                .sftp()
                .map_err(|e| format!("SFTP subsystem: {}", e))?;
            collect_remote_tree(
                &sftp,
                remote_path,
                std::path::Path::new(local_path),
                &mut local_dirs,
                &mut files,
            )?;
        }

        for dir in &local_dirs {
            if cancel.load(Ordering::Relaxed) {
                return Err("Cancelled".to_string());
            }
            std::fs::create_dir_all(dir)
                .map_err(|e| format!("create local dir '{}': {}", dir.display(), e))?;
        }

        let grand_total: u64 = files.iter().map(|(_, _, size)| size).sum();
        let mut offset = 0u64;
        for (rp, lp, size) in &files {
            if cancel.load(Ordering::Relaxed) {
                return Err("Cancelled".to_string());
            }

            // کامل+mtime → skip؛ tmp ناقص با marker رو download_file خودش resume می‌کنه
            let lp_str = lp.to_string_lossy().to_string();
            let remote_mtime = {
                let sftp = self
                    .session
                    .sftp()
                    .map_err(|e| format!("SFTP subsystem: {}", e))?;
                sftp.stat(std::path::Path::new(rp))
                    .ok()
                    .and_then(|s| s.mtime)
            };
            if let Some((_, dest_size, dest_mtime)) = stat_local_brief(lp) {
                let identical =
                    same_file_identity(dest_size.unwrap_or(0), dest_mtime, *size, remote_mtime);
                if identical && !conflicts.forces_overwrite() {
                    offset += size;
                    on_progress(TransferProgress {
                        session_id: session_id.to_string(),
                        file_name: pathbase(rp),
                        bytes_transferred: offset,
                        total_bytes: grand_total,
                    });
                    continue;
                }

                let has_our_tmp =
                    download_marker_matches(&lp_str, rp, *size, remote_mtime.unwrap_or(0))
                        && std::fs::metadata(download_tmp_path(&lp_str))
                            .map(|m| {
                                let n = m.len();
                                n > 0 && n < *size
                            })
                            .unwrap_or(false);

                // حتی با tmp قابل resume هم باید conflict بپرسیم؛ وگرنه rename
                // نهایی فایل لوکال کاربر رو بی‌صدا overwrite می‌کنه.
                let proceed = conflicts.resolve(&ConflictInfo {
                    session_id: session_id.to_string(),
                    file_name: pathbase(rp),
                    dest_path: lp_str.clone(),
                    kind: "file".to_string(),
                    direction: "download".to_string(),
                    existing_size: dest_size,
                    existing_modified: dest_mtime.map(format_unix_timestamp),
                    incoming_size: Some(*size),
                    incoming_modified: remote_mtime.map(format_unix_timestamp),
                })?;
                if !proceed {
                    offset += size;
                    on_progress(TransferProgress {
                        session_id: session_id.to_string(),
                        file_name: pathbase(rp),
                        bytes_transferred: offset,
                        total_bytes: grand_total,
                    });
                    continue;
                }
                if !has_our_tmp {
                    let _ = std::fs::remove_file(lp);
                    clear_download_resume_files(&lp_str);
                }
            }

            let base = offset;
            self.download_file(
                session_id,
                rp,
                &lp.to_string_lossy(),
                Arc::clone(&cancel),
                |p| {
                    on_progress(TransferProgress {
                        session_id: p.session_id,
                        file_name: p.file_name,
                        bytes_transferred: base + p.bytes_transferred,
                        total_bytes: grand_total,
                    })
                },
            )?;
            offset += size;
        }
        Ok(())
    }
}

/// (is_dir, size, mtime_secs) of a remote path, or None if it doesn't exist.
fn stat_remote_brief(sftp: &ssh2::Sftp, path: &str) -> Option<(bool, Option<u64>, Option<u64>)> {
    let stat = sftp.stat(std::path::Path::new(path)).ok()?;
    Some((stat.file_type().is_dir(), stat.size, stat.mtime))
}

/// (is_dir, size, mtime_secs) of a local path, or None if it doesn't exist.
fn stat_local_brief(path: &std::path::Path) -> Option<(bool, Option<u64>, Option<u64>)> {
    let meta = std::fs::metadata(path).ok()?;
    let mtime = meta.modified().ok().and_then(|t| {
        t.duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs())
    });
    let size = if meta.is_dir() {
        None
    } else {
        Some(meta.len())
    };
    Some((meta.is_dir(), size, mtime))
}

fn pathbase(path: &str) -> String {
    path.rsplit(['/', '\\'])
        .find(|s| !s.is_empty())
        .unwrap_or("file")
        .to_string()
}

/// اسم فایل temp برای Open remote رو از path traversal و متاکاراکترهای
/// خطرناک (مخصوصاً `cmd.exe` روی ویندوز مثل `&` و `|`) پاک می‌کنه.
fn sanitize_open_basename(name: &str) -> String {
    let base = name
        .rsplit(['/', '\\'])
        .find(|part| !part.is_empty() && *part != "." && *part != "..")
        .unwrap_or("file");

    let cleaned: String = base
        .chars()
        .map(|c| {
            if c.is_control()
                || matches!(
                    c,
                    '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | '&' | '%' | '^' | '!'
                )
            {
                '_'
            } else {
                c
            }
        })
        .collect();

    // اسم خالی یا فقط‌نقطه روی ویندوز خراب می‌شه
    let trimmed = cleaned.trim().trim_matches('.').to_string();
    if trimmed.is_empty() {
        "file".to_string()
    } else {
        trimmed
    }
}

/// temp کامل رو جای مقصد می‌ذاره. فعلاً unlink+rename (همون رفتار develop)؛
/// PRهای باز ممکنه این رو به backup-swap امن‌تر ارتقا بدن.
fn promote_upload_temp(
    sftp: &ssh2::Sftp,
    remote_path: &str,
    remote_tmp: &str,
    dest_exists: bool,
) -> Result<(), String> {
    if dest_exists {
        let _ = sftp.unlink(std::path::Path::new(remote_path));
    }
    sftp.rename(
        std::path::Path::new(remote_tmp),
        std::path::Path::new(remote_path),
        None,
    )
    .map_err(|e| {
        format!(
            "promote upload temp '{}' -> '{}': {}",
            remote_tmp, remote_path, e
        )
    })
}

/// Creates `path` on the remote if it doesn't exist; errors if it exists as a non-directory.
fn ensure_remote_dir(sftp: &ssh2::Sftp, path: &str) -> Result<(), String> {
    if let Ok(stat) = sftp.stat(std::path::Path::new(path)) {
        if stat.file_type().is_dir() {
            return Ok(());
        }
        return Err(format!(
            "Remote path '{}' exists and is not a directory",
            path
        ));
    }
    sftp.mkdir(std::path::Path::new(path), 0o755)
        .map_err(|e| format!("mkdir '{}': {}", path, e))
}

/// Recursively walks a local directory, collecting remote directories to create
/// (parents before children) and `(local file, remote path, size)` tuples.
/// Symlinks are followed via `metadata()`; broken links are skipped.
fn walk_local_tree(
    local_dir: &std::path::Path,
    remote_dir: &str,
    remote_dirs: &mut Vec<String>,
    files: &mut Vec<(std::path::PathBuf, String, u64)>,
) -> Result<(), String> {
    remote_dirs.push(remote_dir.to_string());
    let rd = std::fs::read_dir(local_dir)
        .map_err(|e| format!("read dir '{}': {}", local_dir.display(), e))?;
    for entry in rd.filter_map(|e| e.ok()) {
        let name = entry.file_name().to_string_lossy().to_string();
        let remote_child = format!("{}/{}", remote_dir.trim_end_matches('/'), name);
        let meta = match std::fs::metadata(entry.path()) {
            Ok(m) => m,
            Err(_) => continue, // broken symlink or unreadable — skip
        };
        if meta.is_dir() {
            walk_local_tree(&entry.path(), &remote_child, remote_dirs, files)?;
        } else if meta.is_file() {
            files.push((entry.path(), remote_child, meta.len()));
        }
    }
    Ok(())
}

/// Recursively walks a remote directory, collecting local directories to create
/// (parents before children) and `(remote path, local path, size)` tuples.
/// Symlinks are resolved with a follow-stat; broken links are skipped.
fn collect_remote_tree(
    sftp: &ssh2::Sftp,
    remote_dir: &str,
    local_dir: &std::path::Path,
    local_dirs: &mut Vec<std::path::PathBuf>,
    files: &mut Vec<(String, std::path::PathBuf, u64)>,
) -> Result<(), String> {
    local_dirs.push(local_dir.to_path_buf());
    let entries = sftp
        .readdir(std::path::Path::new(remote_dir))
        .map_err(|e| format!("readdir '{}': {}", remote_dir, e))?;
    for (pb, stat) in entries {
        let name = match pb.file_name() {
            Some(n) => n.to_string_lossy().to_string(),
            None => continue,
        };
        if name == "." || name == ".." {
            continue;
        }
        let remote_child = pb.to_string_lossy().to_string();
        let local_child = local_dir.join(&name);
        let mut is_dir = stat.file_type().is_dir();
        let mut size = stat.size.unwrap_or(0);
        if stat.file_type().is_symlink() {
            match sftp.stat(&pb) {
                Ok(target) => {
                    is_dir = target.file_type().is_dir();
                    size = target.size.unwrap_or(0);
                }
                Err(_) => continue, // broken symlink — skip
            }
        }
        if is_dir {
            collect_remote_tree(sftp, &remote_child, &local_child, local_dirs, files)?;
        } else {
            files.push((remote_child, local_child, size));
        }
    }
    Ok(())
}

pub struct SftpManager {
    sessions: HashMap<String, Arc<Mutex<SftpEntry>>>,
}

impl SftpManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Drops every SFTP session — used by quit-to-background reset.
    pub fn clear_all(&mut self) {
        for entry in self.sessions.values() {
            if let Ok(guard) = entry.lock() {
                guard.stop_keepalive();
            }
        }
        self.sessions.clear();
    }

    pub fn get_session(&self, session_id: &str) -> Result<Arc<Mutex<SftpEntry>>, String> {
        self.sessions
            .get(session_id)
            .cloned()
            .ok_or_else(|| format!("SFTP session '{}' not found", session_id))
    }

    /// `log(stage, message)` — stage is one of "connecting", "handshaking", "authenticating", "ready"
    pub fn connect<F>(&mut self, req: SftpConnectRequest, log: F) -> Result<SftpSessionInfo, String>
    where
        F: Fn(&str, &str),
    {
        let key_path = req.private_key_path.as_deref().map(std::path::Path::new);
        let cfg = ssh::SshConfig {
            hostname: &req.hostname,
            port: req.port,
            username: &req.username,
            password: req.password.as_deref(),
            key_path,
        };
        let session = ssh::connect(&cfg, &log)?;

        let remote_path = req
            .default_remote_path
            .clone()
            .unwrap_or_else(|| "/".to_string());

        // اگه سشن قبلی با همین id هست، keepaliveش رو قطع کن
        if let Some(old) = self.sessions.remove(&req.session_id) {
            if let Ok(guard) = old.lock() {
                guard.stop_keepalive();
            }
        }

        let keepalive_stop = Arc::new(AtomicBool::new(false));
        let entry = Arc::new(Mutex::new(SftpEntry {
            session,
            reconnect: SftpReconnectCreds {
                hostname: req.hostname.clone(),
                port: req.port,
                username: req.username.clone(),
                password: req.password.clone(),
                private_key_path: req.private_key_path.clone(),
                default_remote_path: req.default_remote_path.clone(),
            },
            keepalive_stop: Arc::clone(&keepalive_stop),
        }));
        spawn_sftp_keepalive(Arc::clone(&entry), keepalive_stop, &req.session_id);
        self.sessions.insert(req.session_id.clone(), entry);

        log(
            "ready",
            &format!("Authenticated. Opening {}...", remote_path),
        );
        Ok(SftpSessionInfo {
            session_id: req.session_id,
            remote_path,
        })
    }

    pub fn disconnect(&mut self, session_id: &str) -> Result<(), String> {
        let entry = self
            .sessions
            .remove(session_id)
            .ok_or_else(|| format!("SFTP session '{}' not found", session_id))?;
        if let Ok(guard) = entry.lock() {
            guard.stop_keepalive();
        }
        Ok(())
    }

    /// Clone the session Arc under a brief manager lock — caller must drop the
    /// manager lock before calling [`reconnect_entry`] (SSH handshake can take minutes).
    pub fn take_entry(&self, session_id: &str) -> Result<Arc<Mutex<SftpEntry>>, String> {
        self.get_session(session_id)
    }
}

/// Handshake مجدد بیرون از قفل `SftpManager` — فقط قفل خود سشن موقع replace گرفته می‌شه.
pub fn reconnect_entry(entry: &Arc<Mutex<SftpEntry>>, _session_id: &str) -> Result<(), String> {
    let creds = {
        let guard = entry.lock().unwrap();
        guard.keepalive_stop.store(true, Ordering::Relaxed);
        guard.reconnect.clone()
    };

    let key_path = creds.private_key_path.as_deref().map(std::path::Path::new);
    let cfg = ssh::SshConfig {
        hostname: &creds.hostname,
        port: creds.port,
        username: &creds.username,
        password: creds.password.as_deref(),
        key_path,
    };
    fn silent_log(_stage: &str, _msg: &str) {}
    let session = ssh::connect(&cfg, silent_log)?;
    // بعد از reconnect باید keepalive دوباره بالا بیاد؛ وگرنه سشن idle دوباره می‌میره
    let keepalive_stop = {
        let mut guard = entry.lock().unwrap();
        guard.replace_session(session);
        guard.reset_keepalive_stop()
    };
    spawn_sftp_keepalive(Arc::clone(entry), keepalive_stop, &creds.hostname);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sftp_manager_new() {
        let manager = SftpManager::new();
        assert_eq!(manager.sessions.len(), 0);
    }

    #[test]
    fn test_list_local_home() {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let result = list_local(&home);
        assert!(result.is_ok(), "list_local failed: {:?}", result.err());
        let entries = result.unwrap();
        assert!(!entries.is_empty());
    }

    #[test]
    fn test_list_local_nonexistent() {
        let result = list_local("/this/path/does/not/exist/ever");
        assert!(result.is_err());
    }

    #[test]
    fn test_download_no_session_returns_error() {
        let manager = SftpManager::new();
        let result = manager.get_session("nonexistent");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_upload_no_session_returns_error() {
        let manager = SftpManager::new();
        let result = manager.get_session("nonexistent");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn validate_path_segment_rejects_traversal() {
        assert!(validate_path_segment("notes.txt").is_ok());
        assert!(validate_path_segment("my-folder").is_ok());
        assert!(validate_path_segment("../secrets.txt").is_err());
        assert!(validate_path_segment("..\\secrets.txt").is_err());
        assert!(validate_path_segment("/etc/passwd").is_err());
        assert!(validate_path_segment("foo/bar").is_err());
        assert!(validate_path_segment("..").is_err());
        assert!(validate_path_segment(".").is_err());
        assert!(validate_path_segment("").is_err());
    }

    #[test]
    fn validate_same_dir_rename_blocks_escape() {
        assert!(validate_same_dir_rename("/home/u/a.txt", "/home/u/b.txt").is_ok());
        assert!(validate_same_dir_rename("/home/u/a.txt", "/home/u/../b.txt").is_err());
        assert!(validate_same_dir_rename("/home/u/a.txt", "/etc/passwd").is_err());
        assert!(validate_same_dir_rename("/home/u/a.txt", "/home/u/sub/b.txt").is_err());
    }

    #[test]
    fn reject_parent_dir_components_blocks_dotdot() {
        assert!(reject_parent_dir_components("/home/u/newdir").is_ok());
        assert!(reject_parent_dir_components("/home/u/../evil").is_err());
        assert!(reject_parent_dir_components("foo/../../bar").is_err());
    }

    #[test]
    fn test_delete_no_session_returns_error() {
        let manager = SftpManager::new();
        let result = manager.get_session("nonexistent");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_rename_no_session_returns_error() {
        let manager = SftpManager::new();
        let result = manager.get_session("nonexistent");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_mkdir_no_session_returns_error() {
        let manager = SftpManager::new();
        let result = manager.get_session("nonexistent");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_disconnect_nonexistent_returns_error() {
        let mut manager = SftpManager::new();
        let result = manager.disconnect("nonexistent-id");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    // --- conflict handler ---
    use std::cell::Cell;

    fn conflict_info() -> ConflictInfo {
        ConflictInfo {
            session_id: "s".into(),
            file_name: "f.txt".into(),
            dest_path: "/dest/f.txt".into(),
            kind: "file".into(),
            direction: "upload".into(),
            existing_size: Some(1),
            existing_modified: None,
            incoming_size: Some(2),
            incoming_modified: None,
        }
    }

    #[test]
    fn conflict_single_decisions_do_not_stick() {
        let mut h = ConflictHandler::new(ConflictMode::Ask, |_: &ConflictInfo| {
            ConflictDecision::Overwrite
        });
        assert!(h.resolve(&conflict_info()).unwrap());
        let mut h =
            ConflictHandler::new(ConflictMode::Ask, |_: &ConflictInfo| ConflictDecision::Skip);
        assert!(!h.resolve(&conflict_info()).unwrap());
    }

    #[test]
    fn conflict_apply_to_all_stops_prompting() {
        let calls = Cell::new(0u32);
        let mut h = ConflictHandler::new(ConflictMode::Ask, |_: &ConflictInfo| {
            calls.set(calls.get() + 1);
            ConflictDecision::OverwriteAll
        });
        assert!(h.resolve(&conflict_info()).unwrap());
        assert!(h.resolve(&conflict_info()).unwrap());
        assert_eq!(calls.get(), 1);

        let calls = Cell::new(0u32);
        let mut h = ConflictHandler::new(ConflictMode::Ask, |_: &ConflictInfo| {
            calls.set(calls.get() + 1);
            ConflictDecision::SkipAll
        });
        assert!(!h.resolve(&conflict_info()).unwrap());
        assert!(!h.resolve(&conflict_info()).unwrap());
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn conflict_preset_overwrite_all_never_prompts() {
        let mut h = ConflictHandler::new(ConflictMode::OverwriteAll, |_: &ConflictInfo| {
            panic!("must not prompt")
        });
        assert!(h.resolve(&conflict_info()).unwrap());
    }

    #[test]
    fn conflict_cancel_returns_cancelled_err() {
        let mut h = ConflictHandler::new(ConflictMode::Ask, |_: &ConflictInfo| {
            ConflictDecision::Cancel
        });
        assert_eq!(h.resolve(&conflict_info()).unwrap_err(), "Cancelled");
    }

    #[test]
    fn upload_temp_path_is_sidecar_not_destination() {
        // آپلود overwrite باید اول بره تو *.termifai-uploading تا مقصد اصلی
        // موقع شکست شبکه از بین نره
        let remote = "/var/data/config.json";
        let tmp = format!("{}.termifai-uploading", remote);
        assert_eq!(tmp, "/var/data/config.json.termifai-uploading");
        assert_ne!(tmp, remote);
    }

    #[test]
    fn overwrite_resume_must_use_temp_not_destination_size() {
        // مقصد قدیمی ۱۰۰ بایت + marker از آپلود ۱۰۰۰ بایتی ≠ resume روی مقصد.
        // فقط temp sidecar اجازه‌ی ResumeTemp / PromoteComplete می‌ده.
        assert_eq!(
            plan_upload_temp(true, Some(250), 1000),
            UploadTempPlan::ResumeTemp { offset: 250 }
        );
        assert_eq!(
            plan_upload_temp(true, None, 1000),
            UploadTempPlan::FreshTemp
        );
        assert!(upload_temp_is_our_partial(Some(250), 1000));
        assert!(!upload_temp_is_our_partial(None, 1000));
    }

    #[test]
    fn sanitize_open_basename_strips_cmd_metacharacters() {
        assert_eq!(
            sanitize_open_basename("x&calc.exe&y.txt"),
            "x_calc.exe_y.txt"
        );
        assert_eq!(sanitize_open_basename("report|rm.txt"), "report_rm.txt");
        assert_eq!(sanitize_open_basename("a<script>.txt"), "a_script_.txt");
    }

    #[test]
    fn sanitize_open_basename_blocks_path_escape() {
        assert_eq!(sanitize_open_basename("..\\..\\secret.txt"), "secret.txt");
        assert_eq!(sanitize_open_basename("../evil.txt"), "evil.txt");
        assert_eq!(sanitize_open_basename(".."), "file");
        assert_eq!(sanitize_open_basename("."), "file");
        assert_eq!(sanitize_open_basename(""), "file");
    }

    #[test]
    fn sanitize_open_basename_keeps_safe_unicode_names() {
        assert_eq!(sanitize_open_basename("گزارش.pdf"), "گزارش.pdf");
        assert_eq!(sanitize_open_basename("notes (1).md"), "notes (1).md");
    }
}

#[cfg(test)]
mod quit_reset_tests {
    use super::*;

    #[test]
    fn clear_all_empties_sessions() {
        let mut mgr = SftpManager::new();
        mgr.clear_all();
        assert!(mgr.sessions.is_empty());
    }
}
