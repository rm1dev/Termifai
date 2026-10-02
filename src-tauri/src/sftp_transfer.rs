//! SFTP transfer engine helpers: retry classification, backoff, status events, markers.
//!
//! هویت resume با marker کنار فایل انجام می‌شه؛ I/O واقعی هنوز تو `sftp.rs` می‌مونه.

use serde::Serialize;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

/// Max automatic reconnect attempts before pausing for manual Resume.
pub const MAX_RECONNECT_ATTEMPTS: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferStatusKind {
    Idle,
    Transferring,
    Reconnecting,
    Resuming,
    Paused,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransferStatusEvent {
    pub status: TransferStatusKind,
    pub message: String,
    pub attempt: Option<u32>,
    pub max_attempts: Option<u32>,
}

/// صف صریح برای فازهای بعدی / تست؛ فاز ۱ با skip/resume داخل path I/O پوشش داده شده.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    Pending,
    Active,
    Paused,
    Done,
    Failed,
    Skipped,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    Upload,
    Download,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct TransferJob {
    pub id: String,
    pub direction: TransferDirection,
    pub local_path: String,
    pub remote_path: String,
    pub total_bytes: u64,
    pub bytes_done: u64,
    pub state: JobState,
    pub error: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct TransferQueue {
    jobs: VecDeque<TransferJob>,
}

#[allow(dead_code)]
impl TransferQueue {
    pub fn new() -> Self {
        Self {
            jobs: VecDeque::new(),
        }
    }

    pub fn push(&mut self, job: TransferJob) {
        self.jobs.push_back(job);
    }

    pub fn len(&self) -> usize {
        self.jobs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }

    pub fn clear(&mut self) {
        self.jobs.clear();
    }

    /// First job that is Pending or Paused (for resume after reconnect).
    pub fn next_actionable_mut(&mut self) -> Option<&mut TransferJob> {
        self.jobs.iter_mut().find(|j| {
            matches!(
                j.state,
                JobState::Pending | JobState::Paused | JobState::Active
            )
        })
    }

    pub fn pending_count(&self) -> usize {
        self.jobs
            .iter()
            .filter(|j| {
                matches!(
                    j.state,
                    JobState::Pending | JobState::Paused | JobState::Active
                )
            })
            .count()
    }

    /// Mark current active/paused job paused with error; leave other pending jobs intact.
    pub fn pause_active(&mut self, error: &str) {
        for job in self.jobs.iter_mut() {
            if matches!(job.state, JobState::Active | JobState::Paused) {
                job.state = JobState::Paused;
                job.error = Some(error.to_string());
                break;
            }
        }
    }

    pub fn mark_active_done(&mut self) {
        if let Some(job) = self
            .jobs
            .iter_mut()
            .find(|j| matches!(j.state, JobState::Active | JobState::Paused))
        {
            job.state = JobState::Done;
            job.bytes_done = job.total_bytes;
            job.error = None;
        }
    }
}

/// Atomically claims the single in-flight transfer slot for a session.
/// A second claim while the first is still registered fails — cancel/done
/// events are keyed only by `session_id`, so overlapping transfers corrupt state.
pub fn claim_transfer_slot(
    flags: &mut HashMap<String, Arc<AtomicBool>>,
    session_id: &str,
) -> Result<Arc<AtomicBool>, String> {
    match flags.entry(session_id.to_string()) {
        Entry::Occupied(_) => Err("A transfer is already in progress for this session".to_string()),
        Entry::Vacant(slot) => {
            let flag = Arc::new(AtomicBool::new(false));
            slot.insert(Arc::clone(&flag));
            Ok(flag)
        }
    }
}

/// Backoff delays: 1, 2, 4, 8, 16 seconds (attempt is 1-based).
pub fn backoff_delay_secs(attempt: u32) -> u64 {
    match attempt {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        4 => 8,
        _ => 16,
    }
}

/// Typed classification — از substring روی path کاربر دوری می‌کنیم.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferErrorClass {
    Cancelled,
    Permanent,
    Retryable,
}

/// Heuristic روی پیام‌های خودمون: transport = Retryable؛ auth/path/cancel = Permanent.
pub fn classify_transfer_error(msg: &str) -> TransferErrorClass {
    let trimmed = msg.trim();
    let lower = trimmed.to_ascii_lowercase();

    if lower == "cancelled"
        || lower == "canceled"
        || lower.starts_with("cancelled")
        || lower.starts_with("canceled")
    {
        return TransferErrorClass::Cancelled;
    }

    // دائم — اول چک می‌شن تا path حاوی کلمه‌های شبکه گول‌مون نزنه
    const PERMANENT: &[&str] = &[
        "permission denied",
        "no such file",
        "not found",
        "host key",
        "not authenticated",
        "authentication failed",
        "auth failed",
        "key auth",
        "password auth",
        "agent auth",
        "disk quota",
        "no space",
        "file too large",
        "is a directory",
        "not a directory",
        "already exists",
    ];
    for needle in PERMANENT {
        if lower.contains(needle) {
            return TransferErrorClass::Permanent;
        }
    }
    // «auth»Alone خطرناکه (مثلاً path)؛ فقط با کنتکست مشخص
    if lower.contains("authentication") {
        return TransferErrorClass::Permanent;
    }

    // شبکه‌ای — فقط عبارات مشخص، نه «session»/«channel»/«socket» لخت
    const RETRYABLE: &[&str] = &[
        "timed out",
        "timeout",
        "connection reset",
        "broken pipe",
        "connection refused",
        "network is unreachable",
        "no route to host",
        "connection aborted",
        "sftp subsystem",
        "failed receiving",
        "failed sending",
        "would block",
        "tcp connect",
        "ssh handshake",
        "ssh session init",
        "channel open",
        "read channel",
        "connection closed",
        "connection lost",
        "software caused connection abort",
        "unable to startup channel",
    ];
    for needle in RETRYABLE {
        if lower.contains(needle) {
            return TransferErrorClass::Retryable;
        }
    }
    // EOF تنها وقتی پیام کوتاه/واضحه، نه داخل path
    if lower == "eof" || lower.ends_with(": eof") || lower.contains("unexpected eof") {
        return TransferErrorClass::Retryable;
    }

    TransferErrorClass::Permanent
}

pub fn is_retryable_network_error(msg: &str) -> bool {
    classify_transfer_error(msg) == TransferErrorClass::Retryable
}

// ─── Download resume identity (marker کنار tmp) ─────────────────────────────

pub fn download_tmp_path(local_path: &str) -> String {
    format!("{local_path}.termifai_dl_tmp")
}

pub fn download_marker_path(local_path: &str) -> String {
    format!("{local_path}.termifai_dl_tmp.meta")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadMarker {
    pub remote_path: String,
    pub remote_size: u64,
    pub remote_mtime: u64,
}

pub fn write_download_marker(local_path: &str, marker: &DownloadMarker) -> Result<(), String> {
    let body = format!(
        "v1\n{}\n{}\n{}\n",
        marker.remote_path, marker.remote_size, marker.remote_mtime
    );
    std::fs::write(download_marker_path(local_path), body)
        .map_err(|e| format!("write download marker: {e}"))
}

pub fn read_download_marker(local_path: &str) -> Option<DownloadMarker> {
    let raw = std::fs::read_to_string(download_marker_path(local_path)).ok()?;
    let mut lines = raw.lines();
    if lines.next()? != "v1" {
        return None;
    }
    let remote_path = lines.next()?.to_string();
    let remote_size = lines.next()?.parse().ok()?;
    let remote_mtime = lines.next()?.parse().ok()?;
    Some(DownloadMarker {
        remote_path,
        remote_size,
        remote_mtime,
    })
}

pub fn download_marker_matches(
    local_path: &str,
    remote_path: &str,
    remote_size: u64,
    remote_mtime: u64,
) -> bool {
    match read_download_marker(local_path) {
        Some(m) => {
            m.remote_path == remote_path
                && m.remote_size == remote_size
                && m.remote_mtime == remote_mtime
        }
        None => false,
    }
}

pub fn clear_download_resume_files(local_path: &str) {
    let _ = std::fs::remove_file(download_tmp_path(local_path));
    let _ = std::fs::remove_file(download_marker_path(local_path));
}

/// Decide download resume offset from tmp file size vs expected total.
/// Returns `Some(offset)` to resume, `None` to start from zero (truncate/recreate tmp).
pub fn download_resume_offset(tmp_len: Option<u64>, total_bytes: u64) -> Option<u64> {
    match tmp_len {
        Some(n) if n > 0 && n < total_bytes => Some(n),
        Some(n) if n == total_bytes && total_bytes > 0 => Some(n), // already complete
        _ => None,
    }
}

/// Resume فقط وقتی هویت marker با ریموت فعلی یکی باشه.
pub fn download_resume_offset_verified(
    tmp_len: Option<u64>,
    total_bytes: u64,
    identity_ok: bool,
) -> Option<u64> {
    if !identity_ok {
        return None;
    }
    download_resume_offset(tmp_len, total_bytes)
}

// ─── Upload resume identity (marker کنار فایل لوکال) ────────────────────────

pub fn upload_marker_path(local_path: &str) -> PathBuf {
    PathBuf::from(format!("{local_path}.termifai_up_meta"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadMarker {
    pub remote_path: String,
    pub local_size: u64,
    pub local_mtime: u64,
}

pub fn write_upload_marker(local_path: &str, marker: &UploadMarker) -> Result<(), String> {
    let body = format!(
        "v1\n{}\n{}\n{}\n",
        marker.remote_path, marker.local_size, marker.local_mtime
    );
    if let Some(parent) = Path::new(local_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(upload_marker_path(local_path), body)
        .map_err(|e| format!("write upload marker: {e}"))
}

pub fn read_upload_marker(local_path: &str) -> Option<UploadMarker> {
    let raw = std::fs::read_to_string(upload_marker_path(local_path)).ok()?;
    let mut lines = raw.lines();
    if lines.next()? != "v1" {
        return None;
    }
    let remote_path = lines.next()?.to_string();
    let local_size = lines.next()?.parse().ok()?;
    let local_mtime = lines.next()?.parse().ok()?;
    Some(UploadMarker {
        remote_path,
        local_size,
        local_mtime,
    })
}

pub fn upload_marker_matches(
    local_path: &str,
    remote_path: &str,
    local_size: u64,
    local_mtime: u64,
) -> bool {
    match read_upload_marker(local_path) {
        Some(m) => {
            m.remote_path == remote_path
                && m.local_size == local_size
                && m.local_mtime == local_mtime
        }
        None => false,
    }
}

pub fn clear_upload_marker(local_path: &str) {
    let _ = std::fs::remove_file(upload_marker_path(local_path));
}

/// Decide upload resume offset from remote size vs local total.
/// `Some(offset)` resume append; `None` overwrite from zero.
pub fn upload_resume_offset(remote_len: Option<u64>, total_bytes: u64) -> Option<u64> {
    match remote_len {
        Some(n) if n > 0 && n < total_bytes => Some(n),
        Some(n) if n == total_bytes && total_bytes > 0 => Some(n),
        _ => None,
    }
}

/// Resume آپلود فقط با marker معتبر (جلوگیری از append روی فایل ریموت غریبه).
pub fn upload_resume_offset_verified(
    remote_len: Option<u64>,
    total_bytes: u64,
    identity_ok: bool,
) -> Option<u64> {
    if !identity_ok {
        return None;
    }
    upload_resume_offset(remote_len, total_bytes)
}

/// برنامه‌ی ادامه‌ی آپلود روی `.termifai-uploading` — هیچ‌وقت سایز مقصد نهایی
/// رو به‌عنوان resume offset استفاده نکن (مقصد ممکنه هنوز فایل قدیمی overwrite باشه).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadTempPlan {
    /// temp کامل نوشته شده؛ فقط promote کن.
    PromoteComplete,
    /// به temp ناقص از این offset ادامه بده.
    ResumeTemp { offset: u64 },
    /// temp قبلی رو دور بریز و از صفر بنویس.
    FreshTemp,
}

pub fn plan_upload_temp(
    identity_ok: bool,
    tmp_len: Option<u64>,
    total_bytes: u64,
) -> UploadTempPlan {
    if !identity_ok {
        return UploadTempPlan::FreshTemp;
    }
    match tmp_len {
        Some(n) if n == total_bytes => UploadTempPlan::PromoteComplete,
        Some(n) if n > 0 && n < total_bytes => UploadTempPlan::ResumeTemp { offset: n },
        _ => UploadTempPlan::FreshTemp,
    }
}

/// سایز sidecar آپلود (نه مقصد) نشون می‌ده این ادامه‌ی transfer خودمونه.
pub fn upload_temp_is_our_partial(tmp_len: Option<u64>, total_bytes: u64) -> bool {
    matches!(
        plan_upload_temp(true, tmp_len, total_bytes),
        UploadTempPlan::PromoteComplete | UploadTempPlan::ResumeTemp { .. }
    )
}

/// فایل هم‌اندازه فقط وقتی mtime هم بخونه «کامل» حساب می‌شه.
pub fn same_file_identity(
    size_a: u64,
    mtime_a: Option<u64>,
    size_b: u64,
    mtime_b: Option<u64>,
) -> bool {
    size_a == size_b && mtime_a.is_some() && mtime_a == mtime_b
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn retryable_detects_socket_and_timeout_errors() {
        assert!(is_retryable_network_error("Timed out waiting on socket"));
        assert!(is_retryable_network_error("Connection reset by peer"));
        assert!(is_retryable_network_error("Broken pipe"));
        assert!(is_retryable_network_error("SFTP subsystem: channel closed"));
        assert!(is_retryable_network_error("failed receiving channel data"));
        assert!(is_retryable_network_error(
            "TCP connect to host: Connection refused"
        ));
        assert!(is_retryable_network_error(
            "SFTP subsystem: [Session(-21)] Unable to startup channel"
        ));
    }

    #[test]
    fn non_retryable_for_cancel_auth_and_path() {
        assert!(!is_retryable_network_error("Cancelled"));
        assert!(!is_retryable_network_error("Permission denied"));
        assert!(!is_retryable_network_error("stat '/x': No such file"));
        assert!(!is_retryable_network_error("Host key mismatch"));
        assert!(!is_retryable_network_error("Key auth failed: bad key"));
    }

    #[test]
    fn path_containing_session_does_not_become_retryable() {
        assert_eq!(
            classify_transfer_error("create remote '/var/lib/session/data': Disk quota exceeded"),
            TransferErrorClass::Permanent
        );
        assert_eq!(
            classify_transfer_error("write remote '/home/session/x': unexpected failure"),
            TransferErrorClass::Permanent
        );
        assert!(!is_retryable_network_error(
            "open remote '/opt/session/app.bin': File too large"
        ));
    }

    #[test]
    fn backoff_schedule_matches_spec() {
        assert_eq!(backoff_delay_secs(1), 1);
        assert_eq!(backoff_delay_secs(2), 2);
        assert_eq!(backoff_delay_secs(3), 4);
        assert_eq!(backoff_delay_secs(4), 8);
        assert_eq!(backoff_delay_secs(5), 16);
        assert_eq!(backoff_delay_secs(6), 16);
    }

    #[test]
    fn download_resume_offset_rules() {
        assert_eq!(download_resume_offset(None, 1000), None);
        assert_eq!(download_resume_offset(Some(0), 1000), None);
        assert_eq!(download_resume_offset(Some(400), 1000), Some(400));
        assert_eq!(download_resume_offset(Some(1000), 1000), Some(1000));
        assert_eq!(download_resume_offset(Some(1200), 1000), None);
    }

    #[test]
    fn download_resume_requires_identity() {
        assert_eq!(
            download_resume_offset_verified(Some(400), 1000, false),
            None
        );
        assert_eq!(
            download_resume_offset_verified(Some(400), 1000, true),
            Some(400)
        );
    }

    #[test]
    fn upload_resume_offset_rules() {
        assert_eq!(upload_resume_offset(None, 500), None);
        assert_eq!(upload_resume_offset(Some(200), 500), Some(200));
        assert_eq!(upload_resume_offset(Some(500), 500), Some(500));
        assert_eq!(upload_resume_offset(Some(600), 500), None);
    }

    #[test]
    fn upload_resume_requires_identity() {
        assert_eq!(upload_resume_offset_verified(Some(200), 500, false), None);
        assert_eq!(
            upload_resume_offset_verified(Some(200), 500, true),
            Some(200)
        );
    }

    #[test]
    fn upload_temp_plan_ignores_destination_sized_partials() {
        // Crash mid-overwrite: dest still holds the old smaller file, temp has
        // the real partial. Planning must key off temp — never dest length.
        let dest_looks_partial = Some(100u64); // old remote size
        let tmp_partial = Some(40u64);
        let total = 1000u64;
        assert_eq!(
            plan_upload_temp(true, tmp_partial, total),
            UploadTempPlan::ResumeTemp { offset: 40 }
        );
        // Even if someone mistakenly passed dest size as tmp_len with no temp,
        // FreshTemp when identity is false; with identity+no temp → FreshTemp.
        assert_eq!(
            plan_upload_temp(true, None, total),
            UploadTempPlan::FreshTemp
        );
        let _ = dest_looks_partial;
        assert_eq!(
            plan_upload_temp(true, Some(total), total),
            UploadTempPlan::PromoteComplete
        );
        assert_eq!(
            plan_upload_temp(false, tmp_partial, total),
            UploadTempPlan::FreshTemp
        );
        assert!(upload_temp_is_our_partial(Some(40), 1000));
        assert!(upload_temp_is_our_partial(Some(1000), 1000));
        assert!(!upload_temp_is_our_partial(None, 1000));
        assert!(!upload_temp_is_our_partial(Some(0), 1000));
    }

    #[test]
    fn download_marker_roundtrip_and_match() {
        let dir = std::env::temp_dir().join(format!(
            "termifai_dl_marker_test_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let local = dir.join("file.bin").to_string_lossy().to_string();
        let marker = DownloadMarker {
            remote_path: "/r/file.bin".into(),
            remote_size: 1000,
            remote_mtime: 42,
        };
        write_download_marker(&local, &marker).unwrap();
        assert!(download_marker_matches(&local, "/r/file.bin", 1000, 42));
        assert!(!download_marker_matches(&local, "/r/other.bin", 1000, 42));
        assert!(!download_marker_matches(&local, "/r/file.bin", 999, 42));
        clear_download_resume_files(&local);
        assert!(read_download_marker(&local).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn upload_marker_roundtrip_and_match() {
        let dir = std::env::temp_dir().join(format!(
            "termifai_up_marker_test_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let local = dir.join("file.bin").to_string_lossy().to_string();
        let marker = UploadMarker {
            remote_path: "/r/file.bin".into(),
            local_size: 500,
            local_mtime: 99,
        };
        write_upload_marker(&local, &marker).unwrap();
        assert!(upload_marker_matches(&local, "/r/file.bin", 500, 99));
        assert!(!upload_marker_matches(&local, "/r/file.bin", 500, 100));
        clear_upload_marker(&local);
        assert!(read_upload_marker(&local).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn same_file_identity_needs_mtime() {
        assert!(same_file_identity(10, Some(1), 10, Some(1)));
        assert!(!same_file_identity(10, Some(1), 10, Some(2)));
        assert!(!same_file_identity(10, None, 10, Some(1)));
        assert!(!same_file_identity(10, Some(1), 11, Some(1)));
    }

    #[test]
    fn claim_transfer_slot_rejects_second_claim() {
        let mut flags = HashMap::new();
        let first = claim_transfer_slot(&mut flags, "sess-1").unwrap();
        assert!(!first.load(std::sync::atomic::Ordering::Relaxed));
        let err = claim_transfer_slot(&mut flags, "sess-1").unwrap_err();
        assert!(err.contains("already in progress"));
        // سشن دیگه آزاد باشه
        assert!(claim_transfer_slot(&mut flags, "sess-2").is_ok());
        flags.remove("sess-1");
        assert!(claim_transfer_slot(&mut flags, "sess-1").is_ok());
    }

    #[test]
    fn queue_pause_keeps_pending_jobs() {
        let mut q = TransferQueue::new();
        q.push(TransferJob {
            id: "1".into(),
            direction: TransferDirection::Download,
            local_path: "/a".into(),
            remote_path: "/r/a".into(),
            total_bytes: 10,
            bytes_done: 4,
            state: JobState::Active,
            error: None,
        });
        q.push(TransferJob {
            id: "2".into(),
            direction: TransferDirection::Download,
            local_path: "/b".into(),
            remote_path: "/r/b".into(),
            total_bytes: 20,
            bytes_done: 0,
            state: JobState::Pending,
            error: None,
        });
        q.pause_active("socket timeout");
        assert_eq!(q.jobs[0].state, JobState::Paused);
        assert_eq!(q.jobs[0].bytes_done, 4);
        assert_eq!(q.jobs[1].state, JobState::Pending);
        assert_eq!(q.pending_count(), 2);
    }
}
