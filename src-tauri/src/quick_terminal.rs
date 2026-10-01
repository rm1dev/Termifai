//! Quick Terminal: a Quake-style slide-in terminal panel on a dedicated,
//! non-draggable, non-resizable window anchored to a screen edge.
//!
//! The native window is never animated or resized by the OS; the slide
//! animation runs inside the webview (CSS transforms) and resizing happens
//! only through an in-panel drag handle that calls `resize_quick_terminal`.
//! See docs/quick-terminal-plan.md for the full design, including why this is
//! best-effort on Linux/Wayland (xdg-shell offers no toplevel positioning).
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use tauri::{AppHandle, Emitter, Manager, PhysicalPosition, PhysicalSize};

pub const WINDOW_LABEL: &str = "quick-terminal";

/// Minimum panel size in logical pixels for the resizable dimension.
const MIN_SIZE_LOGICAL: f64 = 200.0;

/// Slide animation length. The *native window* is animated (not the HTML):
/// the window carries a native backdrop-blur layer that fills its whole rect
/// the moment it's shown, so a CSS slide inside a static window would reveal
/// that blur rectangle instantly.
const SLIDE_DURATION_MS: u64 = 180;
const SLIDE_STEPS: u32 = 12;

/// Bumped to cancel any in-flight slide (new toggle, resize, disable).
static SLIDE_GENERATION: AtomicU64 = AtomicU64::new(0);

/// Logical panel state for toggling. Distinct from `is_visible`: on macOS the
/// native window intentionally stays ordered-in (off-screen) for a moment
/// after a hide while focus is handed back to the previous app, so window
/// visibility alone would misroute a quick re-toggle.
static PANEL_SHOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// On macOS, hiding the key quick-terminal window makes AppKit promote the
/// next window of this app (usually main) to key and active — so a panel
/// summoned over another app would dump focus onto the main window when
/// dismissed. `NSApp deactivate` is not a reliable fix under the cooperative
/// activation model (macOS 14+), so instead the app that was frontmost when
/// the panel was summoned is remembered by pid and explicitly re-activated
/// on hide (the same scheme Quake-style terminals use).
#[cfg(target_os = "macos")]
mod previous_app {
    use std::sync::atomic::{AtomicI32, Ordering};
    use tauri::AppHandle;

    use objc2::rc::Retained;
    use objc2::runtime::AnyObject;
    use objc2::{class, msg_send, sel};

    /// pid of the app the panel chain originates from — the app that was
    /// frontmost when the panel was summoned. 0 = this app itself → nothing
    /// to restore on hide.
    static PID: AtomicI32 = AtomicI32::new(0);

    /// True from the moment a hide starts handing focus back until that
    /// hand-over lands (this app observed inactive). While set, a re-show
    /// that samples *this* app as frontmost is mid-hand-over, not a genuine
    /// "summoned from our own window" — the original pid must be kept.
    static IN_FLIGHT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    /// Must run on the main thread. Both callers below queue it via
    /// `run_on_main_thread`, which preserves ordering relative to the
    /// queued `show`/`set_focus`/`hide` window calls.
    fn remember_frontmost_inner() {
        let own_pid = std::process::id() as i32;
        let pid = unsafe {
            let workspace: Retained<AnyObject> = msg_send![class!(NSWorkspace), sharedWorkspace];
            let frontmost: Option<Retained<AnyObject>> =
                msg_send![&*workspace, frontmostApplication];
            match frontmost {
                Some(app) => msg_send![&*app, processIdentifier],
                None => 0,
            }
        };
        if pid != own_pid {
            PID.store(pid, Ordering::SeqCst);
        } else if !IN_FLIGHT.load(Ordering::SeqCst) {
            // This app is genuinely frontmost (not merely mid-hand-over,
            // where the previous hide's hand-over hasn't landed yet and the
            // chain's original pid must be kept for the next hide).
            PID.store(0, Ordering::SeqCst);
        }
    }

    pub fn remember_frontmost(app: &AppHandle) {
        let _ = app.run_on_main_thread(remember_frontmost_inner);
    }

    /// The chain's origin pid. None = the panel was summoned from this app
    /// itself, so there is nothing to hand focus back to on hide. Not
    /// consumed: a re-show mid-hand-over must still see it (see IN_FLIGHT).
    pub fn origin() -> Option<i32> {
        match PID.load(Ordering::SeqCst) {
            0 => None,
            pid => Some(pid),
        }
    }

    /// Forget everything (feature disabled / panel force-hidden).
    pub fn reset() {
        PID.store(0, Ordering::SeqCst);
        IN_FLIGHT.store(false, Ordering::SeqCst);
    }

    /// One watchdog tick, on the main thread: reports whether this app is
    /// active, and if it is and `hand_over` is set, hands activation to the
    /// previous app.
    fn tick(pid: i32, hand_over: bool) -> bool {
        unsafe {
            let nsapp: Retained<AnyObject> = msg_send![class!(NSApplication), sharedApplication];
            let own_active: bool = msg_send![&*nsapp, isActive];
            if !own_active || !hand_over {
                return own_active;
            }
            let previous: Option<Retained<AnyObject>> = msg_send![
                class!(NSRunningApplication),
                runningApplicationWithProcessIdentifier: pid
            ];
            let Some(previous) = previous else {
                return own_active; // previous app gone; nothing to hand to
            };
            // Cooperative activation (macOS 14+): consent to hand over
            // activation, otherwise the system may refuse the request below.
            let can_yield: bool =
                msg_send![&*nsapp, respondsToSelector: sel!(yieldActivationToApplication:)];
            if can_yield {
                let _: () = msg_send![&*nsapp, yieldActivationToApplication: &*previous];
            }
            // NSApplicationActivateIgnoringOtherApps; deprecated-but-working
            // pre-14 path, ignored on 14+ where the yield above governs.
            let _: bool = msg_send![&*previous, activateWithOptions: 1usize << 1];
            own_active
        }
    }

    /// Post-hide focus watchdog.
    ///
    /// Two async hazards follow a hide, both caused by activation being
    /// asynchronous under cooperative activation (macOS 14+):
    ///  * this app is still active (the panel had focus) — activation must
    ///    be handed back to the previous app, possibly with retries while
    ///    this app's own pending activation settles;
    ///  * this app is NOT active yet, but the activation requested at show
    ///    time can land seconds later — with the panel gone, AppKit would key
    ///    the main window, visibly stealing focus.
    ///
    /// So for a grace period the panel window stays ordered-in (parked
    /// off-screen / fully transparent, i.e. invisible): any late activation
    /// keys the panel instead of the main window, and every tick that finds
    /// this app active hands activation back to `pid`. Afterwards the window
    /// is hidden for real — unless a re-show bumped SLIDE_GENERATION past
    /// `generation`, which cancels the watchdog.
    pub fn watch_and_restore(
        app: &AppHandle,
        window: tauri::WebviewWindow,
        pid: i32,
        generation: u64,
    ) {
        IN_FLIGHT.store(true, Ordering::SeqCst);
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            // Phase machinery to tell a late self-activation apart from a
            // deliberate user return to this app:
            //  * `seen_inactive` — once false→ we're in the initial hand-over
            //    (retry while our pending activation settles);
            //  * `late_quota` — when this app was NOT active at hide time,
            //    the show-time activation request is still pending and may
            //    land once, later; exactly one such re-activation is undone.
            //    Any activation beyond that is the user coming back on
            //    purpose, which must be left alone.
            let mut seen_inactive = false;
            let mut late_quota = 0u32;
            for t in 0..60 {
                if super::SLIDE_GENERATION.load(Ordering::SeqCst) != generation {
                    // Cancelled by a re-show. IN_FLIGHT is deliberately left
                    // as-is: if the hand-over never landed, the re-show has
                    // kept the origin pid and its own hide continues the
                    // chain.
                    return;
                }
                let hand_over = !seen_inactive || late_quota > 0;
                let (tx, rx) = tokio::sync::oneshot::channel();
                let queued = app.run_on_main_thread(move || {
                    let _ = tx.send(tick(pid, hand_over));
                });
                let Ok(active) = rx.await else { break };
                let _ = queued;
                if t == 0 && !active {
                    late_quota = 1;
                }
                if !active {
                    seen_inactive = true;
                    IN_FLIGHT.store(false, Ordering::SeqCst);
                } else if seen_inactive {
                    if late_quota > 0 {
                        // The pending show-time activation just landed and
                        // was handed straight back (this tick's hand_over).
                        late_quota -= 1;
                        IN_FLIGHT.store(true, Ordering::SeqCst);
                    } else {
                        // User deliberately re-activated this app.
                        break;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            IN_FLIGHT.store(false, Ordering::SeqCst);
            let _ = app.run_on_main_thread(move || {
                if super::SLIDE_GENERATION.load(Ordering::SeqCst) == generation {
                    let _ = window.hide();
                }
            });
        });
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Edge {
    Top,
    Bottom,
    Left,
    #[default]
    Right,
}

impl Edge {
    fn is_horizontal(self) -> bool {
        matches!(self, Edge::Left | Edge::Right)
    }
}

/// Per-edge user-chosen size (physical px of the resizable dimension).
/// `None` means the user never resized on that edge → use the default
/// (⅓ monitor width for left/right, ½ monitor height for top/bottom).
#[derive(Serialize, Deserialize, Clone, Copy, Default)]
pub struct EdgeSizes {
    pub top: Option<u32>,
    pub bottom: Option<u32>,
    pub left: Option<u32>,
    pub right: Option<u32>,
}

impl EdgeSizes {
    fn get(&self, edge: Edge) -> Option<u32> {
        match edge {
            Edge::Top => self.top,
            Edge::Bottom => self.bottom,
            Edge::Left => self.left,
            Edge::Right => self.right,
        }
    }

    fn set(&mut self, edge: Edge, size: u32) {
        match edge {
            Edge::Top => self.top = Some(size),
            Edge::Bottom => self.bottom = Some(size),
            Edge::Left => self.left = Some(size),
            Edge::Right => self.right = Some(size),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct QuickTerminalSettings {
    pub enabled: bool,
    pub edge: Edge,
    pub sizes: EdgeSizes,
    /// Panel opacity, 0.3–1.0. The native window is fully transparent; this
    /// is applied by the frontend to the panel content.
    #[serde(default = "default_opacity")]
    pub opacity: f64,
}

fn default_opacity() -> f64 {
    0.45
}

impl Default for QuickTerminalSettings {
    fn default() -> Self {
        QuickTerminalSettings {
            enabled: false,
            edge: Edge::default(),
            sizes: EdgeSizes::default(),
            opacity: default_opacity(),
        }
    }
}

/// Settings + environment info the settings UI needs in one round-trip.
#[derive(Serialize, Clone, Copy)]
pub struct QuickTerminalInfo {
    pub settings: QuickTerminalSettings,
    /// True on Linux/Wayland → the UI shows the reliability warning.
    pub wayland: bool,
}

#[derive(Serialize, Clone, Copy)]
struct ShowPayload {
    edge: Edge,
}

fn settings_path(app: &AppHandle) -> Option<std::path::PathBuf> {
    app.path()
        .app_data_dir()
        .ok()
        .map(|d| d.join("quick_terminal.json"))
}

pub fn load_settings(app: &AppHandle) -> QuickTerminalSettings {
    settings_path(app)
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_settings(app: &AppHandle, settings: &QuickTerminalSettings) {
    if let Some(path) = settings_path(app) {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(settings) {
            let _ = std::fs::write(path, json);
        }
    }
}

/// The monitor the mouse cursor is currently on (Guake/iTerm convention),
/// falling back to the primary monitor.
///
/// Deliberately NOT `monitor_from_point`: `cursor_position()` returns
/// top-left-origin *physical* coordinates while `monitor_from_point` expects
/// *logical* ones (on macOS even bottom-left-origin), so combining them picks
/// a mouse-position-dependent wrong monitor on scaled displays. Monitor
/// `position()`/`size()` are physical, so containment is tested there.
fn target_monitor(app: &AppHandle) -> Option<tauri::Monitor> {
    let monitors = app.available_monitors().unwrap_or_default();
    if let Ok(cursor) = app.cursor_position() {
        for monitor in &monitors {
            let pos = monitor.position();
            let size = monitor.size();
            if cursor.x >= pos.x as f64
                && cursor.x < (pos.x + size.width as i32) as f64
                && cursor.y >= pos.y as f64
                && cursor.y < (pos.y + size.height as i32) as f64
            {
                return Some(monitor.clone());
            }
        }
    }
    app.primary_monitor()
        .ok()
        .flatten()
        .or_else(|| monitors.into_iter().next())
}

/// Applies edge-anchored geometry using *logical* coordinates derived from
/// the target monitor's scale factor. Physical values must not be handed to
/// `set_position`/`set_size` here: Tauri converts them with the *window's*
/// current scale factor, which is unreliable for a hidden (or
/// still-on-another-monitor) window and intermittently lands the panel
/// mid-screen at the wrong size. Logical coordinates are global across
/// monitors (same workaround as `open_settings_window_inner`).
fn apply_geometry(
    window: &tauri::WebviewWindow,
    edge: Edge,
    sizes: &EdgeSizes,
    monitor: &tauri::Monitor,
) {
    let (position, size) = compute_geometry(edge, sizes, monitor);
    let scale = monitor.scale_factor();
    let _ = window.set_size(tauri::LogicalSize::new(
        size.width as f64 / scale,
        size.height as f64 / scale,
    ));
    let _ = window.set_position(tauri::LogicalPosition::new(
        position.x as f64 / scale,
        position.y as f64 / scale,
    ));
}

/// Flush-against-the-edge geometry on the given monitor's work area, spanning
/// the full perpendicular dimension. All values are physical pixels.
fn compute_geometry(
    edge: Edge,
    sizes: &EdgeSizes,
    monitor: &tauri::Monitor,
) -> (PhysicalPosition<i32>, PhysicalSize<u32>) {
    let area = monitor.work_area();
    let min = (MIN_SIZE_LOGICAL * monitor.scale_factor()) as u32;

    let default_size = if edge.is_horizontal() {
        area.size.width / 3
    } else {
        area.size.height / 2
    };
    let max = if edge.is_horizontal() {
        area.size.width
    } else {
        area.size.height
    };
    let size = sizes.get(edge).unwrap_or(default_size).clamp(min, max);

    match edge {
        Edge::Top => (
            PhysicalPosition::new(area.position.x, area.position.y),
            PhysicalSize::new(area.size.width, size),
        ),
        Edge::Bottom => (
            PhysicalPosition::new(
                area.position.x,
                area.position.y + (area.size.height - size) as i32,
            ),
            PhysicalSize::new(area.size.width, size),
        ),
        Edge::Left => (
            PhysicalPosition::new(area.position.x, area.position.y),
            PhysicalSize::new(size, area.size.height),
        ),
        Edge::Right => (
            PhysicalPosition::new(
                area.position.x + (area.size.width - size) as i32,
                area.position.y,
            ),
            PhysicalSize::new(size, area.size.height),
        ),
    }
}

/// True if another monitor sits beyond the given edge of `monitor` — i.e.
/// the space the slide animation would travel through is NOT off-screen but
/// visible desktop on an extended display. Sliding there would show the
/// panel crossing onto the neighbouring monitor, so the animation must be
/// skipped in that case. Checked with a thin strip just past the edge,
/// in physical coordinates.
fn has_monitor_beyond(app: &AppHandle, monitor: &tauri::Monitor, edge: Edge) -> bool {
    let scale = monitor.scale_factor();
    let pos = monitor.position().to_logical::<f64>(scale);
    let size = monitor.size().to_logical::<f64>(scale);
    // (x, y, w, h) strip 2px beyond the edge in logical coordinates, spanning the full edge length.
    let strip: (f64, f64, f64, f64) = match edge {
        Edge::Top => (pos.x, pos.y - 2.0, size.width, 2.0),
        Edge::Bottom => (pos.x, pos.y + size.height, size.width, 2.0),
        Edge::Left => (pos.x - 2.0, pos.y, 2.0, size.height),
        Edge::Right => (pos.x + size.width, pos.y, 2.0, size.height),
    };
    app.available_monitors()
        .unwrap_or_default()
        .iter()
        .filter(|other| other.position() != monitor.position())
        .any(|other| {
            let oscale = other.scale_factor();
            let opos = other.position().to_logical::<f64>(oscale);
            let osize = other.size().to_logical::<f64>(oscale);
            strip.0 < opos.x + osize.width
                && strip.0 + strip.2 > opos.x
                && strip.1 < opos.y + osize.height
                && strip.1 + strip.3 > opos.y
        })
}

/// On-screen (anchored) and off-screen (just past the edge) logical positions
/// plus the logical size, for the slide animation endpoints.
fn slide_endpoints(
    edge: Edge,
    sizes: &EdgeSizes,
    monitor: &tauri::Monitor,
) -> ((f64, f64), (f64, f64), (f64, f64)) {
    let (position, size) = compute_geometry(edge, sizes, monitor);
    let scale = monitor.scale_factor();
    let on = (position.x as f64 / scale, position.y as f64 / scale);
    let (w, h) = (size.width as f64 / scale, size.height as f64 / scale);
    let off = match edge {
        Edge::Top => (on.0, on.1 - h),
        Edge::Bottom => (on.0, on.1 + h),
        Edge::Left => (on.0 - w, on.1),
        Edge::Right => (on.0 + w, on.1),
    };
    (on, off, (w, h))
}

/// Ease-out slide of the native window between two logical positions,
/// optionally hiding it at the end. Cancelled if SLIDE_GENERATION moves on.
/// Returns the slide's generation so callers can chain follow-up work that
/// must abort if a newer slide supersedes this one.
fn slide(window: tauri::WebviewWindow, from: (f64, f64), to: (f64, f64), hide_after: bool) -> u64 {
    let generation = SLIDE_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
    tauri::async_runtime::spawn(async move {
        let step_delay = std::time::Duration::from_millis(SLIDE_DURATION_MS / SLIDE_STEPS as u64);
        for step in 1..=SLIDE_STEPS {
            if SLIDE_GENERATION.load(Ordering::SeqCst) != generation {
                return;
            }
            let t = step as f64 / SLIDE_STEPS as f64;
            let eased = 1.0 - (1.0 - t).powi(3);
            let _ = window.set_position(tauri::LogicalPosition::new(
                from.0 + (to.0 - from.0) * eased,
                from.1 + (to.1 - from.1) * eased,
            ));
            tokio::time::sleep(step_delay).await;
        }
        if hide_after && SLIDE_GENERATION.load(Ordering::SeqCst) == generation {
            let _ = window.hide();
        }
    });
    generation
}

// ── macOS: focus the panel without raising the app's other windows ──────────
//
// Two broken extremes and why:
//  * `set_focus()` (Tauri → `activateIgnoringOtherApps:`) activates the app,
//    and since Big Sur app activation brings ALL of the app's windows to the
//    front — so summoning the panel over another app dragged a backgrounded
//    main window on top of it.
//  * `orderFrontRegardless` + `makeKeyWindow` WITHOUT activating the app
//    leaves the panel with no keyboard focus at all: macOS routes key events
//    to the *active* app, so a merely key window of an inactive app cannot
//    receive input.
//
// The fix activates the app the AppKit-native way (`makeKeyAndOrderFront`
// + `activateIgnoringOtherApps:` — the exact flow tao's `set_focus` uses),
// because only that path was ever observed to deliver FULL focus semantics:
// becomeKeyWindow, WKWebView focus sync (cursor blink), Focused events and
// blur on click-away. Two window-switcher-style alternatives were tried and
// rejected: the private SkyLight front-switch and Carbon's
// SetFrontProcessWithOptions(frontWindowOnly) both routed keystrokes but
// skipped AppKit's activation bookkeeping (no cursor blink / no blur), and
// frontWindowOnly no longer suppresses sibling raises on modern macOS.
//
// To undo the activation's "raise every window" side effect, the sibling
// windows are pushed to the back of their levels in the SAME runloop turn
// (push_siblings_back), with delayed insurance passes in case AppKit
// re-raises them on a later tick.
//
// Keying the panel must wait for the activation to actually land
// (wait_until_active_then_key): activation is asynchronous, and a
// makeKeyWindow issued before it lands gets overwritten when AppKit's
// activation transition picks its own key window. Once active, keying is
// retried a few times and finishes by making the WKWebView (found in the
// window's view tree) the first responder so DOM focus syncs.
//
// If the app is already active (summoned from its own window), no
// activation is needed — keying the panel is all it takes, and nothing
// else gets raised.

#[cfg(target_os = "macos")]
#[repr(C)]
struct ProcessSerialNumber {
    hi: u32,
    lo: u32,
}

#[cfg(target_os = "macos")]
#[link(name = "Carbon", kind = "framework")]
extern "C" {
    fn GetProcessForPID(pid: std::ffi::c_int, psn: *mut ProcessSerialNumber) -> std::ffi::c_int;
}

/// Switches the front process to this app asking the WindowServer to raise
/// only `window_id`. KEPT AS A RESERVE: it routes keystrokes but leaves
/// AppKit focus bookkeeping out of sync (no cursor blink / no blur).
#[allow(dead_code)]
#[cfg(target_os = "macos")]
fn front_switch_raising_only(window_id: u32) -> bool {
    type SlpsSetFrontProcess =
        unsafe extern "C" fn(*mut ProcessSerialNumber, u32, u32) -> std::ffi::c_int;

    // `_SLPSSetFrontProcessWithOptions` mode flag: mark the front-switch as
    // user-initiated so cooperative activation (macOS 14+) honours it. No
    // all-windows bit → only `window_id` comes forward.
    const MODE_USER_GENERATED: u32 = 0x200;
    const SKYLIGHT_DYLIB: &[u8] =
        b"/System/Library/PrivateFrameworks/SkyLight.framework/SkyLight\0";
    const SLPS_SYMBOL: &[u8] = b"_SLPSSetFrontProcessWithOptions\0";

    static SLPS: std::sync::OnceLock<Option<SlpsSetFrontProcess>> = std::sync::OnceLock::new();
    let Some(slps) = *SLPS.get_or_init(|| unsafe {
        extern "C" {
            fn dlopen(
                path: *const std::ffi::c_char,
                mode: std::ffi::c_int,
            ) -> *mut std::ffi::c_void;
            fn dlsym(
                handle: *mut std::ffi::c_void,
                name: *const std::ffi::c_char,
            ) -> *mut std::ffi::c_void;
        }
        // RTLD_LAZY on Darwin.
        let handle = dlopen(SKYLIGHT_DYLIB.as_ptr() as *const std::ffi::c_char, 2);
        if handle.is_null() {
            return None;
        }
        let sym = dlsym(handle, SLPS_SYMBOL.as_ptr() as *const std::ffi::c_char);
        std::mem::transmute::<*mut std::ffi::c_void, Option<SlpsSetFrontProcess>>(sym)
    }) else {
        return false;
    };

    let mut psn = ProcessSerialNumber { hi: 0, lo: 0 };
    unsafe {
        if GetProcessForPID(std::process::id() as std::ffi::c_int, &mut psn) != 0 {
            return false;
        }
        let _ = slps(&mut psn, window_id, MODE_USER_GENERATED);
    }
    true
}

/// TEMPORARY focus diagnostics: release builds have no log sink, so the
/// focus flow appends to `quick_terminal_focus.log` in the app data dir.
#[cfg(target_os = "macos")]
pub fn focus_debug(app: &AppHandle, msg: &str) {
    use std::io::Write;
    let Some(dir) = app.path().app_data_dir().ok() else {
        return;
    };
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("quick_terminal_focus.log"))
    else {
        return;
    };
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let _ = writeln!(file, "[{ts}] {msg}");
}

/// Plain `activateIgnoringOtherApps:` — raises every app window, last resort
/// only, when the targeted front-switch is unavailable/refused.
#[cfg(target_os = "macos")]
fn activate_app_blunt() {
    unsafe {
        let nsapp: objc2::rc::Retained<objc2::runtime::AnyObject> =
            objc2::msg_send![objc2::class!(NSApplication), sharedApplication];
        let _: () = objc2::msg_send![&*nsapp, activateIgnoringOtherApps: true];
    }
}

/// Finds the window's WKWebView. Usually it is the content view itself,
/// but window effects can reparent it into a container — search the view
/// tree if needed.
#[cfg(target_os = "macos")]
unsafe fn find_webview(
    ns_window: *mut objc2::runtime::AnyObject,
) -> Option<objc2::rc::Retained<objc2::runtime::AnyObject>> {
    let wk_class = objc2::runtime::AnyClass::get(c"WKWebView")?;
    let content: Option<objc2::rc::Retained<objc2::runtime::AnyObject>> =
        objc2::msg_send![ns_window, contentView];
    let mut queue = vec![content?];
    while let Some(view) = queue.pop() {
        let is_wk: bool = objc2::msg_send![&*view, isKindOfClass: wk_class];
        if is_wk {
            return Some(view);
        }
        let subs: Option<objc2::rc::Retained<objc2::runtime::AnyObject>> =
            objc2::msg_send![&*view, subviews];
        if let Some(subs) = subs {
            let count: usize = objc2::msg_send![&*subs, count];
            for i in 0..count {
                let sub: Option<objc2::rc::Retained<objc2::runtime::AnyObject>> =
                    objc2::msg_send![&*subs, objectAtIndex: i];
                if let Some(sub) = sub {
                    queue.push(sub);
                }
            }
        }
    }
    None
}

/// Makes the panel the app's key window and first-responder-assigns the
/// WKWebView, so the focused DOM element (the terminal textarea) gets input
/// focus. Returns (isKeyWindow, app isActive, firstResponder accepted).
#[cfg(target_os = "macos")]
fn key_panel_window(window: &tauri::WebviewWindow) -> (bool, bool, bool) {
    let Some(ns_window) = window.ns_window().ok() else {
        return (false, false, false);
    };
    let ns_window = ns_window as *mut objc2::runtime::AnyObject;
    unsafe {
        let _: () = objc2::msg_send![ns_window, makeKeyWindow];
        let mut fr_ok = false;
        if let Some(webview) = find_webview(ns_window) {
            fr_ok = objc2::msg_send![ns_window, makeFirstResponder: &*webview];
        }
        let is_key: bool = objc2::msg_send![ns_window, isKeyWindow];
        let nsapp: objc2::rc::Retained<objc2::runtime::AnyObject> =
            objc2::msg_send![objc2::class!(NSApplication), sharedApplication];
        let is_active: bool = objc2::msg_send![&*nsapp, isActive];
        (is_key, is_active, fr_ok)
    }
}

/// Reads the panel's current focus state without changing anything.
#[cfg(target_os = "macos")]
fn key_panel_state(window: &tauri::WebviewWindow) -> (bool, bool, bool) {
    let tauri_focus = window.is_focused().unwrap_or(false);
    let Some(ns_window) = window.ns_window().ok() else {
        return (false, false, tauri_focus);
    };
    let ns_window = ns_window as *mut objc2::runtime::AnyObject;
    unsafe {
        let is_key: bool = objc2::msg_send![ns_window, isKeyWindow];
        let nsapp: objc2::rc::Retained<objc2::runtime::AnyObject> =
            objc2::msg_send![objc2::class!(NSApplication), sharedApplication];
        let is_active: bool = objc2::msg_send![&*nsapp, isActive];
        (is_key, is_active, tauri_focus)
    }
}

/// Waits until the app's activation lands (isActive), then keys the panel
/// — retrying a few times, because AppKit's asynchronous activation can
/// hand the key window to a sibling first. Keying MUST happen after
/// activation: keying while inactive is discarded by the activation
/// transition itself. Falls back to blunt activation if nothing lands.
#[cfg(target_os = "macos")]
fn wait_until_active_then_key(app: AppHandle, window: tauri::WebviewWindow) {
    tauri::async_runtime::spawn(async move {
        let mut blunt_issued = false;
        for tick in 0..48 {
            tokio::time::sleep(std::time::Duration::from_millis(15)).await;
            if !PANEL_SHOWN.load(std::sync::atomic::Ordering::SeqCst) {
                focus_debug(&app, "watchdog aborted: panel hidden");
                return;
            }
            let (tx, rx) = tokio::sync::oneshot::channel();
            if app
                .run_on_main_thread(move || {
                    let active: bool = unsafe {
                        let nsapp: objc2::rc::Retained<objc2::runtime::AnyObject> =
                            objc2::msg_send![objc2::class!(NSApplication), sharedApplication];
                        objc2::msg_send![&*nsapp, isActive]
                    };
                    let _ = tx.send(active);
                })
                .is_err()
            {
                return;
            }
            let Ok(true) = rx.await else {
                if tick == 23 && !blunt_issued {
                    blunt_issued = true;
                    focus_debug(&app, "activation never landed → blunt activation");
                    let _ = app.run_on_main_thread(move || {
                        if PANEL_SHOWN.load(std::sync::atomic::Ordering::SeqCst) {
                            unsafe { activate_app_blunt() };
                        }
                    });
                }
                continue;
            };
            // Active: key the panel, retrying while AppKit's activation
            // settling keeps handing the key state to another window.
            for attempt in 0..8u32 {
                if !PANEL_SHOWN.load(std::sync::atomic::Ordering::SeqCst) {
                    return;
                }
                let (tx, rx) = tokio::sync::oneshot::channel();
                let w = window.clone();
                if app
                    .run_on_main_thread(move || {
                        if !PANEL_SHOWN.load(std::sync::atomic::Ordering::SeqCst) {
                            let _ = tx.send((false, false, false));
                            return;
                        }
                        let _ = tx.send(key_panel_window(&w));
                    })
                    .is_err()
                {
                    return;
                }
                let Ok((is_key, _, fr_ok)) = rx.await else { return };
                if is_key {
                    focus_debug(
                        &app,
                        &format!("tick {tick} attempt {attempt}: key granted fr={fr_ok}"),
                    );
                    // Recheck shortly after to catch anything stealing the
                    // key state back.
                    let recheck = app.clone();
                    let recheck_window = window.clone();
                    tauri::async_runtime::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
                        let (tx, rx) = tokio::sync::oneshot::channel();
                        if recheck
                            .run_on_main_thread(move || {
                                let _ = tx.send(key_panel_state(&recheck_window));
                            })
                            .is_err()
                        {
                            return;
                        }
                        if let Ok((k, a, f)) = rx.await {
                            focus_debug(&app, &format!("recheck: key={k} act={a} f={f}"));
                        }
                    });
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
            focus_debug(&app, "keying failed after retries");
            return;
        }
        focus_debug(&app, "gave up: app never became active within 720ms");
    });
}

#[cfg(target_os = "macos")]
unsafe fn nsstring_to_string(obj: &objc2::runtime::AnyObject) -> String {
    let utf8: *const std::ffi::c_char = objc2::msg_send![obj, UTF8String];
    if utf8.is_null() {
        return String::new();
    }
    std::ffi::CStr::from_ptr(utf8).to_string_lossy().into_owned()
}

/// Pushes every visible, non-fullscreen app window other than `panel` to
/// the back of its window level. Activating the app raises ALL of the app's
/// windows (since Big Sur); doing this around the activation keeps the
/// raise invisible. Returns how many were pushed (and, when asked, their
/// titles for diagnostics).
#[cfg(target_os = "macos")]
unsafe fn push_siblings_back(
    panel: *mut objc2::runtime::AnyObject,
    collect_titles: bool,
) -> (usize, Vec<String>) {
    let nsapp: objc2::rc::Retained<objc2::runtime::AnyObject> =
        objc2::msg_send![objc2::class!(NSApplication), sharedApplication];
    let windows: Option<objc2::rc::Retained<objc2::runtime::AnyObject>> =
        objc2::msg_send![&*nsapp, windows];
    let Some(windows) = windows else {
        return (0, Vec::new());
    };
    let count: usize = objc2::msg_send![&*windows, count];
    let mut pushed = 0usize;
    let mut titles = Vec::new();
    for i in 0..count {
        let win: *mut objc2::runtime::AnyObject = objc2::msg_send![&*windows, objectAtIndex: i];
        if win.is_null() || win == panel {
            continue;
        }
        let visible: bool = objc2::msg_send![win, isVisible];
        if !visible {
            continue;
        }
        // Fullscreen windows live on their own space/level; activation does
        // not drag them forward, so leave them alone.
        let mask: usize = objc2::msg_send![win, styleMask];
        if mask & (1 << 14) != 0 {
            continue;
        }
        if collect_titles {
            let title: Option<objc2::rc::Retained<objc2::runtime::AnyObject>> =
                objc2::msg_send![win, title];
            titles.push(
                title
                    .as_deref()
                    .map(|t| unsafe { nsstring_to_string(t) })
                    .unwrap_or_default(),
            );
        }
        let _: () = objc2::msg_send![win, orderBack: &*win];
        pushed += 1;
    }
    (pushed, titles)
}

#[cfg(target_os = "macos")]
#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFRunLoopGetMain() -> *mut std::ffi::c_void;
    fn CFRunLoopAddObserver(
        rl: *mut std::ffi::c_void,
        observer: *mut std::ffi::c_void,
        mode: *const std::ffi::c_void,
    );
    fn CFRunLoopObserverCreate(
        allocator: *const std::ffi::c_void,
        activities: u64,
        repeats: u8,
        order: i64,
        callout: unsafe extern "C" fn(*mut std::ffi::c_void, u64, *mut std::ffi::c_void),
        context: *const CFRunLoopObserverContext,
    ) -> *mut std::ffi::c_void;
    fn CFRelease(cf: *const std::ffi::c_void);
    static kCFRunLoopCommonModes: *const std::ffi::c_void;
}

#[cfg(target_os = "macos")]
#[repr(C)]
#[rustfmt::skip]
struct CFRunLoopObserverContext {
    version: i64,
    info: *mut std::ffi::c_void,
    retain: Option<unsafe extern "C" fn(*const std::ffi::c_void) -> *const std::ffi::c_void>,
    release: Option<unsafe extern "C" fn(*const std::ffi::c_void)>,
    copy_description: Option<unsafe extern "C" fn(*const std::ffi::c_void) -> *const std::ffi::c_void>,
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn push_siblings_back_at_idle(
    _observer: *mut std::ffi::c_void,
    _activity: u64,
    info: *mut std::ffi::c_void,
) {
    push_siblings_back(info as *mut objc2::runtime::AnyObject, false);
}

/// Pushes the siblings back once more right before the main runloop goes
/// idle — i.e. after every callback AppKit queued for this activation
/// cycle (including its DEFERRED window raising), so the raise is undone
/// within the same display frame and never becomes visible.
#[cfg(target_os = "macos")]
fn schedule_sibling_pushback_at_idle(panel: *mut objc2::runtime::AnyObject) {
    const K_CF_RUN_LOOP_BEFORE_WAITING: u64 = 1 << 5;
    unsafe {
        let context = CFRunLoopObserverContext {
            version: 0,
            info: panel as *mut std::ffi::c_void,
            retain: None,
            release: None,
            copy_description: None,
        };
        let observer = CFRunLoopObserverCreate(
            std::ptr::null(),
            K_CF_RUN_LOOP_BEFORE_WAITING,
            0,
            0,
            push_siblings_back_at_idle,
            &context,
        );
        if observer.is_null() {
            return;
        }
        CFRunLoopAddObserver(CFRunLoopGetMain(), observer, kCFRunLoopCommonModes);
        // The runloop holds its own reference now.
        CFRelease(observer);
    }
}

/// Keyboard-focus the panel on macOS. Must be called for a panel that was
/// just shown; see the module-section comment above for the full rationale.
#[cfg(target_os = "macos")]
fn focus_panel_macos(app: &AppHandle, window: &tauri::WebviewWindow) {
    let app = app.clone();
    let w = window.clone();
    let _ = app.clone().run_on_main_thread(move || {
        let app_active: bool = unsafe {
            let nsapp: objc2::rc::Retained<objc2::runtime::AnyObject> =
                objc2::msg_send![objc2::class!(NSApplication), sharedApplication];
            objc2::msg_send![&*nsapp, isActive]
        };
        let Some(ns_window) = w.ns_window().ok().map(|p| p as *mut objc2::runtime::AnyObject)
        else {
            focus_debug(&app, "show: ns_window unavailable");
            return;
        };
        focus_debug(&app, &format!("show: active={app_active}"));
        unsafe {
            // Key + front first, then activate: the exact order of tao's
            // proven set_focus flow — the only path observed to deliver
            // full focus semantics (becomeKeyWindow → WKWebView focus sync
            // → cursor blink, blur on click-away). Both private WindowServer
            // front-switches (SkyLight, Carbon frontWindowOnly) routed
            // keystrokes but skipped AppKit's activation bookkeeping.
            let _: () = objc2::msg_send![ns_window, makeKeyAndOrderFront: &*ns_window];
        }
        if !app_active {
            // AppKit activation raises ALL app windows since Big Sur; push
            // the siblings straight back down within the same runloop turn
            // so the user never sees them.
            unsafe {
                let nsapp: objc2::rc::Retained<objc2::runtime::AnyObject> =
                    objc2::msg_send![objc2::class!(NSApplication), sharedApplication];
                let _: () = objc2::msg_send![&*nsapp, activateIgnoringOtherApps: true];
                let (pushed, titles) = push_siblings_back(ns_window, true);
                focus_debug(&app, &format!("activated; pushed {pushed}: {titles:?}"));
                // Undo AppKit's DEFERRED raising too (it queues the real
                // raise on the runloop; catch it before the loop idles).
                schedule_sibling_pushback_at_idle(ns_window);
            }
        }
        if app_active {
            // Summoned while this app is already frontmost: keying now is
            // safe (the app is active) and nothing else gets raised.
            let (is_key, is_active, fr_ok) = key_panel_window(&w);
            focus_debug(
                &app,
                &format!("already-active: key={is_key} act={is_active} fr={fr_ok}"),
            );
            return;
        }
        // Keying must wait for the activation to land; activation is
        // asynchronous and keys the panel too early get overwritten by it.
        let app2 = app.clone();
        let w2 = w.clone();
        wait_until_active_then_key(app, w);
        // Insurance: if AppKit re-raises the siblings on a later runloop
        // tick, push them back once more.
        tauri::async_runtime::spawn(async move {
            for delay_ms in [16u64, 32, 64, 100, 200, 300] {
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                if !PANEL_SHOWN.load(std::sync::atomic::Ordering::SeqCst) {
                    return;
                }
                let (tx, rx) = tokio::sync::oneshot::channel();
                let w3 = w2.clone();
                if app2
                    .run_on_main_thread(move || {
                        let mut pushed = 0usize;
                        if PANEL_SHOWN.load(std::sync::atomic::Ordering::SeqCst) {
                            if let Ok(ns) = w3.ns_window() {
                                let (p, _) = unsafe {
                                    push_siblings_back(
                                        ns as *mut objc2::runtime::AnyObject,
                                        false,
                                    )
                                };
                                pushed = p;
                            }
                        }
                        let _ = tx.send((pushed, key_panel_state(&w3)));
                    })
                    .is_err()
                {
                    return;
                }
                if let Ok((pushed, (is_key, is_active, focus))) = rx.await {
                    focus_debug(
                        &app2,
                        &format!(
                            "{delay_ms}ms push={pushed} key={is_key} act={is_active} f={focus}"
                        ),
                    );
                }
            }
        });
    });
}

fn show_panel(app: &AppHandle, window: tauri::WebviewWindow, settings: &QuickTerminalSettings) {
    let Some(monitor) = target_monitor(app) else {
        return;
    };
    PANEL_SHOWN.store(true, std::sync::atomic::Ordering::SeqCst);
    // Must be sampled before the focus handling below makes this app frontmost.
    #[cfg(target_os = "macos")]
    previous_app::remember_frontmost(app);
    let animate = !has_monitor_beyond(app, &monitor, settings.edge);
    let (on, off, (w, h)) = slide_endpoints(settings.edge, &settings.sizes, &monitor);
    let start = if animate { off } else { on };
    let _ = window.set_size(tauri::LogicalSize::new(w, h));
    let _ = window.set_position(tauri::LogicalPosition::new(start.0, start.1));
    // A previous hide may have parked the window fully transparent (see the
    // monitor-adjoining branch of hide_panel).
    #[cfg(target_os = "macos")]
    set_native_alpha(app, &window, 1.0);
    let _ = window.show();
    // Give the panel keyboard focus WITHOUT dragging the app's other windows
    // to the front (a main window parked behind other apps must stay there).
    #[cfg(target_os = "macos")]
    focus_panel_macos(app, &window);
    #[cfg(not(target_os = "macos"))]
    {
        let _ = window.set_focus();
    }
    let _ = app.emit(
        "quick-terminal:show",
        ShowPayload {
            edge: settings.edge,
        },
    );
    if animate {
        slide(window, off, on, false);
    } else {
        // A monitor adjoins the slide edge: cancel any in-flight slide and
        // appear in place instead of visibly crossing the neighbour display.
        SLIDE_GENERATION.fetch_add(1, Ordering::SeqCst);
    }
}

/// Slide out from wherever the window actually is. The start position must
/// NOT be recomputed from a monitor: with extended displays the monitor
/// lookup (e.g. cursor fallback) can disagree with the monitor the panel is
/// really on, teleporting it there for the exit animation. Shifting the
/// window's real position by its own size clears the screen edge on any
/// monitor.
fn hide_panel(app: &AppHandle, window: tauri::WebviewWindow, settings: &QuickTerminalSettings) {
    PANEL_SHOWN.store(false, std::sync::atomic::Ordering::SeqCst);
    #[cfg(target_os = "macos")]
    focus_debug(app, "hide_panel");
    #[cfg(target_os = "macos")]
    let restore_pid = previous_app::origin();
    // If another monitor adjoins the slide edge, don't animate — the panel
    // would visibly travel across the neighbouring display before hiding.
    let on_monitor = window.current_monitor().ok().flatten();
    if let Some(monitor) = &on_monitor {
        if has_monitor_beyond(app, monitor, settings.edge) {
            let generation = SLIDE_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
            #[cfg(target_os = "macos")]
            if let Some(pid) = restore_pid {
                // Can't slide off-screen here (a monitor adjoins the edge)
                // and can't orderOut yet (focus watchdog) — make the window
                // fully transparent instead until the watchdog hides it.
                // show_panel restores the alpha.
                set_native_alpha(app, &window, 0.0);
                previous_app::watch_and_restore(app, window, pid, generation);
                return;
            }
            let _ = generation;
            let _ = window.hide();
            return;
        }
    }
    let (Ok(position), Ok(size), Ok(scale)) = (
        window.outer_position(),
        window.outer_size(),
        window.scale_factor(),
    ) else {
        let _ = window.hide();
        return;
    };
    let on = (position.x as f64 / scale, position.y as f64 / scale);
    let (w, h) = (size.width as f64 / scale, size.height as f64 / scale);
    let off = offset_past_edge(on, (w, h), settings.edge);
    #[cfg(target_os = "macos")]
    if let Some(pid) = restore_pid {
        // Slide out without hiding; the watchdog orders the window out after
        // the focus grace period.
        let generation = slide(window.clone(), on, off, false);
        previous_app::watch_and_restore(app, window, pid, generation);
        return;
    }
    slide(window, on, off, true);
}

/// Position one panel-size past the screen edge in the hide direction.
fn offset_past_edge(on: (f64, f64), (w, h): (f64, f64), edge: Edge) -> (f64, f64) {
    match edge {
        Edge::Top => (on.0, on.1 - h),
        Edge::Bottom => (on.0, on.1 + h),
        Edge::Left => (on.0 - w, on.1),
        Edge::Right => (on.0 + w, on.1),
    }
}

/// Native NSWindow alpha, applied on the main thread.
#[cfg(target_os = "macos")]
fn set_native_alpha(app: &AppHandle, window: &tauri::WebviewWindow, alpha: f64) {
    let window = window.clone();
    let _ = app.run_on_main_thread(move || {
        if let Ok(ns_window) = window.ns_window() {
            unsafe {
                let ns_window = ns_window as *mut objc2::runtime::AnyObject;
                let _: () = objc2::msg_send![ns_window, setAlphaValue: alpha];
            }
        }
    });
}

/// Whether Quick Terminal is logically open. Used by app-level activation
/// handlers so they do not surface the main window during panel activation.
pub fn is_shown() -> bool {
    PANEL_SHOWN.load(std::sync::atomic::Ordering::SeqCst)
}

/// Toggle entry point, called by the global hotkey and by commands.
/// The native window slides in/out; the frontend only mounts the terminal.
pub fn toggle(app: &AppHandle) {
    let settings = load_settings(app);
    if !settings.enabled {
        return;
    }
    let Some(window) = app.get_webview_window(WINDOW_LABEL) else {
        return;
    };

    // PANEL_SHOWN (not just is_visible): during the post-hide grace period
    // the window is still ordered-in off-screen while focus is handed back,
    // yet logically hidden — a toggle then must re-show, not hide again.
    if PANEL_SHOWN.load(std::sync::atomic::Ordering::SeqCst) && window.is_visible().unwrap_or(false)
    {
        hide_panel(app, window, &settings);
    } else {
        // A panel whose webview died while loading hidden would slide in as
        // an empty transparent shell (i.e. nothing visible at all). Reload it
        // and defer this toggle through the existing PendingToggle handshake:
        // the fresh page calls quick_terminal_frontend_ready once its event
        // listeners are mounted, which performs the slide-in.
        if crate::revive_webview_if_stuck(&window) {
            app.state::<PendingToggle>()
                .0
                .store(true, std::sync::atomic::Ordering::SeqCst);
            return;
        }
        show_panel(app, window, &settings);
    }
}

#[tauri::command]
pub fn toggle_quick_terminal(app: AppHandle) {
    toggle(&app);
}

/// Set when the app was cold-launched by the hotkey daemon with
/// `--hotkey=quick-terminal`: the panel can only slide in after its webview
/// has mounted and subscribed to the show/hide events, so the toggle is
/// deferred until the frontend reports in.
#[derive(Default)]
pub struct PendingToggle(pub std::sync::atomic::AtomicBool);

#[tauri::command]
pub fn quick_terminal_frontend_ready(app: AppHandle) {
    let pending = app.state::<PendingToggle>();
    if pending.0.swap(false, std::sync::atomic::Ordering::SeqCst) {
        toggle(&app);
    }
}

/// Slide-out + hide; called by the panel's close (×) button.
#[tauri::command]
pub fn hide_quick_terminal(app: AppHandle) {
    let settings = load_settings(&app);
    if let Some(window) = app.get_webview_window(WINDOW_LABEL) {
        if PANEL_SHOWN.load(std::sync::atomic::Ordering::SeqCst)
            && window.is_visible().unwrap_or(false)
        {
            hide_panel(&app, window, &settings);
        }
    }
}

/// Re-asserts the panel's key state and the webview's first-responder
/// status. The frontend calls this shortly after a show while the DOM still
/// reports no focus — a cold-launch race: the panel gets keyed before its
/// webview finishes loading, and the finished load resets WKWebView's focus
/// state with nothing around to re-sync it.
#[tauri::command]
pub fn refocus_quick_terminal_webview(app: AppHandle) {
    #[cfg(target_os = "macos")]
    {
        if !PANEL_SHOWN.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let Some(window) = app.get_webview_window(WINDOW_LABEL) else {
            return;
        };
        let logger = app.clone();
        let _ = app.run_on_main_thread(move || {
            if !PANEL_SHOWN.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            let (is_key, _, fr_ok) = key_panel_window(&window);
            focus_debug(&logger, &format!("frontend refocus: key={is_key} fr={fr_ok}"));
        });
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = app;
    }
}

/// Live-resizes the panel while the in-panel handle is dragged. `size` is the
/// new value of the resizable dimension in physical pixels. `commit` persists
/// the size for the current edge (sent on pointer-up).
#[tauri::command]
pub fn resize_quick_terminal(app: AppHandle, size: u32, commit: bool) -> Result<(), String> {
    let mut settings = load_settings(&app);
    let Some(window) = app.get_webview_window(WINDOW_LABEL) else {
        return Err("Quick Terminal window not found".to_string());
    };
    let monitor = window
        .current_monitor()
        .ok()
        .flatten()
        .or_else(|| target_monitor(&app))
        .ok_or("No monitor found")?;

    // Cancel any in-flight slide so it doesn't fight the drag.
    SLIDE_GENERATION.fetch_add(1, Ordering::SeqCst);

    let mut sizes = settings.sizes;
    sizes.set(settings.edge, size);
    // compute_geometry clamps to [min, work area] and re-anchors to the edge,
    // so the panel only ever grows/shrinks away from its screen edge.
    let (_, clamped_size) = compute_geometry(settings.edge, &sizes, &monitor);
    apply_geometry(&window, settings.edge, &sizes, &monitor);

    if commit {
        let committed = if settings.edge.is_horizontal() {
            clamped_size.width
        } else {
            clamped_size.height
        };
        settings.sizes.set(settings.edge, committed);
        save_settings(&app, &settings);
    }
    Ok(())
}

#[tauri::command]
pub fn get_quick_terminal_info(app: AppHandle) -> QuickTerminalInfo {
    QuickTerminalInfo {
        settings: load_settings(&app),
        wayland: crate::global_hotkey::is_wayland(),
    }
}

#[tauri::command]
pub fn set_quick_terminal_edge(app: AppHandle, edge: Edge) {
    let mut settings = load_settings(&app);
    settings.edge = edge;
    save_settings(&app, &settings);
    // If the panel is currently visible, snap it to the new edge immediately.
    if let Some(window) = app.get_webview_window(WINDOW_LABEL) {
        if window.is_visible().unwrap_or(false) {
            if let Some(monitor) = window.current_monitor().ok().flatten() {
                apply_geometry(&window, settings.edge, &settings.sizes, &monitor);
                let _ = app.emit(
                    "quick-terminal:show",
                    ShowPayload {
                        edge: settings.edge,
                    },
                );
            }
        }
    }
}

#[tauri::command]
pub fn set_quick_terminal_opacity(app: AppHandle, opacity: f64) {
    let mut settings = load_settings(&app);
    settings.opacity = opacity.clamp(0.3, 1.0);
    save_settings(&app, &settings);
    // Live-update the panel window if it exists (visible or not).
    let _ = app.emit("quick-terminal:opacity-changed", settings.opacity);
}

#[tauri::command]
pub fn set_quick_terminal_enabled(app: AppHandle, enabled: bool) {
    let mut settings = load_settings(&app);
    settings.enabled = enabled;
    save_settings(&app, &settings);
    if !enabled {
        // Cancel any slide and hide immediately — the feature was turned off.
        PANEL_SHOWN.store(false, std::sync::atomic::Ordering::SeqCst);
        #[cfg(target_os = "macos")]
        previous_app::reset();
        SLIDE_GENERATION.fetch_add(1, Ordering::SeqCst);
        if let Some(window) = app.get_webview_window(WINDOW_LABEL) {
            let _ = window.hide();
        }
    }
}
