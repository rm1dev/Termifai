import { call } from "./transport";

export type QuickTerminalEdge = "top" | "bottom" | "left" | "right";

export interface QuickTerminalSettings {
  enabled: boolean;
  edge: QuickTerminalEdge;
  sizes: {
    top: number | null;
    bottom: number | null;
    left: number | null;
    right: number | null;
  };
  /** Panel opacity, 0.3–1.0. */
  opacity: number;
}

export interface QuickTerminalInfo {
  settings: QuickTerminalSettings;
  /** True on Linux/Wayland → show the reliability warning before enabling. */
  wayland: boolean;
}

export function getQuickTerminalInfo(): Promise<QuickTerminalInfo> {
  return call<QuickTerminalInfo>("get_quick_terminal_info");
}

export function setQuickTerminalEdge(edge: QuickTerminalEdge): Promise<void> {
  return call<void>("set_quick_terminal_edge", { edge });
}

export function setQuickTerminalOpacity(opacity: number): Promise<void> {
  return call<void>("set_quick_terminal_opacity", { opacity });
}

export function setQuickTerminalEnabled(enabled: boolean): Promise<void> {
  return call<void>("set_quick_terminal_enabled", { enabled });
}

export function toggleQuickTerminal(): Promise<void> {
  return call<void>("toggle_quick_terminal");
}

/**
 * Tells the backend the panel webview has mounted and subscribed to events —
 * needed for the cold-launch path where the hotkey daemon starts the app.
 */
export function quickTerminalFrontendReady(): Promise<void> {
  return call<void>("quick_terminal_frontend_ready");
}

/** Called by the Quick Terminal window after its slide-out animation ends. */
export function hideQuickTerminal(): Promise<void> {
  return call<void>("hide_quick_terminal");
}

/**
 * Live-resize during handle drag. `size` is the new physical-pixel value of
 * the resizable dimension; `commit: true` (pointer-up) persists it per edge.
 */
export function resizeQuickTerminal(size: number, commit: boolean): Promise<void> {
  return call<void>("resize_quick_terminal", { size, commit });
}
