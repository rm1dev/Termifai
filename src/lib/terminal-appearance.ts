import { publish } from "./api/transport";

export const terminalFonts = [
  "Source Code Pro",
  "Source Code Pro Medium",
  "Fira Mono",
  "Fira Mono Medium",
  "Inconsolata-g",
  "Anonymous Pro",
  "Ubuntu Mono",
  "Droid Sans Mono",
  "Dejavu Sans Mono",
  "PT Mono",
  "Cascadia Code",
  "Fira Code",
  "JetBrains Mono",
  "Meslo",
  "Vazir Code",
] as const;

export type TerminalFont = (typeof terminalFonts)[number];

export interface TerminalAppearance {
  fontFamily: TerminalFont;
  fontSize: number;
  lineHeight: number;
}

export const terminalAppearanceChangedEvent = "termifai:terminal-appearance-changed";
export const terminalAppearanceStorageKey = "termifai:terminal-appearance";

export const defaultTerminalAppearance: TerminalAppearance = {
  fontFamily: "Vazir Code",
  fontSize: 12,
  lineHeight: 1.1,
};

const fallbackFontFamily = "ui-monospace, monospace";

export function getTerminalFontStack(fontFamily: string) {
  return `"${fontFamily}", ${fallbackFontFamily}`;
}

export async function ensureTerminalFontLoaded(appearance: TerminalAppearance) {
  const fontFamily = getTerminalFontStack(appearance.fontFamily);
  const fontSize = clampTerminalFontSize(appearance.fontSize);

  try {
    // Bold is measured separately by xterm's WidthCache — if only the regular
    // face is loaded, bold cells fall back to a different font and get their
    // own (wrong) advance width.
    await Promise.all([
      document.fonts.load(`${fontSize}px ${fontFamily}`),
      document.fonts.load(`bold ${fontSize}px ${fontFamily}`),
    ]);
    // `fonts.load()` resolves per face; `fonts.ready` waits for the document's
    // whole font-loading pass to settle so a later swap can't land *after* we
    // measured.
    await document.fonts.ready;
  } catch {
    /* Font loading is best-effort; xterm will still attempt to render. */
  }
}

/** Is the terminal font actually usable right now (not a fallback)? */
export function isTerminalFontReady(appearance: TerminalAppearance): boolean {
  try {
    const fontSize = clampTerminalFontSize(appearance.fontSize);
    return (
      document.fonts.check(`${fontSize}px "${appearance.fontFamily}"`) &&
      document.fonts.check(`bold ${fontSize}px "${appearance.fontFamily}"`)
    );
  } catch {
    return true;
  }
}

/**
 * xterm caches character metrics (CharSizeService + the DOM renderer's
 * WidthCache) and only re-measures when an option *value actually changes* —
 * `rawOptions[k] !== v` is the guard inside OptionsService. So re-assigning the
 * same fontFamily/fontSize after a webfont finishes loading is a no-op, and the
 * terminal keeps the cell width it measured against the fallback font. The DOM
 * renderer then keeps `letter-spacing: cellWidth - measure("W")` from that stale
 * measurement, which is exactly the "text indent looks different in this
 * instance" symptom.
 *
 * Flipping the family to something else and straight back forces both
 * invalidations (CharSizeService.measure + widthCache.clear) with the real font
 * in place.
 */
export function remeasureTerminalFont(term: {
  options: { fontFamily?: string; fontSize?: number };
  refresh: (start: number, end: number) => void;
  rows: number;
}) {
  const current = term.options.fontFamily;
  if (!current) return;
  try {
    term.options.fontFamily = current === fallbackFontFamily ? "monospace" : fallbackFontFamily;
    term.options.fontFamily = current;
    term.refresh(0, Math.max(0, term.rows - 1));
  } catch {
    /* terminal disposed mid-flight */
  }
}

export function loadTerminalAppearance(): TerminalAppearance {
  try {
    const stored = localStorage.getItem(terminalAppearanceStorageKey);
    if (!stored) return defaultTerminalAppearance;

    const parsed = JSON.parse(stored) as Partial<TerminalAppearance>;
    const fontFamily = terminalFonts.includes(parsed.fontFamily as TerminalFont)
      ? (parsed.fontFamily as TerminalFont)
      : defaultTerminalAppearance.fontFamily;
    const fontSize =
      typeof parsed.fontSize === "number" && Number.isFinite(parsed.fontSize)
        ? clampTerminalFontSize(parsed.fontSize)
        : defaultTerminalAppearance.fontSize;
    const lineHeight =
      typeof parsed.lineHeight === "number" && Number.isFinite(parsed.lineHeight)
        ? clampTerminalLineHeight(parsed.lineHeight)
        : defaultTerminalAppearance.lineHeight;

    return { fontFamily, fontSize, lineHeight };
  } catch {
    return defaultTerminalAppearance;
  }
}

export function getTerminalAppearanceUpdatedAt(): string | undefined {
  return localStorage.getItem(`${terminalAppearanceStorageKey}:updatedAt`) ?? undefined;
}

export function saveTerminalAppearance(appearance: TerminalAppearance) {
  const normalized = {
    ...appearance,
    fontSize: clampTerminalFontSize(appearance.fontSize),
    lineHeight: clampTerminalLineHeight(appearance.lineHeight),
  };

  localStorage.setItem(terminalAppearanceStorageKey, JSON.stringify(normalized));
  localStorage.setItem(`${terminalAppearanceStorageKey}:updatedAt`, new Date().toISOString());
  window.dispatchEvent(
    new CustomEvent<TerminalAppearance>(terminalAppearanceChangedEvent, {
      detail: normalized,
    })
  );

  void publish(terminalAppearanceChangedEvent, normalized).catch(() => {
    /* Non-Tauri environments fall back to localStorage + storage events. */
  });

  void import("@/lib/sync-settings-cache").then((m) => m.pushSyncSettingsCache());
}

export function clampTerminalFontSize(fontSize: number) {
  return Math.min(24, Math.max(8, fontSize));
}

export function clampTerminalLineHeight(lineHeight: number) {
  return Math.min(2, Math.max(1, Number(lineHeight.toFixed(1))));
}
