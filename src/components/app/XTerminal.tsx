import { useEffect, useRef, useLayoutEffect, useState, useCallback } from "react";
import { Terminal } from "@xterm/xterm";
import { Base64, ClipboardAddon } from "@xterm/addon-clipboard";
import { FitAddon } from "@xterm/addon-fit";
import { SearchAddon } from "@xterm/addon-search";
import { Unicode11Addon } from "@xterm/addon-unicode11";
import { WebLinksAddon } from "@xterm/addon-web-links";
import {
  closeSession,
  createSession,
  onConnectionStatus,
  onSessionExited,
  onSessionOutput,
  removeKnownHost,
  resizeSession,
  runSnippetScript,
  writeToSession,
} from "@/lib/api/terminal";
import { subscribe, type UnlistenFn } from "@/lib/api/transport";
import { readClipboardText } from "@/lib/api/clipboard";
import { writeOnlyOsc52ClipboardProvider } from "@/lib/osc52-clipboard";
import { open as openExternalUrl } from "@tauri-apps/plugin-shell";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { quotePathForShell } from "@/lib/shell-quote";
import { listSnippets } from "@/lib/api/snippets";
import { listHosts } from "@/lib/api/hosts";
import { onSnippetsChanged } from "@/lib/snippets-events";
import { matchesOsTarget } from "@/features/snippets/osTargets";
import {
  ensureTerminalFontLoaded,
  getTerminalFontStack,
  loadTerminalAppearance,
  terminalAppearanceChangedEvent,
  terminalAppearanceStorageKey,
  type TerminalAppearance,
} from "@/lib/terminal-appearance";
import {
  appThemeChangedEvent,
  appThemeStorageKey,
  loadAppTheme,
  type AppTheme,
} from "@/lib/app-theme";
import {
  formatShortcut,
  isShortcutMatch,
  loadShortcuts,
  shortcutsChangedEvent,
  shortcutsStorageKey,
  type ShortcutBinding,
  type ShortcutMap,
} from "@/lib/shortcuts";
import { isMac, platform } from "@/lib/platform";
import { attachRtlOverlay, getRtlAwareSelection } from "@/lib/terminal-rtl-overlay";
import {
  attachSemanticHighlighter,
  loadSemanticHighlighting,
  semanticHighlightingChangedEvent,
  semanticHighlightingStorageKey,
} from "@/lib/terminal-highlighter";
import {
  applyEscapeToLineTracker,
  applyInjectedTextToLineTracker,
  applyRawInputToLineTracker,
  emptyLineTracker,
  isAtLineStart,
  type LineTrackerState,
} from "@/lib/terminal-line-tracker";
import {
  buildSearchOptions,
  clearFindSelectionAnchor,
  compileFindQuery,
  defaultFindOptions,
  finalizeFindSelection,
  findNextWithWrap,
  findPreviousWithWrap,
  getFindResultMeta,
  hasFindQuery,
  isFindSelectionClearSuppressed,
  isSearchableFindQuery,
  patchSearchAddonNonOverlappingHighlights,
  snapFindSelectionToCanonicalMatch,
  type FindOptions,
  type FindPart,
} from "@/lib/terminal-find";
import { TerminalFindBar } from "@/components/app/TerminalFindBar";
import * as ContextMenu from "@radix-ui/react-context-menu";
import type { OsKind, Snippet, SnippetGroup } from "@/components/app/types";
import { Search, Copy, Check, AlertTriangle, RefreshCw } from "lucide-react";

interface Props {
  sessionId?: string;
  initialCommand?: string;
  cwd?: string;
  hostId?: string;
  readyMarker?: string;
  connectionLabel?: string;
  connectionTitle?: string;
  isActive?: boolean;
  onClose?: () => void;
  onSessionCreated?: (sessionId: string) => void;
  /**
   * Quick Terminal glass mode: xterm paints its own opaque background canvas,
   * which would cover the translucent panel — this swaps it for a fully
   * transparent one so the panel's (blurred) backdrop shows through.
   */
  transparentBackground?: boolean;
  owner: "main" | "quick-terminal";
}

type ConnectionStage = "connecting" | "handshaking" | "authenticating" | "shell";
type ConnectionStatus = "active" | "done" | "failed";

interface ConnectionStatusPayload {
  stage: ConnectionStage;
  status: ConnectionStatus;
  message: string;
  log?: string | null;
}

const connectionSteps: Array<{ key: ConnectionStage; label: string; icon: string }> = [
  { key: "connecting", label: "Connecting", icon: "↗" },
  { key: "handshaking", label: "Handshaking", icon: "👋" },
  { key: "authenticating", label: "Authenticating", icon: "🔐" },
  { key: "shell", label: "Opening shell", icon: ">_" },
];

const initialConnectionStatus: ConnectionStatusPayload = {
  stage: "connecting",
  status: "active",
  message: "Opening TCP connection to SSH server...",
};

// Reconnect after an unexpected host disconnect: 3 attempts with increasing
// backoff, then give up and wait for the user to reconnect manually.
const RECONNECT_DELAYS_SEC = [2, 4, 8];
const MAX_RECONNECT_ATTEMPTS = RECONNECT_DELAYS_SEC.length;

interface ReconnectState {
  phase: "waiting" | "connecting" | "failed";
  attempt: number;
  countdown: number;
}

// Once the user has successfully opened a link with the modifier once, they
// know the gesture — the hover hint has done its job and would only be
// noise from then on. Persisted so it stays dismissed across restarts.
const linkHintDismissedKey = "termifai:link-hint-dismissed";

const menuItemCls =
  "flex cursor-pointer select-none items-center gap-2 rounded px-2.5 py-1.5 text-xs text-foreground outline-none data-[highlighted]:bg-[var(--color-surface-2)] data-[disabled]:pointer-events-none data-[disabled]:opacity-40";

function MenuShortcut({ binding }: { binding?: ShortcutBinding }) {
  if (!binding) return null;
  return <span className="text-[10px] text-muted-foreground">{formatShortcut(binding)}</span>;
}

function EnumDropdown({
  options,
  value,
  onChange,
  onConfirm,
  autoFocus,
}: {
  options: string[];
  value: string;
  onChange: (v: string) => void;
  onConfirm: (selectedValue: string) => void;
  autoFocus?: boolean;
}) {
  const [query, setQuery] = useState("");
  const [activeIdx, setActiveIdx] = useState(0);
  const searchRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const filtered = options.filter((o) =>
    o.toLowerCase().includes(query.toLowerCase())
  );

  useEffect(() => {
    if (autoFocus) searchRef.current?.focus();
  }, [autoFocus]);

  useEffect(() => {
    setActiveIdx(0);
  }, [query]);

  useEffect(() => {
    const el = listRef.current?.children[activeIdx] as HTMLElement | undefined;
    el?.scrollIntoView({ block: "nearest" });
  }, [activeIdx]);

  const confirm = (opt: string) => {
    onChange(opt);
    setQuery("");
    onConfirm(opt);
  };

  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center gap-1.5 rounded-md border border-border bg-[var(--color-surface)] px-2">
        <Search className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
        <input
          ref={searchRef}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") { e.preventDefault(); setActiveIdx((i) => Math.min(i + 1, filtered.length - 1)); }
            else if (e.key === "ArrowUp") { e.preventDefault(); setActiveIdx((i) => Math.max(i - 1, 0)); }
            else if (e.key === "Enter" && filtered[activeIdx]) { e.preventDefault(); confirm(filtered[activeIdx]); }
          }}
          placeholder="Search…"
          className="h-7 flex-1 bg-transparent text-sm text-foreground placeholder:text-muted-foreground focus:outline-none"
        />
        {value && <span className="shrink-0 rounded bg-[var(--color-surface-2)] px-1.5 py-0.5 text-xs text-foreground">{value}</span>}
      </div>
      <div ref={listRef} className="max-h-36 overflow-y-auto rounded-md border border-border bg-[var(--color-surface)]">
        {filtered.length === 0 ? (
          <div className="px-3 py-2 text-xs text-muted-foreground">No options</div>
        ) : filtered.map((opt, i) => (
          <button
            key={opt}
            type="button"
            onClick={() => confirm(opt)}
            className={[
              "flex w-full items-center gap-2 px-3 py-1.5 text-left text-sm transition",
              i === activeIdx ? "bg-[var(--color-surface-2)] text-foreground" : "text-foreground hover:bg-[var(--color-surface-2)]/60",
              opt === value ? "font-medium" : "",
            ].join(" ")}
          >
            {opt === value && <span className="h-1.5 w-1.5 rounded-full bg-[var(--color-brand-orange)]" />}
            {opt !== value && <span className="h-1.5 w-1.5" />}
            {opt}
          </button>
        ))}
      </div>
    </div>
  );
}

export function XTerminal({ sessionId, initialCommand, cwd, hostId, readyMarker, connectionLabel, connectionTitle, isActive, onClose, onSessionCreated, transparentBackground, owner }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const [isConnecting, setIsConnecting] = useState(Boolean(readyMarker && !sessionId));
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatusPayload>(initialConnectionStatus);
  const [connectionLogs, setConnectionLogs] = useState<string[]>([]);
  const [showConnectionLogs, setShowConnectionLogs] = useState(false);
  const [logsCopied, setLogsCopied] = useState(false);
  const [reconnectState, setReconnectState] = useState<ReconnectState | null>(null);

  const handleCopyConnectionLogs = useCallback(() => {
    if (connectionLogs.length === 0) return;
    const text = connectionLogs.join("\n");
    void navigator.clipboard.writeText(text);
    setLogsCopied(true);
    setTimeout(() => setLogsCopied(false), 2000);
  }, [connectionLogs]);
  const [snippetPalette, setSnippetPalette] = useState(false);
  const [snippets, setSnippets] = useState<Snippet[]>([]);
  const [snippetGroups, setSnippetGroups] = useState<SnippetGroup[]>([]);
  const [snippetQuery, setSnippetQuery] = useState("");
  const [snippetIndex, setSnippetIndex] = useState(0);
  const [variablePrompt, setVariablePrompt] = useState<{ snippet: Snippet; values: Record<string, string>; currentIdx: number } | null>(null);
  // Find bar — tokenized query + options, similar to Mac terminal
  const [findOpen, setFindOpen] = useState(false);
  const [findParts, setFindParts] = useState<FindPart[]>([]);
  const [findOptions, setFindOptions] = useState<FindOptions>(defaultFindOptions);
  const [findResultIndex, setFindResultIndex] = useState(-1);
  const [findResultCount, setFindResultCount] = useState(0);
  const [findFocusKey, setFindFocusKey] = useState(0);
  // Drives the enabled state of "Copy" in the terminal context menu.
  const [hasSelection, setHasSelection] = useState(false);
  // Hover hint for detected URLs: position (relative to the terminal
  // wrapper) plus the link text, shown as a small tooltip until the mouse
  // leaves the link.
  const [linkHint, setLinkHint] = useState<{ x: number; y: number; uri: string } | null>(null);
  // Resolved once per mount: local terminal tabs have no hostId, so `isLocal`
  // is true; SSH tabs look up the host's OS to gate OS-restricted snippets.
  const osContextRef = useRef<{ isLocal: boolean; hostOs?: OsKind }>({ isLocal: !hostId });
  // keyword -> snippet, for the text-only auto-expand feature. Only snippets
  // with no variables are eligible (mid-line variable prompts would be jarring).
  const keywordSnippetsRef = useRef<Map<string, Snippet>>(new Map());
  // Text typed since last Enter — directly from keystroke, not from xterm buffer
  // (PTY echo arrives later). Used for keyword expand and git command/script.
  const lineTrackerRef = useRef<LineTrackerState>(emptyLineTracker());
  const noteInjectedInput = (text: string) => {
    lineTrackerRef.current = applyInjectedTextToLineTracker(lineTrackerRef.current, text);
  };
  const shortcutsRefLocal = useRef<ShortcutMap>(loadShortcuts());
  const termRef = useRef<Terminal | null>(null);
  const sessionRef = useRef<string | null>(sessionId ?? null);
  const unlistenOutputRef = useRef<UnlistenFn | null>(null);
  const unlistenExitRef = useRef<UnlistenFn | null>(null);
  const unlistenConnectionRef = useRef<UnlistenFn | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);
  const searchAddonRef = useRef<SearchAddon | null>(null);
  const highlighterRef = useRef<ReturnType<typeof attachSemanticHighlighter> | null>(null);
  const rtlOverlayRef = useRef<ReturnType<typeof attachRtlOverlay> | null>(null);
  // Find actions are called from inside the terminal key handler (mount effect)
  const openFindRef = useRef<() => void>(() => {});
  const findNextActionRef = useRef<(incremental?: boolean) => void>(() => {});
  const findPreviousActionRef = useRef<() => void>(() => {});
  const findOptionsRef = useRef(findOptions);
  const findPartsRef = useRef(findParts);
  const findOpenRef = useRef(findOpen);
  const appThemeRef = useRef<AppTheme>(loadAppTheme());
  // Cmd+K / Clear menu — created inside effect because it needs term and highlighter
  const clearTerminalRef = useRef<(() => void) | null>(null);
  const isInitializedRef = useRef(false);
  const mountCountRef = useRef(0);
  const notifiedSessionRef = useRef<string | null>(sessionId ?? null);
  const appearanceRequestRef = useRef(0);
  const reconnectAttemptRef = useRef(0);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  // phase رو تو ref نگه می‌داریم تا handleDisconnect از mount-effect بدون
  // stale closure ببینه الان وسط reconnectیم یا نه.
  const reconnectPhaseRef = useRef<ReconnectState["phase"] | null>(null);
  // The drag-drop event fires at the webview level, not per-DOM-element, and
  // every tab's XTerminal (including hidden ones) mounts this listener — so
  // handlers read isActive from a ref to ignore drops over background tabs.
  const isActiveRef = useRef(isActive);
  useEffect(() => {
    isActiveRef.current = isActive;
  }, [isActive]);

  const clearReconnectTimers = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    if (reconnectIntervalRef.current) {
      clearInterval(reconnectIntervalRef.current);
      reconnectIntervalRef.current = null;
    }
  }, []);

  // Called whenever the PTY session ends unexpectedly. For SSH tabs (hostId
  // present) this kicks off the auto-reconnect flow; local shells just get
  // the old "press any key" message since there's no host to reconnect to.
  const handleDisconnect = () => {
    if (!hostId) {
      termRef.current?.write("\r\n\x1b[38;2;255;207;107m[Shell exited. Press any key to restart.]\x1b[0m\r\n");
      return;
    }
    // وسط backoff/connecting یا بعد از failed، attempt counter رو صفر نکن —
    // وگرنه هر keystroke روی session مرده از اول شروع می‌کنه و هیچ‌وقت failed نمی‌شه.
    const phase = reconnectPhaseRef.current;
    if (phase === "waiting" || phase === "connecting" || phase === "failed") {
      return;
    }
    termRef.current?.write("\r\n\x1b[38;2;255;99;99m[Connection to host lost.]\x1b[0m\r\n");
    reconnectAttemptRef.current = 0;
    scheduleReconnectAttempt();
  };

  const scheduleReconnectAttempt = () => {
    const attempt = reconnectAttemptRef.current + 1;
    reconnectAttemptRef.current = attempt;
    if (attempt > MAX_RECONNECT_ATTEMPTS) {
      clearReconnectTimers();
      reconnectPhaseRef.current = "failed";
      setReconnectState({ phase: "failed", attempt: MAX_RECONNECT_ATTEMPTS, countdown: 0 });
      return;
    }

    const delay = RECONNECT_DELAYS_SEC[attempt - 1];
    let remaining = delay;
    reconnectPhaseRef.current = "waiting";
    setReconnectState({ phase: "waiting", attempt, countdown: remaining });

    clearReconnectTimers();
    reconnectIntervalRef.current = setInterval(() => {
      remaining -= 1;
      setReconnectState((s) => (s && s.phase === "waiting" ? { ...s, countdown: Math.max(remaining, 0) } : s));
    }, 1000);
    reconnectTimeoutRef.current = setTimeout(() => {
      void performReconnect(attempt);
    }, delay * 1000);
  };

  const performReconnect = async (attempt: number) => {
    clearReconnectTimers();
    // termRef is nulled on unmount — a reconnect completing after that would
    // create an ownerless ssh session that (via tmux attach -D on the same
    // named session) kicks the client of whichever terminal replaced us.
    if (!termRef.current) return;
    reconnectPhaseRef.current = "connecting";
    setReconnectState({ phase: "connecting", attempt, countdown: 0 });
    const staleSid = sessionRef.current;
    try {
      const term = termRef.current;
      const newSid = crypto.randomUUID();

      // Register listeners against the new id before creating the session,
      // same ordering as the initial connect — otherwise output emitted
      // right after reconnect can be dropped before anything is listening.
      unlistenOutputRef.current?.();
      unlistenExitRef.current?.();
      unlistenOutputRef.current = await onSessionOutput(newSid, (chunk) => {
        termRef.current?.write(chunk);
      });
      unlistenExitRef.current = await onSessionExited(newSid, () => {
        handleDisconnect();
      });

      const info = await createSession({
        sessionId: newSid,
        cwd: cwd ?? "",
        initialCommand: initialCommand ?? null,
        hostId: hostId ?? null,
        readyMarker: readyMarker ?? null,
        owner,
        cols: term?.cols || undefined,
        rows: term?.rows || undefined,
      });
      if (!termRef.current) {
        closeSession(info.id).catch(() => {});
        return;
      }
      sessionRef.current = info.id;
      lineTrackerRef.current = emptyLineTracker();

      if (term?.cols && term?.rows) {
        await resizeSession(info.id, term.cols, term.rows);
      }

      // Keep the tab's persisted session id (AppShell state) in sync with the
      // live session — otherwise it stays pinned to the pre-reconnect id and
      // any later resync of sessionRef.current from that stale prop makes
      // every keystroke write into a dead/nonexistent session.
      notifiedSessionRef.current = info.id;
      onSessionCreated?.(info.id);
      if (staleSid && staleSid !== info.id) {
        closeSession(staleSid).catch(() => {});
      }

      reconnectAttemptRef.current = 0;
      reconnectPhaseRef.current = null;
      setReconnectState(null);
      term?.write("\r\n\x1b[38;2;120;220;140m[Reconnected.]\x1b[0m\r\n");
    } catch {
      scheduleReconnectAttempt();
    }
  };

  // Manual reconnect from the "failed" screen, or a manual retry at any point.
  const manualReconnect = useCallback(() => {
    clearReconnectTimers();
    reconnectAttemptRef.current = 0;
    reconnectPhaseRef.current = null;
    void performReconnect(1).catch(() => {});
  }, []);

  const [isResettingHostKey, setIsResettingHostKey] = useState(false);

  const isHostKeyChanged =
    connectionStatus.status === "failed" &&
    (connectionStatus.message.toLowerCase().includes("host key") ||
      connectionLogs.some(
        (log) =>
          log.toLowerCase().includes("identification has changed") ||
          log.toLowerCase().includes("host key verification failed") ||
          log.toLowerCase().includes("host key for")
      ));

  useEffect(() => {
    if (isHostKeyChanged) {
      clearReconnectTimers();
      setReconnectState(null);
    }
  }, [isHostKeyChanged, clearReconnectTimers]);

  const handleResetHostKey = useCallback(async () => {
    setIsResettingHostKey(true);
    try {
      let target = connectionLabel || initialCommand || "";
      if (!target) {
        for (const log of connectionLogs) {
          let match = log.match(/Host key for (.*?) has changed/i);
          if (match && match[1]) { target = match[1]; break; }
          
          match = log.match(/Authenticating to ([^\s:]+)/i);
          if (match && match[1]) { target = match[1]; break; }
          
          match = log.match(/Connecting to ([^\s]+)/i);
          if (match && match[1]) { target = match[1]; break; }
        }
      }

      if (!target) {
        throw new Error("Could not determine host IP to reset");
      }

      await removeKnownHost(target);
      setShowConnectionLogs(false);
      setIsResettingHostKey(false);
      setConnectionStatus({
        stage: "connecting",
        status: "active",
        message: "Host key reset. Please connect again.",
      });
    } catch (err) {
      console.error("Failed to reset host key:", err);
    } finally {
      setIsResettingHostKey(false);
    }
  }, [connectionLabel, initialCommand, connectionLogs, clearReconnectTimers]);

  // ── Terminal clipboard actions (context menu + Windows right-click) ───────
  const copySelection = useCallback(() => {
    const term = termRef.current;
    // On Persian/Arabic lines, selection columns are visual not logical — mapping needed
    const selection = term ? getRtlAwareSelection(term) : "";
    if (term && selection) {
      navigator.clipboard.writeText(selection).catch(() => {});
      term.clearSelection();
    }
  }, []);

  const pasteClipboard = useCallback(() => {
    const sid = sessionRef.current;
    if (!sid) return;
    // Read from native path so Mac's Paste confirmation bubble doesn't appear
    readClipboardText()
      .then((text) => {
        if (!text) return;
        noteInjectedInput(text);
        writeToSession(sid, text).catch(() => {});
      })
      .catch(() => {});
  }, []);

  const refocusTerminal = useCallback(() => {
    setTimeout(() => termRef.current?.focus(), 50);
  }, []);

  useEffect(() => {
    findOptionsRef.current = findOptions;
  }, [findOptions]);
  useEffect(() => {
    findPartsRef.current = findParts;
  }, [findParts]);
  useEffect(() => {
    findOpenRef.current = findOpen;
  }, [findOpen]);

  const compiledFindQuery = useCallback(() => {
    const parts = findPartsRef.current;
    if (!hasFindQuery(parts)) return "";
    return compileFindQuery(parts, findOptionsRef.current.matchMode);
  }, []);

  const syncFindResultMeta = useCallback(() => {
    const addon = searchAddonRef.current;
    const term = termRef.current;
    if (!addon || !term) return;
    // onDidChangeResults returns index -1 before snap (short Previous); we fix it ourselves
    const meta = getFindResultMeta(addon, term);
    setFindResultIndex(meta.index);
    setFindResultCount(meta.count);
  }, []);

  const runFindNext = useCallback(
    (incremental = false) => {
      const addon = searchAddonRef.current;
      const term = termRef.current;
      if (!addon || !term) return;
      const query = compiledFindQuery();
      const caseInsensitive = findOptionsRef.current.caseInsensitive;
      if (!query || !isSearchableFindQuery(query, caseInsensitive)) {
        addon.clearDecorations();
        term.clearSelection();
        clearFindSelectionAnchor();
        setFindResultIndex(-1);
        setFindResultCount(0);
        return;
      }
      findNextWithWrap(
        addon,
        term,
        query,
        buildSearchOptions(
          caseInsensitive,
          appThemeRef.current.xterm,
          appThemeRef.current.mode
        ),
        findOptionsRef.current.wrapAround,
        incremental
      );
      syncFindResultMeta();
    },
    [compiledFindQuery, syncFindResultMeta]
  );

  const runFindPrevious = useCallback(() => {
    const addon = searchAddonRef.current;
    const term = termRef.current;
    if (!addon || !term) return;
    const query = compiledFindQuery();
    const caseInsensitive = findOptionsRef.current.caseInsensitive;
    if (!query || !isSearchableFindQuery(query, caseInsensitive)) {
      addon.clearDecorations();
      term.clearSelection();
      clearFindSelectionAnchor();
      setFindResultIndex(-1);
      setFindResultCount(0);
      return;
    }
    findPreviousWithWrap(
      addon,
      term,
      query,
      buildSearchOptions(
        caseInsensitive,
        appThemeRef.current.xterm,
        appThemeRef.current.mode
      ),
      findOptionsRef.current.wrapAround
    );
    syncFindResultMeta();
  }, [compiledFindQuery, syncFindResultMeta]);

  const applyFindSelectionTheme = useCallback((enabled: boolean) => {
    const term = termRef.current;
    if (!term) return;
    const base = xtermTheme(appThemeRef.current);
    // SearchAddon selects again after paste; if selection FG is black
    // text disappears on dark decoration background — force light FG
    term.options.theme = enabled
      ? { ...base, selectionForeground: appThemeRef.current.xterm.brightWhite || "#ffffff" }
      : base;
  }, []);

  const openFind = useCallback(() => {
    const term = termRef.current;
    // RTL mapping — so search is seeded with what the user "sees" not raw buffer bytes
    const selection = term ? getRtlAwareSelection(term).trim() : "";
    if (selection && !findPartsRef.current.length) {
      // If something is selected, put it in the Find input
      const seeded: FindPart[] = [{ kind: "text", value: selection }];
      setFindParts(seeded);
      findPartsRef.current = seeded;
    }
    clearFindSelectionAnchor();
    // Semantic highlight mixes with Find decorations — disabled until Find closes
    highlighterRef.current?.setPaused(true);
    applyFindSelectionTheme(true);
    setFindOpen(true);
    setFindFocusKey((k) => k + 1);
  }, [applyFindSelectionTheme]);

  const closeFind = useCallback(() => {
    setFindOpen(false);
    searchAddonRef.current?.clearDecorations();
    clearFindSelectionAnchor();
    highlighterRef.current?.setPaused(false);
    applyFindSelectionTheme(false);
    setFindResultIndex(-1);
    setFindResultCount(0);
    refocusTerminal();
  }, [applyFindSelectionTheme, refocusTerminal]);

  useEffect(() => {
    openFindRef.current = openFind;
    findNextActionRef.current = runFindNext;
    findPreviousActionRef.current = runFindPrevious;
  }, [openFind, runFindNext, runFindPrevious]);

  // On query/option change, trigger incremental search
  useEffect(() => {
    if (!findOpen) return;
    runFindNext(true);
  }, [findOpen, findParts, findOptions, runFindNext]);

  // SearchAddon selects again after paste/write — clear it immediately
  useEffect(() => {
    if (!findOpen) return;
    const term = termRef.current;
    if (!term) return;
    const disp = term.onSelectionChange(() => {
      if (isFindSelectionClearSuppressed()) return;
      if (!term.hasSelection()) return;
      finalizeFindSelection(term);
    });
    // If there's a leftover selection, clear it right now
    if (term.hasSelection()) finalizeFindSelection(term);
    return () => disp.dispose();
  }, [findOpen]);

  // وقتی فوکوس روی ورودی Find هست، xterm کلید رو نمی‌بینه — از window می‌گیریم
  // فقط تب فعال؛ وگرنه Find مخفی شورتکات تب جاری رو می‌دزده
  useEffect(() => {
    if (!findOpen) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (!isActiveRef.current) return;
      const shortcuts = shortcutsRefLocal.current;
      if (shortcuts["find-in-terminal"] && isShortcutMatch(event, shortcuts["find-in-terminal"])) {
        event.preventDefault();
        event.stopPropagation();
        openFind();
        return;
      }
      if (shortcuts["find-next"] && isShortcutMatch(event, shortcuts["find-next"])) {
        event.preventDefault();
        event.stopPropagation();
        runFindNext(false);
        return;
      }
      if (shortcuts["find-previous"] && isShortcutMatch(event, shortcuts["find-previous"])) {
        event.preventDefault();
        event.stopPropagation();
        runFindPrevious();
      }
    };
    window.addEventListener("keydown", onKeyDown, true);
    return () => window.removeEventListener("keydown", onKeyDown, true);
  }, [findOpen, openFind, runFindNext, runFindPrevious]);

  // Windows terminal convention (VS Code / Windows Terminal default): right
  // click never shows a menu — it copies the selection if there is one,
  // otherwise pastes. macOS/Linux get a context menu instead (see render).
  const handleWindowsRightClick = useCallback(
    (event: React.MouseEvent) => {
      event.preventDefault();
      if (termRef.current?.hasSelection()) {
        copySelection();
      } else {
        pasteClipboard();
      }
    },
    [copySelection, pasteClipboard]
  );

  // Dropping a file/folder from the OS file manager onto the terminal types
  // its (shell-quoted) path, same convention as iTerm2/Terminal.app/Warp.
  // Tauri's drag-drop event is webview-scoped rather than per-element, so
  // every tab mounts this listener; isActiveRef filters drops that land
  // while this pane isn't the visible one.
  useEffect(() => {
    let unlisten: (() => void) | null = null;
    let cancelled = false;
    getCurrentWebview()
      .onDragDropEvent((event) => {
        if (!isActiveRef.current || event.payload.type !== "drop") return;
        const { paths } = event.payload;
        const sid = sessionRef.current;
        if (!sid || !paths.length) return;
        const text = paths.map(quotePathForShell).join(" ");
        noteInjectedInput(text);
        writeToSession(sid, text).catch(() => {});
        refocusTerminal();
      })
      .then((fn) => {
        if (cancelled) fn();
        else unlisten = fn;
      })
      .catch(() => {});
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [refocusTerminal]);

  const loadSnippets = useCallback(() => {
    return listSnippets().then((data) => {
      setSnippets(data.snippets);
      setSnippetGroups(data.groups);
      const map = new Map<string, Snippet>();
      for (const s of data.snippets) {
        if (
          s.kind === "text" &&
          s.keyword &&
          (!s.variables || s.variables.length === 0) &&
          matchesOsTarget(s.osTargets, osContextRef.current)
        ) {
          map.set(s.keyword, s);
        }
      }
      keywordSnippetsRef.current = map;
    });
  }, []);

  // Resolve this tab's OS context once, then (re)build the keyword map with it.
  useEffect(() => {
    let cancelled = false;
    if (!hostId) {
      osContextRef.current = { isLocal: true };
      void loadSnippets();
      return;
    }
    listHosts()
      .then(({ hosts }) => {
        if (cancelled) return;
        const host = hosts.find((h) => h.id === hostId);
        osContextRef.current = { isLocal: false, hostOs: host?.os };
        void loadSnippets();
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hostId]);

  // Refresh the palette + keyword map whenever a snippet is created, edited,
  // removed, or moved — otherwise changes made in the Snippets panel would
  // have no effect on terminals that were already open.
  useEffect(() => {
    const { unlisten } = onSnippetsChanged(() => void loadSnippets());
    return unlisten;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);


  // Constant per window (the quick-terminal window always passes true).
  const xtermTheme = (theme: AppTheme) =>
    transparentBackground ? { ...theme.xterm, background: "#00000000" } : theme.xterm;

  useLayoutEffect(() => {
    if (!ref.current || isInitializedRef.current) return;
    isInitializedRef.current = true;
    const mountId = ++mountCountRef.current;
    let destroyed = false;
    const appearance = loadTerminalAppearance();
    const appTheme = loadAppTheme();
    let unlistenAppearance: UnlistenFn | null = null;
    let unlistenAppTheme: UnlistenFn | null = null;

    const term = new Terminal({
      cursorBlink: true,
      fontFamily: getTerminalFontStack(appearance.fontFamily),
      fontSize: appearance.fontSize,
      lineHeight: appearance.lineHeight,
      theme: xtermTheme(appTheme),
      allowTransparency: true,
      scrollback: 50000,
      // registerDecoration (semantic highlighting) and parser.registerOscHandler
      // (ClipboardAddon's OSC52 support) are gated behind this flag and throw
      // without it.
      allowProposedApi: true,
    });

    // Unicode 6 width table sees emojis as single-cell; version 11 gives correct width (2 cells)
    // So wide glyphs don't overlap the next character (like 🚀Server without space)
    term.loadAddon(new Unicode11Addon());
    term.unicode.activeVersion = "11";

    const fit = new FitAddon();
    fitAddonRef.current = fit;
    term.loadAddon(fit);
    // Links open only with the platform modifier held (⌘ on macOS,
    // Ctrl elsewhere — the standard terminal-emulator convention), so a
    // plain click inside a URL still just moves selection. Opening goes
    // through the Tauri shell plugin: the webview's own window.open (the
    // addon's default handler) doesn't reach the system browser.
    term.loadAddon(
      new WebLinksAddon(
        (event, uri) => {
          if (!(isMac ? event.metaKey : event.ctrlKey)) return;
          setLinkHint(null);
          try {
            localStorage.setItem(linkHintDismissedKey, "1");
          } catch {
            /* storage unavailable — hint just stays on */
          }
          openExternalUrl(uri).catch((err) => console.error("open url failed:", err));
        },
        {
          hover: (event, uri) => {
            if (localStorage.getItem(linkHintDismissedKey)) return;
            const rect = ref.current?.getBoundingClientRect();
            if (!rect) return;
            setLinkHint({
              x: Math.max(0, Math.min(event.clientX - rect.left, rect.width - 340)),
              y: event.clientY - rect.top,
              uri,
            });
          },
          leave: () => setLinkHint(null),
        }
      )
    );
    // OSC52: ریموت می‌تونه به کلیپ‌بورد بنویسه (yank)، ولی کوئری خوندن
    // (`\e]52;c;?\a`) عمداً رد می‌شه تا محتوای لوکال به PTY نره.
    // سازنده Addon: (base64, provider) — provider تنها آرگومان اول نیست.
    term.loadAddon(new ClipboardAddon(new Base64(), writeOnlyOsc52ClipboardProvider));
    // باگ شمارش overlapping regex در addon-search@0.16 رو قبل از ساخت پچ کن
    patchSearchAddonNonOverlappingHighlights();
    const searchAddon = new SearchAddon();
    term.loadAddon(searchAddon);
    searchAddonRef.current = searchAddon;
    // After typing, addon hits findPrevious again via _updateMatches — snap/clear/index
    const resultsDisp = searchAddon.onDidChangeResults((e) => {
      if (findOpenRef.current && !isFindSelectionClearSuppressed()) {
        if (term.hasSelection()) {
          snapFindSelectionToCanonicalMatch(searchAddon, term);
          finalizeFindSelection(term);
        }
        const meta = getFindResultMeta(searchAddon, term);
        setFindResultIndex(meta.index);
        setFindResultCount(meta.count);
        return;
      }
      setFindResultIndex(e.resultIndex);
      setFindResultCount(e.resultCount);
    });
    term.open(ref.current);
    termRef.current = term;
    requestAnimationFrame(() => term.focus());

    // Semantic highlighting (URLs, IPs, paths, emails, ids, timestamps, log
    // keywords), colored from the active theme's own xterm palette so each
    // theme gets its own coherent set of highlight colors.
    let currentTheme = appTheme;
    appThemeRef.current = appTheme;
    const highlighter = attachSemanticHighlighter(term, () => currentTheme.xterm);
    highlighterRef.current = highlighter;
    // RTL layer: browser shaping + selection without breaking characters
    const rtlOverlay = attachRtlOverlay(term, () => currentTheme.xterm);
    rtlOverlayRef.current = rtlOverlay;

    // Cmd+K shouldn't just run synchronous term.clear():
    // 1) clear() mixes with write queue and moves pending cursor output to middle of screen
    // 2) Shell doesn't know about local clear; multiline prompts/starship redraw with wrong offset
    //    -> first few lines of ls etc. "disappear" or start from middle of viewport
    // 3) clearAllMarkers leaves highlighter without refresh
    // Solution: ED3 from write queue (clear scrollback) + Ctrl+L to shell (screen + sync cursor/prompt)
    const clearTerminalBuffer = () => {
      searchAddon.clearDecorations();
      if (term.buffer.active.type === "alternate") {
        // vim etc: viewport only; don't send Ctrl+L to avoid messing with app
        term.write("\x1b[H\x1b[2J", () => {
          if (!destroyed) {
            highlighter.refresh();
            rtlOverlay.refresh();
          }
        });
        return;
      }

      term.write("\x1b[3J", () => {
        if (destroyed) return;
        term.scrollToTop();
        highlighter.refresh();
        rtlOverlay.refresh();
      });

      const sid = sessionRef.current;
      if (sid) {
        writeToSession(sid, "\x0c").catch((err) => {
          console.error("clear terminal failed:", err);
        });
      } else {
        // No session yet — just clear the emulator
        term.write("\x1b[H\x1b[2J", () => {
          if (!destroyed) {
            highlighter.refresh();
            rtlOverlay.refresh();
          }
        });
      }
    };
    clearTerminalRef.current = clearTerminalBuffer;

    // Intercept terminal shortcuts before xterm processes them
    term.attachCustomKeyEventHandler((event) => {
      const shortcuts = shortcutsRefLocal.current;

      if (shortcuts["open-snippets"] && isShortcutMatch(event, shortcuts["open-snippets"])) {
        if (event.type === "keydown") {
          event.preventDefault();
          loadSnippets().then(() => {
            setSnippetQuery("");
            setSnippetIndex(0);
            setSnippetPalette(true);
          }).catch(() => {});
        }
        return false;
      }

      if (shortcuts["terminal-copy"] && isShortcutMatch(event, shortcuts["terminal-copy"])) {
        if (event.type === "keydown") {
          // RTL-aware version — on Persian lines it copies visible text not raw buffer
          const selection = getRtlAwareSelection(term);
          if (selection) {
            navigator.clipboard.writeText(selection).catch(() => {});
            term.clearSelection();
          }
        }
        return false;
      }

      if (shortcuts["terminal-paste"] && isShortcutMatch(event, shortcuts["terminal-paste"])) {
        if (event.type === "keydown") {
          // بدون preventDefault مرورگر هم paste می‌زنه → متن دو بار می‌ره تو PTY
          event.preventDefault();
          const sid = sessionRef.current;
          if (sid) {
            readClipboardText().then((text) => {
              if (!text) return;
              noteInjectedInput(text);
              writeToSession(sid, text).catch(() => {});
            }).catch(() => {});
          }
        }
        return false;
      }

      if (shortcuts["clear-terminal"] && isShortcutMatch(event, shortcuts["clear-terminal"])) {
        if (event.type === "keydown") {
          event.preventDefault();
          clearTerminalBuffer();
        }
        return false;
      }

      if (shortcuts["find-in-terminal"] && isShortcutMatch(event, shortcuts["find-in-terminal"])) {
        if (event.type === "keydown") {
          event.preventDefault();
          openFindRef.current();
        }
        return false;
      }

      if (shortcuts["find-next"] && isShortcutMatch(event, shortcuts["find-next"])) {
        if (event.type === "keydown") {
          event.preventDefault();
          findNextActionRef.current(false);
        }
        return false;
      }

      if (shortcuts["find-previous"] && isShortcutMatch(event, shortcuts["find-previous"])) {
        if (event.type === "keydown") {
          event.preventDefault();
          findPreviousActionRef.current();
        }
        return false;
      }

      return true;
    });

    // Tabs are never unmounted, just toggled with display:none (see
    // AppShell). A hidden container reports clientWidth/Height 0, and
    // fitting against that shrinks the terminal to bogus cols/rows — which
    // then gets pushed to the backend PTY via onResize below, corrupting
    // how already-written lines reflow once the tab is shown again. Skip
    // fitting whenever the container has no real layout box yet.
    const safeFit = () => {
      const el = ref.current;
      if (!el || el.clientWidth === 0 || el.clientHeight === 0) return;
      try {
        fit.fit();
      } catch {
        /* element not visible yet */
      }
    };
    requestAnimationFrame(safeFit);

    // Poll across frames until the container's layout box has been the same
    // size for a few consecutive frames, then fit. Used before creating a
    // fresh SSH session: `ssh -tt` execs straight into `tmux new-session -A`,
    // which births the remote window at whatever size the local PTY has *at
    // that moment* — tmux/byobu's window-size handling frequently doesn't
    // retroactively grow a window past its birth size even after a later
    // resize is forwarded over SSH. So the PTY needs the real, *settled*
    // size up front, not a guess corrected later. A single non-zero reading
    // isn't enough: right after a new tab is inserted the flex layout can
    // still be reflowing (and the terminal font may still be loading, which
    // changes cell measurements), so the first non-zero frame is often a
    // transient, too-small intermediate size rather than the final one.
    const waitForLayoutAndFit = (): Promise<void> =>
      new Promise((resolve) => {
        let attempts = 0;
        let lastW = -1;
        let lastH = -1;
        let stableFrames = 0;
        const tick = () => {
          const el = ref.current;
          const w = el?.clientWidth ?? 0;
          const h = el?.clientHeight ?? 0;
          if (w > 0 && h > 0) {
            stableFrames = w === lastW && h === lastH ? stableFrames + 1 : 0;
            lastW = w;
            lastH = h;
            if (stableFrames >= 4) {
              try {
                fit.fit();
              } catch {
                /* element not visible yet */
              }
              resolve();
              return;
            }
          }
          if (++attempts < 60) {
            requestAnimationFrame(tick);
          } else {
            try {
              fit.fit();
            } catch {
              /* element not visible yet */
            }
            resolve();
          }
        };
        requestAnimationFrame(tick);
      });

    const ro = new ResizeObserver(safeFit);
    ro.observe(ref.current);
    const applyAppearance = (nextAppearance: TerminalAppearance) => {
      const requestId = ++appearanceRequestRef.current;

      void ensureTerminalFontLoaded(nextAppearance).then(() => {
        if (requestId !== appearanceRequestRef.current) return;

        term.options.fontFamily = getTerminalFontStack(nextAppearance.fontFamily);
        term.options.fontSize = nextAppearance.fontSize;
        term.options.lineHeight = nextAppearance.lineHeight;
        safeFit();
        rtlOverlay.refresh();
      });
    };
    const onAppearanceChanged = (event: Event) => {
      applyAppearance((event as CustomEvent<TerminalAppearance>).detail);
    };
    const applyTheme = (theme: AppTheme) => {
      const base = xtermTheme(theme);
      // If Find is open, keep selection FG light so paste doesn't make text black
      term.options.theme = findOpenRef.current
        ? { ...base, selectionForeground: theme.xterm.brightWhite || "#ffffff" }
        : base;
      currentTheme = theme;
      appThemeRef.current = theme;
      // Find decorations were drawn with previous palette — search again with new theme
      highlighter.refresh();
      rtlOverlay.refresh();
      if (findOpenRef.current) {
        findNextActionRef.current(true);
      }
    };
    const onStorageChanged = (event: StorageEvent) => {
      if (event.key === terminalAppearanceStorageKey) {
        applyAppearance(loadTerminalAppearance());
      } else if (event.key === appThemeStorageKey) {
        applyTheme(loadAppTheme());
      } else if (event.key === semanticHighlightingStorageKey) {
        highlighter.setEnabled(loadSemanticHighlighting());
      }
    };
    const onAppThemeChanged = (event: Event) => {
      applyTheme((event as CustomEvent<AppTheme>).detail);
    };
    const onHighlightingChanged = (event: Event) => {
      highlighter.setEnabled((event as CustomEvent<boolean>).detail);
    };
    window.addEventListener(terminalAppearanceChangedEvent, onAppearanceChanged);
    window.addEventListener(appThemeChangedEvent, onAppThemeChanged);
    window.addEventListener(semanticHighlightingChangedEvent, onHighlightingChanged);
    window.addEventListener("storage", onStorageChanged);
    const onShortcutStorageChanged = (event: StorageEvent) => {
      if (event.key === shortcutsStorageKey) {
        shortcutsRefLocal.current = loadShortcuts();
      }
    };
    window.addEventListener("storage", onShortcutStorageChanged);
    void ensureTerminalFontLoaded(appearance).then(() => {
      term.options.fontFamily = getTerminalFontStack(appearance.fontFamily);
      term.options.fontSize = appearance.fontSize;
      term.options.lineHeight = appearance.lineHeight;
      safeFit();
    });
    void subscribe<TerminalAppearance>(terminalAppearanceChangedEvent, (event) => {
      applyAppearance(event.payload);
    })
      .then((unlisten) => {
        if (destroyed) { unlisten(); return; }
        unlistenAppearance = unlisten;
      })
      .catch(() => {});
    void subscribe<AppTheme>(appThemeChangedEvent, (event) => {
      applyTheme(event.payload);
    })
      .then((unlisten) => {
        if (destroyed) { unlisten(); return; }
        unlistenAppTheme = unlisten;
      })
      .catch(() => {});
    let unlistenHighlighting: UnlistenFn | null = null;
    void subscribe<boolean>(semanticHighlightingChangedEvent, (event) => {
      highlighter.setEnabled(event.payload);
    })
      .then((unlisten) => {
        if (destroyed) { unlisten(); return; }
        unlistenHighlighting = unlisten;
      })
      .catch(() => {});

    // Send keystrokes to backend PTY
    const dataDisp = term.onData((data) => {
      const sid = sessionRef.current;
      if (!sid) return;

      const send = (payload: string) =>
        writeToSession(sid, payload).catch((err) => {
          console.error("write_to_session failed:", err);
          // A "Session not found" write means the backend PTY behind sid is
          // gone (e.g. it was superseded by a reconnect this component
          // missed, or the process exited) — every future keystroke would
          // silently no-op otherwise. Trigger the same recovery path as an
          // unexpected disconnect instead of leaving the user stuck typing
          // into a dead session.
          if (sid === sessionRef.current && String(err).toLowerCase().includes("not found")) {
            handleDisconnect();
          }
        });

      if (data.length === 0) {
        return;
      }

      // Escape sequences (arrows, etc.) are tracked separately from printable text
      if (data.startsWith("\x1b")) {
        lineTrackerRef.current = applyEscapeToLineTracker(lineTrackerRef.current, data);
        send(data);
        return;
      }

      lineTrackerRef.current = applyRawInputToLineTracker(lineTrackerRef.current, data);
      send(data);

      // Immediate keyword match: as soon as the word just typed (tracked
      // locally from raw keystrokes, not read from the terminal's rendered
      // buffer — the buffer only reflects a keystroke once the PTY echoes it
      // back asynchronously) exactly equals a known keyword, expand it right
      // away without waiting for a boundary character. Only eligible on
      // kind === "text" snippets with no variables.
      // تو صفحهٔ جایگزین (vim/nano/…) اصلاً دست نزن — DEL+body فایل رو خراب می‌کنه.
      if (term.buffer.active.type === "alternate") {
        return;
      }
      const lineText = lineTrackerRef.current.text;
      const match = /(\S+)$/.exec(lineText);
      const word = match?.[1];
      const snippet = word ? keywordSnippetsRef.current.get(word) : undefined;
      if (snippet) {
        const body = snippet.body ?? "";
        lineTrackerRef.current = {
          ...lineTrackerRef.current,
          text: lineText.slice(0, -word!.length) + body,
        };
        const erase = "\x7f".repeat(word!.length);
        send(erase + body);
      }
    });

    const selectionDisp = term.onSelectionChange(() => {
      setHasSelection(term.hasSelection());
    });

    // Scrolling shifts link ranges under the pointer without a mouseleave,
    // so the hover hint would otherwise linger over unrelated content.
    const scrollDisp = term.onScroll(() => setLinkHint(null));

    // Notify backend on resize
    const resizeDisp = term.onResize(({ cols, rows }) => {
      const sid = sessionRef.current;
      if (sid) {
        resizeSession(sid, cols, rows).catch((err) =>
          console.error("resize_session failed:", err)
        );
      }
    });

    // Create PTY session and subscribe to output
    const setup = async () => {
      try {
        if (readyMarker) {
          unlistenConnectionRef.current = await onConnectionStatus<ConnectionStatusPayload>(
            readyMarker,
            (payload) => {
              if (payload.log) {
                setConnectionLogs((logs) => [...logs.slice(-80), payload.log as string]);
              }
              setConnectionStatus({
                stage: payload.stage,
                status: payload.status,
                message: payload.message,
              });
              if (payload.status === "done") {
                setTimeout(() => setIsConnecting(false), 350);
              } else if (payload.status === "failed") {
                setIsConnecting(true);
                setShowConnectionLogs(true);
              }
            }
          );
        }

        // Registers listeners for a brand-new session id *before* calling
        // createSession (Tauri drops events emitted with no listener
        // attached — any output the backend emits before this registration
        // lands would otherwise be silently lost), waits for the container's
        // real, settled layout so the PTY is opened at the right size (SSH
        // hosts exec straight into `tmux new-session -A`, which births the
        // remote window at whatever size the PTY has *right now* — tmux/byobu
        // won't reliably grow a window past its birth size even once a
        // later resize is forwarded), then creates the session.
        // Returns null when this setup pass was orphaned mid-flight (its
        // mount got cleaned up — Strict Mode double-invoke or a fast
        // unmount). Aborting matters beyond hygiene: a leaked ssh session
        // attaches the same named tmux session as the live one, and since
        // the attach uses `-D` (detach other clients), the orphan and the
        // real session would kick each other's client off in a loop — seen
        // by the user as several spurious auto-reconnects right after
        // connecting.
        const createFresh = async (): Promise<string | null> => {
          if (destroyed) return null;
          const newSid = crypto.randomUUID();
          sessionRef.current = newSid;

          unlistenOutputRef.current?.();
          unlistenExitRef.current?.();
          unlistenOutputRef.current = null;
          unlistenExitRef.current = null;

          const unlistenOutput = await onSessionOutput(newSid, (chunk) => {
            if (!readyMarker) setIsConnecting(false);
            term.write(chunk);
          });
          const unlistenExit = await onSessionExited(newSid, () => {
            if (!readyMarker) setIsConnecting(false);
            handleDisconnect();
          });

          // Tears down only what THIS pass created. The shared refs must
          // never be blanket-disposed here: with two setup passes in flight
          // (Strict Mode double-invoke), the refs may already hold the
          // *newer* pass's live listeners, and disposing those would leave
          // the surviving terminal deaf to all PTY output.
          const abort = (createdId?: string): null => {
            unlistenOutput();
            unlistenExit();
            if (unlistenOutputRef.current === unlistenOutput) unlistenOutputRef.current = null;
            if (unlistenExitRef.current === unlistenExit) unlistenExitRef.current = null;
            if (sessionRef.current === newSid) sessionRef.current = null;
            if (createdId) closeSession(createdId).catch(() => {});
            return null;
          };

          if (destroyed) return abort();
          unlistenOutputRef.current = unlistenOutput;
          unlistenExitRef.current = unlistenExit;

          // Character-cell measurements (and therefore fit()'s cols/rows)
          // depend on the terminal font actually being loaded — fitting
          // against a fallback font can under/over-count columns.
          await ensureTerminalFontLoaded(appearance).catch(() => {});
          await waitForLayoutAndFit();

          if (destroyed) return abort();

          const info = await createSession({
            sessionId: newSid,
            cwd: cwd ?? "",
            initialCommand: initialCommand ?? null,
            hostId: hostId ?? null,
            readyMarker: readyMarker ?? null,
            owner,
            cols: term.cols || undefined,
            rows: term.rows || undefined,
          });

          if (destroyed) return abort(info.id);

          sessionRef.current = info.id;
          notifiedSessionRef.current = info.id;
          lineTrackerRef.current = emptyLineTracker();
          onSessionCreated?.(info.id);
          return info.id;
        };

        let sid = sessionRef.current;
        if (!sid) {
          sid = await createFresh();
          if (!sid) return;
        } else {
          // Reattaching to an already-running session (e.g. remount, or a
          // tab restored from before an app restart/backend rebuild — in
          // which case the backend has no memory of this id at all). Probe
          // liveness with resize_session; if the backend reports the
          // session doesn't exist, fall back to creating a fresh one instead
          // of surfacing "Session not found" as a hard connection failure.
          try {
            if (term.cols && term.rows) {
              await resizeSession(sid, term.cols, term.rows);
            }
            const unlistenOutput = await onSessionOutput(sid, (chunk) => {
              if (!readyMarker) setIsConnecting(false);
              term.write(chunk);
            });
            const unlistenExit = await onSessionExited(sid, () => {
              if (!readyMarker) setIsConnecting(false);
              handleDisconnect();
            });
            // Orphaned mid-flight: dispose only our own listeners, never the
            // shared refs — a newer setup pass may own them by now.
            if (destroyed) {
              unlistenOutput();
              unlistenExit();
              return;
            }
            unlistenOutputRef.current = unlistenOutput;
            unlistenExitRef.current = unlistenExit;
          } catch (err) {
            if (!String(err).toLowerCase().includes("not found")) throw err;
            sid = await createFresh();
            if (!sid) return;
          }
        }

        if (destroyed) return;

        // Do an initial fit + resize notification to backend
        safeFit();
        if (term.cols && term.rows) {
          await resizeSession(sid, term.cols, term.rows);
        }
      } catch (err) {
        setConnectionStatus({
          stage: "connecting",
          status: "failed",
          message: `Failed to start shell: ${err}`,
        });
        setShowConnectionLogs(true);
        term.write(`\r\n\x1b[31mFailed to start shell: ${err}\x1b[0m\r\n`);
      }
    };

    setup();

    return () => {
      if (mountId !== mountCountRef.current) {
        // Strict Mode double-invoke: this mount is old, just clean up
        destroyed = true;
        clearTerminalRef.current = null;
        searchAddonRef.current = null;
        highlighterRef.current = null;
        rtlOverlayRef.current = null;
        ro.disconnect();
        dataDisp.dispose();
        selectionDisp.dispose();
        scrollDisp.dispose();
        resultsDisp.dispose();
        highlighter.dispose();
        rtlOverlay.dispose();
        resizeDisp.dispose();
        isInitializedRef.current = false;
        return;
      }
      destroyed = true;
      clearTerminalRef.current = null;
      searchAddonRef.current = null;
      highlighterRef.current = null;
      rtlOverlayRef.current = null;
      clearReconnectTimers();
      // تب بسته شد → session بک‌اند رو هم ببند، وگرنه PTY/SSH یتیم می‌مونه
      // (با resilient tmux حتی attach زنده‌ی بعدی رو هم با -AD می‌پره).
      const sidToClose = sessionRef.current;
      if (sidToClose) {
        closeSession(sidToClose).catch(() => {});
        sessionRef.current = null;
      }
      appearanceRequestRef.current += 1;
      window.removeEventListener(terminalAppearanceChangedEvent, onAppearanceChanged);
      window.removeEventListener(appThemeChangedEvent, onAppThemeChanged);
      window.removeEventListener(semanticHighlightingChangedEvent, onHighlightingChanged);
      window.removeEventListener("storage", onStorageChanged);
      window.removeEventListener("storage", onShortcutStorageChanged);
      unlistenAppTheme?.();
      unlistenAppearance?.();
      unlistenHighlighting?.();
      ro.disconnect();
      dataDisp.dispose();
      selectionDisp.dispose();
      scrollDisp.dispose();
      resultsDisp.dispose();
      highlighter.dispose();
      rtlOverlay.dispose();
      resizeDisp.dispose();
      unlistenOutputRef.current?.();
      unlistenExitRef.current?.();
      unlistenConnectionRef.current?.();
      unlistenOutputRef.current = null;
      unlistenExitRef.current = null;
      unlistenConnectionRef.current = null;
      fitAddonRef.current = null;
      termRef.current = null;
      isInitializedRef.current = false;
      term.dispose();
    };
  }, []);

  // Handle sessionId prop changes
  useEffect(() => {
    if (sessionId && sessionId !== sessionRef.current) {
      sessionRef.current = sessionId;
    }
  }, [sessionId]);

  const closeConnection = () => {
    const sid = sessionRef.current;
    if (sid) {
      closeSession(sid).catch(() => {});
    }
    onClose?.();
  };

  const activeIndex = connectionSteps.findIndex((step) => step.key === connectionStatus.stage);
  const safeActiveIndex = activeIndex >= 0 ? activeIndex : 0;
  const failedIndex = connectionStatus.status === "failed" ? safeActiveIndex : -1;
  // Notify parent when session is created
  useEffect(() => {
    const sid = sessionRef.current;
    if (sid && onSessionCreated && notifiedSessionRef.current !== sid) {
      notifiedSessionRef.current = sid;
      onSessionCreated(sid);
    }
  }, [onSessionCreated]);

  // A single requestAnimationFrame after a tab's container flips from
  // display:none to visible isn't reliably enough time for layout to land
  // on slower machines (seen on Intel Macs) — fitting too early measures a
  // stale/zero-size box and corrupts how the terminal reflows. Poll across
  // frames until the container actually has a size, capped so we don't spin
  // forever if it's legitimately hidden.
  const fitWhenLaidOut = useCallback((onDone?: () => void) => {
    let attempts = 0;
    const tick = () => {
      const el = ref.current;
      if (el && el.clientWidth > 0 && el.clientHeight > 0) {
        fitAddonRef.current?.fit();
        // fit() -> term.resize() is a no-op when it computes the same
        // cols/rows as before, which skips xterm's internal re-render. If
        // an earlier fit ran against a measurement that turned out to be
        // wrong (e.g. taken while the container was still hidden), this
        // guarantees a real repaint against the current, correct dimensions
        // instead of leaving stale content painted into a stale pixel box.
        const term = termRef.current;
        if (term) term.refresh(0, term.rows - 1);
        onDone?.();
        return;
      }
      if (++attempts < 20) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }, []);

  // تب غیرفعال مونده سوار — پالت/پرامپت/Find رو ببند تا کلید سراسری روی هاست مخفی شلیک نشه
  useEffect(() => {
    if (isActive) return;
    setSnippetPalette(false);
    setVariablePrompt(null);
    if (findOpenRef.current) closeFind();
  }, [isActive, closeFind]);

  // Re-fit and focus when this tab becomes active
  useEffect(() => {
    if (!isActive || isConnecting) return;
    fitWhenLaidOut(() => requestAnimationFrame(() => termRef.current?.focus()));
  }, [isActive, isConnecting, fitWhenLaidOut]);

  // Focus terminal when connection overlay is dismissed
  useEffect(() => {
    if (!isConnecting && termRef.current) {
      fitWhenLaidOut(() => requestAnimationFrame(() => termRef.current?.focus()));
    }
  }, [isConnecting, fitWhenLaidOut]);

  // ── Snippet Palette Logic ──────────────────────────────────────────────────

  // command/script only when input line is empty (not mid-type / shell history)
  const cursorAtLineStart = () => isAtLineStart(lineTrackerRef.current);

  // Full "Parent › Child" path for a snippet's group, or null when ungrouped —
  // used to cluster the palette by group instead of a flat list.
  const groupPathFor = (groupId: string | null | undefined): string | null => {
    if (!groupId) return null;
    const parts: string[] = [];
    let cur = snippetGroups.find((g) => g.id === groupId);
    while (cur) {
      parts.unshift(cur.name);
      cur = cur.parentId ? snippetGroups.find((g) => g.id === cur!.parentId) : undefined;
    }
    return parts.length > 0 ? parts.join(" › ") : null;
  };

  const filteredSnippets = snippets
    .filter((s) => {
      if (!matchesOsTarget(s.osTargets, osContextRef.current)) return false;
      if ((s.kind === "command" || s.kind === "script") && !cursorAtLineStart()) return false;
      // Filter by search query
      if (!snippetQuery.trim()) return true;
      const q = snippetQuery.toLowerCase();
      const content = s.body || s.command || s.script || "";
      return s.name.toLowerCase().includes(q) || content.toLowerCase().includes(q);
    })
    .sort((a, b) => {
      const pa = groupPathFor(a.groupId);
      const pb = groupPathFor(b.groupId);
      if (pa === pb) return 0;
      if (pa === null) return 1; // ungrouped snippets sort after grouped ones
      if (pb === null) return -1;
      return pa.localeCompare(pb);
    });

  const executeSnippet = useCallback((snippet: Snippet, varValues?: Record<string, string>) => {
    // تب مخفی نباید دستور بفرسته — پالت سراسری قبلاً روی هاست اشتباه شلیک می‌کرد
    if (!isActiveRef.current) return;
    const sid = sessionRef.current;
    if (!sid) return;
    if ((snippet.kind === "command" || snippet.kind === "script") && !cursorAtLineStart()) return;

    const resolveVars = (text: string) => {
      if (!snippet.variables?.length) return text;
      let resolved = text;
      for (const v of snippet.variables) {
        const val = varValues?.[v.name] ?? v.defaultValue ?? "";
        resolved = resolved.replaceAll(`{{${v.name}}}`, val);
        resolved = resolved.replaceAll(`\${${v.name}}`, val);
        resolved = resolved.replaceAll(`{${v.name}}`, val);
      }
      return resolved;
    };

    if (snippet.kind === "text") {
      const body = resolveVars(snippet.body ?? "");
      noteInjectedInput(body);
      writeToSession(sid, body).catch(() => {});
    } else if (snippet.kind === "command") {
      const cmd = resolveVars(snippet.command ?? "");
      noteInjectedInput(cmd + "\r");
      writeToSession(sid, cmd + "\r").catch(() => {});
    } else if (snippet.kind === "script") {
      const script = resolveVars(snippet.script ?? "");
      // Script executes from backend; assume input line is empty
      lineTrackerRef.current = emptyLineTracker();
      runSnippetScript(sid, snippet.name, script, snippet.runAsSudo).catch((err) =>
        console.error("run_snippet_script failed:", err)
      );
    }

    setSnippetPalette(false);
    setVariablePrompt(null);
    // Refocus terminal
    setTimeout(() => termRef.current?.focus(), 50);
  }, []);

  const selectSnippet = useCallback((snippet: Snippet) => {
    if (snippet.variables && snippet.variables.length > 0) {
      // Show variable prompt
      const defaults: Record<string, string> = {};
      for (const v of snippet.variables) {
        defaults[v.name] = v.defaultValue ?? (v.type === "enum" ? (v.options?.[0] ?? "") : "");
      }
      setVariablePrompt({ snippet, values: defaults, currentIdx: 0 });
      setSnippetPalette(false);
    } else {
      executeSnippet(snippet);
    }
  }, [executeSnippet]);

  const submitVariables = useCallback(() => {
    if (!variablePrompt) return;
    executeSnippet(variablePrompt.snippet, variablePrompt.values);
  }, [variablePrompt, executeSnippet]);

  // Palette keyboard navigation — فقط تب فعال؛ تب‌های display:none سوار می‌مونن
  useEffect(() => {
    if (!snippetPalette) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (!isActiveRef.current) return;
      if (e.key === "Escape") {
        e.preventDefault();
        setSnippetPalette(false);
        setTimeout(() => termRef.current?.focus(), 50);
      } else if (e.key === "ArrowDown") {
        e.preventDefault();
        setSnippetIndex((i) => Math.min(i + 1, filteredSnippets.length - 1));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setSnippetIndex((i) => Math.max(i - 1, 0));
      } else if (e.key === "Enter") {
        e.preventDefault();
        const selected = filteredSnippets[snippetIndex];
        if (selected) selectSnippet(selected);
      }
    };
    window.addEventListener("keydown", onKeyDown, true);
    return () => window.removeEventListener("keydown", onKeyDown, true);
  }, [snippetPalette, filteredSnippets, snippetIndex, selectSnippet]);

  // Reset index when query changes
  useEffect(() => { setSnippetIndex(0); }, [snippetQuery]);

  return (
    <div className="relative h-full w-full bg-background">
      {findOpen && (
        <TerminalFindBar
          options={findOptions}
          parts={findParts}
          resultIndex={findResultIndex}
          resultCount={findResultCount}
          focusKey={findFocusKey}
          onOptionsChange={setFindOptions}
          onPartsChange={setFindParts}
          onFindNext={() => runFindNext(false)}
          onFindPrevious={runFindPrevious}
          onClose={closeFind}
        />
      )}
      {linkHint && (
        <div
          className="pointer-events-none absolute z-30 flex max-w-[340px] items-center gap-2 rounded-md border border-border bg-popover px-2 py-1 text-xs shadow-lg"
          style={{ left: linkHint.x, top: linkHint.y + 18 }}
        >
          <span className="truncate font-mono text-foreground">{linkHint.uri}</span>
          <span className="shrink-0 text-muted-foreground">
            {isMac ? "⌘ + click to open" : "Ctrl + click to open"}
          </span>
        </div>
      )}
      {isConnecting && (
        <div className="absolute inset-0 z-10 flex flex-col items-center justify-center bg-background px-4 text-center">
          <div className="w-full max-w-2xl">
            <div className="mb-8 flex items-center gap-3 text-left">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-foreground text-background">
                <span className="font-mono text-sm font-bold">&gt;_</span>
              </div>
              <div>
                <h3 className="text-lg font-bold text-foreground select-text cursor-text">{connectionTitle ?? "SSH Session"}</h3>
                <p className="mt-0.5 text-sm font-medium text-muted-foreground select-text cursor-text">{connectionLabel}</p>
              </div>
            </div>

            <div className="mb-7 flex items-center">
              {connectionSteps.map((step, index) => {
                const isDone = index < safeActiveIndex || connectionStatus.status === "done";
                const isActive = index === safeActiveIndex && connectionStatus.status === "active";
                const isFailed = index === failedIndex;
                const lineDone = index < safeActiveIndex && connectionStatus.status !== "failed";
                return (
                  <div key={step.key} className="contents">
                    <div
                      className={[
                        "flex h-9 w-9 shrink-0 items-center justify-center rounded-full text-sm font-bold",
                        isFailed
                          ? "bg-red-500 text-white"
                          : isDone
                            ? "bg-[var(--color-brand-green)] text-white"
                            : isActive
                              ? "border-[3px] border-border bg-[var(--color-surface-2)] text-foreground"
                              : "border-[3px] border-border text-muted-foreground",
                      ].join(" ")}
                      title={step.label}
                    >
                      {isFailed ? "!" : isDone ? "✓" : isActive ? <div className="h-4 w-4 animate-spin rounded-full border-2 border-muted-foreground border-t-[var(--color-brand-orange)]" /> : step.icon}
                    </div>
                    {index < connectionSteps.length - 1 && (
                      <div className={`h-0.5 flex-1 ${lineDone ? "bg-[var(--color-brand-green)]" : "bg-border"}`} />
                    )}
                  </div>
                );
              })}
            </div>

            <div className="rounded-2xl bg-[var(--color-surface)] px-5 py-4 text-left">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <span className="block text-base font-bold text-foreground select-text cursor-text">
                    {connectionSteps[safeActiveIndex]?.label ?? "Connecting"}
                  </span>
                  <span className={`mt-1 block text-xs select-text cursor-text ${connectionStatus.status === "failed" ? "text-red-400" : "text-muted-foreground"}`}>
                    {connectionStatus.message}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  {showConnectionLogs && connectionLogs.length > 0 && (
                    <button
                      type="button"
                      onClick={handleCopyConnectionLogs}
                      className="flex items-center gap-1.5 rounded-md border border-border bg-[var(--color-surface-2)] px-2.5 py-1 text-xs font-semibold text-muted-foreground transition hover:text-foreground active:scale-95"
                      title="Copy all connection logs"
                    >
                      {logsCopied ? (
                        <>
                          <Check className="h-3.5 w-3.5 text-emerald-400" />
                          <span className="text-emerald-400">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="h-3.5 w-3.5" />
                          <span>Copy Logs</span>
                        </>
                      )}
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => setShowConnectionLogs((show) => !show)}
                    className="rounded-md border border-border bg-[var(--color-surface-2)] px-3 py-1 text-xs font-semibold text-muted-foreground hover:text-foreground"
                  >
                    {showConnectionLogs ? "Hide Logs" : "Show Logs"}
                  </button>
                </div>
              </div>
              {showConnectionLogs && (
                <div className="mt-3 max-h-40 overflow-auto rounded-lg border border-border bg-background/60 p-2.5 font-mono text-[11px] leading-5 text-muted-foreground select-text cursor-text">
                  {connectionLogs.length ? (
                    connectionLogs.map((log, index) => (
                      <div key={`${index}-${log}`} className="select-text cursor-text whitespace-pre-wrap break-all">
                        {log}
                      </div>
                    ))
                  ) : (
                    <span className="select-text cursor-text">Waiting for SSH logs...</span>
                  )}
                </div>
              )}
              {isHostKeyChanged && (
                <div className="mt-4 rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 text-left">
                  <div className="flex items-start gap-3">
                    <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-400" />
                    <div className="flex-1">
                      <h4 className="text-sm font-bold text-amber-300 select-text cursor-text">
                        Host Key Verification Failed
                      </h4>
                      <p className="mt-1 text-xs leading-relaxed text-amber-200/90 select-text cursor-text">
                        The remote host key for this server has changed since your last connection. This usually happens if the server was reinstalled or its SSH key was rotated.
                      </p>
                      <div className="mt-3 flex items-center gap-2">
                        <button
                          type="button"
                          disabled={isResettingHostKey}
                          onClick={handleResetHostKey}
                          className="flex items-center gap-2 rounded-lg bg-amber-500 px-3.5 py-1.5 text-xs font-bold text-black transition hover:bg-amber-400 active:scale-95 disabled:opacity-50"
                        >
                          {isResettingHostKey ? (
                            <span>Resetting host key...</span>
                          ) : (
                            <>
                              <RefreshCw className="h-3.5 w-3.5" />
                              <span>Reset Host Key</span>
                            </>
                          )}
                        </button>
                        <button
                          type="button"
                          onClick={closeConnection}
                          className="flex items-center gap-2 rounded-lg border border-amber-500/50 bg-transparent px-3.5 py-1.5 text-xs font-bold text-amber-500 transition hover:bg-amber-500/10 active:scale-95 disabled:opacity-50"
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>

            <button
              type="button"
              onClick={closeConnection}
              className="mt-6 h-9 w-full rounded-md border border-border bg-[var(--color-surface-2)] text-sm font-semibold text-foreground hover:bg-[var(--color-surface)]"
            >
              Close
            </button>
          </div>
        </div>
      )}
      {!isConnecting && reconnectState && (reconnectState.phase === "waiting" || reconnectState.phase === "connecting") && (
        <div className="absolute inset-x-0 top-0 z-10 flex items-center justify-between gap-3 border-b border-border bg-[var(--color-surface)]/95 px-4 py-2 text-xs backdrop-blur">
          <div className="flex items-center gap-3">
            {reconnectState.phase === "connecting" ? (
              <div className="flex items-center gap-2">
                <div className="h-3.5 w-3.5 shrink-0 animate-spin rounded-full border-2 border-muted-foreground border-t-red-400" />
                <span className="font-medium text-foreground">
                  Reconnecting… (attempt {reconnectState.attempt} of {MAX_RECONNECT_ATTEMPTS})
                </span>
              </div>
            ) : (
              <div className="flex items-center gap-3">
                <div className="relative flex h-6 w-6 items-center justify-center">
                  <svg className="h-full w-full -rotate-90 transform" viewBox="0 0 24 24">
                    <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="2" fill="none" className="text-muted/30" />
                    <circle 
                      cx="12" cy="12" r="10" 
                      stroke="currentColor" 
                      strokeWidth="2" 
                      fill="none" 
                      strokeDasharray="62.83" 
                      strokeDashoffset={Math.max(0, 62.83 - (62.83 * (reconnectState.countdown / (RECONNECT_DELAYS_SEC[reconnectState.attempt - 1] || 1))))} 
                      className="text-red-400 transition-all duration-1000 ease-linear" 
                    />
                  </svg>
                  <span className="absolute text-[9px] font-bold text-foreground">{reconnectState.countdown}</span>
                </div>
                <span className="font-medium text-foreground">
                  Connection lost — retrying ({reconnectState.attempt}/{MAX_RECONNECT_ATTEMPTS})
                </span>
              </div>
            )}
          </div>
          {reconnectState.phase === "waiting" && (
            <button
              type="button"
              onClick={() => { clearReconnectTimers(); void performReconnect(reconnectState.attempt); }}
              className="shrink-0 flex items-center gap-1.5 rounded-md border border-border bg-[var(--color-surface-2)] px-2.5 py-1 text-xs font-semibold text-foreground transition hover:bg-[var(--color-surface)] active:scale-95"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Reconnect Now
            </button>
          )}
        </div>
      )}

      {!isConnecting && reconnectState?.phase === "failed" && (
        <div className="absolute inset-0 z-20 flex flex-col items-center justify-center bg-background/95 px-4 text-center backdrop-blur">
          <div className="w-full max-w-sm">
            <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-red-500/15 text-red-400">
              <span className="text-2xl">⚠</span>
            </div>
            <h3 className="text-base font-bold text-foreground">Connection lost</h3>
            <p className="mt-1.5 text-sm text-muted-foreground">
              Couldn&apos;t reconnect after {MAX_RECONNECT_ATTEMPTS} attempts. Your terminal history is preserved.
            </p>
            <button
              type="button"
              onClick={manualReconnect}
              className="mt-5 h-9 w-full rounded-md bg-[var(--color-brand-orange,oklch(0.75_0.15_55))] text-sm font-semibold text-white hover:opacity-90"
            >
              Connect
            </button>
          </div>
        </div>
      )}

      {/*
        The terminal element is never itself hidden while connecting — the
        opaque, fully-covering overlay above (bg-background, inset-0, z-10)
        already obscures it visually. Toggling this element's own
        `visibility` used to also gate it, but xterm.js's FitAddon/
        CharSizeService measures character-cell size via a probe element in
        this same DOM subtree, and `visibility:hidden` produced unreliable
        cell measurements on some platforms — cols/rows would get pinned to
        a stale, too-small size that a later fit (once visible) wouldn't
        recompute, since xterm.js treats a resize() to the same cols/rows as
        a no-op and skips re-rendering its internal canvas to the right
        pixel size.
      */}
      {platform === "windows" ? (
        <div
          ref={ref}
          className="xterm-wrapper h-full w-full pl-1 pt-1"
          onContextMenu={handleWindowsRightClick}
        />
      ) : (
        <ContextMenu.Root>
          <ContextMenu.Trigger asChild>
            <div
              ref={ref}
              className="xterm-wrapper h-full w-full pl-1 pt-1"
            />
          </ContextMenu.Trigger>
          <ContextMenu.Portal>
            <ContextMenu.Content
              className="z-50 min-w-[180px] overflow-hidden rounded-lg border border-border bg-popover p-1 shadow-xl"
              onCloseAutoFocus={(e) => {
                e.preventDefault();
                refocusTerminal();
              }}
            >
              <ContextMenu.Item className={menuItemCls} disabled={!hasSelection} onSelect={copySelection}>
                <span className="flex-1">Copy</span>
                <MenuShortcut binding={shortcutsRefLocal.current["terminal-copy"]} />
              </ContextMenu.Item>
              <ContextMenu.Item className={menuItemCls} onSelect={pasteClipboard}>
                <span className="flex-1">Paste</span>
                <MenuShortcut binding={shortcutsRefLocal.current["terminal-paste"]} />
              </ContextMenu.Item>
              <ContextMenu.Item className={menuItemCls} onSelect={() => termRef.current?.selectAll()}>
                <span className="flex-1">Select All</span>
              </ContextMenu.Item>
              <ContextMenu.Item className={menuItemCls} onSelect={() => openFind()}>
                <span className="flex-1">Find…</span>
                <MenuShortcut binding={shortcutsRefLocal.current["find-in-terminal"]} />
              </ContextMenu.Item>
              <ContextMenu.Separator className="my-1 h-px bg-border" />
              <ContextMenu.Item className={menuItemCls} onSelect={() => clearTerminalRef.current?.()}>
                <span className="flex-1">Clear</span>
                <MenuShortcut binding={shortcutsRefLocal.current["clear-terminal"]} />
              </ContextMenu.Item>
            </ContextMenu.Content>
          </ContextMenu.Portal>
        </ContextMenu.Root>
      )}

      {/* Snippet Palette */}
      {snippetPalette && (
        <div className="absolute inset-0 z-20 flex items-start justify-center pt-12" onClick={() => { setSnippetPalette(false); setTimeout(() => termRef.current?.focus(), 50); }}>
          <div
            className="w-[420px] max-h-[360px] flex flex-col overflow-hidden rounded-lg border border-border bg-popover shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center gap-2 border-b border-border px-3 py-2">
              <svg className="h-4 w-4 text-muted-foreground" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
              <input
                autoFocus
                value={snippetQuery}
                onChange={(e) => setSnippetQuery(e.target.value)}
                placeholder="Search snippets…"
                className="flex-1 bg-transparent text-sm text-foreground placeholder:text-muted-foreground focus:outline-none"
              />
              <kbd className="rounded border border-border bg-[var(--color-surface-2)] px-1.5 py-0.5 text-[10px] text-muted-foreground">ESC</kbd>
            </div>
            <div className="flex-1 overflow-y-auto">
              {filteredSnippets.length === 0 ? (
                <div className="px-4 py-6 text-center text-sm text-muted-foreground">
                  No snippets found.
                </div>
              ) : (
                filteredSnippets.map((s, i) => {
                  const kindColors: Record<string, string> = { text: "oklch(0.55_0.15_160)", command: "oklch(0.45_0.15_230)", script: "oklch(0.55_0.15_300)" };
                  const kindLabels: Record<string, string> = { text: "Text", command: "Cmd", script: "Script" };
                  const groupPath = groupPathFor(s.groupId);
                  const prevGroupPath = i > 0 ? groupPathFor(filteredSnippets[i - 1].groupId) : undefined;
                  const showGroupHeader = groupPath !== prevGroupPath;
                  return (
                    <div key={s.id}>
                      {showGroupHeader && (
                        <div className="px-3 pb-1 pt-2.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/70 first:pt-1.5">
                          {groupPath ?? "Ungrouped"}
                        </div>
                      )}
                      <div
                        onClick={() => selectSnippet(s)}
                        className={[
                          "flex cursor-pointer items-center gap-3 px-3 py-2 transition",
                          i === snippetIndex ? "bg-[var(--color-surface-2)]" : "hover:bg-[var(--color-surface-2)]/60",
                        ].join(" ")}
                      >
                        <div className="flex items-center gap-1.5 shrink-0">
                          <span className="flex h-7 w-7 items-center justify-center rounded text-[10px] font-bold text-white" style={{ backgroundColor: kindColors[s.kind] || kindColors.command }}>
                            {kindLabels[s.kind]?.[0] || "C"}
                          </span>
                          {s.runAsSudo && (
                            <span className="rounded bg-red-600 px-1 py-0.5 text-[8px] font-black text-white uppercase tracking-wider select-none leading-none">
                              sudo
                            </span>
                          )}
                        </div>
                        <div className="min-w-0 flex-1">
                          <div className="truncate text-sm font-medium text-foreground">{s.name}</div>
                          <div className="truncate text-xs text-muted-foreground font-mono">{s.body || s.command || s.script || ""}</div>
                        </div>
                        <span className="shrink-0 rounded bg-[var(--color-surface-2)] px-1.5 py-0.5 text-[10px] text-muted-foreground">{kindLabels[s.kind] || "Command"}</span>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>
      )}

      {/* Variable Prompt — wizard: one variable at a time */}
      {variablePrompt && (() => {
        const vars = variablePrompt.snippet.variables ?? [];
        const idx = variablePrompt.currentIdx;
        const v = vars[idx];
        const isLast = idx === vars.length - 1;
        if (!v) return null;

        const goNext = (val: string) => {
          const merged = { ...variablePrompt.values, [v.name]: val };
          if (isLast) {
            executeSnippet(variablePrompt.snippet, merged);
          } else {
            setVariablePrompt((prev) => prev ? { ...prev, values: merged, currentIdx: idx + 1 } : null);
          }
        };

        const goPrev = () => {
          if (idx > 0) setVariablePrompt((prev) => prev ? { ...prev, currentIdx: idx - 1 } : null);
        };

        return (
          <div className="absolute inset-0 z-20 flex items-start justify-center pt-12" onClick={() => { setVariablePrompt(null); setTimeout(() => termRef.current?.focus(), 50); }}>
            <div
              className="w-[400px] flex flex-col overflow-hidden rounded-lg border border-border bg-popover shadow-2xl"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="border-b border-border px-4 py-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-foreground">{variablePrompt.snippet.name}</h3>
                  <span className="text-xs text-muted-foreground">{idx + 1} / {vars.length}</span>
                </div>
                <div className="mt-1.5 flex gap-1">
                  {vars.map((_, i) => (
                    <span key={i} className={["h-1 flex-1 rounded-full transition-colors", i <= idx ? "bg-[var(--color-brand-orange)]" : "bg-border"].join(" ")} />
                  ))}
                </div>
              </div>
              <div className="px-4 py-4">
                <label className="mb-2 block text-xs font-medium text-foreground">{v.label || v.name}</label>
                {v.type === "enum" ? (
                  <EnumDropdown
                    options={v.options ?? []}
                    value={variablePrompt.values[v.name] ?? ""}
                    onChange={(val) => setVariablePrompt((prev) => prev ? { ...prev, values: { ...prev.values, [v.name]: val } } : null)}
                    onConfirm={(val) => goNext(val)}
                    autoFocus
                  />
                ) : (
                  <input
                    autoFocus
                    value={variablePrompt.values[v.name] ?? ""}
                    onChange={(e) => setVariablePrompt((prev) => prev ? { ...prev, values: { ...prev.values, [v.name]: e.target.value } } : null)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") goNext(variablePrompt.values[v.name] ?? "");
                    }}
                    placeholder={v.defaultValue || v.name}
                    className="h-8 w-full rounded-md border border-border bg-[var(--color-surface)] px-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring/40"
                  />
                )}
              </div>
              <div className="flex items-center justify-between border-t border-border px-4 py-2.5">
                <button
                  onClick={() => { setVariablePrompt(null); setTimeout(() => termRef.current?.focus(), 50); }}
                  className="rounded-md px-3 py-1.5 text-xs font-medium text-muted-foreground hover:bg-[var(--color-surface-2)] hover:text-foreground"
                >
                  Cancel
                </button>
                <div className="flex items-center gap-2">
                  {idx > 0 && (
                    <button
                      onClick={goPrev}
                      className="rounded-md border border-border px-3 py-1.5 text-xs font-medium text-foreground hover:bg-[var(--color-surface-2)]"
                    >
                      Back
                    </button>
                  )}
                  <button
                    onClick={() => goNext(variablePrompt.values[v.name] ?? "")}
                    className="rounded-md bg-[var(--color-brand-orange,oklch(0.75_0.15_55))] px-3 py-1.5 text-xs font-semibold text-white hover:opacity-90"
                  >
                    {isLast ? "Execute" : "Next"}
                  </button>
                </div>
              </div>
            </div>
          </div>
        );
      })()}
    </div>
  );
}
