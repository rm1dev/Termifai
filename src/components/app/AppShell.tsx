import { useState, useRef, useEffect, useCallback, forwardRef } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { platform } from "@/lib/platform";
import { posixShellQuote } from "@/lib/shell-quote";
import { subscribe } from "@/lib/api/transport";
import { forceQuitApp, openSettingsWindow, quitApp, takePendingOpenFolders } from "@/lib/api/terminal";
import { listSshKeys } from "@/lib/api/ssh-keys";
import { pushSyncSettingsCache } from "@/lib/sync-settings-cache";
import {
  Server,
  Network,
  Braces,
  KeyRound,
  ClipboardList,
  Plus,
  TerminalSquare,
  Folder,
  PanelTopClose,
  PanelBottomClose,
  PanelLeftClose,
  PanelRightClose,
  Pin,
  PinOff,
  X,
  LayoutDashboard,
  LayoutGrid,
  Minus,
  Square,
  Menu,
  Maximize2,
  ChevronLeft,
  ChevronRight,
  ListFilter,
  Search,
} from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import type { AppTab, Host, SidebarKey, TabKind } from "./types";
import { XTerminal } from "./XTerminal";
import type { QuickTerminalEdge } from "@/lib/api/quick-terminal";
import {
  isShortcutMatch,
  loadShortcuts,
  shortcutsChangedEvent,
  shortcutsStorageKey,
  type ShortcutMap,
} from "@/lib/shortcuts";
import {
  DndContext,
  PointerSensor,
  useSensor,
  useSensors,
  closestCenter,
  type DragEndEvent,
} from "@dnd-kit/core";
import { restrictToHorizontalAxis, restrictToParentElement } from "@dnd-kit/modifiers";
import {
  SortableContext,
  horizontalListSortingStrategy,
  useSortable,
  arrayMove,
} from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
import { VaultGate } from "./VaultGate";
import { vaultStatus, vaultLock } from "@/lib/api/vault";
import type { VaultStatus } from "@/lib/api/vault";
import { EmptyState } from "@/components/shared/modal-primitives";
import { PortForwardingView } from "@/features/port-forwarding/PortForwardingView";
import { SshKeysView } from "@/features/ssh-keys/SshKeysView";
import { HostsView } from "@/features/hosts/HostsView";
import { SftpView } from "@/features/sftp/SftpView";
import { DashboardView } from "@/features/dashboard/DashboardView";
import { SnippetsView } from "@/features/snippets/SnippetsView";

const sidebarItems: { key: SidebarKey; label: string; icon: typeof Server }[] = [
  { key: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { key: "hosts", label: "Hosts", icon: Server },
  { key: "port-forwarding", label: "Port Forwarding", icon: Network },
  { key: "snippets", label: "Snippets", icon: Braces },
  { key: "ssh-keys", label: "SSH Keys", icon: KeyRound },
  // { key: "logs", label: "Logs", icon: ClipboardList },
];

export interface AppShellProps {
  /**
   * "main" (default): standard window with window controls and drag region.
   * "quick-terminal": Quake-style drop-down panel with glassmorphism,
   * no window dragging, no window controls, and a hide button in the tab
   * bar that collapses the panel via `onRequestClose`.
   */
  variant?: "main" | "quick-terminal";
  onRequestClose?: () => void;
  quickTerminalEdge?: QuickTerminalEdge;
}

export function AppShell({
  variant = "main",
  onRequestClose,
  quickTerminalEdge,
}: AppShellProps = {}) {
  const [tabs, setTabs] = useState<AppTab[]>([
    { id: "t-vaults", kind: "vaults", title: "Hosts", closable: false },
    { id: "t-term", kind: "terminal", title: "Local Terminal", closable: true },
  ]);
  const [activeTab, setActiveTab] = useState("t-term");
  const [activeSidebar, setActiveSidebar] = useState<SidebarKey>("hosts");
  // Cached vault status; the Hosts view is gated by VaultGate until the vault
  // is unlocked, rather than prompting with a modal on app startup.
  const [vaultInfo, setVaultInfo] = useState<{ initialized: boolean; unlocked: boolean } | null>(null);
  const shortcutsRef = useRef<ShortcutMap>(loadShortcuts());
  const newTabRef = useRef<(kind: TabKind) => void>(null!);

  const newTab = (kind: TabKind) => {
    const id = `t-${kind}-${Date.now()}`;
    const title =
      kind === "terminal" ? "Local Terminal" : kind === "sftp" ? "SFTP" : "Hosts";
    setTabs((t) => [...t, { id, kind, title, closable: true }]);
    setActiveTab(id);
  };
  const openFolderTab = (folderPath: string) => {
    const id = `t-terminal-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const title = folderPath.split(/[/\\]/).filter(Boolean).pop() || folderPath;
    setTabs((t) => [...t, { id, kind: "terminal", title, closable: true, cwd: folderPath }]);
    setActiveTab(id);
  };

  // Folders arriving from the macOS Finder extension ("Open in Termifai").
  // Paths are queued on the Rust side; drain on mount (covers cold launch,
  // where the URL arrives before the webview is ready) and on every
  // open-folder-pending signal (app already running).
  useEffect(() => {
    if (variant !== "main") return;
    const drain = () => {
      void takePendingOpenFolders().then((paths) => {
        for (const p of paths) openFolderTab(p);
      });
    };
    drain();
    const unlistenPromise = subscribe("open-folder-pending", drain);
    return () => {
      void unlistenPromise.then((unlisten) => unlisten());
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [variant]);

  const openSshTerminal = async (host: Host) => {
    const id = `t-ssh-${host.id}-${Date.now()}`;
    let keyArg = "";
    if (host.sshKeyId) {
      try {
        const keys = await listSshKeys();
        const key = keys.find((item) => item.id === host.sshKeyId);
        if (key?.privateKeyPath) keyArg = ` -i ${posixShellQuote(key.privateKeyPath)}`;
      } catch {
        /* SSH can still use agent/default keys. */
      }
    }
    const portArg = host.port && host.port !== 22 ? ` -p ${host.port}` : "";
    const readyMarker = `__TERMIFAI_CONNECTED_${Date.now()}__`;
    // مسیر working dir رو quote کن وگرنه فاصله/متاکاراکتر شل ریموت رو می‌شکنه یا تزریق می‌کنه
    const cdPart = host.workingDirectory?.trim()
      ? `cd ${posixShellQuote(host.workingDirectory.trim())} 2>/dev/null; `
      : "";
    // Stable per-tab tmux session name (fixed at tab creation, reused verbatim
    // on every reconnect attempt): if tmux is on the remote host, attach to —
    // or create — this named session instead of spawning a plain login shell,
    // so a dropped connection resumes the exact same shell (cwd, env, running
    // jobs, scrollback) rather than a fresh one. Falls back to a plain shell
    // when tmux isn't installed.
    //
    // این مسیر tmux فقط وقتی فعاله که «Resilient Session» روی هاست روشن باشه.
    // چون tmux موقع خروجی burst (مثل cat یه فایل ۱۰۰ خطی) فقط آخرین صفحه رو
    // برای ترمینال می‌کشه و خط‌های قبلی هیچ‌وقت به اسکرول‌بک لوکال xterm
    // نمی‌رسن (رفتار عمدی tmux — issue #1019). vim هم با ترفند smcup@ روی
    // بافر عادی می‌مونه و چرخ موس به‌جای حرکت کرسر، اسکرول‌بک رو تکون می‌ده.
    // پیش‌فرض: شل سادهٔ ssh → اسکرول‌بک کامل و رفتار native برای vim/nano.
    const tmuxSession = id.replace(/[^a-zA-Z0-9_-]/g, "_");
    const plainShell = "${SHELL:-/bin/sh} -i";
    // -D detaches every other client from the session when attaching. Without
    // it, a client left over from a previous connection that died without
    // detaching (network drop, app quit, reconnect) stays "attached" from
    // tmux's point of view, and tmux clamps the window to the smallest
    // attached client — pinning the visible area to that dead client's old
    // geometry and filling the rest of the pane with its dotted placeholder
    // pattern. Each tab owns its named session exclusively, so stealing the
    // attachment is always correct here.
    //
    // `\; set-option status off` hides tmux's status bar in these sessions:
    // tmux here is an invisible resilience layer (the session survives a
    // dropped connection), not something the user asked for, so its status
    // line reads as unexplained UI. Session-scoped — a user's own tmux
    // sessions on the host keep their status bar.
    //
    // `smcup@:rmcup@` tells tmux the outer terminal has no alternate
    // screen, so tmux draws on the NORMAL buffer. That's what keeps the
    // terminal behaving like a plain (non-tmux) one: lines that scroll off
    // the top land in xterm.js's own local scrollback, giving the native
    // scrollbar, instant wheel scrolling with no network round-trip, and no
    // wheel→arrow-keys translation (xterm.js only does that in the alt
    // buffer). tmux's mouse mode stays OFF for the same reason — with it
    // on, tmux owns the wheel (laggy remote copy-mode), drag-selection, and
    // right-click (its own popup menu instead of the app's). This is the
    // standard "native scrollback" tmux setup.
    //
    // `-L termifai` runs these sessions on a dedicated tmux server socket:
    // terminal-overrides is server-global, and quietly stripping alt-screen
    // support from the user's own tmux sessions on the host would corrupt
    // their setup.
    //
    // terminal-overrides must be set BEFORE new-session — it's consulted
    // when the client attaches. status off is session-scoped, so it comes
    // after. Plain -g (not -ga) keeps the override idempotent across
    // reconnects.
    const tmuxAttach =
      `tmux -L termifai set-option -g terminal-overrides ",xterm-256color:smcup@:rmcup@"` +
      ` \\; new-session -AD -s ${tmuxSession}` +
      ` \\; set-option status off`;
    const remoteBootstrap = host.resilientSession
      ? `printf '${readyMarker}\\n'; ${cdPart}` +
        `if command -v tmux >/dev/null 2>&1; then exec ${tmuxAttach}; else exec ${plainShell}; fi`
      : `printf '${readyMarker}\\n'; ${cdPart}exec ${plainShell}`;
    // accept-new: trust a host's key on first contact and record it in the user's
    // known_hosts, but hard-fail if a previously recorded key changes (unlike
    // StrictHostKeyChecking=no, which trusted every connection unconditionally).
    // ServerAlive*: let ssh itself detect a dead connection (3 missed keepalives,
    // ~15s) instead of us guessing from unanswered keystrokes — that would
    // misfire on ordinary latency spikes or brief network blips.
    const command = `ssh -v -tt -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=5 -o ServerAliveCountMax=3${keyArg}${portArg} ${posixShellQuote(`${host.user}@${host.hostname}`)} ${posixShellQuote(remoteBootstrap)}`;

    // Count existing tabs for this host to generate a numbered title
    const baseTitle = host.name || host.hostname;
    setTabs((currentTabs) => {
      const existingCount = currentTabs.filter((t) => t.hostId === host.id).length;
      const title = existingCount > 0 ? `${baseTitle} (${existingCount + 1})` : baseTitle;
      return [
        ...currentTabs,
        {
          id,
          kind: "terminal",
          title,
          closable: true,
          initialCommand: command,
          readyMarker,
          connectionLabel: `${host.user}@${host.hostname}:${host.port}`,
          connectionTitle: host.name || host.hostname,
          hostId: host.id,
        },
      ];
    });
    setActiveTab(id);
  };

  const openSftpSession = (host?: Host) => {
    const id = host ? `t-sftp-${host.id}-${Date.now()}` : `t-sftp-${Date.now()}`;
    const baseTitle = host ? (host.name || host.hostname) : "SFTP";
    setTabs((currentTabs) => {
      const existingCount = host ? currentTabs.filter((t) => t.sftpHostId === host.id).length : 0;
      const title = existingCount > 0 ? `${baseTitle} (${existingCount + 1})` : baseTitle;
      return [
        ...currentTabs,
        {
          id,
          kind: "sftp" as const,
          title,
          closable: true,
          sftpHostId: host?.id,
        },
      ];
    });
    setActiveTab(id);
  };

  const closeTab = (id: string) => {
    const curr = tabsRef.current;
    const tgt = curr.find((t) => t.id === id);
    if (tgt && !tgt.closable) return;

    const next = curr.filter((t) => t.id !== id);
    setTabs(next);

    if (id === activeTabRef.current && next.length) {
      const closedIndex = curr.findIndex((t) => t.id === id);
      const newActive = next[closedIndex - 1] ?? next[next.length - 1];
      setActiveTab(newActive.id);
    }
  };

  const renameTab = (id: string, title: string) => {
    setTabs((curr) => curr.map((t) => (t.id === id ? { ...t, title } : t)));
  };

  const reorderTab = (fromId: string, toId: string) => {
    setTabs((curr) => {
      const from = curr.findIndex((t) => t.id === fromId);
      const to = curr.findIndex((t) => t.id === toId);
      if (from === -1 || to === -1 || from === to) return curr;
      if (!curr[from].closable) return curr;
      const pinnedCount = curr.filter((t) => !t.closable).length;
      if (to < pinnedCount) return curr;
      return arrayMove(curr, from, to);
    });
  };

  const updateTabSession = (tabId: string, sessionId: string) => {
    setTabs((curr) =>
      curr.map((t) =>
        t.id === tabId && t.sessionId !== sessionId ? { ...t, sessionId } : t
      )
    );
  };

  useEffect(() => {
    const refreshVault = () =>
      vaultStatus()
        .then((status: VaultStatus) => {
          setVaultInfo({ initialized: status.initialized, unlocked: status.unlocked });
          if (status.unlocked) {
            pushSyncSettingsCache();
          }
        })
        .catch(console.error);

    void refreshVault();

    // Backend locks the vault on screen lock (per policy); re-gate immediately.
    const unlistenPromise = subscribe("vault-locked", () => {
      setVaultInfo((prev) => ({ initialized: prev?.initialized ?? true, unlocked: false }));
    });

    // Fallback: re-check status whenever the window regains focus, so returning
    // from a locked screen re-gates even if the event was missed.
    const onFocus = () => void refreshVault();
    window.addEventListener("focus", onFocus);

    return () => {
      void unlistenPromise.then((un) => un());
      window.removeEventListener("focus", onFocus);
    };
  }, []);

  const [mainWindowOpacity, setMainWindowOpacity] = useState(0.7);

  useEffect(() => {
    if (variant === "main") {
      const loadOpacity = () => {
        try {
          const stored = localStorage.getItem("termifai:main-window-opacity");
          setMainWindowOpacity(stored ? parseFloat(stored) : 0.7);
        } catch {
          setMainWindowOpacity(0.7);
        }
      };
      loadOpacity();

      const unlistenPromise = subscribe<number>("main-window:opacity-changed", (event) => {
        setMainWindowOpacity(event.payload);
      });

      const targets = [
        document.documentElement,
        document.body,
        document.getElementById("root"),
      ].filter((el): el is HTMLElement => el !== null);
      const previous = targets.map((el) => el.style.backgroundColor);
      targets.forEach((el) => (el.style.backgroundColor = "transparent"));

      return () => {
        void unlistenPromise.then((un) => un());
        targets.forEach((el, i) => (el.style.backgroundColor = previous[i]));
      };
    }
  }, [variant]);

  useEffect(() => {
    newTabRef.current = newTab;
  });

  const activeTabRef = useRef(activeTab);
  const tabsRef = useRef(tabs);
  useEffect(() => {
    activeTabRef.current = activeTab;
    tabsRef.current = tabs;
  });

  useEffect(() => {
    let destroyed = false;
    let unlistenShortcuts: (() => void) | null = null;
    let unlistenMenuNewTerminal: (() => void) | null = null;

    const applyShortcuts = (shortcuts: ShortcutMap) => {
      shortcutsRef.current = shortcuts;
    };
    const onStorageChanged = (event: StorageEvent) => {
      if (event.key === shortcutsStorageKey) {
        applyShortcuts(loadShortcuts());
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      const isEditable =
        target?.tagName === "INPUT" ||
        target?.tagName === "TEXTAREA" ||
        target?.isContentEditable;
      const isXtermInput = Boolean(target?.closest(".xterm"));

      if (isEditable && !isXtermInput) return;

      const shortcuts = shortcutsRef.current;

      if (isShortcutMatch(event, shortcuts["new-terminal"])) {
        event.preventDefault();
        newTabRef.current("terminal");
      } else if (isShortcutMatch(event, shortcuts["close-tab"])) {
        event.preventDefault();
        closeTab(activeTabRef.current);
      } else if (isShortcutMatch(event, shortcuts["next-tab"])) {
        event.preventDefault();
        const index = tabsRef.current.findIndex((item) => item.id === activeTabRef.current);
        const next = tabsRef.current[(index + 1) % tabsRef.current.length];
        if (next) setActiveTab(next.id);
      } else if (isShortcutMatch(event, shortcuts["previous-tab"])) {
        event.preventDefault();
        const index = tabsRef.current.findIndex((item) => item.id === activeTabRef.current);
        const previous = tabsRef.current[(index - 1 + tabsRef.current.length) % tabsRef.current.length];
        if (previous) setActiveTab(previous.id);
      } else if (isShortcutMatch(event, shortcuts["open-settings"])) {
        event.preventDefault();
        openSettingsWindow().catch((err) =>
          console.error("open_settings_window failed:", err)
        );
      } else if (isShortcutMatch(event, shortcuts["lock-vault"])) {
        event.preventDefault();
        vaultLock().catch((err) => console.error("vault_lock failed:", err));
      } else if (
        // Skip while focus is inside the terminal: Ctrl+Q/Ctrl+S are XON/XOFF
        // flow-control bytes shells and TUI apps rely on, so we only treat
        // them as app shortcuts outside of xterm.
        platform === "linux" &&
        !isXtermInput &&
        event.ctrlKey &&
        !event.altKey &&
        !event.shiftKey &&
        !event.metaKey &&
        event.code === "KeyQ"
      ) {
        event.preventDefault();
        void quitApp();
      } else if (
        platform === "linux" &&
        !isXtermInput &&
        event.ctrlKey &&
        event.altKey &&
        !event.shiftKey &&
        !event.metaKey &&
        event.code === "KeyQ"
      ) {
        event.preventDefault();
        void forceQuitApp();
      }
    };

    window.addEventListener("storage", onStorageChanged);
    window.addEventListener("keydown", onKeyDown);

    subscribe<ShortcutMap>(shortcutsChangedEvent, (event) => {
      applyShortcuts(event.payload);
    })
      .then((unlisten) => {
        if (destroyed) { unlisten(); return; }
        unlistenShortcuts = unlisten;
      })
      .catch(() => {});

    // The macOS menu event broadcasts to every window; only the main shell
    // should react, or a quick-terminal shell would also grow a tab.
    if (variant === "main") {
      subscribe("menu-new-terminal", () => {
        newTabRef.current("terminal");
      })
        .then((unlisten) => {
          if (destroyed) { unlisten(); return; }
          unlistenMenuNewTerminal = unlisten;
        })
        .catch(() => {});
    }

    return () => {
      destroyed = true;
      window.removeEventListener("storage", onStorageChanged);
      window.removeEventListener("keydown", onKeyDown);
      unlistenShortcuts?.();
      unlistenMenuNewTerminal?.();
    };
  }, []);

  const tab = tabs.find((t) => t.id === activeTab);
  const glassClasses = variant === "main" ? "qt-glass" : "";
  const alphaStyle = variant === "main" ? { ["--qt-alpha" as string]: mainWindowOpacity } : {};

  return (
    <div
      className={`flex flex-col bg-background text-foreground ${glassClasses} ${
        variant === "quick-terminal" ? "h-full w-full" : "h-screen w-screen"
      }`}
      style={alphaStyle}
    >
      <TitleBar
        tabs={tabs}
        activeTab={activeTab}
        onSelect={setActiveTab}
        onClose={closeTab}
        onNew={newTab}
        onRename={renameTab}
        onReorder={reorderTab}
        platform={platform}
        variant={variant}
        onRequestClose={onRequestClose}
        quickTerminalEdge={quickTerminalEdge}
        transparentBg={variant === "quick-terminal" || (variant === "main" && mainWindowOpacity < 1.0)}
      />

      <div className="flex min-h-0 flex-1">
        {/* Render all terminal tabs (keep them mounted) */}
        {tabs.map((t) => 
          t.kind === "terminal" ? (
            <div
              key={t.id}
              style={{ display: t.id === activeTab ? "flex" : "none" }}
              className="min-w-0 flex-1"
            >
              <XTerminal
                sessionId={t.sessionId}
                initialCommand={t.initialCommand}
                cwd={t.cwd}
                hostId={t.hostId}
                readyMarker={t.readyMarker}
                connectionLabel={t.connectionLabel}
                connectionTitle={t.connectionTitle}
                isActive={t.id === activeTab}
                onClose={() => closeTab(t.id)}
                onSessionCreated={(sid) => updateTabSession(t.id, sid)}
                owner={variant}
                transparentBackground={variant === "quick-terminal" || (variant === "main" && mainWindowOpacity < 1.0)}
              />
            </div>
          ) : null
        )}

        {/* Render all tabs but only show the active one */}
        {tabs.map((t) => 
          t.kind !== "terminal" ? (
            <div
              key={t.id}
              style={{ display: t.id === activeTab ? "flex" : "none" }}
              className="min-w-0 flex-1"
            >
            {t.kind === "vaults" && (
              vaultInfo && !vaultInfo.unlocked ? (
                <VaultGate
                  initialized={vaultInfo.initialized}
                  active={t.id === activeTab}
                  onUnlocked={() => setVaultInfo({ initialized: true, unlocked: true })}
                />
              ) : (
                <>
                  <Sidebar active={activeSidebar} onChange={setActiveSidebar} variant={variant} />
                  <main className="flex min-w-0 flex-1 flex-col">
                    {activeSidebar === "dashboard" && <DashboardView />}
                    {activeSidebar === "hosts" && <HostsView onNewTerminal={() => newTab("terminal")} onNewSftp={(host?) => openSftpSession(host)} onConnectHost={(host) => void openSshTerminal(host)} />}
                    {activeSidebar === "port-forwarding" && <PortForwardingView />}
                    {activeSidebar === "snippets" && <SnippetsView />}
                    {activeSidebar === "ssh-keys" && <SshKeysView />}
                    {activeSidebar === "logs" && (
                      <EmptyState icon={ClipboardList} title="Connection logs" subtitle="Audit of recent sessions, transfers and tunnels." />
                    )}
                  </main>
                </>
              )
            )}
            {t.kind === "sftp" && <SftpView tab={t} />}
          </div>
          ) : null
        )}
      </div>

    </div>
  );
}

/* ---------------- Title bar with tabs ---------------- */

function TitleBar({
  tabs,
  activeTab,
  onSelect,
  onClose,
  onNew,
  onRename,
  onReorder,
  platform,
  variant,
  onRequestClose,
  quickTerminalEdge,
  transparentBg,
}: {
  tabs: AppTab[];
  activeTab: string;
  onSelect: (id: string) => void;
  onClose: (id: string) => void;
  onNew: (kind: TabKind) => void;
  onRename: (id: string, title: string) => void;
  onReorder: (fromId: string, toId: string) => void;
  platform: string;
  variant: "main" | "quick-terminal";
  onRequestClose?: () => void;
  quickTerminalEdge?: QuickTerminalEdge;
  transparentBg?: boolean;
}) {
  const isQuickTerminal = variant === "quick-terminal";
  const win = getCurrentWindow();
  const [isQuickTerminalPinned, setIsQuickTerminalPinned] = useState(true);
  const QuickTerminalHideIcon = {
    top: PanelTopClose,
    bottom: PanelBottomClose,
    left: PanelLeftClose,
    right: PanelRightClose,
  }[quickTerminalEdge ?? "top"];
  const dragRegion = isQuickTerminal ? {} : { "data-tauri-drag-region": true };

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 5 } }),
  );

  // On macOS the green zoom button also enters native fullscreen, which hides the
  // traffic lights — collapse their reserved space then so tabs don't sit in a gap.
  const [isFullscreen, setIsFullscreen] = useState(false);
  useEffect(() => {
    if (platform !== "macos") return;
    const win = getCurrentWindow();
    void win.isFullscreen().then(setIsFullscreen);
    let unlisten: (() => void) | undefined;
    void win.onResized(() => { void win.isFullscreen().then(setIsFullscreen); }).then((fn) => { unlisten = fn; });
    return () => unlisten?.();
  }, [platform]);

  useEffect(() => {
    if (!isQuickTerminal) return;
    void win.isAlwaysOnTop().then(setIsQuickTerminalPinned).catch((error) => {
      console.error("Failed to read Quick Terminal pin state", error);
    });
  }, [isQuickTerminal, win]);

  const toggleQuickTerminalPin = () => {
    const next = !isQuickTerminalPinned;
    void win.setAlwaysOnTop(next).then(() => {
      setIsQuickTerminalPinned(next);
    }).catch((error) => {
      console.error("Failed to change Quick Terminal pin state", error);
    });
  };

  const handleDragEnd = (e: DragEndEvent) => {
    const { active, over } = e;
    if (!over || active.id === over.id) return;
    onReorder(String(active.id), String(over.id));
  };

  const pinnedTabs = tabs.filter((t) => !t.closable);
  const closableTabs = tabs.filter((t) => t.closable);
  const carouselRef = useRef<HTMLDivElement | null>(null);
  const carouselTrackRef = useRef<HTMLDivElement | null>(null);
  const [tabsOverflow, setTabsOverflow] = useState(false);
  const [canScrollLeft, setCanScrollLeft] = useState(false);
  const [canScrollRight, setCanScrollRight] = useState(false);

  const updateCarouselState = useCallback(() => {
    const viewport = carouselRef.current;
    if (!viewport) return;
    const overflowing = viewport.scrollWidth > viewport.clientWidth + 1;
    const maxScroll = Math.max(0, viewport.scrollWidth - viewport.clientWidth);
    setTabsOverflow(overflowing);
    setCanScrollLeft(overflowing && viewport.scrollLeft > 1);
    setCanScrollRight(overflowing && viewport.scrollLeft < maxScroll - 1);
  }, []);

  useEffect(() => {
    const viewport = carouselRef.current;
    const track = carouselTrackRef.current;
    if (!viewport || !track) return;

    const observer = new ResizeObserver(updateCarouselState);
    observer.observe(viewport);
    observer.observe(track);
    updateCarouselState();
    return () => observer.disconnect();
  }, [updateCarouselState]);

  useEffect(() => {
    const frame = requestAnimationFrame(() => {
      updateCarouselState();
      const viewport = carouselRef.current;
      const active = carouselTrackRef.current?.querySelector(
        `[data-tab-id="${activeTab}"]`
      ) as HTMLElement | null;
      if (!viewport || !active) return;

      // تب فعال همیشه باید داخل قاب carousel دیده بشه، حتی اگه با shortcut عوض شده.
      const viewportRect = viewport.getBoundingClientRect();
      const activeRect = active.getBoundingClientRect();
      if (activeRect.left < viewportRect.left) {
        viewport.scrollBy({ left: activeRect.left - viewportRect.left - 4, behavior: "smooth" });
      } else if (activeRect.right > viewportRect.right) {
        viewport.scrollBy({ left: activeRect.right - viewportRect.right + 4, behavior: "smooth" });
      }
    });
    return () => cancelAnimationFrame(frame);
  }, [activeTab, tabs, updateCarouselState]);

  const scrollTabs = (direction: -1 | 1) => {
    const viewport = carouselRef.current;
    if (!viewport) return;
    viewport.scrollBy({
      left: direction * Math.max(160, Math.round(viewport.clientWidth * 0.7)),
      behavior: "smooth",
    });
  };

  return (
    <div
      className={`flex h-11 shrink-0 items-center border-b border-border select-none ${
        transparentBg ? "bg-transparent" : "bg-[var(--color-surface)]"
      }`}
      {...dragRegion}
    >
      {/* Space for native macOS traffic lights — collapses in fullscreen, where they hide */}
      {!isQuickTerminal && platform === "macos" && (
        <div
          className="h-full shrink-0 flex items-center overflow-hidden transition-[width] duration-200"
          style={{ width: isFullscreen ? 0 : 80 }}
        />
      )}
      {(isQuickTerminal || platform !== "macos") && <div className="w-3 h-full shrink-0" />}

      {isQuickTerminal && (
        <button
          type="button"
          onClick={toggleQuickTerminalPin}
          title={isQuickTerminalPinned ? "Unpin Quick Terminal" : "Pin Quick Terminal"}
          aria-label={isQuickTerminalPinned ? "Unpin Quick Terminal" : "Pin Quick Terminal"}
          className={`mr-1 flex h-8 w-8 shrink-0 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-[var(--color-surface-2)] hover:text-foreground ${
            isQuickTerminalPinned ? "text-[var(--color-brand-green)]" : ""
          }`}
        >
          {isQuickTerminalPinned ? <Pin className="h-4 w-4" /> : <PinOff className="h-4 w-4" />}
        </button>
      )}

      <div className="flex h-full min-w-0 flex-1 items-end gap-0.5 pl-1" {...dragRegion}>
        {tabsOverflow && (
          <button
            type="button"
            onClick={() => scrollTabs(-1)}
            disabled={!canScrollLeft}
            className="self-center flex h-8 w-7 shrink-0 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-[var(--color-surface-2)] hover:text-foreground disabled:opacity-30 disabled:hover:bg-transparent"
            aria-label="Scroll tabs left"
          >
            <ChevronLeft className="h-4 w-4" />
          </button>
        )}

        <div
          ref={carouselRef}
          onScroll={updateCarouselState}
          onWheel={(event) => {
            if (!tabsOverflow) return;
            const viewport = carouselRef.current;
            if (!viewport) return;
            const delta = Math.abs(event.deltaX) > Math.abs(event.deltaY) ? event.deltaX : event.deltaY;
            if (delta) viewport.scrollLeft += delta;
          }}
          className="h-full min-w-0 flex-1 overflow-hidden"
          aria-label="Open tabs carousel"
        >
          <div
            ref={carouselTrackRef}
            className="flex h-full w-max min-w-full items-end gap-1"
            {...dragRegion}
          >
            {/* تب Hosts پین شده و وارد drag-and-drop نمی‌شه */}
            {pinnedTabs.map((t) => (
              <BaseTabChip
                key={t.id}
                tab={t}
                active={t.id === activeTab}
                onClick={() => onSelect(t.id)}
                onClose={() => onClose(t.id)}
                onRename={(title) => onRename(t.id, title)}
              />
            ))}

            {/* تب‌های قابل‌بستن داخل carousel قابل جابه‌جایی می‌مونن */}
            <div className="flex items-end gap-1" {...dragRegion}>
              <DndContext
                sensors={sensors}
                collisionDetection={closestCenter}
                modifiers={[restrictToHorizontalAxis, restrictToParentElement]}
                onDragEnd={handleDragEnd}
              >
                <SortableContext items={closableTabs.map((t) => t.id)} strategy={horizontalListSortingStrategy}>
                  {closableTabs.map((t) => (
                    <SortableTabChip
                      key={t.id}
                      tab={t}
                      active={t.id === activeTab}
                      onClick={() => onSelect(t.id)}
                      onClose={() => onClose(t.id)}
                      onRename={(title) => onRename(t.id, title)}
                    />
                  ))}
                </SortableContext>
              </DndContext>
            </div>
          </div>
        </div>

        {tabsOverflow && (
          <button
            type="button"
            onClick={() => scrollTabs(1)}
            disabled={!canScrollRight}
            className="self-center flex h-8 w-7 shrink-0 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-[var(--color-surface-2)] hover:text-foreground disabled:opacity-30 disabled:hover:bg-transparent"
            aria-label="Scroll tabs right"
          >
            <ChevronRight className="h-4 w-4" />
          </button>
        )}

        <button
          type="button"
          onClick={() => onNew("terminal")}
          className={`self-center flex h-8 w-8 shrink-0 items-center justify-center rounded-md text-muted-foreground hover:bg-[var(--color-surface-2)] hover:text-foreground ${
            tabsOverflow ? "" : "mr-2"
          }`}
          aria-label="New Local Terminal"
        >
          <Plus className="h-4 w-4" />
        </button>

        {tabsOverflow && (
          <TabListMenu tabs={tabs} activeTab={activeTab} onSelect={onSelect} onClose={onClose} />
        )}
      </div>

      {/* Linux/Windows: hamburger app menu + window controls */}
      {isQuickTerminal ? (
        <button
          onClick={() => onRequestClose?.()}
          title="Hide Quick Terminal"
          className="mr-2 flex h-8 w-8 shrink-0 items-center justify-center self-center rounded-md text-muted-foreground outline-none hover:bg-[var(--color-surface-2)] hover:text-foreground focus:outline-none transition-colors"
          aria-label="Hide Quick Terminal"
        >
          <QuickTerminalHideIcon className="h-4 w-4" />
        </button>
      ) : (
        platform !== "macos" && (
          <>
            <AppHamburgerMenu onNew={onNew} />
            <WindowControls />
          </>
        )
      )}
    </div>
  );
}

function TabListMenu({
  tabs,
  activeTab,
  onSelect,
  onClose,
}: {
  tabs: AppTab[];
  activeTab: string;
  onSelect: (id: string) => void;
  onClose: (id: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const searchRef = useRef<HTMLInputElement | null>(null);
  const normalizedQuery = query.trim().toLocaleLowerCase();
  const filteredTabs = normalizedQuery
    ? tabs.filter((tab) =>
        `${tab.title} ${tab.connectionLabel ?? ""}`.toLocaleLowerCase().includes(normalizedQuery)
      )
    : tabs;

  useEffect(() => {
    if (!open) return;
    const frame = requestAnimationFrame(() => searchRef.current?.focus());
    return () => cancelAnimationFrame(frame);
  }, [open]);

  return (
    <DropdownMenu
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) setQuery("");
      }}
    >
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          className="self-center mr-2 flex h-8 w-8 shrink-0 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-[var(--color-surface-2)] hover:text-foreground data-[state=open]:bg-[var(--color-surface-2)] data-[state=open]:text-foreground"
          aria-label="Show all tabs"
          title="All tabs"
        >
          <ListFilter className="h-4 w-4" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent
        align="end"
        sideOffset={6}
        className="flex max-h-[min(420px,var(--radix-dropdown-menu-content-available-height))] w-72 flex-col overflow-hidden p-0"
        onCloseAutoFocus={(event) => event.preventDefault()}
      >
        <div className="shrink-0 border-b border-border p-2">
          <div className="flex h-8 items-center gap-2 rounded-md border border-input bg-background px-2 focus-within:ring-1 focus-within:ring-ring">
            <Search className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
            <input
              ref={searchRef}
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              onKeyDown={(event) => event.stopPropagation()}
              onPointerDown={(event) => event.stopPropagation()}
              placeholder="Search tabs…"
              aria-label="Search tabs"
              className="min-w-0 flex-1 bg-transparent text-xs text-foreground outline-none placeholder:text-muted-foreground"
            />
          </div>
        </div>

        <div className="min-h-0 overflow-y-auto p-1">
          {filteredTabs.length ? (
            filteredTabs.map((tab) => (
              <DropdownMenuItem
                key={tab.id}
                onSelect={() => onSelect(tab.id)}
                onPointerDown={(event) => {
                  // میدل‌کلیک نباید autoscroll مرورگر رو فعال کنه
                  if (event.button === 1) event.preventDefault();
                }}
                onPointerUp={(event) => {
                  // با preventDefault، هندلر داخلی Radix اجرا نمی‌شه و
                  // میدل‌کلیک باعث select شدن آیتم و بسته شدن منو نمی‌شه
                  if (event.button === 1) event.preventDefault();
                }}
                onAuxClick={(event) => {
                  // میدل‌کلیک روی گزینه = بستن همون تب، بدون این که منو بسته شه
                  if (event.button === 1 && tab.closable) {
                    event.preventDefault();
                    event.stopPropagation();
                    onClose(tab.id);
                  }
                }}
                className="group min-w-0 cursor-pointer py-2"
              >
                <TabIcon tab={tab} />
                <span className="min-w-0 flex-1 truncate">{tab.title}</span>
                {tab.id === activeTab && (
                  <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-primary" aria-label="Active tab" />
                )}
                {tab.closable && (
                  <button
                    type="button"
                    onPointerDown={(event) => {
                      // جلوی select شدن آیتم توسط Radix رو می‌گیریم
                      event.stopPropagation();
                      event.preventDefault();
                    }}
                    onPointerUp={(event) => {
                      // Radix روی pointerup آیتم، click مصنوعی می‌زنه و منو رو می‌بنده؛
                      // نباید این رویداد از دکمه X به آیتم برسه
                      event.stopPropagation();
                    }}
                    onClick={(event) => {
                      event.stopPropagation();
                      onClose(tab.id);
                    }}
                    className="flex h-5 w-5 shrink-0 items-center justify-center rounded text-muted-foreground opacity-0 transition-opacity hover:bg-[var(--color-surface-2)] hover:text-foreground group-hover:opacity-100 group-data-[highlighted]:opacity-100"
                    aria-label={`Close ${tab.title}`}
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                )}
              </DropdownMenuItem>
            ))
          ) : (
            <div className="px-3 py-6 text-center text-xs text-muted-foreground">
              No tabs found
            </div>
          )}
        </div>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function AppHamburgerMenu({ onNew }: { onNew: (kind: TabKind) => void }) {
  const win = getCurrentWindow();
  const [isFullscreen, setIsFullscreen] = useState(false);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    win.isFullscreen().then(setIsFullscreen).catch(() => {});
    win.onResized(() => {
      win.isFullscreen().then(setIsFullscreen).catch(() => {});
    }).then((fn) => { unlisten = fn; }).catch(() => {});
    return () => { unlisten?.(); };
  }, []);

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          className="flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground hover:bg-[var(--color-surface-2)] hover:text-foreground self-center mr-1"
          aria-label="App menu"
        >
          <Menu className="h-4 w-4" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent
        align="end"
        className="w-48"
        // On Linux, a fullscreen webview can emit a spurious focus-outside event right after
        // the menu opens (GTK/wry focus quirk), which Radix's dismissable layer otherwise reads
        // as "user focused something else" and closes the menu within a frame of opening it.
        // Ignore focus-outside; real outside clicks (pointerDownOutside) still close it.
        onFocusOutside={(e) => e.preventDefault()}
      >
        <DropdownMenuItem onSelect={() => onNew("terminal")}>
          New Terminal
          <span className="ml-auto text-xs text-muted-foreground">Ctrl+T</span>
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={() => void openSettingsWindow()}>
          Settings
          <span className="ml-auto text-xs text-muted-foreground">Ctrl+,</span>
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => void vaultLock()}>
          Lock Vault
          <span className="ml-auto text-xs text-muted-foreground">Ctrl+Shift+L</span>
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => void win.setFullscreen(!isFullscreen)}>
          {isFullscreen ? "Exit Full Screen" : "Full Screen"}
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => void quitApp()}>
          Quit
          <span className="ml-auto text-xs text-muted-foreground">
            {platform === "linux" ? "Ctrl+Q" : "Alt+F4"}
          </span>
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={() => void forceQuitApp()}>
          Force Quit
          {platform === "linux" && (
            <span className="ml-auto text-xs text-muted-foreground">Ctrl+Alt+Q</span>
          )}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function WindowControls() {
  const win = getCurrentWindow();
  // Fullscreen and "maximized" are separate window states (most visible on Linux/X11+Wayland).
  // toggleMaximize() while fullscreen produces an inconsistent state — e.g. the window ends up
  // maximized underneath but still rendered fullscreen, or fullscreen won't exit cleanly. So
  // this button exits fullscreen first when active, instead of toggling maximize on top of it.
  const [isFullscreen, setIsFullscreen] = useState(false);
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    void win.isFullscreen().then(setIsFullscreen).catch(() => {});
    void win.onResized(() => {
      void win.isFullscreen().then(setIsFullscreen).catch(() => {});
    }).then((fn) => { unlisten = fn; }).catch(() => {});
    return () => { unlisten?.(); };
  }, [win]);

  return (
    <div className="flex items-center h-full shrink-0">
      <button
        onClick={() => void win.minimize()}
        className="flex h-full w-11 items-center justify-center text-muted-foreground outline-none hover:bg-[var(--color-surface-2)] hover:text-foreground focus:outline-none focus-visible:outline-none transition-colors"
        aria-label="Minimize"
      >
        <Minus className="h-3.5 w-3.5" />
      </button>
      <button
        onClick={() => void (isFullscreen ? win.setFullscreen(false) : win.toggleMaximize())}
        className="flex h-full w-11 items-center justify-center text-muted-foreground outline-none hover:bg-[var(--color-surface-2)] hover:text-foreground focus:outline-none focus-visible:outline-none transition-colors"
        aria-label="Maximize"
      >
        <Square className="h-3 w-3" />
      </button>
      <button
        onClick={() => void win.close()}
        className="flex h-full w-11 items-center justify-center text-muted-foreground outline-none hover:bg-red-500 hover:text-white focus:outline-none focus-visible:outline-none transition-colors"
        aria-label="Close"
      >
        <X className="h-3.5 w-3.5" />
      </button>
    </div>
  );
}

/* ---------- Base tab chip (no DnD) ---------- */
function TabIcon({ tab }: { tab: AppTab }) {
  if (tab.kind === "terminal" && tab.hostId) {
    return <Server className="h-3.5 w-3.5 shrink-0 text-[var(--color-brand-orange)]" />;
  }
  if (tab.kind === "terminal") {
    return <TerminalSquare className="h-3.5 w-3.5 shrink-0 text-[var(--color-brand-green)]" />;
  }
  if (tab.kind === "sftp") {
    return <Folder className="h-3.5 w-3.5 shrink-0 text-[var(--color-brand-cyan)]" />;
  }
  return <LayoutGrid className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />;
}

interface BaseTabChipProps {
  tab: AppTab;
  active: boolean;
  onClick: () => void;
  onClose: () => void;
  onRename: (title: string) => void;
  style?: React.CSSProperties;
  dragAttributes?: any;
  dragListeners?: any;
  setNodeRef?: (node: HTMLElement | null) => void;
}

const BaseTabChip = forwardRef<HTMLDivElement, BaseTabChipProps>(function BaseTabChip(
  { tab, active, onClick, onClose, onRename, style, dragAttributes, dragListeners, setNodeRef },
  ref
) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(tab.title);
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (editing) {
      inputRef.current?.focus();
      inputRef.current?.select();
    }
  }, [editing]);

  const commit = () => {
    const v = draft.trim();
    if (v) onRename(v);
    else setDraft(tab.title);
    setEditing(false);
  };

  return (
    <div
      data-tab-id={tab.id}
      ref={(node) => {
        setNodeRef?.(node);
        if (typeof ref === "function") ref(node);
        else if (ref) (ref as React.MutableRefObject<HTMLElement | null>).current = node;
      }}
      style={style}
      {...(dragAttributes ?? {})}
      {...(tab.closable && !editing ? dragListeners : {})}
      onClick={onClick}
      onDoubleClick={(e) => {
        e.stopPropagation();
        if (!tab.closable) return;
        setDraft(tab.title);
        setEditing(true);
      }}
      onAuxClick={(e) => {
        if (e.button === 1 && tab.closable) {
          e.preventDefault();
          onClose();
        }
      }}
      className={[
        "group relative flex h-9 shrink-0 cursor-pointer items-center gap-2 rounded-t-md px-3 text-xs font-medium outline-none border-t-2 transition-colors",
        active
          ? "bg-[var(--color-tab-active)] text-foreground border-primary"
          : "bg-[var(--color-tab-inactive)] text-muted-foreground hover:text-foreground border-transparent",
      ].join(" ")}
    >
      <TabIcon tab={tab} />
      {editing ? (
        <input
          ref={inputRef}
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onBlur={commit}
          onKeyDown={(e) => {
            if (e.key === "Enter") commit();
            else if (e.key === "Escape") {
              setDraft(tab.title);
              setEditing(false);
            }
          }}
          onClick={(e) => e.stopPropagation()}
          onDoubleClick={(e) => e.stopPropagation()}
          onPointerDown={(e) => e.stopPropagation()}
          className="h-5 w-24 rounded bg-[var(--color-surface-2)] px-1 text-xs text-foreground outline-none ring-1 ring-ring/40"
        />
      ) : (
        <span className="whitespace-nowrap">{tab.title}</span>
      )}
      {tab.closable && (
        <button
          onPointerDown={(e) => e.stopPropagation()}
          onClick={(e) => {
            e.stopPropagation();
            onClose();
          }}
          className="flex h-4 w-4 items-center justify-center rounded text-muted-foreground opacity-0 group-hover:opacity-100 hover:bg-[var(--color-surface-2)] hover:text-foreground"
        >
          <X className="h-3 w-3" />
        </button>
      )}
    </div>
  );
});

/* ---------- Sortable tab chip ---------- */
function SortableTabChip(props: Omit<BaseTabChipProps, "style" | "dragAttributes" | "dragListeners" | "setNodeRef">) {
  const {
    attributes,
    listeners,
    setNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({
    id: props.tab.id,
    disabled: !props.tab.closable,
  });

  const style: React.CSSProperties = {
    transform: CSS.Transform.toString(transform ? { ...transform, y: 0, scaleX: 1, scaleY: 1 } : null),
    transition,
    opacity: isDragging ? 0.6 : 1,
    zIndex: isDragging ? 10 : undefined,
  };

  return (
    <BaseTabChip
      {...props}
      style={style}
      dragAttributes={attributes}
      dragListeners={listeners}
      setNodeRef={setNodeRef}
    />
  );
}


/* ---------------- Sidebar ---------------- */

function Sidebar({
  active,
  onChange,
  variant,
}: {
  active: SidebarKey;
  onChange: (k: SidebarKey) => void;
  variant?: "main" | "quick-terminal";
}) {
  const isQuickTerminal = variant === "quick-terminal";
  const [collapsed, setCollapsed] = useState(() => {
    if (isQuickTerminal) return true;
    return localStorage.getItem("sidebar-collapsed") === "true";
  });

  const isCurrentlyCollapsed = isQuickTerminal || collapsed;

  const toggleCollapsed = () => {
    if (isQuickTerminal) return;
    const next = !collapsed;
    setCollapsed(next);
    localStorage.setItem("sidebar-collapsed", String(next));
  };

  return (
    <aside className={`relative flex shrink-0 flex-col border-r border-border bg-sidebar py-3 text-sidebar-foreground transition-all duration-200 ${isCurrentlyCollapsed ? "w-14" : "w-56"}`}>
      {!isQuickTerminal && (
        <button
          onClick={toggleCollapsed}
          className="absolute top-6 right-0 translate-x-1/2 z-40 flex h-5 w-5 items-center justify-center rounded-full border border-border bg-[var(--color-surface)] text-sidebar-foreground hover:bg-[var(--color-sidebar-active)] hover:text-foreground shadow-sm transition-all"
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? <ChevronRight className="h-3 w-3" /> : <ChevronLeft className="h-3 w-3" />}
        </button>
      )}

      <nav className="flex-1 space-y-0.5 px-2">
        {sidebarItems.map((item) => {
          const Icon = item.icon;
          const isActive = active === item.key;
          return (
            <button
              key={item.key}
              onClick={() => onChange(item.key)}
              title={isCurrentlyCollapsed ? item.label : undefined}
              className={[
                "flex items-center rounded-md py-2 transition-colors",
                isCurrentlyCollapsed ? "w-10 h-10 justify-center px-0 mx-auto" : "w-full gap-3 px-3 text-sm",
                isActive
                  ? "bg-[var(--color-sidebar-active)] text-foreground"
                  : "text-sidebar-foreground hover:bg-[var(--color-sidebar-active)]/60 hover:text-foreground",
              ].join(" ")}
            >
              <Icon className="h-4 w-4" />
              {!isCurrentlyCollapsed && <span>{item.label}</span>}
            </button>
          );
        })}
      </nav>
      <div className="px-3 pt-3 text-[10px] tracking-wider text-muted-foreground text-center truncate">
        {isCurrentlyCollapsed ? "v1.2.0" : "v1.2.0 · Termifai"}
      </div>
    </aside>
  );
}

