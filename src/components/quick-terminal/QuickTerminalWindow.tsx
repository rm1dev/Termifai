import { useEffect, useRef, useState } from "react";
import { AppShell } from "@/components/app/AppShell";
import { subscribe, type UnlistenFn } from "@/lib/api/transport";
import {
  getQuickTerminalInfo,
  hideQuickTerminal,
  quickTerminalFrontendReady,
  resizeQuickTerminal,
  type QuickTerminalEdge,
} from "@/lib/api/quick-terminal";

/**
 * The Quick Terminal panel window (`?window=quick-terminal`).
 *
 * The slide animation is native: Rust animates the window's position past the
 * screen edge (see quick_terminal.rs). The HTML here renders statically — it
 * must NOT animate, because the window carries a native backdrop-blur layer
 * that fills its whole rect, so any content-level slide would play on top of
 * an already-visible blur rectangle.
 *
 * The terminal session survives hides because the window is only hidden,
 * never destroyed.
 */
export function QuickTerminalWindow() {
  const [edge, setEdge] = useState<QuickTerminalEdge>("top");
  // Don't spawn a PTY session at app startup for a panel that may never be
  // used — mount the terminal on first show, keep it alive across hides.
  const [hasOpened, setHasOpened] = useState(false);
  const [opacity, setOpacity] = useState(1);
  const dragState = useRef<{ pointerId: number; raf: number; lastSize: number } | null>(null);

  // The native window is transparent; the page must be too, or the webview
  // paints an opaque rectangle over the native blur layer. index.html's
  // anti-flash <style> puts an opaque background on html, body AND #root,
  // so all three need inline overrides.
  useEffect(() => {
    const targets = [
      document.documentElement,
      document.body,
      document.getElementById("root"),
    ].filter((el): el is HTMLElement => el !== null);
    const previous = targets.map((el) => el.style.backgroundColor);
    targets.forEach((el) => (el.style.backgroundColor = "transparent"));
    return () => {
      targets.forEach((el, i) => (el.style.backgroundColor = previous[i]));
    };
  }, []);

  useEffect(() => {
    const unlisteners: UnlistenFn[] = [];
    let cancelled = false;
    const push = (unlisten: UnlistenFn) => {
      if (cancelled) unlisten();
      else unlisteners.push(unlisten);
    };
    const setup = async () => {
      // The subscriptions MUST be registered before signalling readiness:
      // on a cold hotkey launch the backend fires "quick-terminal:show" the
      // moment we report ready, and a show event that races past an
      // unregistered listener leaves the panel visible but empty (hasOpened
      // never flips, so AppShell never mounts).
      push(
        await subscribe<{ edge: QuickTerminalEdge }>("quick-terminal:show", (event) => {
          setEdge(event.payload.edge);
          setHasOpened(true);
        }),
      );
      push(
        await subscribe<number>("quick-terminal:opacity-changed", (event) => {
          setOpacity(event.payload);
        }),
      );
      try {
        const info = await getQuickTerminalInfo();
        setEdge(info.settings.edge);
        setOpacity(info.settings.opacity);
      } catch {
        /* keep defaults */
      }
      await quickTerminalFrontendReady().catch(() => {});
    };
    void setup();
    return () => {
      cancelled = true;
      unlisteners.forEach((unlisten) => unlisten());
    };
  }, []);

  const close = () => {
    void hideQuickTerminal().catch(() => {});
  };
  // No Esc-to-close: the panel hosts the full app shell (vim in terminals,
  // dialogs, palettes…), all of which need Escape for themselves. Closing is
  // the tab-bar × button or the global hotkey.

  // ── Resize handle (the only way to resize the panel) ─────────────────────
  const sizeFromPointer = (event: PointerEvent | React.PointerEvent) => {
    let size = 0;
    switch (edge) {
      case "top":
        size = event.clientY;
        break;
      case "bottom":
        size = window.innerHeight - event.clientY;
        break;
      case "left":
        size = event.clientX;
        break;
      case "right":
        size = window.innerWidth - event.clientX;
        break;
    }
    if ((edge === "left" || edge === "right") && size < 500) {
      return 500;
    }
    return size;
  };

  const onHandlePointerDown = (event: React.PointerEvent<HTMLDivElement>) => {
    event.preventDefault();
    (event.target as HTMLElement).setPointerCapture(event.pointerId);
    dragState.current = { pointerId: event.pointerId, raf: 0, lastSize: sizeFromPointer(event) };
  };

  const onHandlePointerMove = (event: React.PointerEvent<HTMLDivElement>) => {
    const drag = dragState.current;
    if (!drag || drag.pointerId !== event.pointerId) return;
    drag.lastSize = sizeFromPointer(event);
    if (drag.raf) return; // throttle to one backend call per frame
    drag.raf = requestAnimationFrame(() => {
      drag.raf = 0;
      const physical = Math.round(drag.lastSize * window.devicePixelRatio);
      void resizeQuickTerminal(physical, false).catch(() => {});
    });
  };

  const onHandlePointerUp = (event: React.PointerEvent<HTMLDivElement>) => {
    const drag = dragState.current;
    if (!drag || drag.pointerId !== event.pointerId) return;
    if (drag.raf) cancelAnimationFrame(drag.raf);
    dragState.current = null;
    const physical = Math.round(sizeFromPointer(event) * window.devicePixelRatio);
    void resizeQuickTerminal(physical, true).catch(() => {});
  };

  // The handle sits on the free edge: bottom for a top panel, top for a
  // bottom panel, right for a left panel, left for a right panel.
  const handleClass = {
    top: "bottom-0 left-0 h-1.5 w-full cursor-ns-resize",
    bottom: "top-0 left-0 h-1.5 w-full cursor-ns-resize",
    left: "right-0 top-0 w-1.5 h-full cursor-ew-resize",
    right: "left-0 top-0 w-1.5 h-full cursor-ew-resize",
  }[edge];

  return (
    <div className="h-screen w-screen overflow-hidden bg-transparent">
      <div
        className="qt-glass relative flex h-full w-full flex-col border border-border bg-background"
        style={{
          // Glass mode: --qt-alpha drives the .qt-glass background translucency
          // (see styles.css). Text stays fully opaque; the see-through areas
          // reveal the native backdrop blur applied to this window in Rust.
          ["--qt-alpha" as string]: opacity,
        }}
      >
        <div className="min-h-0 flex-1">
          {hasOpened && (
            <AppShell
              variant="quick-terminal"
              onRequestClose={close}
              quickTerminalEdge={edge}
            />
          )}
        </div>

        <div
          className={`absolute z-40 ${handleClass} bg-transparent hover:bg-[var(--color-brand-green)]/40`}
          onPointerDown={onHandlePointerDown}
          onPointerMove={onHandlePointerMove}
          onPointerUp={onHandlePointerUp}
          onPointerCancel={onHandlePointerUp}
        />
      </div>
    </div>
  );
}
