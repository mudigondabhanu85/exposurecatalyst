import { createContext, useCallback, useContext, useEffect, useId, useRef, useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, type HelpPage, type Tooltips } from "./api";
import { Markdown } from "./components/Markdown";

// ---- Help drawer ---------------------------------------------------------------------------------

interface HelpCtx { openHelp: (id: string) => void }
const Ctx = createContext<HelpCtx>({ openHelp: () => {} });
export const useHelp = () => useContext(Ctx);

export function HelpProvider({ children }: { children: ReactNode }) {
  const [topic, setTopic] = useState<string | null>(null);
  const returnFocus = useRef<HTMLElement | null>(null);
  const openHelp = useCallback((id: string) => {
    returnFocus.current = document.activeElement as HTMLElement | null;
    setTopic(id);
  }, []);
  const close = useCallback(() => {
    setTopic(null);
    returnFocus.current?.focus();
  }, []);
  return (
    <Ctx.Provider value={{ openHelp }}>
      {children}
      {topic && <HelpDrawer id={topic} onClose={close} />}
    </Ctx.Provider>
  );
}

function HelpDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const titleId = useId();
  const panel = useRef<HTMLDivElement>(null);
  const q = useQuery({ queryKey: ["help", id], queryFn: () => api<HelpPage>(`/api/help/pages/${encodeURIComponent(id)}`) });

  useEffect(() => {
    panel.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
      if (e.key === "Tab" && panel.current) {
        // Keep focus inside the dialog (WCAG 2.1.2 / 2.4.3).
        const f = panel.current.querySelectorAll<HTMLElement>("a[href], button, input, [tabindex]:not([tabindex='-1'])");
        if (!f.length) return;
        const first = f[0], last = f[f.length - 1];
        if (e.shiftKey && document.activeElement === first) { last.focus(); e.preventDefault(); }
        else if (!e.shiftKey && document.activeElement === last) { first.focus(); e.preventDefault(); }
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-40 flex justify-end">
      <div className="absolute inset-0 bg-slate-900/30" aria-hidden="true" onClick={onClose} />
      <div ref={panel} role="dialog" aria-modal="true" aria-labelledby={titleId} tabIndex={-1}
           className="relative z-50 flex h-full w-full max-w-xl flex-col bg-white shadow-xl focus:outline-none">
        <div className="flex items-center justify-between border-b-2 border-ec-orange bg-ec-navy px-5 py-3">
          <h2 id={titleId} className="flex items-center gap-2 font-heading text-lg font-bold text-white">
            <img src="/brand/svg/mark-simple-dark.svg" alt="" aria-hidden="true" className="h-6 w-6" />
            {q.data?.title ?? "Help"}
          </h2>
          <button className="rounded-sm px-2 py-1 text-white hover:bg-white/10 focus-visible:outline-ec-orange-bright" onClick={onClose} aria-label="Close help">✕</button>
        </div>
        <div className="flex-1 overflow-y-auto px-5 py-4">
          {q.isLoading && <p className="text-sm text-ec-slate">Loading…</p>}
          {q.isError && <p className="text-sm text-red-700">This help topic is unavailable for your role.</p>}
          {q.data && (
            <>
              {q.data.summary && <p className="mb-3 text-sm text-ec-slate">{q.data.summary}</p>}
              <Markdown source={q.data.markdown} />
            </>
          )}
        </div>
        <div className="flex items-center justify-between border-t border-ec-border px-5 py-3 text-sm">
          <a className="link" href="/help">Help Center</a>
          {q.data?.docs && <a className="link" href={`/docs/${q.data.docs}`} target="_blank" rel="noopener noreferrer">Learn more in the documentation ↗</a>}
        </div>
      </div>
    </div>
  );
}

export function HelpButton({ id }: { id: string }) {
  const { openHelp } = useHelp();
  return (
    <button type="button" onClick={() => openHelp(id)} aria-label="Open help for this page" title="Help (?)"
            className="inline-flex h-8 w-8 items-center justify-center rounded-full border border-ec-navy bg-white font-heading text-sm font-bold text-ec-navy hover:bg-ec-navy hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-ec-orange">
      ?
    </button>
  );
}

// ---- Tooltips ------------------------------------------------------------------------------------

export function useTooltips() {
  return useQuery({ queryKey: ["tooltips"], queryFn: () => api<Tooltips>("/api/help/tooltips"), staleTime: Infinity });
}

/** "ⓘ" tooltip: opens on hover and keyboard focus, closes on Esc/blur (WCAG 1.4.13). */
export function InfoTip({ k, text }: { k?: string; text?: string }) {
  const tips = useTooltips();
  const [open, setOpen] = useState(false);
  const id = useId();
  const tip = k ? tips.data?.[k] : undefined;
  const body = text ?? tip?.text;
  if (!body) return null;
  return (
    <span className="relative inline-flex" onMouseEnter={() => setOpen(true)} onMouseLeave={() => setOpen(false)}>
      <button type="button" aria-label={`About ${tip?.label ?? "this field"}`} aria-describedby={open ? id : undefined}
              onFocus={() => setOpen(true)} onBlur={() => setOpen(false)}
              onKeyDown={(e) => e.key === "Escape" && setOpen(false)}
              className="rounded-full text-xs leading-none text-ec-slate hover:text-ec-orange focus:outline-none focus-visible:ring-2 focus-visible:ring-ec-orange">
        ⓘ
      </button>
      {open && (
        <span role="tooltip" id={id}
              className="absolute left-1/2 top-5 z-30 w-64 -translate-x-1/2 rounded-sm bg-ec-navy px-3 py-2 text-xs font-normal normal-case tracking-normal text-white shadow-lg">
          {body}
        </span>
      )}
    </span>
  );
}
