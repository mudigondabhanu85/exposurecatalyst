import { createContext, useCallback, useContext, useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { api, type Me } from "../api";
import { useAuth } from "../auth";

interface Step { target?: string; title: string; body: string; path?: string }
type Role = "Admin" | "Approver" | "Analyst" | "Viewer";

export function tourRole(perms: string[]): Role {
  if (["settings:manage", "user:manage", "integration:manage", "sso:manage"].some((p) => perms.includes(p))) return "Admin";
  if (perms.includes("advisory:approve")) return "Approver";
  if (perms.includes("advisory:create")) return "Analyst";
  return "Viewer";
}

const COMMON_START: Step[] = [
  { title: "Welcome to ExposureCatalyst", body: "A two-minute tour of what matters for your role. Press Esc to skip — you can replay it any time from “Tour” in the header.", path: "/cves" },
  { target: "nav-cves", title: "CVE Intelligence", body: "Every new and updated CVE from NVD, CISA KEV and FIRST EPSS — merged into one record with the source of every value." },
];
const COMMON_END: Step[] = [
  { target: "help-button", title: "Help on every page", body: "The ? button (or the ? key) opens help for the page you are on — steps, field definitions, permissions and common errors." },
  { target: "nav-help", title: "Help Center", body: "Search all topics, the glossary (CVSS, EPSS, KEV…), FAQ, shortcuts and what’s new. Replay this tour any time from “Tour” in the header." },
];
const ROLE_STEPS: Record<Role, Step[]> = {
  Analyst: [
    { target: "cve-search", title: "Find what matters", body: "Search by CVE ID or keyword, then filter by severity, CVSS, EPSS, KEV and vendor. Save searches you reuse." },
    { target: "source-strip", title: "Freshness", body: "Source health shows when each feed last refreshed. “Refresh now” queues an immediate fetch." },
    { target: "nav-advisories", title: "Advisories", body: "Open a CVE and click “Create Advisory Email”: pull affected assets from integrations, edit, then submit for review. After approval you can send, copy for Outlook or download .eml / Excel." },
    { target: "nav-news", title: "Security News", body: "Trusted news, de-duplicated across outlets, with CVE links into CVE Intelligence." },
  ],
  Approver: [
    { target: "nav-advisories", title: "Your review queue", body: "Filter Advisories by “in review”. Check recipients, the validation matrix (Yes only where assets were found) and the SLA, then Approve or Request changes with a comment." },
    { target: "nav-advisories", title: "Segregation of duties", body: "You can never approve an advisory you authored — the server enforces this. Approved advisories are the only ones that can be sent or exported." },
  ],
  Admin: [
    { target: "nav-settings", title: "Set up in this order", body: "Settings → Identity & SSO (Okta + SailPoint mapping), Integrations (Qualys, Tanium, Wiz…), SMTP, Alerts and — optionally — AI Providers. Each has a guided setup with a Test step." },
    { target: "nav-settings", title: "Access control", body: "Users & RBAC shows the roles × permissions matrix. SSO users get roles only from group mappings; keep a local break-glass account with MFA." },
  ],
  Viewer: [
    { target: "nav-news", title: "Security News", body: "Recent attacks and advisories from trusted sources, linked to CVEs." },
  ],
};

interface TourCtx { start: () => void }
const Ctx = createContext<TourCtx>({ start: () => {} });
export const useTour = () => useContext(Ctx);

export function TourProvider({ children }: { children: ReactNode }) {
  const { me } = useAuth();
  const qc = useQueryClient();
  const [steps, setSteps] = useState<Step[] | null>(null);
  const [i, setI] = useState(0);
  const autoStarted = useRef(false);

  const start = useCallback(() => {
    if (!me) return;
    setSteps([...COMMON_START, ...ROLE_STEPS[tourRole(me.permissions)], ...COMMON_END]);
    setI(0);
  }, [me]);

  useEffect(() => {  // first login: start automatically once
    if (me && !me.tour_completed && !autoStarted.current) { autoStarted.current = true; start(); }
  }, [me, start]);

  const finish = useCallback(async () => {
    setSteps(null);
    try {
      await api("/api/auth/tour-complete", { method: "POST" });
      qc.setQueryData<Me | null>(["me"], (m) => (m ? { ...m, tour_completed: true } : m));
    } catch { /* remembered next time instead */ }
  }, [qc]);

  return (
    <Ctx.Provider value={{ start }}>
      {children}
      {steps && <TourStep step={steps[i]} index={i} total={steps.length} onBack={() => setI((x) => Math.max(0, x - 1))}
                          onNext={() => (i + 1 < steps.length ? setI(i + 1) : finish())} onClose={finish} />}
    </Ctx.Provider>
  );
}

function TourStep({ step, index, total, onBack, onNext, onClose }: { step: Step; index: number; total: number; onBack: () => void; onNext: () => void; onClose: () => void }) {
  const nav = useNavigate();
  const loc = useLocation();
  const box = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);

  useEffect(() => { if (step.path && loc.pathname !== step.path) nav(step.path); }, [step, loc.pathname, nav]);

  useLayoutEffect(() => {
    const el = step.target ? document.querySelector<HTMLElement>(`[data-tour="${step.target}"]`) : null;
    if (!el) { setPos(null); return; }
    el.classList.add("tour-target");
    el.scrollIntoView({ block: "nearest" });
    const r = el.getBoundingClientRect();
    const width = 340;
    setPos({ top: Math.min(r.bottom + 10, window.innerHeight - 220), left: Math.max(12, Math.min(r.left, window.innerWidth - width - 12)) });
    return () => el.classList.remove("tour-target");
  }, [step, loc.pathname]);

  useEffect(() => {
    box.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
      if (e.key === "ArrowRight") onNext();
      if (e.key === "ArrowLeft") onBack();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [step, onClose, onNext, onBack]);

  // React sets `style` through the CSSOM, which CSP style-src 'self' permits (only inline style attributes
  // in markup are blocked), so dynamic positioning needs no 'unsafe-inline'.
  return (
    <div className="fixed inset-0 z-50">
      <div className="absolute inset-0 bg-black/20" onClick={onClose} aria-hidden="true" />
      <div ref={box} role="dialog" aria-modal="true" aria-labelledby="tour-title" aria-describedby="tour-body" tabIndex={-1}
           className={`fixed w-[340px] rounded-md border-t-4 border-ec-orange bg-white p-4 shadow-xl focus:outline-none ${pos ? "" : "left-1/2 top-1/3 -translate-x-1/2"}`}
           style={pos ? { top: pos.top, left: pos.left } : undefined}>
        <p className="text-[11px] font-semibold uppercase tracking-wide text-ec-slate">Step {index + 1} of {total}</p>
        <h2 id="tour-title" className="font-heading text-lg font-bold text-ec-navy">{step.title}</h2>
        <p id="tour-body" className="mt-1 text-sm text-ec-slate">{step.body}</p>
        <div className="mt-4 flex items-center justify-between">
          <button className="text-xs underline" onClick={onClose}>Skip tour</button>
          <span className="flex gap-2">
            {index > 0 && <button className="btn-secondary" onClick={onBack}>Back</button>}
            <button className="btn-primary" onClick={onNext}>{index + 1 === total ? "Finish" : "Next"}</button>
          </span>
        </div>
      </div>
    </div>
  );
}
