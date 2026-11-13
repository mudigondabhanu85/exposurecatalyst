import { useEffect, useRef } from "react";
import { NavLink, Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import { useAuth } from "./auth";
import { useHelp } from "./help";
import LoginPage from "./pages/Login";
import CveListPage from "./pages/CveList";
import CveDetailPage from "./pages/CveDetail";
import SettingsPage from "./pages/Settings";
import HelpCenterPage from "./pages/HelpCenter";
import { AdvisoriesPage, NewsPage } from "./pages/Placeholders";

/** Route → help topic, used by the global "?" shortcut. */
export function helpIdFor(path: string): string {
  if (/^\/cves\/.+/.test(path)) return "cve-detail";
  if (path.startsWith("/cves")) return "cve-intelligence";
  if (path.startsWith("/advisories")) return "advisories";
  if (path.startsWith("/news")) return "news";
  if (path.startsWith("/settings/rbac")) return "settings-rbac";
  if (path.startsWith("/settings")) return "settings-sources";
  return "help-center";
}

function useShortcuts() {
  const { openHelp } = useHelp();
  const nav = useNavigate();
  const loc = useLocation();
  const pendingG = useRef(false);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      if (["INPUT", "TEXTAREA", "SELECT"].includes(t.tagName) || t.isContentEditable || e.metaKey || e.ctrlKey) return;
      if (e.key === "?") { e.preventDefault(); openHelp(helpIdFor(loc.pathname)); }
      else if (e.key === "/") { const s = document.getElementById("cve-search"); if (s) { e.preventDefault(); s.focus(); } }
      else if (pendingG.current && e.key === "c") { nav("/cves"); pendingG.current = false; }
      else if (pendingG.current && e.key === "h") { nav("/help"); pendingG.current = false; }
      else if (e.key === "g") { pendingG.current = true; setTimeout(() => (pendingG.current = false), 1000); }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [openHelp, nav, loc.pathname]);
}

const tab = ({ isActive }: { isActive: boolean }) =>
  `rounded-md px-3 py-2 text-sm font-medium ${isActive ? "bg-white/15 text-white" : "text-blue-100 hover:bg-white/10 hover:text-white"}`;

const SETTINGS_PERMS = ["source:manage", "user:manage", "integration:manage", "settings:manage", "sso:manage", "ai:manage"];

function Shell() {
  const { me, can } = useAuth();
  const qc = useQueryClient();
  useShortcuts();
  const logout = async () => {
    await api("/api/auth/logout", { method: "POST" }).catch(() => undefined);
    qc.clear();
    window.location.assign("/login");
  };
  return (
    <div className="min-h-screen">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-white focus:px-3 focus:py-2">Skip to content</a>
      <header className="bg-ec-navy">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-4 px-4 py-2">
          <span className="text-lg font-bold text-white">ExposureCatalyst</span>
          <nav aria-label="Main" className="flex flex-wrap gap-1">
            {can("cve:view") && <NavLink to="/cves" className={tab}>CVE Intelligence</NavLink>}
            {can("cve:view") && <NavLink to="/advisories" className={tab}>Advisories</NavLink>}
            {can("news:view") && <NavLink to="/news" className={tab}>Security News</NavLink>}
            {SETTINGS_PERMS.some(can) && <NavLink to="/settings" className={tab}>Settings</NavLink>}
            <NavLink to="/help" className={tab}>Help Center</NavLink>
          </nav>
          <div className="ml-auto flex items-center gap-3 text-sm text-blue-100">
            <span title={me?.roles.join(", ")}>{me?.display_name ?? me?.username}</span>
            <button className="rounded-md border border-blue-300/40 px-2 py-1 text-xs hover:bg-white/10" onClick={logout}>Sign out</button>
          </div>
        </div>
      </header>
      <main id="main" className="mx-auto max-w-7xl px-4 py-6">
        <Routes>
          <Route path="/" element={<Navigate to="/cves" replace />} />
          <Route path="/cves" element={<CveListPage />} />
          <Route path="/cves/:cveId" element={<CveDetailPage />} />
          <Route path="/advisories/*" element={<AdvisoriesPage />} />
          <Route path="/news" element={<NewsPage />} />
          <Route path="/settings/*" element={<SettingsPage />} />
          <Route path="/help" element={<HelpCenterPage />} />
          <Route path="*" element={<p className="text-sm text-ec-slate">Page not found.</p>} />
        </Routes>
      </main>
    </div>
  );
}

export default function App() {
  const { me, loading } = useAuth();
  const loc = useLocation();
  if (loading) return <p className="p-8 text-sm text-slate-500">Loading…</p>;
  if (!me) {
    return (
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="*" element={<Navigate to={`/login?next=${encodeURIComponent(loc.pathname + loc.search)}`} replace />} />
      </Routes>
    );
  }
  if (loc.pathname === "/login") return <Navigate to="/cves" replace />;
  return <Shell />;
}
