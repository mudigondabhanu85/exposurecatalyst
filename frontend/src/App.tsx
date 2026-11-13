import { useEffect, useRef } from "react";
import { Link, NavLink, Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import { useAuth } from "./auth";
import { useHelp } from "./help";
import LoginPage from "./pages/Login";
import CveListPage from "./pages/CveList";
import CveDetailPage from "./pages/CveDetail";
import SettingsPage from "./pages/Settings";
import HelpCenterPage from "./pages/HelpCenter";
import { NewsPage } from "./pages/Placeholders";
import AdvisoriesRoutes from "./pages/Advisories";
import { LoadingScreen, NotFound } from "./components/StatusScreen";

/** Route → help topic, used by the global "?" shortcut. */
export function helpIdFor(path: string): string {
  if (/^\/cves\/.+/.test(path)) return "cve-detail";
  if (path.startsWith("/cves")) return "cve-intelligence";
  if (path.startsWith("/advisories/templates")) return "advisory-templates";
  if (/^\/advisories\/\d+/.test(path)) return "advisory-editor";
  if (path.startsWith("/advisories")) return "advisories";
  if (path.startsWith("/settings/smtp")) return "settings-smtp";
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

// Active tab: white text + orange-bright indicator (#FF7A3D on navy = 6.7:1).
const tab = ({ isActive }: { isActive: boolean }) =>
  `border-b-2 px-3 py-3 text-sm font-medium ${isActive ? "border-ec-orange-bright text-white" : "border-transparent text-ec-slate-light hover:text-white"}`;

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
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-4 px-4">
          <Link to="/cves" className="flex shrink-0 items-center py-2" aria-label="ExposureCatalyst — CVE Intelligence">
            {/* Wordmark at 36 px; compact widths show the simple mark (brand rule: < 64 px → mark-simple). */}
            <img src="/brand/svg/logo-dark-wordmark.svg" alt="ExposureCatalyst" height={36} className="hidden h-9 w-auto sm:block" />
            <img src="/brand/svg/mark-simple-dark.svg" alt="ExposureCatalyst" height={32} className="h-8 w-8 sm:hidden" />
          </Link>
          <nav aria-label="Main" className="flex flex-wrap gap-1">
            {can("cve:view") && <NavLink to="/cves" className={tab}>CVE Intelligence</NavLink>}
            {["advisory:create", "advisory:approve", "advisory:send", "advisory:export", "template:manage"].some(can) && <NavLink to="/advisories" className={tab}>Advisories</NavLink>}
            {can("news:view") && <NavLink to="/news" className={tab}>Security News</NavLink>}
            {SETTINGS_PERMS.some(can) && <NavLink to="/settings" className={tab}>Settings</NavLink>}
            <NavLink to="/help" className={tab}>Help Center</NavLink>
          </nav>
          <div className="ml-auto flex items-center gap-3 text-sm text-ec-slate-light">
            <span title={me?.roles.join(", ")}>{me?.display_name ?? me?.username}</span>
            <button className="rounded-sm border border-ec-slate-light/50 px-2 py-1 text-xs text-white hover:bg-white/10 focus-visible:outline-ec-orange-bright" onClick={logout}>Sign out</button>
          </div>
        </div>
      </header>
      <main id="main" className="mx-auto max-w-7xl px-4 py-6">
        <Routes>
          <Route path="/" element={<Navigate to="/cves" replace />} />
          <Route path="/cves" element={<CveListPage />} />
          <Route path="/cves/:cveId" element={<CveDetailPage />} />
          <Route path="/advisories/*" element={<AdvisoriesRoutes />} />
          <Route path="/news" element={<NewsPage />} />
          <Route path="/settings/*" element={<SettingsPage />} />
          <Route path="/help" element={<HelpCenterPage />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </main>
    </div>
  );
}

export default function App() {
  const { me, loading } = useAuth();
  const loc = useLocation();
  if (loading) return <LoadingScreen fullPage />;
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
