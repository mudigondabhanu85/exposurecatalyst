import { useState, type FormEvent } from "react";
import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, fmtDateTime, type SourceInfo, type SourcesResp } from "../api";
import { useAuth } from "../auth";
import { InfoTip } from "../help";
import { Forbidden } from "../components/StatusScreen";
import { EmptyState, ErrorNote, HealthBadge, PageHeader } from "../components/ui";

interface Role { id: number; name: string; description: string | null; is_system: boolean; permissions: string[]; user_count: number }
interface Matrix { permissions: { id: string; description: string }[]; roles: Role[] }
interface UserRow { id: number; username: string; email: string | null; display_name: string | null; is_active: boolean; is_local: boolean; mfa_enabled: boolean; locked: boolean; roles: string[]; last_login_at: string | null }
interface JobRun { id: number; source: string; trigger: string; started_at: string; finished_at: string | null; status: string; records: number; error: string | null }

const SUBTABS: { to: string; label: string; perm: string; phase?: number }[] = [
  { to: "sso", label: "Identity & SSO", perm: "sso:manage", phase: 4 },
  { to: "rbac", label: "Users & RBAC", perm: "user:manage" },
  { to: "database", label: "Database", perm: "settings:manage", phase: 6 },
  { to: "integrations", label: "Integrations", perm: "integration:manage", phase: 3 },
  { to: "smtp", label: "SMTP", perm: "settings:manage", phase: 2 },
  { to: "sources", label: "CVE Sources", perm: "source:manage" },
  { to: "alerts", label: "Alerts & Scheduling", perm: "settings:manage", phase: 4 },
  { to: "ai", label: "AI Providers", perm: "ai:manage", phase: 5 },
];

export default function SettingsPage() {
  const { can } = useAuth();
  const visible = SUBTABS.filter((t) => can(t.perm));
  return (
    <div className="flex flex-col gap-6 md:flex-row">
      <nav aria-label="Settings" className="md:w-56">
        <ul className="space-y-1">
          {visible.map((t) => (
            <li key={t.to}>
              <NavLink to={t.to} className={({ isActive }) => `block rounded-md px-3 py-2 text-sm ${isActive ? "bg-ec-navy text-white" : "text-ec-slate hover:bg-ec-surface-alt"}`}>
                {t.label}{t.phase && <span className="ml-1 text-xs opacity-70">(Phase {t.phase})</span>}
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>
      <div className="flex-1">
        <Routes>
          <Route index element={visible[0] ? <Navigate to={visible.find((t) => !t.phase)?.to ?? visible[0].to} replace /> : <EmptyState title="No settings available" why="Your role does not include any administrative permissions." />} />
          <Route path="sources" element={can("source:manage") ? <SourcesSettings /> : <Forbidden />} />
          <Route path="rbac" element={can("user:manage") ? <RbacSettings /> : <Forbidden />} />
          {SUBTABS.filter((t) => t.phase).map((t) => (
            <Route key={t.to} path={t.to} element={can(t.perm) ? (
              <><PageHeader title={t.label} helpId="help-center" /><EmptyState title={`${t.label} arrives in Phase ${t.phase}`} why="This settings area is part of the delivery plan and will include a step-by-step setup wizard with Test validation at each step." /></>
            ) : <Forbidden />} />
          ))}
        </Routes>
      </div>
    </div>
  );
}



function SourceRow({ s }: { s: SourceInfo }) {
  const qc = useQueryClient();
  const [interval, setInterval] = useState(String(s.interval_minutes));
  const [enabled, setEnabled] = useState(s.enabled);
  const m = useMutation({
    mutationFn: () => api(`/api/sources/${s.source}`, { method: "PATCH", body: { enabled, interval_minutes: Number(interval) } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["sources"] }),
  });
  return (
    <tr className="border-t border-ec-surface-alt">
      <td className="td font-medium">{s.label}</td>
      <td className="td"><HealthBadge health={s.health} /></td>
      <td className="td"><input type="checkbox" aria-label={`Enable ${s.label}`} checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /></td>
      <td className="td"><input aria-label={`${s.label} interval in minutes`} type="number" min={5} max={10080} className="input w-24" value={interval} onChange={(e) => setInterval(e.target.value)} /></td>
      <td className="td text-xs">{fmtDateTime(s.last_success_at)}</td>
      <td className="td">{s.records_last_run}</td>
      <td className="td max-w-xs break-words text-xs text-red-800">{s.last_error ?? ""}</td>
      <td className="td"><button className="btn-secondary" onClick={() => m.mutate()} disabled={m.isPending}>Save</button>{m.error && <ErrorNote error={m.error} />}</td>
    </tr>
  );
}

function SourcesSettings() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["sources"], queryFn: () => api<SourcesResp>("/api/sources") });
  const runs = useQuery({ queryKey: ["runs"], queryFn: () => api<JobRun[]>("/api/sources/runs", { query: { limit: 20 } }), refetchInterval: 30_000 });
  const refresh = useMutation({ mutationFn: () => api("/api/sources/refresh", { method: "POST" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["sources"] }) });
  return (
    <>
      <PageHeader title="CVE Sources" helpId="settings-sources" subtitle="Ingestion health, intervals and recent runs"
                  actions={can("cve:refresh") && <button className="btn-primary" onClick={() => refresh.mutate()}>Refresh now</button>} />
      {q.data && !q.data.scheduler_alive && (
        <p role="status" className="mb-4 rounded-md bg-amber-50 px-3 py-2 text-sm text-amber-900">
          The scheduler has not reported a heartbeat recently ({fmtDateTime(q.data.scheduler_heartbeat_at)}). Scheduled and manual refreshes will not run until the <code>scheduler</code> service is started.
        </p>
      )}
      <div className="card mb-6 overflow-x-auto p-0">
        <table className="min-w-full">
          <thead className="bg-ec-surface-alt"><tr>
            <th className="th">Source</th><th className="th"><span className="inline-flex gap-1">Health<InfoTip k="source_health" /></span></th><th className="th">Enabled</th>
            <th className="th"><span className="inline-flex gap-1">Interval (min)<InfoTip k="interval" /></span></th><th className="th">Last success</th><th className="th">Records</th><th className="th">Last error</th><th className="th" />
          </tr></thead>
          <tbody>{q.data?.sources.map((s) => <SourceRow key={`${s.source}-${s.interval_minutes}-${s.enabled}`} s={s} />)}</tbody>
        </table>
      </div>
      <h2 className="mb-2 font-semibold">Recent runs</h2>
      <div className="card overflow-x-auto p-0">
        <table className="min-w-full text-sm">
          <thead className="bg-ec-surface-alt"><tr><th className="th">Started</th><th className="th">Source</th><th className="th">Trigger</th><th className="th">Status</th><th className="th">Records</th><th className="th">Error</th></tr></thead>
          <tbody>{runs.data?.map((r) => (
            <tr key={r.id} className="border-t border-ec-surface-alt"><td className="td">{fmtDateTime(r.started_at)}</td><td className="td">{r.source}</td><td className="td">{r.trigger}</td>
              <td className="td">{r.status}</td><td className="td">{r.records}</td><td className="td text-xs text-red-800">{r.error}</td></tr>))}
          </tbody>
        </table>
        {runs.data?.length === 0 && <p className="p-4 text-sm text-ec-slate">No runs yet — start the scheduler or click Refresh now.</p>}
      </div>
    </>
  );
}

function RbacSettings() {
  const { can, me } = useAuth();
  const qc = useQueryClient();
  const matrix = useQuery({ queryKey: ["rbac"], queryFn: () => api<Matrix>("/api/admin/rbac") });
  const users = useQuery({ queryKey: ["users"], queryFn: () => api<UserRow[]>("/api/admin/users") });
  const roleId = (name: string) => matrix.data?.roles.find((r) => r.name === name)?.id;
  const invalidate = () => { qc.invalidateQueries({ queryKey: ["users"] }); qc.invalidateQueries({ queryKey: ["rbac"] }); };

  const setRoles = useMutation({
    mutationFn: ({ id, roles }: { id: number; roles: string[] }) => api(`/api/admin/users/${id}/roles`, { method: "PUT", body: { role_ids: roles.map(roleId).filter(Boolean) } }),
    onSuccess: invalidate,
  });
  const unlock = useMutation({ mutationFn: (id: number) => api(`/api/admin/users/${id}`, { method: "PATCH", body: { unlock: true } }), onSuccess: invalidate });
  const create = useMutation({
    mutationFn: (body: Record<string, unknown>) => api("/api/admin/users", { method: "POST", body }),
    onSuccess: invalidate,
  });
  const onCreate = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const form = e.currentTarget;
    create.mutate({ username: fd.get("username"), email: fd.get("email") || null, password: fd.get("password"), role_ids: fd.getAll("roles").map(Number) },
                  { onSuccess: () => form.reset() });
  };

  return (
    <>
      <PageHeader title="Users & RBAC" helpId="settings-rbac" subtitle="Server-enforced role-based access control" />
      <ErrorNote error={setRoles.error ?? unlock.error} />

      <h2 className="mb-2 font-semibold">Users</h2>
      <div className="card mb-6 overflow-x-auto p-0">
        <table className="min-w-full text-sm">
          <thead className="bg-ec-surface-alt"><tr><th className="th">User</th><th className="th">Roles</th><th className="th"><span className="inline-flex gap-1">MFA<InfoTip k="mfa" /></span></th><th className="th"><span className="inline-flex gap-1">Local<InfoTip k="local_account" /></span></th><th className="th">Last login</th><th className="th" /></tr></thead>
          <tbody>{users.data?.map((u) => (
            <tr key={u.id} className="border-t border-ec-surface-alt">
              <td className="td"><div className="font-medium">{u.username}</div><div className="text-xs text-ec-slate">{u.email}</div></td>
              <td className="td">
                <details>
                  <summary className="cursor-pointer">{u.roles.join(", ") || "No roles"}</summary>
                  <form className="mt-2 space-y-1" onSubmit={(e) => { e.preventDefault(); setRoles.mutate({ id: u.id, roles: new FormData(e.currentTarget).getAll("r").map(String) }); }}>
                    {matrix.data?.roles.map((r) => (
                      <label key={r.id} className="flex items-center gap-2 text-xs"><input type="checkbox" name="r" value={r.name} defaultChecked={u.roles.includes(r.name)} disabled={u.id === me?.id} />{r.name}</label>
                    ))}
                    <button className="btn-secondary" disabled={u.id === me?.id}>Save roles</button>
                  </form>
                </details>
              </td>
              <td className="td">{u.mfa_enabled ? "Enrolled" : "—"}</td>
              <td className="td">{u.is_local ? "Yes" : "SSO"}</td>
              <td className="td text-xs">{fmtDateTime(u.last_login_at)}</td>
              <td className="td">{u.locked && <button className="btn-secondary" onClick={() => unlock.mutate(u.id)}>Unlock</button>}</td>
            </tr>))}
          </tbody>
        </table>
      </div>

      <h2 className="mb-2 font-semibold">Add local user</h2>
      <form onSubmit={onCreate} className="card mb-6 grid gap-3 md:grid-cols-4">
        <div><label className="label" htmlFor="nu">Username</label><input id="nu" name="username" className="input w-full" required minLength={3} pattern="[A-Za-z0-9._@-]+" /></div>
        <div><label className="label" htmlFor="ne">Email</label><input id="ne" name="email" type="email" className="input w-full" /></div>
        <div><label className="label" htmlFor="np">Initial password</label><input id="np" name="password" type="password" autoComplete="new-password" className="input w-full" required minLength={12} /></div>
        <fieldset><legend className="label">Roles</legend>
          {matrix.data?.roles.map((r) => <label key={r.id} className="flex items-center gap-2 text-xs"><input type="checkbox" name="roles" value={r.id} />{r.name}</label>)}
        </fieldset>
        <div className="md:col-span-4"><button className="btn-primary" disabled={create.isPending}>Create user</button><ErrorNote error={create.error} /></div>
      </form>

      <h2 className="mb-2 font-semibold">Roles × permissions</h2>
      <div className="card overflow-x-auto p-0">
        <table className="min-w-full text-xs">
          <caption className="sr-only">Roles and permissions matrix</caption>
          <thead className="bg-ec-surface-alt"><tr><th className="th">Permission</th>{matrix.data?.roles.map((r) => <th key={r.id} className="th text-center" title={r.description ?? ""}>{r.name}{!r.is_system && " *"}</th>)}</tr></thead>
          <tbody>{matrix.data?.permissions.map((p) => (
            <tr key={p.id} className="border-t border-ec-surface-alt">
              <th scope="row" className="td text-left font-normal"><code>{p.id}</code><div className="text-ec-slate">{p.description}</div></th>
              {matrix.data?.roles.map((r) => <td key={r.id} className="td text-center">{r.permissions.includes(p.id) ? <span aria-label="granted">✅</span> : <span aria-label="not granted" className="text-slate-300">—</span>}</td>)}
            </tr>))}
          </tbody>
        </table>
      </div>
      {can("role:manage") && <p className="mt-2 text-xs text-ec-slate">* custom role. Custom role editing UI ships with Phase 4; the API (<code>POST/PUT /api/admin/roles</code>) is available now.</p>}
    </>
  );
}
