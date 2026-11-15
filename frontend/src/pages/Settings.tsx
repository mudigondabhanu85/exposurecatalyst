import { useState, type FormEvent } from "react";
import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, fmtDateTime, type SourceInfo, type SourcesResp } from "../api";
import { useAuth } from "../auth";
import { InfoTip } from "../help";
import { Forbidden } from "../components/StatusScreen";
import IntegrationsSettings from "./Integrations";
import SsoSettings from "./Sso";
import AlertsSettings from "./Alerts";
import AiSettings from "./AiSettings";
import DatabaseSettings from "./Database";
import { EmptyState, ErrorNote, HealthBadge, PageHeader } from "../components/ui";

interface Role { id: number; name: string; description: string | null; is_system: boolean; permissions: string[]; user_count: number }
interface Matrix { permissions: { id: string; description: string }[]; roles: Role[] }
interface UserRow { id: number; username: string; email: string | null; display_name: string | null; is_active: boolean; is_local: boolean; mfa_enabled: boolean; locked: boolean; roles: string[]; last_login_at: string | null; auth_source: string; sso_groups: string[] }
interface JobRun { id: number; source: string; trigger: string; started_at: string; finished_at: string | null; status: string; records: number; error: string | null }

const SUBTABS: { to: string; label: string; perm: string; phase?: number }[] = [
  { to: "sso", label: "Identity & SSO", perm: "sso:manage" },
  { to: "rbac", label: "Users & RBAC", perm: "user:manage" },
  { to: "database", label: "Database", perm: "settings:manage" },
  { to: "integrations", label: "Integrations", perm: "integration:manage" },
  { to: "smtp", label: "SMTP", perm: "settings:manage" },
  { to: "sources", label: "CVE Sources", perm: "source:manage" },
  { to: "alerts", label: "Alerts & Scheduling", perm: "settings:manage" },
  { to: "news", label: "News feeds", perm: "news:manage" },
  { to: "ai", label: "AI Providers", perm: "ai:manage" },
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
              <NavLink to={`/settings/${t.to}`} className={({ isActive }) => `block rounded-md px-3 py-2 text-sm ${isActive ? "bg-ec-navy text-white" : "text-ec-slate hover:bg-ec-surface-alt"}`}>
                {t.label}{t.phase && <span className="ml-1 text-xs opacity-70">(Phase {t.phase})</span>}
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>
      <div className="flex-1">
        <Routes>
          <Route index element={visible[0] ? <Navigate to={`/settings/${visible.find((t) => !t.phase)?.to ?? visible[0].to}`} replace /> : <EmptyState title="No settings available" why="Your role does not include any administrative permissions." />} />
          <Route path="sources" element={can("source:manage") ? <SourcesSettings /> : <Forbidden />} />
          <Route path="rbac" element={can("user:manage") ? <RbacSettings /> : <Forbidden />} />
          <Route path="smtp" element={can("settings:manage") ? <SmtpSettings /> : <Forbidden />} />
          <Route path="integrations" element={can("integration:manage") ? <IntegrationsSettings /> : <Forbidden />} />
          <Route path="sso" element={can("sso:manage") ? <SsoSettings /> : <Forbidden />} />
          <Route path="alerts" element={can("settings:manage") ? <AlertsSettings /> : <Forbidden />} />
          <Route path="news" element={can("news:manage") ? <NewsFeedsSettings /> : <Forbidden />} />
          <Route path="ai" element={can("ai:manage") ? <AiSettings /> : <Forbidden />} />
          <Route path="database" element={can("settings:manage") ? <DatabaseSettings /> : <Forbidden />} />
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
                {!u.is_local ? (<div>{u.roles.join(", ") || <span className="text-red-800">No access (no mapped group)</span>}
                  <div className="text-xs text-ec-slate" title="Roles come from group → role mappings (Settings → Identity & SSO)">via groups: {u.sso_groups.join(", ") || "—"}</div></div>) : (
                <details>
                  <summary className="cursor-pointer">{u.roles.join(", ") || "No roles"}</summary>
                  <form className="mt-2 space-y-1" onSubmit={(e) => { e.preventDefault(); setRoles.mutate({ id: u.id, roles: new FormData(e.currentTarget).getAll("r").map(String) }); }}>
                    {matrix.data?.roles.map((r) => (
                      <label key={r.id} className="flex items-center gap-2 text-xs"><input type="checkbox" name="r" value={r.name} defaultChecked={u.roles.includes(r.name)} disabled={u.id === me?.id} />{r.name}</label>
                    ))}
                    <button className="btn-secondary" disabled={u.id === me?.id}>Save roles</button>
                  </form>
                </details>)}
              </td>
              <td className="td">{u.mfa_enabled ? "Enrolled" : "—"}</td>
              <td className="td">{u.is_local ? "Yes" : u.auth_source.toUpperCase()}</td>
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
      {can("role:manage") && matrix.data && <RoleEditor permissions={matrix.data.permissions} roles={matrix.data.roles.filter((r) => !r.is_system)} onChange={invalidate} />}
    </>
  );
}

interface SmtpCfg {
  configured: boolean; provider?: "smtp" | "ses_api"; auth?: "password" | "oauth2_m365"; host?: string | null; port?: number | null;
  security?: string | null; username?: string | null; has_password?: boolean; from_address?: string; from_name?: string | null; reply_to?: string | null;
  m365_tenant_id?: string | null; m365_client_id?: string | null; has_m365_client_secret?: boolean; m365_cloud?: string;
  ses_region?: string | null; ses_configuration_set?: string | null;
}
type Method = "password" | "m365" | "ses_api";
interface Preset { id: string; label: string; provider: "smtp" | "ses_api"; auth?: string; host?: string; port?: number; security?: string; m365_cloud?: string }

const METHODS: { id: Method; label: string; hint: string }[] = [
  { id: "password", label: "SMTP relay — username & password", hint: "Any relay, including Amazon SES SMTP credentials." },
  { id: "m365", label: "Microsoft 365 — OAuth2", hint: "Entra ID app (client credentials) with SMTP.SendAsApp. No mailbox password stored." },
  { id: "ses_api", label: "Amazon SES — API (IAM role)", hint: "SESv2 SendEmail with the task's IAM role. No keys stored." },
];

function SmtpSettings() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["smtp"], queryFn: () => api<SmtpCfg>("/api/settings/smtp") });
  const presets = useQuery({ queryKey: ["smtp-presets"], queryFn: () => api<Preset[]>("/api/settings/smtp/presets") });
  const [msg, setMsg] = useState<string | null>(null);
  const [method, setMethod] = useState<Method | null>(null);
  const [form, setForm] = useState<Record<string, string>>({});
  const save = useMutation({ mutationFn: (body: Record<string, unknown>) => api<SmtpCfg>("/api/settings/smtp", { method: "PUT", body }),
                             onSuccess: (d) => { qc.setQueryData(["smtp"], d); setMsg("Saved."); } });
  const test = useMutation({ mutationFn: (to: string) => api<{ message_id?: string }>("/api/settings/smtp/test", { method: "POST", body: { to } }),
                             onSuccess: () => setMsg("Test email sent.") });
  const c = q.data;
  if (!c) return null;
  const m: Method = method ?? (c.provider === "ses_api" ? "ses_api" : c.auth === "oauth2_m365" ? "m365" : "password");
  const val = (k: keyof SmtpCfg, dflt = "") => form[k] ?? (c[k] == null ? dflt : String(c[k]));
  const setVal = (k: string) => (e: { target: { value: string } }) => setForm((f) => ({ ...f, [k]: e.target.value }));
  const applyPreset = (id: string) => {
    const p = presets.data?.find((x) => x.id === id);
    if (!p) return;
    setMethod(p.provider === "ses_api" ? "ses_api" : p.auth === "oauth2_m365" ? "m365" : "password");
    setForm((f) => ({ ...f, ...(p.host ? { host: p.host } : {}), ...(p.port ? { port: String(p.port) } : {}),
                      ...(p.security ? { security: p.security } : {}), ...(p.m365_cloud ? { m365_cloud: p.m365_cloud } : {}) }));
  };
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const g = (k: string) => { const v = fd.get(k); return v === null || v === "" ? null : String(v); };
    const body: Record<string, unknown> = { provider: m === "ses_api" ? "ses_api" : "smtp", auth: m === "m365" ? "oauth2_m365" : "password",
      from_address: g("from_address"), from_name: g("from_name"), reply_to: g("reply_to") };
    if (m === "ses_api") Object.assign(body, { ses_region: g("ses_region"), ses_configuration_set: g("ses_configuration_set") });
    else Object.assign(body, { host: g("host"), port: Number(fd.get("port")), security: g("security"), username: g("username") });
    if (m === "password" && g("password")) body.password = g("password");
    if (m === "m365") Object.assign(body, { m365_tenant_id: g("m365_tenant_id"), m365_client_id: g("m365_client_id"), m365_cloud: g("m365_cloud") ?? "global",
                                            ...(g("m365_client_secret") ? { m365_client_secret: g("m365_client_secret") } : {}) });
    save.mutate(body);
  };
  return (
    <>
      <PageHeader title="SMTP" helpId="settings-smtp" subtitle="Outbound mail for advisories and alerts: SMTP relay, Microsoft 365 (OAuth2) or Amazon SES" />
      {msg && <p role="status" className="mb-3 rounded-sm bg-ec-surface-alt px-3 py-2 text-sm">{msg}</p>}
      <ErrorNote error={save.error ?? test.error} />
      <form onSubmit={submit} className="card mb-4 space-y-4">
        <div className="flex flex-wrap items-end gap-3">
          <fieldset className="flex-1">
            <legend className="label">Delivery method</legend>
            <div className="grid gap-2 md:grid-cols-3">
              {METHODS.map((x) => (
                <label key={x.id} className={`cursor-pointer rounded-md border p-3 text-sm ${m === x.id ? "border-ec-navy bg-ec-surface-alt" : "border-ec-border"}`}>
                  <span className="flex items-center gap-2 font-semibold"><input type="radio" name="method" checked={m === x.id} onChange={() => setMethod(x.id)} />{x.label}</span>
                  <span className="mt-1 block text-xs text-ec-slate">{x.hint}</span>
                </label>
              ))}
            </div>
          </fieldset>
          <div><label className="label" htmlFor="preset">Start from a preset</label>
            <select id="preset" className="input w-64" value="" onChange={(e) => applyPreset(e.target.value)}>
              <option value="">Choose…</option>{presets.data?.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
            </select></div>
        </div>

        <div className="grid gap-3 md:grid-cols-3">
          {m !== "ses_api" ? (<>
            <div><label className="label" htmlFor="h">Host</label><input id="h" name="host" className="input w-full" value={val("host")} onChange={setVal("host")} placeholder={m === "m365" ? "smtp.office365.com" : "smtp.example.com"} required /></div>
            <div><label className="label" htmlFor="pt">Port</label><input id="pt" name="port" type="number" className="input w-full" value={val("port", "587")} onChange={setVal("port")} required /></div>
            <div><label className="label" htmlFor="sec">Security</label><select id="sec" name="security" className="input w-full" value={val("security", "starttls")} onChange={setVal("security")}><option value="starttls">STARTTLS (587)</option><option value="ssl">SSL/TLS (465)</option>{m === "password" && <option value="none">None (dev only)</option>}</select></div>
            <div><label className="label" htmlFor="un">{m === "m365" ? "Sending mailbox" : "Username"}</label><input id="un" name="username" className="input w-full" value={val("username")} onChange={setVal("username")} autoComplete="off" required={m === "m365"} placeholder={m === "m365" ? "secops@contoso.com" : ""} /></div>
            {m === "password" && <div><label className="label" htmlFor="pw">Password</label><input id="pw" name="password" type="password" className="input w-full" autoComplete="new-password" placeholder={c.has_password ? "•••••• (stored — leave blank to keep)" : ""} /></div>}
          </>) : (<>
            <div><label className="label" htmlFor="sr">SES region</label><input id="sr" name="ses_region" className="input w-full" value={val("ses_region")} onChange={setVal("ses_region")} placeholder="us-east-1" required pattern="[a-z]{2}(-gov)?-[a-z]+-\d" /></div>
            <div><label className="label" htmlFor="cs">Configuration set (optional)</label><input id="cs" name="ses_configuration_set" className="input w-full" value={val("ses_configuration_set")} onChange={setVal("ses_configuration_set")} placeholder="excat-events" /></div>
            <p className="self-end text-xs text-ec-slate">Credentials come from the AWS default chain (the ECS task role in the reference deployment). The From address must be a verified SES identity.</p>
          </>)}
          {m === "m365" && (<>
            <div><label className="label" htmlFor="mt">Directory (tenant) ID</label><input id="mt" name="m365_tenant_id" className="input w-full" value={val("m365_tenant_id")} onChange={setVal("m365_tenant_id")} required /></div>
            <div><label className="label" htmlFor="mc">Application (client) ID</label><input id="mc" name="m365_client_id" className="input w-full" value={val("m365_client_id")} onChange={setVal("m365_client_id")} required /></div>
            <div><label className="label" htmlFor="ms">Client secret</label><input id="ms" name="m365_client_secret" type="password" className="input w-full" autoComplete="new-password" required={!c.has_m365_client_secret} placeholder={c.has_m365_client_secret ? "•••••• (stored — leave blank to keep)" : ""} /></div>
            <div><label className="label" htmlFor="mcl">Cloud</label><select id="mcl" name="m365_cloud" className="input w-full" value={val("m365_cloud", "global")} onChange={setVal("m365_cloud")}><option value="global">Commercial / GCC</option><option value="usgov">GCC High / DoD</option></select></div>
          </>)}
          <div><label className="label" htmlFor="fa">From address</label><input id="fa" name="from_address" type="email" className="input w-full" value={val("from_address")} onChange={setVal("from_address")} required /></div>
          <div><label className="label" htmlFor="fn">From name</label><input id="fn" name="from_name" className="input w-full" value={val("from_name", "ExposureCatalyst")} onChange={setVal("from_name")} /></div>
          <div><label className="label" htmlFor="rt">Reply-To</label><input id="rt" name="reply_to" type="email" className="input w-full" value={val("reply_to")} onChange={setVal("reply_to")} /></div>
        </div>
        {m === "m365" && <p className="text-xs text-ec-slate">Entra ID app with the <strong>Office 365 Exchange Online → SMTP.SendAsApp</strong> application permission (admin consent), its service principal registered in Exchange Online, and FullAccess on the sending mailbox. See the help for the PowerShell steps.</p>}
        <div><button className="btn-primary" disabled={save.isPending}>Save</button></div>
      </form>
      {c.configured && (
        <form className="card flex flex-wrap items-end gap-2" onSubmit={(e) => { e.preventDefault(); test.mutate(String(new FormData(e.currentTarget).get("to"))); }}>
          <div><label className="label" htmlFor="tt">Send a test email to</label><input id="tt" name="to" type="email" className="input w-72" required /></div>
          <button className="btn-secondary" disabled={test.isPending}>{test.isPending ? "Sending…" : "Send test"}</button>
          <span className="text-xs text-ec-slate">Uses the saved settings ({c.provider === "ses_api" ? "Amazon SES API" : c.auth === "oauth2_m365" ? "Microsoft 365 OAuth2" : "SMTP"}).</span>
        </form>
      )}
    </>
  );
}

function RoleEditor({ permissions, roles, onChange }: { permissions: { id: string; description: string }[]; roles: Role[]; onChange: () => void }) {
  const [editing, setEditing] = useState<Role | "new" | null>(null);
  const save = useMutation({
    mutationFn: (body: { name: string; description: string; permissions: string[] }) =>
      editing && editing !== "new" ? api(`/api/admin/roles/${editing.id}`, { method: "PUT", body }) : api("/api/admin/roles", { method: "POST", body }),
    onSuccess: () => { setEditing(null); onChange(); },
  });
  const del = useMutation({ mutationFn: (id: number) => api(`/api/admin/roles/${id}`, { method: "DELETE" }), onSuccess: onChange });
  const cur = editing && editing !== "new" ? editing : undefined;
  return (
    <section className="card mt-6">
      <div className="mb-2 flex items-center justify-between"><h2 className="font-heading font-bold">Custom roles</h2><button className="btn-primary" onClick={() => setEditing("new")}>New role</button></div>
      <p className="mb-3 text-xs text-ec-slate">* marks custom roles in the matrix. Keep segregation of duties: avoid combining <code>advisory:approve</code> with <code>advisory:create</code> in one role.</p>
      <ErrorNote error={save.error ?? del.error} />
      <ul className="mb-3 space-y-1 text-sm">{roles.map((r) => (
        <li key={r.id} className="flex items-center gap-2"><strong>{r.name}</strong><span className="text-xs text-ec-slate">{r.permissions.length} permission(s) · {r.user_count} user(s)</span>
          <button className="text-xs underline" onClick={() => setEditing(r)}>Edit</button>
          <button className="text-xs text-red-800 underline" onClick={() => window.confirm(`Delete role ${r.name}?`) && del.mutate(r.id)}>Delete</button></li>))}
        {roles.length === 0 && <li className="text-ec-slate">No custom roles yet.</li>}</ul>
      {editing && (
        <form key={cur?.id ?? "new"} className="space-y-3 rounded-md border border-ec-border p-3" onSubmit={(e) => { e.preventDefault(); const fd = new FormData(e.currentTarget);
          save.mutate({ name: String(fd.get("name")), description: String(fd.get("desc") ?? ""), permissions: fd.getAll("perm").map(String) }); }}>
          <div className="grid gap-3 md:grid-cols-2">
            <div><label className="label" htmlFor="rn">Role name</label><input id="rn" name="name" className="input w-full" required minLength={2} defaultValue={cur?.name} /></div>
            <div><label className="label" htmlFor="rd">Description</label><input id="rd" name="desc" className="input w-full" defaultValue={cur?.description ?? ""} /></div>
          </div>
          <fieldset className="grid gap-1 md:grid-cols-2"><legend className="label">Permissions</legend>
            {permissions.map((p) => <label key={p.id} className="flex items-start gap-2 text-xs"><input type="checkbox" name="perm" value={p.id} defaultChecked={cur?.permissions.includes(p.id)} /><span><code>{p.id}</code> — {p.description}</span></label>)}
          </fieldset>
          <div className="flex gap-2"><button className="btn-primary">Save role</button><button type="button" className="btn-secondary" onClick={() => setEditing(null)}>Cancel</button></div>
        </form>
      )}
    </section>
  );
}

interface Feed { id: number; name: string; url: string; category: string; enabled: boolean; is_default: boolean; status: string; last_fetched_at: string | null; last_error: string | null; items_last_run: number; items_total: number }

function NewsFeedsSettings() {
  const qc = useQueryClient();
  const feeds = useQuery({ queryKey: ["news-feeds"], queryFn: () => api<Feed[]>("/api/news/feeds") });
  const inv = () => qc.invalidateQueries({ queryKey: ["news-feeds"] });
  const add = useMutation({ mutationFn: (body: Record<string, unknown>) => api("/api/news/feeds", { method: "POST", body }), onSuccess: inv });
  const toggle = useMutation({ mutationFn: (f: Feed) => api(`/api/news/feeds/${f.id}`, { method: "PATCH", body: { enabled: !f.enabled } }), onSuccess: inv });
  const del = useMutation({ mutationFn: (f: Feed) => api(`/api/news/feeds/${f.id}`, { method: "DELETE" }), onSuccess: inv });
  return (
    <>
      <PageHeader title="News feeds" helpId="settings-news" subtitle="RSS/Atom sources for the Security News tab (refresh interval: CVE Sources → Security news feeds)" />
      <ErrorNote error={add.error ?? toggle.error ?? del.error} />
      <form className="card mb-4 grid gap-3 md:grid-cols-4" onSubmit={(e) => { e.preventDefault(); const fd = new FormData(e.currentTarget); const form = e.currentTarget;
        add.mutate({ name: fd.get("name"), url: fd.get("url"), category: fd.get("category") }, { onSuccess: () => form.reset() }); }}>
        <div><label className="label" htmlFor="fn">Name</label><input id="fn" name="name" className="input w-full" required minLength={2} /></div>
        <div className="md:col-span-2"><label className="label" htmlFor="fu">Feed URL (https)</label><input id="fu" name="url" type="url" className="input w-full" required placeholder="https://example.com/feed.xml" /></div>
        <div><label className="label" htmlFor="fc">Category</label><select id="fc" name="category" className="input w-full"><option value="news">News</option><option value="government">Government</option><option value="vendor-intel">Vendor threat intel</option></select></div>
        <div><button className="btn-primary">Add feed</button></div>
      </form>
      <div className="card overflow-x-auto p-0"><table className="min-w-full text-sm">
        <thead className="bg-ec-surface-alt"><tr><th className="th">Feed</th><th className="th">Category</th><th className="th">Health</th><th className="th">Enabled</th><th className="th">Last fetch</th><th className="th text-right">Items</th><th className="th" /></tr></thead>
        <tbody>{feeds.data?.map((f) => (
          <tr key={f.id} className="border-t border-ec-surface-alt">
            <td className="td font-medium">{f.name}{f.is_default && <span className="ml-1 text-xs text-ec-slate">(default)</span>}<div className="break-all text-xs text-ec-slate">{f.url}</div>{f.last_error && <div className="text-xs text-red-800">{f.last_error}</div>}</td>
            <td className="td">{f.category}</td><td className="td"><HealthBadge health={f.status === "ok" ? "healthy" : f.status === "error" ? "failing" : "pending"} /></td>
            <td className="td"><input type="checkbox" aria-label={`Enable ${f.name}`} checked={f.enabled} onChange={() => toggle.mutate(f)} /></td>
            <td className="td text-xs">{fmtDateTime(f.last_fetched_at)}</td><td className="td text-right">{f.items_total} <span className="text-xs text-ec-slate">(+{f.items_last_run})</span></td>
            <td className="td"><button className="text-xs text-red-800 underline" onClick={() => window.confirm(`Remove ${f.name}? Its stored items are deleted.`) && del.mutate(f)}>Remove</button></td>
          </tr>))}</tbody></table></div>
    </>
  );
}
