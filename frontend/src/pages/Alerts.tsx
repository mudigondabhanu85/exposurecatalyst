import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, fmtDateTime } from "../api";
import { EmptyState, ErrorNote, PageHeader } from "../components/ui";

interface Rule {
  id: number; name: string; enabled: boolean; criteria: Record<string, unknown>; recipients: { emails?: string[]; user_ids?: number[]; role_ids?: number[] };
  channels: string[]; webhooks_set: string[]; mode: string; throttle_minutes: number; digest_minutes: number;
  last_delivered_at: string | null; last_error: string | null; pending: number; total_matches: number;
}
interface Role { id: number; name: string }
const list = (s: FormDataEntryValue | null) => String(s ?? "").split(/[,\n]/).map((x) => x.trim()).filter(Boolean);

function describe(c: Record<string, unknown>): string {
  const parts: string[] = [];
  if (c.min_severity) parts.push(`severity ≥ ${c.min_severity}`);
  if (c.cvss_min !== undefined) parts.push(`CVSS ≥ ${c.cvss_min}`);
  if (c.epss_min !== undefined) parts.push(`EPSS ≥ ${Number(c.epss_min) * 100}%`);
  if (c.kev_added) parts.push("added to KEV");
  if ((c.vendors as string[])?.length) parts.push(`vendor: ${(c.vendors as string[]).join(", ")}`);
  if ((c.products as string[])?.length) parts.push(`product: ${(c.products as string[]).join(", ")}`);
  if ((c.keywords as string[])?.length) parts.push(`keywords: ${(c.keywords as string[]).join(", ")}`);
  if (c.affected_assets) parts.push("affected assets > 0");
  return parts.join(" AND ");
}

function RuleForm({ rule, roles, onDone }: { rule?: Rule; roles: Role[]; onDone: () => void }) {
  const qc = useQueryClient();
  const c = rule?.criteria ?? {};
  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => rule ? api(`/api/alerts/${rule.id}`, { method: "PUT", body }) : api("/api/alerts", { method: "POST", body }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["alerts"] }); onDone(); },
  });
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const num = (k: string) => (fd.get(k) === "" || fd.get(k) === null ? null : Number(fd.get(k)));
    const webhooks: Record<string, string> = {};
    for (const k of ["slack", "teams"]) if (fd.get(`hook_${k}`)) webhooks[k] = String(fd.get(`hook_${k}`));
    save.mutate({
      name: fd.get("name"), enabled: fd.get("enabled") === "on", mode: fd.get("mode"),
      throttle_minutes: Number(fd.get("throttle")), digest_minutes: Number(fd.get("digest")),
      criteria: { min_severity: fd.get("sev") || null, cvss_min: num("cvss"), epss_min: num("epss"), kev_added: fd.get("kev") === "on",
                  vendors: list(fd.get("vendors")), products: list(fd.get("products")), keywords: list(fd.get("keywords")), affected_assets: fd.get("assets") === "on" },
      channels: ["email", "slack", "teams"].filter((ch) => fd.get(`ch_${ch}`) === "on"),
      recipients: { emails: list(fd.get("emails")), role_ids: fd.getAll("roles").map(Number) },
      ...(Object.keys(webhooks).length ? { webhooks } : {}),
    });
  };
  return (
    <form onSubmit={submit} className="card mb-4 space-y-4">
      <div className="grid gap-3 md:grid-cols-3">
        <div><label className="label" htmlFor="an">Rule name</label><input id="an" name="name" className="input w-full" required minLength={2} defaultValue={rule?.name} /></div>
        <label className="flex items-end gap-2 text-sm"><input type="checkbox" name="enabled" defaultChecked={rule?.enabled ?? true} />Enabled</label>
      </div>
      <fieldset className="grid gap-3 rounded-md border border-ec-border p-3 md:grid-cols-4">
        <legend className="label px-1">Criteria (all must match)</legend>
        <div><label className="label" htmlFor="sev">Severity at least</label><select id="sev" name="sev" className="input w-full" defaultValue={String(c.min_severity ?? "")}><option value="">Any</option>{["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((s) => <option key={s}>{s}</option>)}</select></div>
        <div><label className="label" htmlFor="cvss">CVSS ≥</label><input id="cvss" name="cvss" type="number" step="0.1" min={0} max={10} className="input w-full" defaultValue={c.cvss_min as number | undefined} /></div>
        <div><label className="label" htmlFor="epss">EPSS ≥ (0–1)</label><input id="epss" name="epss" type="number" step="0.01" min={0} max={1} className="input w-full" defaultValue={c.epss_min as number | undefined} /></div>
        <div className="flex flex-col justify-end gap-1 text-sm"><label className="flex items-center gap-2"><input type="checkbox" name="kev" defaultChecked={Boolean(c.kev_added)} />Newly added to KEV</label>
          <label className="flex items-center gap-2"><input type="checkbox" name="assets" defaultChecked={Boolean(c.affected_assets)} />Affected assets &gt; 0</label></div>
        <div><label className="label" htmlFor="vendors">Vendor watchlist</label><input id="vendors" name="vendors" className="input w-full" placeholder="fortinet, cisco" defaultValue={((c.vendors as string[]) ?? []).join(", ")} /></div>
        <div><label className="label" htmlFor="products">Product watchlist</label><input id="products" name="products" className="input w-full" placeholder="fortios" defaultValue={((c.products as string[]) ?? []).join(", ")} /></div>
        <div className="md:col-span-2"><label className="label" htmlFor="kw">Keywords</label><input id="kw" name="keywords" className="input w-full" placeholder="remote code execution, authentication bypass" defaultValue={((c.keywords as string[]) ?? []).join(", ")} /></div>
      </fieldset>
      <fieldset className="grid gap-3 rounded-md border border-ec-border p-3 md:grid-cols-3">
        <legend className="label px-1">Notify</legend>
        <div className="space-y-1 text-sm">
          {["email", "slack", "teams"].map((ch) => <label key={ch} className="flex items-center gap-2 capitalize"><input type="checkbox" name={`ch_${ch}`} defaultChecked={rule ? rule.channels.includes(ch) : ch === "email"} />{ch}</label>)}
        </div>
        <div><label className="label" htmlFor="emails">Email addresses</label><textarea id="emails" name="emails" rows={2} className="input w-full" defaultValue={(rule?.recipients.emails ?? []).join(", ")} />
          <div className="label mt-2">Roles</div>{roles.map((r) => <label key={r.id} className="mr-3 inline-flex items-center gap-1 text-xs"><input type="checkbox" name="roles" value={r.id} defaultChecked={rule?.recipients.role_ids?.includes(r.id)} />{r.name}</label>)}</div>
        <div className="space-y-2">
          <div><label className="label" htmlFor="hs">Slack incoming webhook URL</label><input id="hs" name="hook_slack" type="url" className="input w-full" placeholder={rule?.webhooks_set.includes("slack") ? "•••••• stored — leave blank to keep" : "https://hooks.slack.com/services/…"} /></div>
          <div><label className="label" htmlFor="ht">Teams workflow / webhook URL</label><input id="ht" name="hook_teams" type="url" className="input w-full" placeholder={rule?.webhooks_set.includes("teams") ? "•••••• stored — leave blank to keep" : "https://…webhook.office.com/… or …logic.azure.com/…"} /></div>
        </div>
      </fieldset>
      <div className="grid gap-3 md:grid-cols-4">
        <div><label className="label" htmlFor="mode">Delivery</label><select id="mode" name="mode" className="input w-full" defaultValue={rule?.mode ?? "immediate"}><option value="immediate">Immediate (throttled)</option><option value="digest">Digest</option></select></div>
        <div><label className="label" htmlFor="thr">Throttle (min)</label><input id="thr" name="throttle" type="number" min={0} className="input w-full" defaultValue={rule?.throttle_minutes ?? 60} /></div>
        <div><label className="label" htmlFor="dig">Digest every (min)</label><input id="dig" name="digest" type="number" min={15} className="input w-full" defaultValue={rule?.digest_minutes ?? 1440} /></div>
      </div>
      <ErrorNote error={save.error} />
      <div className="flex gap-2"><button className="btn-primary" disabled={save.isPending}>Save rule</button><button type="button" className="btn-secondary" onClick={onDone}>Cancel</button></div>
    </form>
  );
}

export default function AlertsSettings() {
  const qc = useQueryClient();
  const rules = useQuery({ queryKey: ["alerts"], queryFn: () => api<Rule[]>("/api/alerts") });
  const roles = useQuery({ queryKey: ["rbac"], queryFn: () => api<{ roles: Role[] }>("/api/admin/rbac") });
  const [editing, setEditing] = useState<Rule | "new" | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const run = useMutation({ mutationFn: (id: number) => api<{ new_matches: number; delivered: number }>(`/api/alerts/${id}/run`, { method: "POST" }),
                            onSuccess: (r) => { setMsg(`${r.new_matches} new match(es), ${r.delivered} delivered.`); qc.invalidateQueries({ queryKey: ["alerts"] }); } });
  const del = useMutation({ mutationFn: (id: number) => api(`/api/alerts/${id}`, { method: "DELETE" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["alerts"] }) });
  return (
    <>
      <PageHeader title="Alerts & Scheduling" helpId="settings-alerts" subtitle="Notify people when CVEs that matter to you appear or change"
                  actions={<button className="btn-primary" onClick={() => setEditing("new")}>New rule</button>} />
      <p className="mb-4 text-sm text-ec-slate">Rules are evaluated after every ingestion tick against CVEs that changed since the last evaluation. Fetch intervals per source are set in <Link className="link" to="/settings/sources">CVE Sources</Link>; the news refresh interval arrives with Security News (Phase 5).</p>
      {msg && <p role="status" className="mb-3 rounded-sm bg-ec-surface-alt px-3 py-2 text-sm">{msg}</p>}
      <ErrorNote error={run.error ?? del.error} />
      {editing && <RuleForm key={editing === "new" ? "new" : editing.id} rule={editing === "new" ? undefined : editing} roles={roles.data?.roles ?? []} onDone={() => setEditing(null)} />}
      {rules.data?.length === 0 && !editing ? <EmptyState title="No alert rules yet" why="Create a rule, e.g. “Critical or KEV-listed CVEs for our vendor watchlist”, and choose email, Slack or Teams." /> : (
        <div className="card overflow-x-auto p-0"><table className="min-w-full text-sm">
          <thead className="bg-ec-surface-alt"><tr><th className="th">Rule</th><th className="th">Criteria</th><th className="th">Channels</th><th className="th">Matches (pending)</th><th className="th">Last sent</th><th className="th" /></tr></thead>
          <tbody>{rules.data?.map((r) => (
            <tr key={r.id} className="border-t border-ec-surface-alt">
              <td className="td font-medium">{r.name}{!r.enabled && <span className="ml-1 text-xs text-ec-slate">(disabled)</span>}<div className="text-xs text-ec-slate">{r.mode === "digest" ? `digest / ${r.digest_minutes} min` : `throttle ${r.throttle_minutes} min`}</div></td>
              <td className="td text-xs">{describe(r.criteria)}</td><td className="td text-xs">{r.channels.join(", ")}</td>
              <td className="td">{r.total_matches} ({r.pending})</td>
              <td className="td text-xs">{fmtDateTime(r.last_delivered_at)}{r.last_error && <div className="text-red-800">{r.last_error}</div>}</td>
              <td className="td whitespace-nowrap"><button className="btn-secondary" onClick={() => setEditing(r)}>Edit</button>
                <button className="btn-secondary ml-2" onClick={() => run.mutate(r.id)} title="Evaluate now and send pending matches, ignoring throttle">Run now</button>
                <button className="ml-2 text-xs text-red-800 underline" onClick={() => window.confirm(`Delete rule ${r.name}?`) && del.mutate(r.id)}>Delete</button></td>
            </tr>))}</tbody></table></div>)}
    </>
  );
}
