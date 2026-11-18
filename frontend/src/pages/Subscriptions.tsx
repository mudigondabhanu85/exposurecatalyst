import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, fmtDateTime } from "../api";
import { ErrorNote } from "../components/ui";
import { useSubscriptionsOn } from "../components/Intel";

interface Endpoint { name: string; target: string; method: string; path: string; params: Record<string, string>; results_path: string; pagination: Record<string, unknown>; mapping: Record<string, string> }
interface Preset { key: string; vendor: string; source_type: string; api_status: string; base_url: string | null; auth: { type: string; [k: string]: unknown }; secrets: string[]; fields: string[] | null; endpoints: Endpoint[] | null; docs: string }
interface Sub {
  id: number; name: string; vendor: string; preset: string; source_type: string; api_status: string; enabled: boolean; base_url: string | null;
  config: Record<string, unknown>; effective_config: { auth: { type: string; [k: string]: unknown }; endpoints: Endpoint[] }; secrets_set: string[];
  license: Record<string, string | number>; redistribution: { email: string; ai: boolean; default_tlp: string }; status: string;
  last_sync_at: string | null; last_success_at: string | null; last_error: string | null; error_log: { at: string; error: string }[];
  usage: { api_calls?: number; items?: number; period_start?: string }; quota_left: number | null; items: number;
}
interface PreviewResp { ok: boolean; error?: string; records: { kind: string; title: string; cve_ids: string[]; severity: string | null; exploited: boolean | null; published_at: string | null }[]; skipped?: number; raw_sample?: string | null }

const MAP_FIELDS = ["external_id", "cve_id", "title", "summary", "description", "severity", "exploited", "references", "url", "published", "tags"];
const SECRET_LABEL: Record<string, string> = { api_key: "API key", token: "Token", username: "Username", password: "Password", client_id: "Client ID", client_secret: "Client secret", custom_headers: "Custom headers (JSON)" };
const AUTH_SECRETS: Record<string, string[]> = { none: [], api_key_header: ["api_key"], api_key_query: ["api_key"], bearer: ["token"], basic: ["username", "password"], oauth2_cc: ["client_id", "client_secret"], custom_headers: ["custom_headers"] };
const LICENSE = [["contract_owner", "Contract owner"], ["license_tier", "Licence tier"], ["seats", "Seats"], ["api_quota", "API quota"], ["start_date", "Start date"], ["renewal_date", "Renewal date"], ["cost_center", "Cost center"]] as const;

function EndpointEditor({ ep, onChange, onRemove }: { ep: Endpoint; onChange: (e: Endpoint) => void; onRemove: () => void }) {
  const set = (k: keyof Endpoint, v: unknown) => onChange({ ...ep, [k]: v });
  const pag = ep.pagination as { type?: string; param?: string; next_path?: string };
  return (
    <div className="space-y-2 rounded-sm border border-ec-border p-3 text-sm">
      <div className="grid gap-2 md:grid-cols-4">
        <div><label className="label">Name</label><input className="input w-full" value={ep.name} onChange={(e) => set("name", e.target.value)} /></div>
        <div><label className="label">Maps to</label><select className="input w-full" value={ep.target} onChange={(e) => set("target", e.target.value)}><option value="cve">CVE intelligence</option><option value="news">Security news</option></select></div>
        <div className="md:col-span-2"><label className="label">Path (GET, relative to base URL)</label><input className="input w-full font-mono text-xs" value={ep.path} onChange={(e) => set("path", e.target.value)} /></div>
        <div className="md:col-span-2"><label className="label">Query parameters (JSON; {"{since_iso}"}, {"{since_epoch}"}, {"{limit}"} …)</label>
          <input className="input w-full font-mono text-xs" defaultValue={JSON.stringify(ep.params ?? {})} onBlur={(e) => { try { set("params", JSON.parse(e.target.value || "{}")); } catch { /* keep previous */ } }} /></div>
        <div className="md:col-span-2"><label className="label">Results path (JSONPath)</label><input className="input w-full font-mono text-xs" value={ep.results_path} onChange={(e) => set("results_path", e.target.value)} /></div>
        <div><label className="label">Pagination</label><select className="input w-full" value={pag.type ?? "none"} onChange={(e) => set("pagination", { ...pag, type: e.target.value })}>{["none", "offset", "page", "cursor", "next_url", "link_header"].map((t) => <option key={t}>{t}</option>)}</select></div>
        <div><label className="label">Page / cursor param</label><input className="input w-full font-mono text-xs" value={pag.param ?? ""} onChange={(e) => set("pagination", { ...pag, param: e.target.value })} /></div>
        <div className="md:col-span-2"><label className="label">Next cursor / URL path</label><input className="input w-full font-mono text-xs" value={pag.next_path ?? ""} onChange={(e) => set("pagination", { ...pag, next_path: e.target.value })} /></div>
      </div>
      <details open><summary className="cursor-pointer text-xs font-semibold">Field mapping (JSONPath into each record; “=value” sets a constant)</summary>
        <div className="mt-2 grid gap-1 md:grid-cols-2">{MAP_FIELDS.map((f) => (
          <div key={f} className="flex items-center gap-2"><label className="w-28 text-xs font-semibold" htmlFor={`m-${ep.name}-${f}`}>{f}</label>
            <input id={`m-${ep.name}-${f}`} className="input flex-1 font-mono text-xs" value={ep.mapping?.[f] ?? ""} onChange={(e) => set("mapping", { ...ep.mapping, [f]: e.target.value })} /></div>))}
        </div></details>
      <button type="button" className="text-xs text-red-800 underline" onClick={onRemove}>Remove endpoint</button>
    </div>
  );
}

function SubForm({ preset, existing, onDone }: { preset: Preset; existing?: Sub; onDone: () => void }) {
  const qc = useQueryClient();
  const eff = existing?.effective_config;
  const [auth, setAuth] = useState<Record<string, unknown>>((existing?.config.auth as Record<string, unknown>) ?? eff?.auth ?? preset.auth);
  const [endpoints, setEndpoints] = useState<Endpoint[]>((existing?.config.endpoints as Endpoint[]) ?? eff?.endpoints ?? preset.endpoints ?? []);
  const [preview, setPreview] = useState<PreviewResp | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const authType = String(auth.type ?? "none");
  const secretKeys = Array.from(new Set([...(preset.secrets ?? []), ...(AUTH_SECRETS[authType] ?? [])]));
  const isRest = preset.source_type === "rest";

  const gather = (form: HTMLFormElement) => {
    const fd = new FormData(form);
    const g = (k: string) => String(fd.get(k) ?? "").trim();
    const config: Record<string, unknown> = { auth };
    for (const k of ["poll_minutes", "rate_per_minute", "page_size", "initial_days"]) if (g(k)) config[k] = Number(g(k));
    for (const k of preset.fields ?? []) if (g(k)) config[k] = g(k);
    if (isRest) config.endpoints = endpoints;
    const secrets: Record<string, string> = {};
    for (const k of secretKeys) if (g(`s_${k}`)) secrets[k] = g(`s_${k}`);
    const license: Record<string, unknown> = {};
    for (const [k] of LICENSE) if (g(`l_${k}`)) license[k] = g(`l_${k}`);
    if (g("l_quota_period")) license.quota_period = g("l_quota_period");
    if (g("l_notes")) license.notes = g("l_notes");
    return { name: g("name"), base_url: g("base_url") || null, enabled: fd.get("enabled") === "on", config, secrets, license,
             redistribution: { email: g("r_email"), ai: fd.get("r_ai") === "on", default_tlp: g("r_tlp") } };
  };
  const run = async (form: HTMLFormElement, what: "preview" | "save") => {
    setBusy(true); setErr(null);
    try {
      const b = gather(form);
      if (what === "preview") {
        setPreview(await api<PreviewResp>("/api/subscriptions/preview", { method: "POST", body: { subscription_id: existing?.id ?? null, preset: preset.key, base_url: b.base_url, config: b.config, secrets: b.secrets } }));
      } else {
        if (existing) await api(`/api/subscriptions/${existing.id}`, { method: "PATCH", body: { ...b, secrets: Object.keys(b.secrets).length ? b.secrets : undefined } });
        else await api("/api/subscriptions", { method: "POST", body: { ...b, preset: preset.key, vendor: preset.vendor } });
        qc.invalidateQueries({ queryKey: ["subscriptions"] }); onDone();
      }
    } catch (x) { setErr(x); } finally { setBusy(false); }
  };
  const lic = existing?.license ?? {};
  const red = existing?.redistribution ?? { email: "summary", ai: false, default_tlp: "AMBER" };
  return (
    <form className="space-y-4" onSubmit={(e: FormEvent<HTMLFormElement>) => { e.preventDefault(); run(e.currentTarget, "save"); }}>
      <p className="text-sm text-ec-slate">{preset.docs}{preset.api_status === "confirm" && <span className="ml-1 rounded-sm bg-amber-50 px-1.5 text-xs font-semibold text-amber-900">Confirm defaults with Test &amp; preview</span>}</p>
      <div className="grid gap-3 md:grid-cols-3">
        <div><label className="label" htmlFor="sb-name">Name</label><input id="sb-name" name="name" className="input w-full" required minLength={2} defaultValue={existing?.name ?? preset.vendor} /></div>
        {preset.source_type !== "manual" && <div className="md:col-span-2"><label className="label" htmlFor="sb-url">{preset.source_type === "taxii" ? "TAXII API root" : preset.source_type === "rss" ? "Feed URL" : "Base URL"}</label>
          <input id="sb-url" name="base_url" className="input w-full" defaultValue={existing?.base_url ?? preset.base_url ?? ""} required /></div>}
        {(preset.fields ?? []).map((f) => <div key={f}><label className="label" htmlFor={`sb-${f}`}>{f.replace(/_/g, " ")}</label><input id={`sb-${f}`} name={f} className="input w-full" defaultValue={String(existing?.config[f] ?? "")} /></div>)}
        {preset.source_type !== "manual" && (<>
          <div><label className="label" htmlFor="sb-auth">Authentication</label>
            <select id="sb-auth" className="input w-full" value={authType} onChange={(e) => setAuth({ ...auth, type: e.target.value })}>{Object.keys(AUTH_SECRETS).map((t) => <option key={t}>{t}</option>)}</select></div>
          {authType === "api_key_header" && <div><label className="label">Header name / prefix</label><div className="flex gap-1"><input className="input w-1/2" value={String(auth.header ?? "")} onChange={(e) => setAuth({ ...auth, header: e.target.value })} /><input className="input w-1/2" value={String(auth.prefix ?? "")} onChange={(e) => setAuth({ ...auth, prefix: e.target.value })} /></div></div>}
          {authType === "api_key_query" && <div><label className="label">Query parameter</label><input className="input w-full" value={String(auth.param ?? "")} onChange={(e) => setAuth({ ...auth, param: e.target.value })} /></div>}
          {authType === "oauth2_cc" && <div className="md:col-span-2"><label className="label">Token URL · scope</label><div className="flex gap-1"><input className="input w-2/3" value={String(auth.token_url ?? "")} onChange={(e) => setAuth({ ...auth, token_url: e.target.value })} /><input className="input w-1/3" value={String(auth.scope ?? "")} onChange={(e) => setAuth({ ...auth, scope: e.target.value })} /></div></div>}
          {secretKeys.map((k) => <div key={k}><label className="label" htmlFor={`sb-s-${k}`}>{SECRET_LABEL[k] ?? k}</label>
            <input id={`sb-s-${k}`} name={`s_${k}`} type={k === "username" || k === "client_id" ? "text" : "password"} autoComplete="new-password" className="input w-full" placeholder={existing?.secrets_set.includes(k) ? "•••••• stored — leave blank to keep" : ""} /></div>)}
          <div><label className="label" htmlFor="sb-poll">Poll every (minutes)</label><input id="sb-poll" name="poll_minutes" type="number" min={5} className="input w-full" defaultValue={Number(existing?.config.poll_minutes ?? 60)} /></div>
          <div><label className="label" htmlFor="sb-rate">Rate limit (requests/min)</label><input id="sb-rate" name="rate_per_minute" type="number" min={1} className="input w-full" defaultValue={Number(existing?.config.rate_per_minute ?? 30)} /></div>
          <div><label className="label" htmlFor="sb-init">First pull: last N days</label><input id="sb-init" name="initial_days" type="number" min={1} className="input w-full" defaultValue={Number(existing?.config.initial_days ?? 7)} /></div>
        </>)}
      </div>

      {isRest && <div className="space-y-2"><h4 className="text-sm font-semibold">Endpoints</h4>
        {endpoints.map((ep, n) => <EndpointEditor key={n} ep={ep} onChange={(e) => setEndpoints(endpoints.map((x, i) => (i === n ? e : x)))} onRemove={() => setEndpoints(endpoints.filter((_, i) => i !== n))} />)}
        <button type="button" className="btn-secondary" onClick={() => setEndpoints([...endpoints, { name: "Endpoint", target: "cve", method: "GET", path: "/", params: {}, results_path: "$[*]", pagination: { type: "none" }, mapping: { title: "$.title", cve_id: "$.cve" } }])}>Add endpoint</button></div>}

      <fieldset className="rounded-sm border border-ec-border p-3"><legend className="px-1 text-sm font-semibold">Licence &amp; contract</legend>
        <div className="grid gap-2 md:grid-cols-4">
          {LICENSE.map(([k, label]) => <div key={k}><label className="label" htmlFor={`sb-l-${k}`}>{label}</label><input id={`sb-l-${k}`} name={`l_${k}`} type={k.endsWith("date") ? "date" : k === "seats" || k === "api_quota" ? "number" : "text"} className="input w-full" defaultValue={String(lic[k] ?? "")} /></div>)}
          <div><label className="label" htmlFor="sb-l-qp">Quota period</label><select id="sb-l-qp" name="l_quota_period" className="input w-full" defaultValue={String(lic.quota_period ?? "month")}><option value="day">day</option><option value="month">month</option><option value="year">year</option></select></div>
          <div className="md:col-span-3"><label className="label" htmlFor="sb-l-notes">Notes</label><input id="sb-l-notes" name="l_notes" className="input w-full" defaultValue={String(lic.notes ?? "")} /></div>
        </div>
        <p className="mt-1 text-xs text-ec-slate">Renewal reminders are emailed at 60, 30 and 7 days to integration admins and the contract owner (if an email).</p></fieldset>

      <fieldset className="rounded-sm border border-ec-border p-3"><legend className="px-1 text-sm font-semibold">Redistribution (enforced by the email generator and AI layer)</legend>
        <div className="grid gap-2 md:grid-cols-3">
          <div><label className="label" htmlFor="sb-r-email">Content in stakeholder emails</label><select id="sb-r-email" name="r_email" className="input w-full" defaultValue={red.email}><option value="full">Full</option><option value="summary">Summary only</option><option value="none">None</option></select></div>
          <div><label className="label" htmlFor="sb-r-tlp">Default TLP</label><select id="sb-r-tlp" name="r_tlp" className="input w-full" defaultValue={red.default_tlp}>{["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"].map((t) => <option key={t}>{t}</option>)}</select></div>
          <label className="flex items-end gap-2 text-sm"><input type="checkbox" name="r_ai" defaultChecked={red.ai} /> Allow sending to external AI providers</label>
        </div></fieldset>

      <label className="flex items-center gap-2 text-sm"><input type="checkbox" name="enabled" defaultChecked={existing?.enabled ?? false} /> Enabled (pulled on schedule)</label>
      {preview && (
        <div role="status" className={`rounded-sm px-3 py-2 text-sm ${preview.ok ? "bg-emerald-50 text-emerald-950" : "bg-red-50 text-red-800"}`}>
          {preview.ok ? <><strong>{preview.records.length} record(s) parsed</strong>{preview.skipped ? ` · ${preview.skipped} skipped (unmapped)` : ""}
            <ul className="ml-5 mt-1 list-disc text-xs">{preview.records.map((r, n) => <li key={n}>[{r.kind}] {r.title} {r.cve_ids.join(", ")} {r.severity ?? ""} {r.exploited ? "· exploited" : ""} {r.published_at ? `· ${fmtDateTime(r.published_at)}` : ""}</li>)}</ul>
            {preview.raw_sample && <details className="mt-1"><summary className="cursor-pointer text-xs">First raw record</summary><pre className="max-h-48 overflow-auto text-[11px]">{preview.raw_sample}</pre></details>}</>
            : preview.error}
        </div>)}
      <ErrorNote error={err} />
      <div className="flex gap-2">
        {preset.source_type !== "manual" && <button type="button" className="btn-secondary" disabled={busy} onClick={(e) => run(e.currentTarget.form!, "preview")}>Test &amp; preview</button>}
        <button className="btn-primary" disabled={busy}>{existing ? "Save" : "Add subscription"}</button>
        <button type="button" className="btn-secondary" onClick={onDone}>Close</button>
      </div>
    </form>
  );
}

/** Integrations → Threat Intel & News Subscriptions (features.subscriptions). */
export default function SubscriptionsSettings() {
  const on = useSubscriptionsOn();
  const qc = useQueryClient();
  const presets = useQuery({ queryKey: ["subscription-presets"], enabled: on, queryFn: () => api<Preset[]>("/api/subscriptions/presets") });
  const list = useQuery({ queryKey: ["subscriptions"], enabled: on, queryFn: () => api<Sub[]>("/api/subscriptions") });
  const [open, setOpen] = useState<{ preset: Preset; existing?: Sub } | null>(null);
  const [pick, setPick] = useState("");
  const act = useMutation({ mutationFn: ({ s, what }: { s: Sub; what: "sync" | "toggle" | "delete" }) =>
      what === "sync" ? api(`/api/subscriptions/${s.id}/sync`, { method: "POST" })
      : what === "toggle" ? api(`/api/subscriptions/${s.id}`, { method: "PATCH", body: { enabled: !s.enabled } })
      : api(`/api/subscriptions/${s.id}`, { method: "DELETE" }),
    onSettled: () => qc.invalidateQueries({ queryKey: ["subscriptions"] }) });
  if (!on) return null;
  const presetFor = (key: string) => presets.data?.find((p) => p.key === key);
  return (
    <section className="mt-8">
      <h2 className="mb-1 font-heading font-bold">Threat Intel &amp; News Subscriptions</h2>
      <p className="mb-3 text-sm text-ec-slate">Paid / licensed intel feeds CVE Intelligence and Security News with source attribution. Redistribution controls decide what may appear in stakeholder emails and be sent to AI providers; TLP:RED never leaves the platform.</p>
      <ErrorNote error={list.error ?? act.error} />
      {open && <div className="card mb-4"><h3 className="mb-2 font-heading font-bold">{open.existing ? `Edit ${open.existing.name}` : `Add ${open.preset.vendor}`}</h3>
        <SubForm key={`${open.preset.key}-${open.existing?.id ?? "new"}`} preset={open.preset} existing={open.existing} onDone={() => setOpen(null)} /></div>}
      {list.data && list.data.length > 0 && (
        <div className="card mb-4 overflow-x-auto p-0"><table className="min-w-full text-sm">
          <thead className="bg-ec-surface-alt"><tr>{["Subscription", "Status", "Usage (period)", "Licence", "Redistribution", ""].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
          <tbody>{list.data.map((s) => (
            <tr key={s.id} className="border-t border-ec-surface-alt align-top">
              <td className="td"><strong>{s.name}</strong><div className="text-xs text-ec-slate">{s.vendor} · {s.source_type}{s.api_status === "confirm" && " · confirm defaults"}</div>
                <label className="mt-1 flex items-center gap-1 text-xs"><input type="checkbox" checked={s.enabled} onChange={() => act.mutate({ s, what: "toggle" })} /> enabled</label></td>
              <td className="td text-xs"><span className={s.status === "ok" ? "text-emerald-800" : s.status === "error" ? "text-red-800" : "text-ec-slate"}>{s.status}</span>
                <div>last pull: {fmtDateTime(s.last_success_at)}</div>{s.last_error && <div className="max-w-xs break-words text-red-800">{s.last_error}</div>}
                {s.error_log.length > 1 && <details><summary className="cursor-pointer">Error log ({s.error_log.length})</summary><ul>{s.error_log.map((e, n) => <li key={n}>{fmtDateTime(e.at)} — {e.error}</li>)}</ul></details>}</td>
              <td className="td text-xs">{s.usage.api_calls ?? 0} API calls{s.license.api_quota ? ` of ${s.license.api_quota}` : ""}<div>{s.items} item(s) stored</div>
                {s.license.api_quota ? <div className="mt-1 h-1.5 w-28 rounded bg-ec-surface-alt"><div className="h-1.5 rounded bg-ec-navy" style={{ width: `${Math.min(100, ((s.usage.api_calls ?? 0) / Number(s.license.api_quota)) * 100)}%` }} /></div> : null}</td>
              <td className="td text-xs">{s.license.license_tier ?? "—"}{s.license.renewal_date && <div>renews {String(s.license.renewal_date)}</div>}{s.license.contract_owner && <div>{String(s.license.contract_owner)}</div>}</td>
              <td className="td text-xs">email: {s.redistribution.email}<div>AI: {s.redistribution.ai ? "allowed" : "not allowed"}</div><div>default TLP:{s.redistribution.default_tlp}</div></td>
              <td className="td whitespace-nowrap">
                {presetFor(s.preset) && <button className="btn-secondary" onClick={() => setOpen({ preset: presetFor(s.preset)!, existing: s })}>Configure</button>}
                {s.source_type !== "manual" && <button className="ml-2 text-xs underline" onClick={() => act.mutate({ s, what: "sync" })}>Pull now</button>}
                <button className="ml-2 text-xs text-red-800 underline" onClick={() => window.confirm(`Delete ${s.name} and its ${s.items} intel item(s)?`) && act.mutate({ s, what: "delete" })}>Delete</button></td>
            </tr>))}</tbody></table></div>)}
      <div className="flex flex-wrap items-end gap-2">
        <div><label className="label" htmlFor="sub-pick">Add a subscription</label>
          <select id="sub-pick" className="input w-80" value={pick} onChange={(e) => setPick(e.target.value)}>
            <option value="">Choose a vendor or custom source…</option>
            {presets.data?.map((p) => <option key={p.key} value={p.key}>{p.key.startsWith("custom_") ? `Custom — ${p.source_type.toUpperCase()}` : p.key === "manual" ? "Manual (portal / PDF / email)" : p.vendor}{p.api_status === "confirm" ? " (confirm defaults)" : ""}</option>)}
          </select></div>
        <button className="btn-primary" disabled={!pick} onClick={() => { const p = presetFor(pick); if (p) setOpen({ preset: p }); }}>Set up</button>
      </div>
    </section>
  );
}
