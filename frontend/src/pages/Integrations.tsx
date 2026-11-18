import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, fmtDateTime } from "../api";
import { HealthBadge, PageHeader, ErrorNote, EmptyState } from "../components/ui";
import SubscriptionsSettings from "./Subscriptions";

interface Field { key: string; label: string; kind: string; required: boolean; default: unknown; help: string; options: string[] }
interface Spec {
  kind: string; label: string; vendor: string; description: string; host_patterns: string[]; base_url_example: string;
  fields: Field[]; default_field_map: Record<string, string>; prerequisites: string[]; docs: string; capabilities: string[];
  category: string; regions: [string, string][]; api_status: "documented" | "confirm"; fixed_base_url: string | null;
}
interface Integ {
  id: number; kind: string; label: string; name: string; enabled: boolean; base_url: string; config: Record<string, unknown>;
  secrets_set: string[]; status: string; last_test_at: string | null; last_sync_at: string | null; last_error: string | null;
}
const NORMALIZED = ["hostname", "ip_address", "os", "cloud_account", "resource_id", "owner", "business_unit", "environment", "detection_date", "source_ref"];
const health = (s: string) => (s === "ok" ? "healthy" : s === "error" ? "failing" : "pending");
const isAction = (s: Spec) => !s.capabilities.includes("assets_for_cve");
const CATEGORY_ORDER = ["Vulnerability & exposure", "Cloud security (CNAPP)", "Application security (SCA / code)",
  "Asset inventory (CAASM)", "Exposure management (CTEM / RBVM)", "Ticketing", "Notifications"];

function ApiStatus({ spec }: { spec: Spec }) {
  return spec.api_status === "confirm"
    ? <span className="rounded-sm bg-amber-50 px-1.5 py-0.5 text-xs font-semibold text-amber-900" title="This vendor's API reference is not public. Defaults are editable; confirm them against your tenant's API docs.">Confirm defaults</span>
    : <span className="rounded-sm bg-ec-surface-alt px-1.5 py-0.5 text-xs font-semibold text-ec-slate" title="Follows the vendor's public API reference">Documented API</span>;
}

function IntegrationForm({ spec, existing, onDone }: { spec: Spec; existing?: Integ; onDone: () => void }) {
  const qc = useQueryClient();
  const [result, setResult] = useState<{ ok: boolean; message: string } | null>(null);
  const [baseUrl, setBaseUrl] = useState(existing?.base_url ?? (spec.regions.length ? spec.regions[0][1] : ""));
  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => existing
      ? api<Integ>(`/api/integrations/${existing.id}`, { method: "PATCH", body })
      : api<Integ>("/api/integrations", { method: "POST", body: { ...body, kind: spec.kind } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["integrations"] }),
  });
  const test = useMutation({
    mutationFn: (id: number) => api<{ ok: boolean; message: string }>(`/api/integrations/${id}/test`, { method: "POST" }),
    onSuccess: (r) => { setResult(r); qc.invalidateQueries({ queryKey: ["integrations"] }); },
  });

  const submit = (e: FormEvent<HTMLFormElement>, thenTest: boolean) => {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const config: Record<string, unknown> = {};
    const secrets: Record<string, string> = {};
    for (const f of spec.fields) {
      const v = fd.get(f.key);
      if (f.kind === "secret") { if (v) secrets[f.key] = String(v); continue; }
      if (f.kind === "bool") { config[f.key] = fd.get(f.key) === "on"; continue; }
      if (v !== null && v !== "") config[f.key] = f.kind === "number" ? Number(v) : String(v);
    }
    const fieldMap: Record<string, string> = {};
    for (const k of NORMALIZED) { const v = String(fd.get(`fm_${k}`) ?? "").trim(); if (v && v !== spec.default_field_map[k]) fieldMap[k] = v; }
    if (!isAction(spec)) config.field_map = fieldMap;
    const body: Record<string, unknown> = { name: fd.get("name"), config };
    if (!spec.fixed_base_url) body.base_url = baseUrl;
    if (Object.keys(secrets).length || !existing) body.secrets = secrets;
    save.mutate(body, { onSuccess: (i) => { if (thenTest) test.mutate(i.id); } });
  };

  return (
    <form className="space-y-4" onSubmit={(e) => submit(e, true)}>
      <div className="grid gap-4 lg:grid-cols-3">
        <section className="rounded-md bg-ec-surface-alt p-4 text-sm lg:col-span-1">
          <h3 className="mb-2 font-heading font-bold">Setup guide — {spec.vendor}</h3>
          <ol className="ml-4 list-decimal space-y-1">
            <li><strong>Prerequisites</strong><ul className="ml-4 list-disc">{spec.prerequisites.map((p) => <li key={p}>{p}</li>)}</ul></li>
            {isAction(spec) ? (<>
              <li><strong>Credentials</strong> — use a dedicated account that can only create tickets / post. Secrets are encrypted and never shown again.</li>
              <li><strong>Save &amp; test</strong> — checks the connection{spec.kind === "teams" || spec.kind === "slack" ? " (a webhook test posts a test message)" : ""}.</li>
              <li><strong>Enable</strong> — users with <em>advisory:send</em> can then create a ticket or post from an approved advisory.</li>
            </>) : (<>
              <li><strong>Credentials</strong> — use a dedicated, read-only service account. Secrets are encrypted and never shown again.</li>
              <li><strong>Save &amp; test</strong> — checks authentication with one read-only call.</li>
              <li><strong>Enable</strong> — enabled integrations are queried when a CVE's assets are refreshed or pulled into an advisory.</li>
            </>)}
          </ol>
          {spec.api_status === "confirm" && <p className="mt-2 rounded-sm bg-amber-50 p-2 text-xs text-amber-900">{spec.vendor}'s API reference is not public. The endpoint, filter and field defaults are editable — confirm them against your tenant's API docs, then use <strong>Check now</strong> on a CVE you know is present before enabling.</p>}
          {!spec.fixed_base_url && <p className="mt-2 text-xs text-ec-slate">Allowed hosts: {spec.host_patterns.length ? spec.host_patterns.join(", ") : "self-hosted — add yours to"} {spec.host_patterns.length ? <>(plus <code>EXCAT_EGRESS_ALLOWLIST</code> for on-prem)</> : <code>EXCAT_EGRESS_ALLOWLIST</code>}.</p>}
          <a className="link mt-2 inline-block" href={`/docs/${spec.docs}`} target="_blank" rel="noopener noreferrer">Full {spec.vendor} integration guide ↗</a>
        </section>
        <div className="space-y-3 lg:col-span-2">
          <div className="grid gap-3 md:grid-cols-2">
            <div><label className="label" htmlFor={`n-${spec.kind}`}>Name</label><input id={`n-${spec.kind}`} name="name" className="input w-full" required minLength={2} defaultValue={existing?.name ?? spec.vendor} /></div>
            {!spec.fixed_base_url && (
              <div>
                <label className="label" htmlFor={`u-${spec.kind}`}>Base URL</label>
                {spec.regions.length > 0 && (
                  <select aria-label="Region" className="input mb-1 w-full" value={spec.regions.find(([, u]) => u === baseUrl)?.[1] ?? ""}
                          onChange={(e) => e.target.value && setBaseUrl(e.target.value)}>
                    <option value="">Custom URL…</option>
                    {spec.regions.map(([label, u]) => <option key={u} value={u}>{label} — {u.replace("https://", "")}</option>)}
                  </select>
                )}
                <input id={`u-${spec.kind}`} name="base_url" type="url" className="input w-full" required value={baseUrl}
                       onChange={(e) => setBaseUrl(e.target.value)} placeholder={spec.base_url_example} />
              </div>
            )}
            {spec.fields.map((f) => {
              const id = `${spec.kind}-${f.key}`;
              const cur = existing?.config[f.key] ?? f.default ?? "";
              return (
                <div key={f.key} className={f.kind === "bool" ? "flex items-end" : ""}>
                  {f.kind === "bool" ? (
                    <label className="flex items-center gap-2 text-sm"><input type="checkbox" name={f.key} defaultChecked={Boolean(cur)} />{f.label}</label>
                  ) : (<>
                    <label className="label" htmlFor={id}>{f.label}{f.required && " *"}</label>
                    {f.kind === "select" ? (
                      <select id={id} name={f.key} className="input w-full" defaultValue={String(cur)}>{f.options.map((o) => <option key={o}>{o}</option>)}</select>
                    ) : (
                      <input id={id} name={f.key} className="input w-full" type={f.kind === "secret" ? "password" : f.kind === "number" ? "number" : "text"}
                             autoComplete={f.kind === "secret" ? "new-password" : "off"} required={f.required && (f.kind !== "secret" || !existing?.secrets_set.includes(f.key))}
                             defaultValue={f.kind === "secret" ? "" : String(cur)} placeholder={f.kind === "secret" && existing?.secrets_set.includes(f.key) ? "•••••• stored — leave blank to keep" : ""} />
                    )}
                    {f.help && <p className="mt-0.5 text-xs text-ec-slate">{f.help}</p>}
                  </>)}
                </div>
              );
            })}
          </div>
          {!isAction(spec) && <details className="rounded-md border border-ec-border p-3">
            <summary className="cursor-pointer text-sm font-semibold">Field mapping (advanced)</summary>
            <p className="my-2 text-xs text-ec-slate">Dotted path into the tool's record for each normalized asset field, e.g. <code>vulnerableAsset.ipAddresses.0</code>. A leading <code>=</code> sets a constant (<code>=Production</code>). Empty = vendor default.</p>
            <div className="grid gap-2 md:grid-cols-2">{NORMALIZED.map((k) => {
              const fm = (existing?.config.field_map ?? {}) as Record<string, string>;
              return <div key={k} className="flex items-center gap-2"><label className="w-32 text-xs font-semibold" htmlFor={`fm-${spec.kind}-${k}`}>{k}</label>
                <input id={`fm-${spec.kind}-${k}`} name={`fm_${k}`} className="input flex-1 font-mono text-xs" defaultValue={fm[k] ?? spec.default_field_map[k] ?? ""} /></div>;
            })}</div>
          </details>}
          <ErrorNote error={save.error ?? test.error} />
          {result && <p role="status" className={`rounded-sm px-3 py-2 text-sm ${result.ok ? "bg-emerald-50 text-emerald-900" : "bg-red-50 text-red-900"}`}>{result.ok ? "✓ " : "✗ "}{result.message}</p>}
          <div className="flex gap-2">
            <button className="btn-primary" disabled={save.isPending || test.isPending}>{test.isPending ? "Testing…" : "Save & test"}</button>
            <button type="button" className="btn-secondary" onClick={onDone}>Close</button>
          </div>
        </div>
      </div>
    </form>
  );
}

export default function IntegrationsSettings() {
  const qc = useQueryClient();
  const catalog = useQuery({ queryKey: ["integration-catalog"], queryFn: () => api<Spec[]>("/api/integrations/catalog") });
  const list = useQuery({ queryKey: ["integrations"], queryFn: () => api<Integ[]>("/api/integrations") });
  const [open, setOpen] = useState<{ spec: Spec; existing?: Integ } | null>(null);
  const [filter, setFilter] = useState("");
  const toggle = useMutation({ mutationFn: (i: Integ) => api(`/api/integrations/${i.id}`, { method: "PATCH", body: { enabled: !i.enabled } }),
                               onSuccess: () => qc.invalidateQueries({ queryKey: ["integrations"] }) });
  const remove = useMutation({ mutationFn: (i: Integ) => api(`/api/integrations/${i.id}`, { method: "DELETE" }),
                               onSuccess: () => qc.invalidateQueries({ queryKey: ["integrations"] }) });
  const specFor = (kind: string) => catalog.data?.find((s) => s.kind === kind);

  return (
    <>
      <PageHeader title="Integrations" helpId="settings-integrations" subtitle="Security tools that report which assets a CVE affects, plus ticketing and chat for advisories" />
      <ErrorNote error={list.error ?? toggle.error ?? remove.error} />
      {open && <section className="card mb-6"><IntegrationForm key={`${open.spec.kind}-${open.existing?.id ?? "new"}`} spec={open.spec} existing={open.existing} onDone={() => setOpen(null)} /></section>}

      <h2 className="mb-2 font-heading font-bold">Configured</h2>
      {list.data?.length === 0 ? (
        <div className="mb-6"><EmptyState title="No integrations configured" why="Add a connector below. Until then advisories show “Not Integrated” for every source and rely on manual entry." /></div>
      ) : (
        <div className="card mb-6 overflow-x-auto p-0">
          <table className="min-w-full text-sm">
            <thead className="bg-ec-surface-alt"><tr><th className="th">Name</th><th className="th">Tool</th><th className="th">Status</th><th className="th">Enabled</th><th className="th">Last test / sync</th><th className="th">Last error</th><th className="th" /></tr></thead>
            <tbody>{list.data?.map((i) => (
              <tr key={i.id} className="border-t border-ec-surface-alt">
                <td className="td font-medium">{i.name}<div className="text-xs text-ec-slate">{i.base_url}</div></td>
                <td className="td">{i.label}{specFor(i.kind) && isAction(specFor(i.kind)!) && <div className="text-xs text-ec-slate">{specFor(i.kind)!.category}</div>}</td>
                <td className="td"><HealthBadge health={health(i.status)} /></td>
                <td className="td"><input type="checkbox" aria-label={`Enable ${i.name}`} checked={i.enabled} onChange={() => toggle.mutate(i)} /></td>
                <td className="td text-xs">{fmtDateTime(i.last_test_at)}<br />{fmtDateTime(i.last_sync_at)}</td>
                <td className="td max-w-xs break-words text-xs text-red-800">{i.last_error}</td>
                <td className="td whitespace-nowrap">
                  {specFor(i.kind) && <button className="btn-secondary" onClick={() => setOpen({ spec: specFor(i.kind)!, existing: i })}>Configure</button>}
                  <button className="ml-2 text-xs text-red-800 underline" onClick={() => window.confirm(`Delete ${i.name}? Cached findings are removed.`) && remove.mutate(i)}>Delete</button>
                </td>
              </tr>))}
            </tbody>
          </table>
        </div>
      )}

      <div className="mb-2 flex flex-wrap items-end justify-between gap-2">
        <h2 className="font-heading font-bold">Add a connector <span className="text-sm font-normal text-ec-slate">({catalog.data?.length ?? 0} available)</span></h2>
        <input type="search" aria-label="Filter connectors" placeholder="Filter connectors…" className="input w-64" value={filter} onChange={(e) => setFilter(e.target.value)} />
      </div>
      {CATEGORY_ORDER.concat([...new Set((catalog.data ?? []).map((s) => s.category))].filter((c) => !CATEGORY_ORDER.includes(c))).map((cat) => {
        const specs = (catalog.data ?? []).filter((s) => s.category === cat && (!filter || `${s.vendor} ${s.label} ${s.description}`.toLowerCase().includes(filter.toLowerCase())));
        if (!specs.length) return null;
        return (
          <section key={cat} className="mb-6">
            <h3 className="mb-2 text-sm font-semibold uppercase tracking-wide text-ec-slate">{cat}</h3>
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
              {specs.map((s) => (
                <div key={s.kind} className="card flex flex-col">
                  <div className="flex items-start justify-between gap-2"><h4 className="font-heading font-bold">{s.vendor}</h4><ApiStatus spec={s} /></div>
                  <p className="mt-1 flex-1 text-sm text-ec-slate">{s.description}</p>
                  <p className="mt-2 text-xs text-ec-slate">{isAction(s) ? <>Action connector · used from approved advisories</> : <>Matrix row: <strong className="text-ec-navy">{s.label}</strong>{s.capabilities.includes("asset_details") && " · enriches other sources"}</>}</p>
                  <div className="mt-3 flex gap-2"><button className="btn-primary" onClick={() => setOpen({ spec: s })}>Set up</button>
                    <a className="btn-secondary" href={`/docs/${s.docs}`} target="_blank" rel="noopener noreferrer">Guide ↗</a></div>
                </div>
              ))}
            </div>
          </section>
        );
      })}
      <SubscriptionsSettings />
    </>
  );
}
