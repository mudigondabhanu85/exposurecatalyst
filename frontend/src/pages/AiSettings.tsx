import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api";
import { ErrorNote, HealthBadge, PageHeader } from "../components/ui";

interface Spec { kind: string; label: string; group: string; protocol: string; base_url: string; hosts: string[]; example_models: string[]; secrets: string[]; config_keys: string[]; self_hosted: boolean; notes: string }
interface Provider { id: number; kind: string; label: string; name: string; enabled: boolean; base_url: string; models: string[]; default_model: string; temperature: number; max_tokens: number;
  config: Record<string, string | number>; secrets_set: string[]; status: string; last_error: string | null; blocked_by_allowlist: boolean; self_hosted: boolean }
interface Policy { enabled: boolean; allowed_kinds: string[]; redact_external: boolean; redact_self_hosted: boolean; routes: Record<string, { provider_id: number; model?: string | null }[]>; monthly_budget_usd: number | null; month_cost_usd: number }
interface UsageRow { provider: string; feature: string; status: string; requests: number; input_tokens: number; output_tokens: number; cost_usd: number; redacted_requests: number }
const GROUPS: Record<string, string> = { commercial: "Commercial", cloud: "Cloud platforms", aggregator: "Inference hosts / aggregators", "self-hosted": "Self-hosted" };

function ProviderForm({ specs, existing, onDone }: { specs: Spec[]; existing?: Provider; onDone: () => void }) {
  const qc = useQueryClient();
  const [kind, setKind] = useState(existing?.kind ?? "openai");
  const spec = specs.find((s) => s.kind === kind)!;
  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => existing ? api(`/api/ai/providers/${existing.id}`, { method: "PUT", body }) : api("/api/ai/providers", { method: "POST", body }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["ai-providers"] }); onDone(); },
  });
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const secrets: Record<string, string> = {};
    for (const s of spec.secrets) if (fd.get(`s_${s}`)) secrets[s] = String(fd.get(`s_${s}`));
    const config: Record<string, unknown> = {};
    for (const k of [...spec.config_keys, "price_in_per_mtok", "price_out_per_mtok"]) { const v = fd.get(`c_${k}`); if (v) config[k] = k.startsWith("price") ? Number(v) : String(v); }
    save.mutate({ kind, name: fd.get("name"), base_url: fd.get("base_url"), default_model: fd.get("default_model"),
                  models: String(fd.get("models") ?? "").split(",").map((m) => m.trim()).filter(Boolean),
                  temperature: Number(fd.get("temperature")), max_tokens: Number(fd.get("max_tokens")), enabled: fd.get("enabled") === "on",
                  config, ...(Object.keys(secrets).length || !existing ? { secrets } : {}) });
  };
  return (
    <form onSubmit={submit} className="card mb-4 space-y-3" key={kind}>
      <div className="grid gap-3 md:grid-cols-3">
        <div><label className="label" htmlFor="pk">Provider</label>
          <select id="pk" className="input w-full" value={kind} disabled={!!existing} onChange={(e) => setKind(e.target.value)}>
            {Object.entries(GROUPS).map(([g, l]) => <optgroup key={g} label={l}>{specs.filter((s) => s.group === g).map((s) => <option key={s.kind} value={s.kind}>{s.label}</option>)}</optgroup>)}
          </select></div>
        <div><label className="label" htmlFor="pn">Name</label><input id="pn" name="name" className="input w-full" required minLength={2} defaultValue={existing?.name ?? spec.label} /></div>
        <label className="flex items-end gap-2 text-sm"><input type="checkbox" name="enabled" defaultChecked={existing?.enabled ?? false} />Enabled</label>
        <div className="md:col-span-2"><label className="label" htmlFor="pu">Endpoint URL</label><input id="pu" name="base_url" className="input w-full" required defaultValue={existing?.base_url ?? spec.base_url} />
          <p className="mt-0.5 text-xs text-ec-slate">{spec.hosts.length ? `Allowed hosts: ${spec.hosts.join(", ")}` : "Self-hosted: exactly this host (private addresses need EXCAT_AI_ALLOW_PRIVATE_ENDPOINTS=true)."}</p></div>
        <div><label className="label" htmlFor="pm">Default model</label><input id="pm" name="default_model" className="input w-full" required defaultValue={existing?.default_model ?? spec.example_models[0]} /></div>
        <div><label className="label" htmlFor="pms">Other models (comma-separated)</label><input id="pms" name="models" className="input w-full" defaultValue={(existing?.models ?? spec.example_models.slice(1)).filter((m) => m !== existing?.default_model).join(", ")} /></div>
        <div><label className="label" htmlFor="pt">Temperature</label><input id="pt" name="temperature" type="number" step="0.1" min={0} max={2} className="input w-full" defaultValue={existing?.temperature ?? 0.2} /></div>
        <div><label className="label" htmlFor="px">Max output tokens</label><input id="px" name="max_tokens" type="number" min={64} max={32000} className="input w-full" defaultValue={existing?.max_tokens ?? 1200} /></div>
        {spec.secrets.map((s) => <div key={s}><label className="label" htmlFor={`s_${s}`}>{s.replace(/_/g, " ")}</label>
          {s === "service_account_json" ? <textarea id={`s_${s}`} name={`s_${s}`} rows={3} className="input w-full font-mono text-xs" placeholder={existing?.secrets_set.includes(s) ? "stored — leave blank to keep" : "{ … }"} />
            : <input id={`s_${s}`} name={`s_${s}`} type="password" autoComplete="new-password" className="input w-full" placeholder={existing?.secrets_set.includes(s) ? "•••••• stored — leave blank to keep" : ""} />}</div>)}
        {spec.config_keys.map((k) => <div key={k}><label className="label" htmlFor={`c_${k}`}>{k.replace(/_/g, " ")}</label><input id={`c_${k}`} name={`c_${k}`} className="input w-full" defaultValue={String(existing?.config[k] ?? "")} /></div>)}
        <div><label className="label" htmlFor="c_in">Price in (USD / 1M tokens)</label><input id="c_in" name="c_price_in_per_mtok" type="number" step="0.01" min={0} className="input w-full" defaultValue={String(existing?.config.price_in_per_mtok ?? "")} /></div>
        <div><label className="label" htmlFor="c_out">Price out (USD / 1M tokens)</label><input id="c_out" name="c_price_out_per_mtok" type="number" step="0.01" min={0} className="input w-full" defaultValue={String(existing?.config.price_out_per_mtok ?? "")} /></div>
      </div>
      {spec.notes && <p className="rounded-sm bg-[#FFF4CC] px-3 py-2 text-xs text-[#5C4200]">{spec.notes}</p>}
      <ErrorNote error={save.error} />
      <div className="flex gap-2"><button className="btn-primary">Save provider</button><button type="button" className="btn-secondary" onClick={onDone}>Cancel</button></div>
    </form>
  );
}

export default function AiSettings() {
  const qc = useQueryClient();
  const catalog = useQuery({ queryKey: ["ai-catalog"], queryFn: () => api<{ providers: Spec[]; features: Record<string, string> }>("/api/ai/catalog") });
  const providers = useQuery({ queryKey: ["ai-providers"], queryFn: () => api<Provider[]>("/api/ai/providers") });
  const policy = useQuery({ queryKey: ["ai-policy"], queryFn: () => api<Policy>("/api/ai/policy") });
  const usage = useQuery({ queryKey: ["ai-usage"], queryFn: () => api<{ rows: UsageRow[] }>("/api/ai/usage") });
  const [editing, setEditing] = useState<Provider | "new" | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const savePolicy = useMutation({ mutationFn: (body: Omit<Policy, "month_cost_usd">) => api<Policy>("/api/ai/policy", { method: "PUT", body }),
                                   onSuccess: () => { qc.invalidateQueries({ queryKey: ["ai-policy"] }); qc.invalidateQueries({ queryKey: ["ai-providers"] }); qc.invalidateQueries({ queryKey: ["ai-status"] }); setMsg("Policy saved."); } });
  const test = useMutation({ mutationFn: (id: number) => api<{ ok: boolean; message: string }>(`/api/ai/providers/${id}/test`, { method: "POST" }),
                             onSuccess: (r) => { setMsg((r.ok ? "✓ " : "✗ ") + r.message); qc.invalidateQueries({ queryKey: ["ai-providers"] }); } });
  const del = useMutation({ mutationFn: (id: number) => api(`/api/ai/providers/${id}`, { method: "DELETE" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["ai-providers"] }) });
  const pol = policy.data, specs = catalog.data?.providers ?? [];
  if (!pol || !catalog.data) return null;

  const submitPolicy = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const routes: Policy["routes"] = {};
    for (const f of ["default", ...Object.keys(catalog.data.features)]) {
      const chain = [fd.get(`r1_${f}`), fd.get(`r2_${f}`)].filter(Boolean).map((v) => ({ provider_id: Number(v) }));
      if (chain.length) routes[f] = chain;
    }
    savePolicy.mutate({ enabled: fd.get("enabled") === "on", allowed_kinds: fd.getAll("allowed").map(String), redact_external: fd.get("rex") === "on",
                        redact_self_hosted: fd.get("rsh") === "on", monthly_budget_usd: fd.get("budget") ? Number(fd.get("budget")) : null, routes });
  };
  const provOpts = (providers.data ?? []).filter((p) => p.enabled);
  return (
    <>
      <PageHeader title="AI Providers" helpId="settings-ai" subtitle="Optional AI assistance — admin-enabled, provider-allowlisted, with redaction of your environment's identifiers" />
      {msg && <p role="status" className="mb-3 rounded-sm bg-ec-surface-alt px-3 py-2 text-sm">{msg}</p>}
      <ErrorNote error={savePolicy.error ?? test.error ?? del.error} />

      <form onSubmit={submitPolicy} className="card mb-6 space-y-4" key={JSON.stringify(pol)}>
        <h2 className="font-heading font-bold">Policy</h2>
        <div className="flex flex-wrap gap-6 text-sm">
          <label className="flex items-center gap-2"><input type="checkbox" name="enabled" defaultChecked={pol.enabled} /><strong>Enable AI features</strong></label>
          <label className="flex items-center gap-2"><input type="checkbox" name="rex" defaultChecked={pol.redact_external} />Redact hostnames, IPs, owners, emails, cloud IDs before sending to external providers (recommended)</label>
          <label className="flex items-center gap-2"><input type="checkbox" name="rsh" defaultChecked={pol.redact_self_hosted} />Also redact for self-hosted models</label>
          <label className="flex items-center gap-2">Monthly budget (USD)<input name="budget" type="number" min={0} step="1" className="input w-28" defaultValue={pol.monthly_budget_usd ?? ""} /></label>
          <span className="text-ec-slate">Spent this month: ${pol.month_cost_usd.toFixed(2)}</span>
        </div>
        <fieldset><legend className="label">Provider allowlist (none ticked = all allowed)</legend>
          <div className="grid gap-x-4 gap-y-1 md:grid-cols-4">{specs.map((s) => <label key={s.kind} className="flex items-center gap-2 text-xs"><input type="checkbox" name="allowed" value={s.kind} defaultChecked={pol.allowed_kinds.includes(s.kind)} />{s.label}</label>)}</div>
        </fieldset>
        <fieldset><legend className="label">Per-feature model routing (primary → fallback)</legend>
          <table className="min-w-full text-sm"><tbody>{[["default", "Default for all features"], ...Object.entries(catalog.data.features)].map(([f, desc]) => {
            const r = pol.routes[f] ?? [];
            return <tr key={f} className="border-t border-ec-surface-alt"><td className="td"><code>{f}</code><div className="text-xs text-ec-slate">{desc}</div></td>
              {[0, 1].map((i) => <td key={i} className="td"><select aria-label={`${f} ${i ? "fallback" : "primary"}`} name={`r${i + 1}_${f}`} className="input w-full" defaultValue={r[i]?.provider_id ?? ""}>
                <option value="">{i ? "— no fallback —" : f === "default" ? "— first enabled provider —" : "— use default —"}</option>{provOpts.map((p) => <option key={p.id} value={p.id}>{p.name} · {p.default_model}</option>)}</select></td>)}</tr>;
          })}</tbody></table>
        </fieldset>
        <button className="btn-primary">Save policy</button>
      </form>

      <div className="mb-2 flex items-center justify-between"><h2 className="font-heading font-bold">Providers</h2><button className="btn-primary" onClick={() => setEditing("new")}>Add provider</button></div>
      {editing && <ProviderForm specs={specs} existing={editing === "new" ? undefined : editing} onDone={() => setEditing(null)} />}
      <div className="card mb-6 overflow-x-auto p-0"><table className="min-w-full text-sm">
        <thead className="bg-ec-surface-alt"><tr><th className="th">Name</th><th className="th">Provider</th><th className="th">Model</th><th className="th">Status</th><th className="th" /></tr></thead>
        <tbody>{providers.data?.map((p) => (
          <tr key={p.id} className="border-t border-ec-surface-alt">
            <td className="td font-medium">{p.name}{!p.enabled && <span className="ml-1 text-xs text-ec-slate">(disabled)</span>}{p.blocked_by_allowlist && <span className="ml-1 text-xs text-red-800">(blocked by allowlist)</span>}<div className="text-xs text-ec-slate">{p.base_url}</div></td>
            <td className="td">{p.label}{p.self_hosted && <span className="ml-1 text-xs text-ec-slate">self-hosted</span>}</td><td className="td text-xs">{p.default_model}</td>
            <td className="td"><HealthBadge health={p.status === "ok" ? "healthy" : p.status === "error" ? "failing" : "pending"} title={p.last_error ?? undefined} /></td>
            <td className="td whitespace-nowrap"><button className="btn-secondary" onClick={() => test.mutate(p.id)} disabled={test.isPending} title="Sends a fixed 'ping' prompt — no ExposureCatalyst data">Test</button>
              <button className="btn-secondary ml-2" onClick={() => setEditing(p)}>Edit</button>
              <button className="ml-2 text-xs text-red-800 underline" onClick={() => window.confirm(`Delete ${p.name}?`) && del.mutate(p.id)}>Delete</button></td>
          </tr>))}</tbody></table>
        {providers.data?.length === 0 && <p className="p-4 text-sm text-ec-slate">No providers yet. Add one, test it, then route features to it in the policy.</p>}
      </div>

      <h2 className="mb-2 font-heading font-bold">Usage & cost (30 days)</h2>
      <div className="card overflow-x-auto p-0"><table className="min-w-full text-sm">
        <thead className="bg-ec-surface-alt"><tr><th className="th">Provider</th><th className="th">Feature</th><th className="th">Status</th><th className="th text-right">Requests</th><th className="th text-right">Tokens in / out</th><th className="th text-right">Cost (USD)</th><th className="th text-right">Redacted</th></tr></thead>
        <tbody>{usage.data?.rows.map((r, i) => (
          <tr key={i} className="border-t border-ec-surface-alt"><td className="td">{r.provider}</td><td className="td"><code>{r.feature}</code></td><td className="td">{r.status}</td><td className="td text-right">{r.requests}</td>
            <td className="td text-right">{r.input_tokens.toLocaleString()} / {r.output_tokens.toLocaleString()}</td><td className="td text-right">{r.cost_usd.toFixed(4)}</td><td className="td text-right">{r.redacted_requests}</td></tr>))}</tbody></table>
        {usage.data?.rows.length === 0 && <p className="p-4 text-sm text-ec-slate">No AI requests yet.</p>}
      </div>
    </>
  );
}
