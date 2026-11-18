import type { ReactNode } from "react";
import { CveIntelPanel } from "../components/Intel";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, fmtDate, fmtDateTime, pct, type CveDetail } from "../api";
import { useAuth } from "../auth";
import { InfoTip } from "../help";
import { LoadingScreen } from "../components/StatusScreen";
import { CveAiPanel, useAi } from "../components/Ai";
import { EmptyState, ErrorNote, KevBadge, PageHeader, SeverityBadge } from "../components/ui";

interface PanelSource { integration_id: number; name: string; source: string; checked_at: string | null; status: string; error: string | null; asset_count: number; truncated: boolean }
interface PanelAsset { hostname: string | null; ip_address: string | null; resource_id: string | null; owner: string | null; environment: string | null; sources: string[] }
interface AssetPanel { integrations_configured: boolean; total_unique_assets: number; sources: PanelSource[]; assets: PanelAsset[]; message: string }

function Stat({ label, tip, value, sub }: { label: string; tip: string; value: ReactNode; sub?: ReactNode }) {
  return (
    <div className="card">
      <div className="label">{label}<InfoTip k={tip} /></div>
      <div className="text-2xl font-semibold">{value}</div>
      {sub && <div className="mt-1 text-xs text-ec-slate">{sub}</div>}
    </div>
  );
}

function Prov({ cve, field }: { cve: CveDetail; field: string }) {
  const p = cve.provenance[field];
  if (!p) return null;
  return <span className="ml-1 rounded bg-ec-surface-alt px-1.5 py-0.5 text-[10px] font-medium uppercase text-ec-slate" title={`Source: ${p.source} · ${fmtDateTime(p.at)}`}>{p.source}</span>;
}

const range = (p: CveDetail["products"][number]) =>
  [p.version_start_including && `≥ ${p.version_start_including}`, p.version_start_excluding && `> ${p.version_start_excluding}`,
   p.version_end_excluding && `< ${p.version_end_excluding}`, p.version_end_including && `≤ ${p.version_end_including}`]
    .filter(Boolean).join(", ") || (p.cpe?.split(":")[5] && p.cpe.split(":")[5] !== "*" ? p.cpe.split(":")[5] : "all versions");

export default function CveDetailPage() {
  const { cveId = "" } = useParams();
  const { can } = useAuth();
  const nav = useNavigate();
  const q = useQuery({ queryKey: ["cve", cveId], queryFn: () => api<CveDetail>(`/api/cves/${encodeURIComponent(cveId)}`) });
  const assets = useQuery({ queryKey: ["cve-assets", cveId], queryFn: () => api<AssetPanel>(`/api/cves/${encodeURIComponent(cveId)}/assets`) });
  const qc = useQueryClient();
  const aiOn = useAi();
  const news = useQuery({ queryKey: ["cve-news", cveId], queryFn: () => api<{ id: number; title: string; url: string; source: string; published_at: string }[]>(`/api/news/by-cve/${encodeURIComponent(cveId)}`),
                          enabled: can("news:view") });
  const refreshAssets = useMutation({ mutationFn: () => api<AssetPanel>(`/api/cves/${encodeURIComponent(cveId)}/assets/refresh`, { method: "POST" }),
                                      onSuccess: (p) => qc.setQueryData(["cve-assets", cveId], p) });
  const c = q.data;

  if (q.isError) return <><PageHeader title={cveId} helpId="cve-detail" /><ErrorNote error={q.error} /></>;
  if (!c) return <LoadingScreen />;

  return (
    <>
      <nav aria-label="Breadcrumb" className="mb-2 text-sm"><Link className="link" to="/cves">CVE Intelligence</Link> / {c.cve_id}</nav>
      <PageHeader
        title={c.cve_id}
        subtitle={c.title ?? undefined}
        helpId="cve-detail"
        actions={
          <button className="btn-primary" disabled={!can("advisory:create")}
                  title={can("advisory:create") ? "Open the Advisory Email Generator pre-filled with this CVE" : "Requires the advisory:create permission"}
                  onClick={() => nav(`/advisories/new?cve=${encodeURIComponent(c.cve_id)}`)}>
            Create Advisory Email
          </button>
        }
      />
      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="CVSS" tip="cvss" value={<span className="flex items-center gap-2">{c.cvss_score?.toFixed(1) ?? "—"}<SeverityBadge severity={c.severity} /></span>}
              sub={c.cvss_version ? `v${c.cvss_version} · ${c.cvss_vector ?? ""}` : c.vuln_status ?? undefined} />
        <Stat label="EPSS" tip="epss" value={pct(c.epss_score)} sub={c.epss_percentile !== null ? `${(c.epss_percentile * 100).toFixed(1)}th percentile · ${fmtDate(c.epss_date)}` : "Not yet scored"} />
        <Stat label="CISA KEV" tip="kev" value={c.kev ? <KevBadge due={c.kev_due_date} /> : "Not listed"}
              sub={c.kev ? `Added ${fmtDate(c.kev_date_added)}${c.kev_ransomware_use ? ` · ransomware: ${c.kev_ransomware_use}` : ""}` : undefined} />
        <Stat label="Exploit" tip="exploit" value={c.exploit_available ? "Available" : "None known"} sub={c.exploit_refs.length ? `${c.exploit_refs.length} public reference(s)` : undefined} />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          {aiOn && <CveAiPanel cveId={c.cve_id} />}
          <section className="card">
            <h2 className="mb-2 font-semibold">Description<Prov cve={c} field="description" /></h2>
            {/* Rendered as text: upstream content is untrusted and never interpreted as HTML. */}
            <p className="whitespace-pre-line text-sm leading-6 text-ec-slate">{c.description ?? "No description yet."}</p>
            {c.kev_required_action && <p className="mt-3 rounded bg-red-50 p-2 text-sm text-red-900"><strong>CISA required action:</strong> {c.kev_required_action}</p>}
            <dl className="mt-3 grid grid-cols-2 gap-2 text-sm">
              <div><dt className="label">NVD status<InfoTip k="vuln_status" /></dt><dd>{c.vuln_status ?? "—"}</dd></div>
              <div><dt className="label">Weakness (CWE)<InfoTip k="cwe" /></dt><dd>{c.cwes.join(", ") || "—"}</dd></div>
              <div><dt className="label">Published</dt><dd>{fmtDateTime(c.published_at)}</dd></div>
              <div><dt className="label">Last modified</dt><dd>{fmtDateTime(c.last_modified_at)}</dd></div>
            </dl>
          </section>

          <section className="card overflow-x-auto">
            <h2 className="mb-2 font-semibold">All CVSS scores<Prov cve={c} field="cvss" /></h2>
            {c.cvss_metrics.length === 0 ? <p className="text-sm text-ec-slate">No CVSS assessments published yet.</p> : (
              <table className="min-w-full text-sm"><thead><tr><th className="th">Version</th><th className="th">Score</th><th className="th">Severity</th><th className="th">Assessor</th><th className="th">Vector</th></tr></thead>
                <tbody>{c.cvss_metrics.map((m, i) => (
                  <tr key={i} className="border-t border-ec-surface-alt"><td className="td">{m.version}</td><td className="td">{m.score ?? "—"}</td><td className="td"><SeverityBadge severity={m.severity} /></td>
                    <td className="td">{m.source} <span className="text-xs text-ec-slate">{m.type}</span></td><td className="td break-all font-mono text-xs">{m.vector}</td></tr>))}
                </tbody></table>)}
          </section>

          <section className="card overflow-x-auto">
            <h2 className="mb-2 flex items-center gap-1 font-semibold">Affected products<InfoTip k="cpe" /><Prov cve={c} field="products" /></h2>
            {c.products.length === 0 ? <p className="text-sm text-ec-slate">No CPE applicability published yet.</p> : (
              <table className="min-w-full text-sm"><thead><tr><th className="th">Vendor</th><th className="th">Product</th><th className="th">Versions</th><th className="th">Source</th></tr></thead>
                <tbody>{c.products.map((p, i) => (
                  <tr key={i} className="border-t border-ec-surface-alt"><td className="td">{p.vendor}</td><td className="td">{p.product}</td><td className="td">{range(p)}</td><td className="td text-xs uppercase text-ec-slate">{p.source}</td></tr>))}
                </tbody></table>)}
          </section>

          <section className="card">
            <h2 className="mb-2 font-semibold">References<Prov cve={c} field="references" /></h2>
            <ul className="space-y-1 text-sm">
              {c.references.map((r) => (
                <li key={r.url} className="break-all">
                  {/* URLs were filtered to http(s) on ingestion; rel=noopener prevents tab-nabbing. */}
                  <a className="link" href={r.url} target="_blank" rel="noopener noreferrer nofollow">{r.url}</a>
                  {r.tags.map((t) => <span key={t} className={`ml-1 rounded px-1.5 py-0.5 text-[10px] font-semibold ${t === "Exploit" ? "bg-ec-navy text-white" : t === "Patch" || t === "Vendor Advisory" ? "bg-emerald-100 text-emerald-900" : "bg-slate-100 text-ec-slate"}`}>{t}</span>)}
                </li>
              ))}
              {c.references.length === 0 && <li className="text-ec-slate">No references.</li>}
            </ul>
          </section>
        </div>

        <div className="space-y-4">
          <CveIntelPanel cveId={cveId} />
          <section className="card">
            <h2 className="mb-2 flex items-center gap-1 font-semibold">Affected assets<InfoTip k="affected_assets" /></h2>
            {assets.data && !assets.data.integrations_configured ? (
              <EmptyState title="No integrations configured" why={assets.data.message} fix={can("integration:manage") ? { label: "Configure integrations", to: "/settings/integrations" } : undefined} />
            ) : assets.data && (<>
              <div className="mb-2 flex items-center justify-between">
                <p className="text-2xl font-semibold">{assets.data.total_unique_assets}<span className="ml-1 text-sm font-normal text-ec-slate">unique assets</span></p>
                {can("cve:refresh") && <button className="btn-secondary" onClick={() => refreshAssets.mutate()} disabled={refreshAssets.isPending}>{refreshAssets.isPending ? "Checking…" : "Check now"}</button>}
              </div>
              <ErrorNote error={refreshAssets.error} />
              <ul className="mb-2 space-y-1 text-xs">{assets.data.sources.map((s) => (
                <li key={s.integration_id} className="flex justify-between gap-2" title={s.error ?? undefined}>
                  <span><strong>{s.source}</strong> · {s.name}</span>
                  <span className={s.status === "error" ? "text-red-800" : "text-ec-slate"}>{s.status === "never" ? "not checked" : s.status === "ok" ? `${s.asset_count}${s.truncated ? "+ (truncated)" : ""} · ${fmtDateTime(s.checked_at)}` : s.status}</span>
                </li>))}</ul>
              {assets.data.assets.length > 0 && <div className="max-h-64 overflow-auto"><table className="min-w-full text-xs">
                <thead className="sticky top-0 bg-ec-surface-alt"><tr><th className="th">Host / IP</th><th className="th">Owner</th><th className="th">Sources</th></tr></thead>
                <tbody>{assets.data.assets.map((x, i) => (
                  <tr key={i} className="border-t border-ec-surface-alt"><td className="td">{x.hostname ?? x.ip_address ?? x.resource_id}<div className="text-ec-slate">{x.hostname ? x.ip_address : ""}</div></td>
                    <td className="td">{x.owner}{x.environment && <div className="text-ec-slate">{x.environment}</div>}</td><td className="td">{x.sources.join(", ")}</td></tr>))}
                </tbody></table></div>}
            </>)}
          </section>

          {news.data && news.data.length > 0 && (
            <section className="card">
              <h2 className="mb-2 font-semibold">In the news</h2>
              <ul className="space-y-1 text-sm">{news.data.map((n) => (
                <li key={n.id}><a className="link" href={n.url} target="_blank" rel="noopener noreferrer nofollow">{n.title}</a>
                  <div className="text-xs text-ec-slate">{n.source} · {fmtDate(n.published_at)}</div></li>))}</ul>
            </section>
          )}
          <section className="card">
            <h2 className="mb-2 font-semibold">Timeline</h2>
            <ol className="relative ml-2 border-l border-ec-border">
              {c.events.map((e, i) => (
                <li key={i} className="mb-3 ml-4">
                  <span className="absolute -left-1.5 mt-1.5 h-3 w-3 rounded-full border border-white bg-ec-navy" aria-hidden="true" />
                  <p className="text-sm font-medium">{e.event_type.replace("_", " ")}</p>
                  <p className="text-xs text-ec-slate">{fmtDateTime(e.occurred_at)} · {e.source}</p>
                  {e.event_type === "EPSS_CHANGED" && <p className="text-xs">{pct(e.detail.from as number)} → {pct(e.detail.to as number)}</p>}
                </li>
              ))}
            </ol>
          </section>

          <section className="card">
            <h2 className="mb-2 flex items-center gap-1 font-semibold">Field provenance<InfoTip k="provenance" /></h2>
            <dl className="space-y-1 text-xs">
              {Object.entries(c.provenance).sort().map(([f, p]) => (
                <div key={f} className="flex justify-between gap-2"><dt className="font-mono">{f}</dt><dd className="text-ec-slate">{p.source} · {fmtDateTime(p.at)}</dd></div>
              ))}
            </dl>
          </section>
        </div>
      </div>
    </>
  );
}
