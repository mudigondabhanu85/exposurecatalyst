import { useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, fmtDate, fmtDateTime, pct, type CvePage, type SavedSearch, type SourcesResp } from "../api";
import { useAuth } from "../auth";
import { InfoTip } from "../help";
import { AiMeta, useAi } from "../components/Ai";
import { EmptyState, ErrorNote, Field, HealthBadge, KevBadge, PageHeader, SeverityBadge } from "../components/ui";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
const FILTER_KEYS = ["q", "vendor", "product", "cvss_min", "cvss_max", "epss_min", "kev", "exploit", "published_from", "published_to", "sort"];

function SourceStrip() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["sources"], queryFn: () => api<SourcesResp>("/api/sources"), refetchInterval: 30_000 });
  const refresh = useMutation({
    mutationFn: () => api("/api/sources/refresh", { method: "POST" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["sources"] }),
  });
  if (!q.data) return null;
  const pending = q.data.sources.some((s) => s.refresh_pending);
  return (
    <section aria-label="Source health" data-tour="source-strip" className="card mb-4 flex flex-wrap items-center gap-x-6 gap-y-2 py-3">
      <span className="label mb-0">Source health<InfoTip k="source_health" /></span>
      {q.data.sources.map((s) => (
        <span key={s.source} className="flex items-center gap-2 text-sm">
          <span className="font-medium">{s.label}</span>
          <HealthBadge health={s.health} title={s.last_error ?? undefined} />
          <span className="text-xs text-ec-slate">{s.last_success_at ? `ok ${fmtDateTime(s.last_success_at)}` : "never"}</span>
        </span>
      ))}
      <span className="flex items-center gap-1 text-xs">
        <span className={q.data.scheduler_alive ? "text-emerald-700" : "text-red-700"}>
          {q.data.scheduler_alive ? "● Scheduler running" : "● Scheduler not running"}
        </span>
        <InfoTip k="scheduler" />
      </span>
      {can("cve:refresh") && (
        <span className="ml-auto flex items-center gap-1">
          <button className="btn-secondary" onClick={() => refresh.mutate()} disabled={refresh.isPending || pending}>
            {pending ? "Refresh queued…" : "Refresh now"}
          </button>
          <InfoTip k="refresh_now" />
        </span>
      )}
    </section>
  );
}

function NlSearch({ onApply }: { onApply: (filters: Record<string, unknown>) => void }) {
  const [q, setQ] = useState("");
  const m = useMutation({ mutationFn: (text: string) => api<{ filters: Record<string, unknown>; items: { cve_id: string }[]; provider: string; model: string; redacted_values: number; fallbacks: string[] }>("/api/ai/search", { method: "POST", body: { q: text } }),
                          onSuccess: (r) => onApply(r.filters) });
  return (
    <form className="card mb-4 border-l-4 border-l-ec-orange" onSubmit={(e) => { e.preventDefault(); if (q.trim().length >= 3) m.mutate(q); }}>
      <label className="label" htmlFor="nl">Ask in plain English <span className="rounded-sm bg-ec-navy px-1 text-[10px] text-white">AI</span></label>
      <div className="flex gap-2"><input id="nl" className="input flex-1" value={q} onChange={(e) => setQ(e.target.value)} maxLength={300} placeholder="e.g. critical Fortinet CVEs exploited in the last 7 days" />
        <button className="btn-primary" disabled={m.isPending}>{m.isPending ? "Thinking…" : "Search"}</button></div>
      <ErrorNote error={m.error} />
      {m.data && <p className="mt-1 text-xs text-ec-slate">Applied filters: <code>{JSON.stringify(m.data.filters)}</code> — edit them below.</p>}
      {m.data && <AiMeta r={m.data} />}
    </form>
  );
}

export default function CveListPage() {
  const aiOn = useAi();
  const [params, setParams] = useSearchParams();
  const qc = useQueryClient();
  const page = Number(params.get("page") ?? 1);
  const query = Object.fromEntries(FILTER_KEYS.map((k) => [k, params.get(k) ?? undefined]));
  const severity = params.getAll("severity");

  const cves = useQuery({
    queryKey: ["cves", params.toString()],
    queryFn: () => api<CvePage>("/api/cves", { query: { ...query, severity, page, page_size: 25 } }),
    placeholderData: keepPreviousData,
  });
  const saved = useQuery({ queryKey: ["saved"], queryFn: () => api<SavedSearch[]>("/api/saved-searches") });
  const [saveName, setSaveName] = useState("");
  const save = useMutation({
    mutationFn: () => {
      const q: Record<string, unknown> = {};
      for (const k of FILTER_KEYS) {
        const v = params.get(k);
        if (v) q[k] = ["kev", "exploit"].includes(k) ? v === "true" : ["cvss_min", "cvss_max", "epss_min"].includes(k) ? Number(v) : v;
      }
      if (severity.length) q.severity = severity;
      return api("/api/saved-searches", { method: "POST", body: { name: saveName, query: q } });
    },
    onSuccess: () => { setSaveName(""); qc.invalidateQueries({ queryKey: ["saved"] }); },
  });

  const apply = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const next = new URLSearchParams();
    for (const [k, v] of fd.entries()) if (v !== "" && v !== "any") next.append(k, String(v));
    if (params.get("sort")) next.set("sort", params.get("sort")!);
    setParams(next);
  };
  const loadSaved = (s: SavedSearch) => {
    const next = new URLSearchParams();
    for (const [k, v] of Object.entries(s.query)) Array.isArray(v) ? v.forEach((x) => next.append(k, String(x))) : next.set(k, String(v));
    setParams(next);
  };
  const sortBy = (col: string) => {
    const next = new URLSearchParams(params);
    next.set("sort", params.get("sort") === `-${col}` ? col : `-${col}`);
    next.delete("page");
    setParams(next);
  };
  const goPage = (p: number) => { const n = new URLSearchParams(params); n.set("page", String(p)); setParams(n); };
  const sortMark = (col: string) => (params.get("sort") === col ? " ▲" : params.get("sort") === `-${col}` ? " ▼" : "");
  const ariaSort = (col: string) => (params.get("sort") === col ? "ascending" : params.get("sort") === `-${col}` ? "descending" : "none");
  const data = cves.data;
  const pages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1;
  const filtered = params.toString().replace(/(^|&)(page|sort)=[^&]*/g, "") !== "";

  return (
    <>
      <PageHeader title="CVE Intelligence" helpId="cve-intelligence" subtitle="NVD · CISA KEV · FIRST EPSS — normalized and de-duplicated" />
      <SourceStrip />
      {aiOn && <NlSearch onApply={(f) => { const n = new URLSearchParams(); for (const [k, v] of Object.entries(f)) Array.isArray(v) ? v.forEach((x) => n.append(k, String(x))) : n.set(k, String(v)); setParams(n); }} />}

      <form onSubmit={apply} key={params.toString()} className="card mb-4 grid grid-cols-2 gap-3 md:grid-cols-6" aria-label="CVE filters">
        <div className="col-span-2 md:col-span-3">
          <Field label="CVE ID or keyword" htmlFor="cve-search">
            <input id="cve-search" data-tour="cve-search" name="q" className="input" defaultValue={query.q} placeholder="CVE-2024-21762 or 'fortios' — press / to focus" maxLength={200} />
          </Field>
        </div>
        <Field label="Vendor" htmlFor="f-vendor" tip="cpe"><input id="f-vendor" name="vendor" className="input" defaultValue={query.vendor} maxLength={128} /></Field>
        <Field label="Product" htmlFor="f-product"><input id="f-product" name="product" className="input" defaultValue={query.product} maxLength={256} /></Field>
        <Field label="Severity" htmlFor="f-sev" tip="severity">
          <select id="f-sev" name="severity" className="input" defaultValue={severity[0] ?? "any"}>
            <option value="any">Any</option>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </Field>
        <Field label="CVSS min" htmlFor="f-cmin" tip="cvss"><input id="f-cmin" name="cvss_min" type="number" min={0} max={10} step={0.1} className="input" defaultValue={query.cvss_min} /></Field>
        <Field label="CVSS max" htmlFor="f-cmax"><input id="f-cmax" name="cvss_max" type="number" min={0} max={10} step={0.1} className="input" defaultValue={query.cvss_max} /></Field>
        <Field label="EPSS ≥ (0–1)" htmlFor="f-epss" tip="epss"><input id="f-epss" name="epss_min" type="number" min={0} max={1} step={0.01} className="input" defaultValue={query.epss_min} /></Field>
        <Field label="Published from" htmlFor="f-pf"><input id="f-pf" name="published_from" type="date" className="input" defaultValue={query.published_from} /></Field>
        <Field label="Published to" htmlFor="f-pt"><input id="f-pt" name="published_to" type="date" className="input" defaultValue={query.published_to} /></Field>
        <div className="flex items-end gap-4 pb-1.5 text-sm">
          <label className="flex items-center gap-1"><input type="checkbox" name="kev" value="true" defaultChecked={query.kev === "true"} /> KEV only<InfoTip k="kev" /></label>
          <label className="flex items-center gap-1"><input type="checkbox" name="exploit" value="true" defaultChecked={query.exploit === "true"} /> Exploit<InfoTip k="exploit" /></label>
        </div>
        <div className="col-span-2 flex flex-wrap items-end gap-2 md:col-span-6">
          <button className="btn-primary">Apply filters</button>
          <button type="button" className="btn-secondary" onClick={() => setParams(new URLSearchParams())}>Clear</button>
          <span className="ml-auto flex flex-wrap items-end gap-2">
            {saved.data && saved.data.length > 0 && (
              <select aria-label="Saved searches" className="input" value="" onChange={(e) => { const s = saved.data.find((x) => String(x.id) === e.target.value); if (s) loadSaved(s); }}>
                <option value="">Saved searches…</option>
                {saved.data.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
              </select>
            )}
            <input aria-label="Saved search name" className="input w-40" placeholder="Name this search" value={saveName} onChange={(e) => setSaveName(e.target.value)} maxLength={100} />
            <button type="button" className="btn-secondary" disabled={!saveName.trim() || save.isPending} onClick={() => save.mutate()}>Save search</button>
            <InfoTip k="saved_search" />
          </span>
        </div>
        <div className="col-span-2 md:col-span-6"><ErrorNote error={save.error} /></div>
      </form>

      <ErrorNote error={cves.error} />
      {data && data.total === 0 ? (
        filtered ? (
          <EmptyState title="No CVEs match these filters" why="Try widening the CVSS or EPSS range, clearing the date range or removing the vendor filter." />
        ) : (
          <EmptyState title="No CVEs yet" why="The first ingestion has not completed. On first run ExposureCatalyst fetches the last 7 days from NVD, then CISA KEV and EPSS. Check Source health above — if the scheduler is not running, ask an admin to start it."
                      fix={{ label: "Open Source settings", to: "/settings/sources" }} />
        )
      ) : (
        <div className="card overflow-x-auto p-0">
          <table className="min-w-full divide-y divide-ec-border">
            <caption className="sr-only">CVE results</caption>
            <thead className="bg-ec-surface-alt">
              <tr>
                <th className="th" aria-sort={ariaSort("cve_id")}><button onClick={() => sortBy("cve_id")}>CVE ID{sortMark("cve_id")}</button></th>
                <th className="th">Title / vendors</th>
                <th className="th"><span className="inline-flex items-center gap-1">Severity<InfoTip k="severity" /></span></th>
                <th className="th" aria-sort={ariaSort("cvss_score")}><span className="inline-flex items-center gap-1"><button onClick={() => sortBy("cvss_score")}>CVSS{sortMark("cvss_score")}</button><InfoTip k="cvss" /></span></th>
                <th className="th" aria-sort={ariaSort("epss_score")}><span className="inline-flex items-center gap-1"><button onClick={() => sortBy("epss_score")}>EPSS{sortMark("epss_score")}</button><InfoTip k="epss" /></span></th>
                <th className="th"><span className="inline-flex items-center gap-1">KEV / Exploit<InfoTip k="kev" /></span></th>
                <th className="th" aria-sort={ariaSort("published_at")}><button onClick={() => sortBy("published_at")}>Published{sortMark("published_at")}</button></th>
                <th className="th" aria-sort={ariaSort("last_modified_at")}><button onClick={() => sortBy("last_modified_at")}>Modified{sortMark("last_modified_at")}</button></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ec-surface-alt">
              {data?.items.map((c) => (
                <tr key={c.cve_id} className="hover:bg-ec-surface-alt">
                  <td className="td whitespace-nowrap font-mono"><Link className="link" to={`/cves/${c.cve_id}`}>{c.cve_id}</Link></td>
                  <td className="td max-w-md"><div className="line-clamp-2">{c.title ?? "—"}</div><div className="text-xs text-ec-slate">{c.vendors.join(", ")}</div></td>
                  <td className="td"><SeverityBadge severity={c.severity} /></td>
                  <td className="td whitespace-nowrap">{c.cvss_score?.toFixed(1) ?? "—"} <span className="text-xs text-ec-slate">{c.cvss_version ? `v${c.cvss_version}` : ""}</span></td>
                  <td className="td whitespace-nowrap">{pct(c.epss_score)}</td>
                  <td className="td space-x-1 whitespace-nowrap">{c.kev && <KevBadge due={c.kev_due_date} />}{c.exploit_available && <span className="rounded bg-slate-800 px-2 py-0.5 text-xs font-semibold text-white">Exploit</span>}</td>
                  <td className="td whitespace-nowrap">{fmtDate(c.published_at)}</td>
                  <td className="td whitespace-nowrap">{fmtDate(c.last_modified_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {data && (
            <nav aria-label="Pagination" className="flex items-center justify-between border-t border-ec-border px-4 py-2 text-sm">
              <span>{data.total.toLocaleString()} CVEs · page {page} of {pages}</span>
              <span className="flex gap-2">
                <button className="btn-secondary" disabled={page <= 1} onClick={() => goPage(page - 1)}>Previous</button>
                <button className="btn-secondary" disabled={page >= pages} onClick={() => goPage(page + 1)}>Next</button>
              </span>
            </nav>
          )}
        </div>
      )}
    </>
  );
}
