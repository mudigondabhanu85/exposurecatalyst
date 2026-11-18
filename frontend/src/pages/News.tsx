import { type FormEvent } from "react";
import { NewsIntelSection } from "../components/Intel";
import { Link, useSearchParams } from "react-router-dom";
import { keepPreviousData, useMutation, useQuery } from "@tanstack/react-query";
import { api, fmtDateTime } from "../api";
import { useAuth } from "../auth";
import { AiBox, AiMeta, AiText, useAi } from "../components/Ai";
import { EmptyState, ErrorNote, PageHeader } from "../components/ui";

interface Story { id: number; title: string; url: string; source: string; published_at: string; summary: string | null; cve_ids: string[]; tags: string[]; also: { source: string; url: string; title: string }[] }
interface NewsPage { items: Story[]; total: number; page: number; page_size: number; tags: string[]; sources: { id: number; name: string }[] }
interface Brief { summary: string; themes: { title: string; items: { id: number; title: string; url: string }[] }[]; actors: { name: string; campaign: string | null; items: number[] }[];
  provider: string; model: string; redacted_values: number; fallbacks: string[]; items_considered: number }

const ext = { target: "_blank", rel: "noopener noreferrer nofollow" } as const;

export default function NewsPage() {
  const { can } = useAuth();
  const aiOn = useAi();
  const [params, setParams] = useSearchParams();
  const page = Number(params.get("page") ?? 1);
  const q = useQuery({
    queryKey: ["news", params.toString()],
    queryFn: () => api<NewsPage>("/api/news", { query: { q: params.get("q"), tag: params.get("tag"), cve: params.get("cve"), source: params.getAll("source"),
                                                        date_from: params.get("date_from"), date_to: params.get("date_to"), page } }),
    placeholderData: keepPreviousData, refetchInterval: 120_000,
  });
  const brief = useMutation({ mutationFn: (days: number) => api<Brief>("/api/ai/news/brief", { method: "POST", body: { days } }) });
  const apply = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const next = new URLSearchParams();
    for (const [k, v] of fd.entries()) if (v) next.append(k, String(v));
    setParams(next);
  };
  const d = q.data;
  const pages = d ? Math.max(1, Math.ceil(d.total / d.page_size)) : 1;
  return (
    <>
      <PageHeader title="Security News" helpId="news" subtitle="Trusted sources, de-duplicated across outlets, linked to CVEs"
                  actions={aiOn && can("news:view") && <button className="btn-primary" disabled={brief.isPending} onClick={() => brief.mutate(3)}>{brief.isPending ? "Summarizing…" : "AI brief (3 days)"}</button>} />
      {(brief.data || brief.error) && (
        <div className="mb-4"><AiBox title="Security news brief">
          <ErrorNote error={brief.error} />
          {brief.data && (<>
            <AiText text={brief.data.summary} />
            {brief.data.themes.length > 0 && <div className="mt-3 grid gap-3 md:grid-cols-2">{brief.data.themes.map((t, i) => (
              <div key={i} className="rounded-md bg-ec-surface-alt p-3"><p className="font-heading font-bold">{t.title}</p>
                <ul className="ml-4 list-disc text-sm">{t.items.map((it) => <li key={it.id}><a className="link" href={it.url} {...ext}>{it.title}</a></li>)}</ul></div>))}</div>}
            {brief.data.actors.length > 0 && <p className="mt-3 text-sm"><strong>Threat actors / campaigns mentioned:</strong> {brief.data.actors.map((a) => a.campaign ? `${a.name} (${a.campaign})` : a.name).join(" · ")}</p>}
            <AiMeta r={brief.data} />
          </>)}
        </AiBox></div>
      )}
      <form key={params.toString()} onSubmit={apply} className="card mb-4 grid gap-3 md:grid-cols-6" aria-label="News filters">
        <div className="md:col-span-2"><label className="label" htmlFor="nq">Keyword</label><input id="nq" name="q" className="input w-full" defaultValue={params.get("q") ?? ""} maxLength={200} /></div>
        <div><label className="label" htmlFor="ns">Source</label><select id="ns" name="source" className="input w-full" defaultValue={params.get("source") ?? ""}><option value="">All</option>{d?.sources.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select></div>
        <div><label className="label" htmlFor="nt">Tag</label><select id="nt" name="tag" className="input w-full" defaultValue={params.get("tag") ?? ""}><option value="">All</option>{d?.tags.map((t) => <option key={t}>{t}</option>)}</select></div>
        <div><label className="label" htmlFor="nc">CVE</label><input id="nc" name="cve" className="input w-full" placeholder="CVE-2024-…" defaultValue={params.get("cve") ?? ""} /></div>
        <div><label className="label" htmlFor="nf">From</label><input id="nf" name="date_from" type="date" className="input w-full" defaultValue={params.get("date_from") ?? ""} /></div>
        <div className="flex items-end gap-2 md:col-span-6"><button className="btn-primary">Apply</button><button type="button" className="btn-secondary" onClick={() => setParams(new URLSearchParams())}>Clear</button></div>
      </form>
      <ErrorNote error={q.error} />
      {d?.total === 0 ? (
        <EmptyState title="No stories yet" why="News feeds refresh every 30 minutes. If this persists, an admin can check feed health under Settings → News feeds." fix={can("news:manage") ? { label: "Open News feeds", to: "/settings/news" } : undefined} />
      ) : (
        <ul className="space-y-3">{d?.items.map((s) => (
          <li key={s.id} className="card">
            <a className="font-heading text-base font-bold text-ec-navy hover:text-ec-orange" href={s.url} {...ext}>{s.title} <span aria-hidden="true">↗</span><span className="sr-only">(opens source in a new tab)</span></a>
            <p className="mt-0.5 text-xs text-ec-slate">{s.source} · {fmtDateTime(s.published_at)}{s.also.length > 0 && <> · also covered by {s.also.map((a, i) => <span key={i}>{i > 0 && ", "}<a className="link" href={a.url} {...ext}>{a.source}</a></span>)}</>}</p>
            {s.summary && <p className="mt-1 text-sm text-ec-slate">{s.summary}</p>}
            <div className="mt-2 flex flex-wrap gap-1">
              {s.cve_ids.map((c) => <Link key={c} to={`/cves/${c}`} className="rounded-sm bg-ec-navy px-1.5 py-0.5 font-mono text-[11px] text-white hover:opacity-90">{c}</Link>)}
              {s.tags.map((t) => <button key={t} className="rounded-sm bg-ec-surface-alt px-1.5 py-0.5 text-[11px]" onClick={() => setParams(new URLSearchParams({ tag: t }))}>#{t}</button>)}
            </div>
          </li>))}
        </ul>
      )}
      {d && d.total > d.page_size && (
        <nav aria-label="Pagination" className="mt-4 flex items-center justify-between text-sm">
          <span>{d.total} stories · page {page} of {pages}</span>
          <span className="flex gap-2"><button className="btn-secondary" disabled={page <= 1} onClick={() => { const n = new URLSearchParams(params); n.set("page", String(page - 1)); setParams(n); }}>Previous</button>
            <button className="btn-secondary" disabled={page >= pages} onClick={() => { const n = new URLSearchParams(params); n.set("page", String(page + 1)); setParams(n); }}>Next</button></span>
        </nav>
      )}
      <NewsIntelSection />
      <p className="mt-6 text-xs text-ec-slate">Headlines and short excerpts only; read full articles at the source.</p>
    </>
  );
}
