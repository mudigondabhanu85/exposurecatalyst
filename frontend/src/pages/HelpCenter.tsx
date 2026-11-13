import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, type HelpPage, type HelpTopic } from "../api";
import { useHelp } from "../help";
import { Markdown } from "../components/Markdown";
import { ErrorNote, PageHeader } from "../components/ui";
import { AiBox, AiMeta, AiText, useAi, type AiResult } from "../components/Ai";
import { useMutation } from "@tanstack/react-query";

type Tab = "topics" | "glossary" | "faq" | "shortcuts" | "whatsnew";
const TABS: { id: Tab; label: string }[] = [
  { id: "topics", label: "Topics" }, { id: "glossary", label: "Glossary" }, { id: "faq", label: "FAQ" },
  { id: "shortcuts", label: "Keyboard shortcuts" }, { id: "whatsnew", label: "What's new" },
];

function HelpDoc({ id }: { id: string }) {
  const q = useQuery({ queryKey: ["help", id], queryFn: () => api<HelpPage>(`/api/help/pages/${id}`) });
  return q.data ? <Markdown source={q.data.markdown} /> : null;
}

export default function HelpCenterPage() {
  const { openHelp } = useHelp();
  const [tab, setTab] = useState<Tab>("topics");
  const [term, setTerm] = useState("");
  const topics = useQuery({ queryKey: ["help-index"], queryFn: () => api<HelpTopic[]>("/api/help") });
  const results = useQuery({
    queryKey: ["help-search", term],
    queryFn: () => api<{ id: string; title: string; snippet: string }[]>("/api/help/search", { query: { q: term } }),
    enabled: term.trim().length >= 2,
  });
  const changelog = useQuery({ queryKey: ["changelog"], queryFn: () => api<string>("/api/help/changelog"), enabled: tab === "whatsnew" });
  const aiOn = useAi();
  const [question, setQuestion] = useState("");
  const ask = useMutation({ mutationFn: (qq: string) => api<AiResult & { citations: { id: string; title: string }[] }>("/api/ai/help", { method: "POST", body: { question: qq } }) });
  const pages = topics.data?.filter((t) => !["glossary", "faq", "shortcuts"].includes(t.id)) ?? [];

  return (
    <>
      <div className="mb-4 flex items-center gap-4 rounded-md bg-ec-navy px-5 py-4">
        <img src="/brand/svg/mark-dark.svg" alt="" aria-hidden="true" className="h-16 w-16" />
        <div>
          <p className="font-heading text-xl font-bold text-white">ExposureCatalyst Help Center</p>
          <p className="text-sm text-ec-slate-light">Guides, glossary and answers — filtered to your role</p>
        </div>
      </div>
      <PageHeader title="Help Center" helpId="help-center" subtitle="Everything you need to use ExposureCatalyst"
                  actions={<a className="btn-secondary" href="/docs/" target="_blank" rel="noopener noreferrer">Full documentation ↗</a>} />
      <div className="card mb-4">
        <label className="label" htmlFor="help-search">Search help</label>
        <input id="help-search" type="search" className="input w-full" placeholder="e.g. EPSS, refresh, unlock user" value={term} onChange={(e) => setTerm(e.target.value)} maxLength={100} />
        {results.data && (
          <ul className="mt-3 divide-y divide-ec-surface-alt" aria-live="polite">
            {results.data.length === 0 && <li className="py-2 text-sm text-ec-slate">No matching topics.</li>}
            {results.data.map((r) => (
              <li key={r.id} className="py-2">
                <button className="text-left text-sm font-medium link" onClick={() => openHelp(r.id)}>{r.title}</button>
                <p className="text-xs text-ec-slate">…{r.snippet}…</p>
              </li>
            ))}
          </ul>
        )}
      </div>

      {aiOn && (
        <div className="mb-4"><AiBox title="Ask Help">
          <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); if (question.trim().length >= 3) ask.mutate(question); }}>
            <label htmlFor="askhelp" className="sr-only">Question</label>
            <input id="askhelp" className="input flex-1" value={question} onChange={(e) => setQuestion(e.target.value)} maxLength={500} placeholder="e.g. How do I connect SailPoint?" />
            <button className="btn-primary" disabled={ask.isPending}>{ask.isPending ? "Looking…" : "Ask"}</button>
          </form>
          <ErrorNote error={ask.error} />
          {ask.data && (<div className="mt-3"><AiText text={ask.data.text} />
            {ask.data.citations.length > 0 && <p className="mt-2 text-xs">Sources: {ask.data.citations.map((c, i) => <span key={c.id}>{i > 0 && ", "}<button className="link" onClick={() => openHelp(c.id)}>{c.title}</button></span>)}</p>}
            {ask.data.provider && <AiMeta r={ask.data} />}</div>)}
          <p className="mt-2 text-xs text-ec-slate">Answers only from the help topics you can see, with citations.</p>
        </AiBox></div>
      )}

      <div role="tablist" aria-label="Help sections" className="mb-4 flex flex-wrap gap-1 border-b border-ec-border">
        {TABS.map((t) => (
          <button key={t.id} role="tab" aria-selected={tab === t.id} onClick={() => setTab(t.id)}
                  className={`-mb-px border-b-2 px-3 py-2 text-sm ${tab === t.id ? "border-ec-orange font-semibold text-ec-navy" : "border-transparent text-ec-slate hover:text-ec-navy"}`}>
            {t.label}
          </button>
        ))}
      </div>

      <div role="tabpanel" className="card">
        {tab === "topics" && (
          <ul className="grid gap-3 md:grid-cols-2">
            {pages.map((t) => (
              <li key={t.id} className="rounded-md border border-ec-border p-3">
                <button className="text-left font-medium link" onClick={() => openHelp(t.id)}>{t.title}</button>
                <p className="mt-1 text-sm text-ec-slate">{t.summary}</p>
              </li>
            ))}
          </ul>
        )}
        {tab === "glossary" && <HelpDoc id="glossary" />}
        {tab === "faq" && <HelpDoc id="faq" />}
        {tab === "shortcuts" && <HelpDoc id="shortcuts" />}
        {tab === "whatsnew" && changelog.data && <Markdown source={changelog.data} />}
      </div>

      <section className="card mt-4">
        <h2 className="mb-1 font-semibold">Download documentation</h2>
        <p className="text-sm text-ec-slate">
          DOCX and standalone HTML exports of the full guide and the audience-specific guides (User, Admin, Security &amp; Architecture) are produced by the documentation pipeline in Phase 6.
          Until then, use the <a className="link" href="/docs/" target="_blank" rel="noopener noreferrer">online documentation</a>.
        </p>
      </section>
    </>
  );
}
