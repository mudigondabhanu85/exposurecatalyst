import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, type HelpPage, type HelpTopic } from "../api";
import { useHelp } from "../help";
import { Markdown } from "../components/Markdown";
import { PageHeader } from "../components/ui";

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
  const pages = topics.data?.filter((t) => !["glossary", "faq", "shortcuts"].includes(t.id)) ?? [];

  return (
    <>
      <PageHeader title="Help Center" helpId="help-center" subtitle="Everything you need to use ExposureCatalyst"
                  actions={<a className="btn-secondary" href="/docs/" target="_blank" rel="noopener noreferrer">Full documentation ↗</a>} />
      <div className="card mb-4">
        <label className="label" htmlFor="help-search">Search help</label>
        <input id="help-search" type="search" className="input w-full" placeholder="e.g. EPSS, refresh, unlock user" value={term} onChange={(e) => setTerm(e.target.value)} maxLength={100} />
        {results.data && (
          <ul className="mt-3 divide-y divide-slate-100" aria-live="polite">
            {results.data.length === 0 && <li className="py-2 text-sm text-slate-500">No matching topics.</li>}
            {results.data.map((r) => (
              <li key={r.id} className="py-2">
                <button className="text-left text-sm font-medium link" onClick={() => openHelp(r.id)}>{r.title}</button>
                <p className="text-xs text-ec-slate">…{r.snippet}…</p>
              </li>
            ))}
          </ul>
        )}
      </div>

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
