import { useState, type FormEvent } from "react";
import { useMutation } from "@tanstack/react-query";
import { api } from "../api";
import { AiMeta, AiText, useAi, type AiResult } from "../components/Ai";
import { EmptyState, ErrorNote, PageHeader } from "../components/ui";

interface Msg { role: "user" | "assistant"; content: string; meta?: AiResult }

export default function AssistantPage() {
  const aiOn = useAi();
  const [msgs, setMsgs] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const send = useMutation({
    mutationFn: (history: Msg[]) => api<AiResult>("/api/ai/chat", { method: "POST", body: { messages: history.map(({ role, content }) => ({ role, content })) } }),
    onSuccess: (r) => setMsgs((m) => [...m, { role: "assistant", content: r.text, meta: r }]),
  });
  if (!aiOn) return <><PageHeader title="Analyst assistant" helpId="assistant" /><EmptyState title="AI is not enabled" why="An administrator can enable AI providers under Settings → AI Providers. Your role also needs the ai:use permission." /></>;
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!input.trim()) return;
    const next = [...msgs, { role: "user" as const, content: input.trim() }];
    setMsgs(next); setInput(""); send.mutate(next);
  };
  return (
    <>
      <PageHeader title="Analyst assistant" helpId="assistant" subtitle="Answers from ExposureCatalyst data only — CVE records and your exposure. AI output can be wrong; verify before acting." />
      <div className="card mb-3 min-h-[320px] space-y-3" aria-live="polite">
        {msgs.length === 0 && <p className="text-sm text-ec-slate">Try: “Which CVE-2024-21762 assets are in production and what should we do first?” or “Summarize the risk of CVE-2024-3400 for our exec team.”</p>}
        {msgs.map((m, i) => (
          <div key={i} className={m.role === "user" ? "ml-auto max-w-[80%] rounded-md bg-ec-navy px-3 py-2 text-sm text-white" : "max-w-[90%] rounded-md bg-ec-surface-alt px-3 py-2"}>
            {m.role === "user" ? m.content : <><AiText text={m.content} />{m.meta && <AiMeta r={m.meta} />}</>}
          </div>))}
        {send.isPending && <p className="text-sm text-ec-slate">Thinking…</p>}
        <ErrorNote error={send.error} />
      </div>
      <form onSubmit={submit} className="flex gap-2">
        <label htmlFor="ask" className="sr-only">Message</label>
        <input id="ask" className="input flex-1" value={input} onChange={(e) => setInput(e.target.value)} maxLength={4000} placeholder="Ask about a CVE or your exposure…" />
        <button className="btn-primary" disabled={send.isPending}>Send</button>
        {msgs.length > 0 && <button type="button" className="btn-secondary" onClick={() => setMsgs([])}>Clear</button>}
      </form>
    </>
  );
}
