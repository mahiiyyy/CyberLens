import React, { useState } from "react";
import { api, currentResult, setCurrentResult } from "../lib/api";
import { Badge, Button, Card, PageTitle, Section } from "../components/ui";

export default function Summary() {
  const [result, setResult] = useState(currentResult);
  const [summary, setSummary] = useState(result?.summary ?? null);
  const [busy, setBusy] = useState(false), [error, setError] = useState(""), [confirm, setConfirm] = useState(false);
  if (!result) return <><PageTitle eyebrow="Investigation" title="Investigation Summary"/><Card className="p-5"><p className="text-sm text-slate-400">No completed investigation in this session.</p><a className="mt-3 inline-block text-sm text-cyan-300" href="/investigate">Start an investigation</a></Card></>;
  if (!result.id) return <><PageTitle eyebrow="Investigation" title="Investigation Summary" sub="Evidence-grounded summaries are generated from saved investigations."/><Card className="p-5"><p className="text-sm text-slate-400">This investigation has not been saved. Summaries are built from the stored evidence record so every statement can be traced to it. Save the investigation from the Result page first.</p></Card></>;
  const generate = async mode => {
    setBusy(true); setError("");
    try {
      const r = await api(`/investigations/${result.id}/summary`, { method: "POST", body: JSON.stringify(mode === "ai" ? { mode, confirm: true } : { mode }) });
      setSummary(r.summary); const next = { ...result, summary: r.summary }; setCurrentResult(next); setResult(next);
    } catch (e) { setError(e.message); } finally { setBusy(false); }
  };
  const facts = Object.fromEntries((summary?.facts || []).map(f => [f.id, f]));
  return <div className="fade-up"><PageTitle eyebrow="Evidence-grounded" title="Investigation Summary" sub="Every statement cites the evidence fact it is based on."/>
    <Card className="mb-4 space-y-3 p-4 text-xs text-slate-300">
      <div className="flex flex-wrap items-center gap-3"><Button variant="secondary" disabled={busy} onClick={() => generate("rule")}>Generate rule-based summary</Button><span className="text-slate-500">Built locally from the evidence facts. No external service, no AI.</span></div>
      <div className="border-t border-cyber-line pt-3"><label className="flex items-start gap-2"><input type="checkbox" checked={confirm} onChange={e => setConfirm(e.target.checked)} className="mt-0.5"/>I consent to sending the numbered evidence facts (headers, findings, hashes, URL hosts, subject text) to the AI provider. The email body and attachment contents are never sent.</label><Button className="mt-2" disabled={busy || !confirm} onClick={() => generate("ai")}>{busy ? "Working…" : "Generate AI summary"}</Button><span className="ml-3 text-slate-500">Requires ANTHROPIC_API_KEY on the server.</span></div>
      {error && <p role="alert" className="text-red-300">{error}</p>}</Card>
    {summary ? <><Section title="Summary" action={<Badge tone={summary.mode === "ai" ? "purple" : "cyan"}>{summary.mode === "ai" ? `AI-generated · ${summary.model}` : "Rule-based · not AI"}</Badge>}>
      <p className="mb-3 text-[11px] text-slate-500">Generated {new Date(summary.generatedAt).toLocaleString()}. {summary.mode === "ai" ? "AI output is validated to cite real evidence, but can still misstate it. Check each statement against the cited fact." : ""}</p>
      {summary.statements.map((s, i) => <div key={i} className="border-b border-cyber-line py-3 text-sm last:border-0"><p className="text-slate-200">{s.statement}</p><div className="mt-1 flex flex-wrap gap-2">{s.evidence.map(id => <span key={id} title={facts[id]?.text} className="cursor-help rounded border border-cyber-line px-1.5 py-0.5 font-mono text-[10px] text-cyan-300">{id}</span>)}</div></div>)}
      <p className="mt-4 text-xs text-slate-500">Limitations: {summary.limitations.join(" ")}</p></Section>
      <Section title="Evidence facts" className="mt-4"><div className="max-h-96 overflow-auto">{summary.facts.map(f => <div key={f.id} className="flex gap-3 border-b border-cyber-line py-2 text-[11px] last:border-0"><span className="w-8 shrink-0 font-mono text-cyan-300">{f.id}</span><span className="break-all text-slate-300">{f.text}</span><span className="ml-auto shrink-0 text-slate-600">{f.ref}</span></div>)}</div></Section></> : <p className="text-xs text-slate-500">No summary generated yet.</p>}
  </div>;
}
