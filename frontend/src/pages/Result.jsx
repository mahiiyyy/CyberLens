import React, { useState } from "react";
import { api, currentResult, pendingIntake, setCurrentResult } from "../lib/api";
import { BrainCircuit } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { Badge, Button, Card, PageTitle, Section } from "../components/ui";

export default function Result() {
  const nav = useNavigate();
  const [d, setD] = useState(currentResult);
  const [review, setReview] = useState("Needs Review");
  const [saveTitle, setSaveTitle] = useState("");
  const [saving, setSaving] = useState(false); const [saved, setSaved] = useState(null); const [saveError, setSaveError] = useState("");
  const [consent, setConsent] = useState(false); const [storeOriginal, setStoreOriginal] = useState(false); const [persisting, setPersisting] = useState(false);

  if (!d) return <div><PageTitle eyebrow="Investigation" title="No completed investigation" sub="Upload or paste an email to view its analysis."/><Button onClick={() => nav("/investigate")}>Start investigation</Button></div>;

  const findings = Array.isArray(d.findings) ? d.findings : [];
  const evidence = d.evidence || {};
  const a = d.analysis || {};
  const isBenign = String(d.verdict).startsWith("BENIGN");
  const tone = isBenign ? "cyan" : d.score >= 75 ? "red" : "amber";

  const persist = async () => {
    if (!consent || persisting || !pendingIntake.bytes) return;
    setPersisting(true); setSaveError("");
    try {
      const params = new URLSearchParams({ kind: pendingIntake.kind, save: "1", consent: "1" });
      if (pendingIntake.filename) params.set("filename", pendingIntake.filename);
      if (pendingIntake.sample) params.set("sample", "1");
      if (storeOriginal) params.set("storeOriginal", "1");
      const next = await api("/investigations/analyze?" + params, { method: "POST", headers: { "Content-Type": "application/octet-stream" }, body: pendingIntake.bytes });
      setCurrentResult(next); setD(next);
    } catch (e) { setSaveError(e.message); } finally { setPersisting(false); }
  };

  const saveCase = async (e) => {
    e.preventDefault(); if (saving || saved) return; setSaving(true); setSaveError("");
    try {
      const data = await api("/cases", { method: "POST", body: JSON.stringify({ title: saveTitle.trim() }) });
      if (d.id) await api("/investigations/" + d.id, { method: "PATCH", body: JSON.stringify({ caseId: data.case.id }) });
      setSaved(data.case);
    } catch (err) { setSaveError(err.message); } finally { setSaving(false); }
  };

  return <div className="fade-up">
    <PageTitle eyebrow={`Reference ${d.reference || d.caseId || "Unsaved"}`} title="Investigation Result" sub={`${evidence.subject || "Untitled email"} · ${d.saved ? "saved to your account" : "not saved"}`}/>
    {d.isSample && <div role="status" className="mb-4 rounded-lg border border-cyan-400/30 bg-cyan-400/10 p-3 text-xs text-cyan-200"><b>SAMPLE DATA.</b> This result comes from the built-in fictional sample email, not a real message.</div>}
    <div className="grid gap-3 lg:grid-cols-4">
      <Card className="p-5 lg:col-span-2"><div className="flex justify-between gap-5"><div><Badge tone={tone}>{d.verdict}</Badge><div className={`mt-3 text-5xl font-black ${isBenign ? "text-cyan-300" : d.score >= 75 ? "text-red-300" : "text-amber-300"}`}>{d.score}<span className="text-lg text-slate-600">/100</span></div><div className="text-xs font-bold">{d.score >= 75 ? "CRITICAL THREAT" : d.score >= 50 ? "SUSPICIOUS" : d.score >= 25 ? "NEEDS REVIEW" : "LOW RISK"}</div></div><div className="text-right"><div className="text-3xl font-black text-purple-300">{d.confidence}%</div><div className="text-[10px] text-slate-600">REPORTED CONFIDENCE (UNCALIBRATED)</div><div className="mt-2 text-[9px] text-slate-500">{d.aiModel}</div></div></div><div className="mt-5 flex flex-wrap gap-2">{[isBenign ? "Low risk" : d.verdict, d.aiMode === "local-ai" ? "AI analyzed" : "Local analysis"].map(x => <Badge key={x} tone="amber">{x}</Badge>)}</div></Card>
      <Card className="p-5 lg:col-span-2"><h2 className="text-sm font-bold">Threat score breakdown</h2>{(d.factors || []).map(([x, v, why]) => <div className="mt-3" key={x}><div className="flex justify-between text-[11px]"><span>{x}</span><span className="text-slate-600">{v}</span></div><div className="mt-1 h-1.5 rounded bg-black/30"><div className="h-full rounded bg-red-400" style={{ width: `${Math.min(100, v / 20 * 100)}%` }}/></div>{why && <div className="mt-1 text-[10px] text-slate-500">{why}</div>}</div>)}{!d.factors?.length && <p className="mt-4 text-xs text-slate-500">No deterministic risk factors were raised.</p>}<div className="mt-4 text-xs text-cyan-300">Deterministic score: {d.deterministicScore ?? "Unavailable"} · AI score: {d.aiScore ?? "Unavailable"}</div></Card>
    </div>
    <div className="my-4 grid gap-4 lg:grid-cols-2">
      <Section title="Parsed email details"><div className="space-y-2 text-xs text-slate-300">{[["Subject", evidence.subject], ["From", evidence.sender], ["Reply-To", evidence.reply_to], ["Return-Path", evidence.return_path], ["Message-ID", a.metadata?.messageId], ["Date", a.metadata?.date], ["Received hops", a.received?.length], ["URLs", a.urls?.length], ["Attachments", a.attachments?.length]].map(([label, value]) => <div key={label} className="break-all"><span className="text-slate-500">{label}: </span>{value ?? "Not present in message"}</div>)}</div>{a.warnings?.length > 0 && <ul className="mt-3 list-disc pl-4 text-[11px] text-amber-300">{a.warnings.map(w => <li key={w}>{w}</li>)}</ul>}<p className="mt-4 text-xs text-slate-500">Values are what the message claims. Risk assessment is heuristic and does not establish that an email is safe or malicious.</p></Section>
      <Section title="Original-file fingerprint"><p className="text-xs text-slate-400">SHA-256 of the {d.integrity?.source === "original-file-bytes" ? "original uploaded file bytes" : "pasted text (UTF-8 bytes as submitted)"}, computed on the server.</p><div className="mt-3 break-all rounded-lg bg-black/20 p-3 font-mono text-xs text-cyan-300">{d.integrity?.sha256 || "Unavailable"}</div><p className="mt-2 text-xs text-slate-500">{d.integrity?.size} bytes</p><Button variant="secondary" className="mt-3" onClick={() => nav("/evidence")}>Evidence &amp; custody</Button></Section>
    </div>
    <Section title="Storage" className="mb-4">{d.saved ? <p className="text-xs text-emerald-300">Saved to your account{d.storedOriginal ? " together with the original email bytes" : " (original bytes not stored)"}. <button className="ml-2 text-cyan-300" onClick={() => nav("/history")}>Saved investigations →</button></p> : <>
      <p className="mb-3 text-xs text-slate-400">This result exists only in this browser session. You can save it to your account; the email is re-submitted from memory for this purpose.</p>
      {pendingIntake.bytes ? <div className="space-y-2 text-xs text-slate-300"><label className="flex items-start gap-2"><input type="checkbox" checked={consent} onChange={e => { setConsent(e.target.checked); if (!e.target.checked) setStoreOriginal(false); }} className="mt-0.5"/>I consent to saving parsed headers, URLs, attachment hashes, findings and a text excerpt to my account.</label><label className={`flex items-start gap-2 ${consent ? "" : "opacity-40"}`}><input type="checkbox" disabled={!consent} checked={storeOriginal} onChange={e => setStoreOriginal(e.target.checked)} className="mt-0.5"/>Also store the original email bytes for later integrity verification.</label><Button disabled={!consent || persisting} onClick={persist}>{persisting ? "Saving…" : "Save investigation"}</Button></div> : <p className="text-xs text-slate-500">The original email is no longer in memory. Run a new investigation to save it.</p>}</>}</Section>
    <Section title="Create a case" className="mb-4"><p className="mb-3 text-xs text-slate-400">Choose a non-sensitive title for a case record.{d.saved ? " This investigation will be linked to it." : " Save the investigation first to link it to the case; otherwise only the title and status are stored."}</p>{saved ? <div className="flex flex-wrap items-center gap-3"><span className="text-xs text-emerald-300">Case created successfully.</span><Button variant="secondary" onClick={() => nav("/cases")}>View cases</Button></div> : <form onSubmit={saveCase} className="flex flex-wrap gap-3"><input aria-label="Case title" required maxLength={160} value={saveTitle} onChange={e => setSaveTitle(e.target.value)} placeholder="Investigation reference title" className="min-w-0 flex-1 rounded-lg border border-cyber-line bg-black/20 p-3 text-sm"/><Button type="submit" disabled={saving || !saveTitle.trim()}>{saving ? "Saving…" : "Create case"}</Button></form>}{saveError && <p role="alert" className="mt-2 text-xs text-red-300">{saveError}</p>}</Section>
    <Section title="Analysis findings" action={<Badge tone="purple"><BrainCircuit size={12} className="mr-1 inline"/> {d.aiMode || "Evidence-grounded"}</Badge>}><div className="mb-4 rounded-lg border border-purple-400/20 bg-purple-400/5 p-3 text-xs text-purple-200">{d.aiExplanation || "The AI explains its interpretation from supplied evidence; deterministic checks remain separate."}</div>{!findings.length && <p className="text-xs text-slate-500">No findings returned.</p>}{findings.map((f, i) => <div className="border-b border-cyber-line py-4 last:border-0" key={f.title || i}><div className="flex justify-between gap-4"><div><div className="font-bold text-sm text-white">{f.title}</div><div className="mt-1 text-xs text-slate-400">{f.explanation}</div></div><Badge tone={f.severity === "CRITICAL" ? "red" : "amber"}>{f.severity}</Badge></div><div className="mt-3 rounded-lg bg-black/20 p-3 font-mono text-[10px] text-slate-500">EVIDENCE: {f.evidence}</div><div className="mt-2 text-[10px] text-purple-300">Confidence {f.confidence}% {f.contribution ? `· +${f.contribution} score` : "· AI contextual signal"}</div></div>)}</Section>
    <Card className="mt-4 flex flex-wrap items-center justify-between gap-3 p-4"><div><div className="text-[9px] font-bold tracking-widest text-slate-600">ANALYST REVIEW · NOT SAVED</div><div className="mt-1 text-sm font-bold">Disposition: {review}</div></div><div className="flex flex-wrap gap-2"><Button variant="danger" onClick={() => setReview("Confirmed Threat")}>Confirm Threat</Button><Button variant="secondary" onClick={() => setReview("False Positive")}>False Positive</Button><Button variant="secondary" onClick={() => setReview("Needs Review")}>Needs Review</Button></div></Card>
  </div>;
}
