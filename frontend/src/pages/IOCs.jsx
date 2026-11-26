import React, { useEffect, useMemo, useState } from "react";
import { api, currentResult, setCurrentResult } from "../lib/api";
import { Badge, Button, Card, PageTitle, Section } from "../components/ui";

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const domainOf = a => (a && a.includes("@") ? a.split("@").pop().toLowerCase() : null);

function collect(a) {
  const map = new Map();
  const add = (type, value, where) => { if (value && !map.has(type + value)) map.set(type + value, { key: type + value, type, value, where }); };
  for (const u of a.urls || []) { add("url", u.url, `URL in ${u.source}`); if (u.host && !IPV4.test(u.host)) add("domain", u.host, "URL host"); else if (u.host) add("ip", u.host, "URL host"); }
  const m = a.metadata || {};
  for (const x of [...(m.from || []), ...(m.replyTo || [])]) add("domain", domainOf(x.address), "sender / reply-to domain");
  add("domain", domainOf(m.returnPath), "Return-Path domain");
  for (const h of a.received || []) for (const i of h.ips) if (i.public) add("ip", i.ip, "Received header (claimed)");
  for (const at of a.attachments || []) add("sha256", at.sha256, `attachment ${at.filename || ""}`.trim());
  return [...map.values()];
}

const statusTone = s => (s === "ok" ? "cyan" : s === "not_found" ? "slate" : s === "not_configured" ? "slate" : "amber");

export default function IOCs() {
  const [result, setResult] = useState(currentResult);
  const [query, setQuery] = useState(""), [picked, setPicked] = useState(new Set()), [confirm, setConfirm] = useState(false);
  const [providers, setProviders] = useState(null), [busy, setBusy] = useState(false), [error, setError] = useState(""), [out, setOut] = useState(null);
  useEffect(() => { api("/reputation/providers").then(r => setProviders(r.providers)).catch(() => {}); }, []);
  const rows = useMemo(() => collect(result?.analysis || {}), [result]);
  if (!result) return <><PageTitle eyebrow="Indicators" title="IOC Center"/><Card className="p-5"><p className="text-sm text-slate-400">No completed investigation in this session.</p><a className="mt-3 inline-block text-sm text-cyan-300" href="/investigate">Start an investigation</a></Card></>;
  const shown = rows.filter(r => r.value.toLowerCase().includes(query.toLowerCase()));
  const configured = providers ? Object.entries(providers).filter(([, p]) => p.configured).map(([, p]) => p.label) : [];
  const toggle = k => setPicked(s => { const n = new Set(s); n.has(k) ? n.delete(k) : n.add(k); return n; });
  const lookup = async () => {
    setBusy(true); setError(""); setOut(null);
    try {
      const chosen = rows.filter(r => picked.has(r.key)).slice(0, 10).map(({ type, value }) => ({ type, value }));
      const res = await api("/reputation/lookup", { method: "POST", body: JSON.stringify({ indicators: chosen, confirm: true, ...(result.id ? { investigationId: result.id } : {}) }) });
      setOut(res);
      if (result.id) { const fresh = await api("/investigations/" + result.id); setCurrentResult(fresh); setResult(fresh); }
    } catch (e) { setError(e.message); } finally { setBusy(false); }
  };
  const byValue = v => (out?.results || []).filter(r => r.indicator === v);
  return <div className="fade-up"><PageTitle eyebrow="Indicators" title="IOC Center" sub="Indicators extracted from the parsed message. Reputation lookups are optional and sent only after you confirm."/>
    <Card className="mb-4 p-4"><input aria-label="Filter indicators" value={query} onChange={e => setQuery(e.target.value)} placeholder="Filter indicators" className="w-full rounded-lg border border-cyber-line bg-black/20 p-3 text-sm"/><p className="mt-2 text-xs text-slate-500">{shown.length} of {rows.length} unique indicators · select up to 10 for a reputation check</p></Card>
    <Section title="Extracted indicators">{shown.length ? shown.map(r => <div key={r.key} className="border-b border-cyber-line py-3 text-xs last:border-0"><div className="flex flex-wrap items-center gap-3"><input type="checkbox" aria-label={`Select ${r.value}`} checked={picked.has(r.key)} onChange={() => toggle(r.key)} disabled={!picked.has(r.key) && picked.size >= 10}/><Badge tone="slate">{r.type.toUpperCase()}</Badge><span className="min-w-0 flex-1 break-all font-mono text-slate-300">{r.value}</span><span className="text-[10px] text-slate-600">{r.where}</span></div>
      {[...(result.reputation || []).filter(l => l.indicator === r.value).map(l => ({ ...l, checkedAt: l.checked_at, saved: true })), ...byValue(r.value).filter(l => !result.id || !['ok', 'not_found'].includes(l.status))].map((l, i) => <div key={i} className="ml-8 mt-2 rounded-lg bg-black/20 p-2"><Badge tone={statusTone(l.status)}>{l.provider} · {l.status.replace("_", " ")}</Badge>{l.cached && <span className="ml-2 text-[10px] text-slate-500">cached</span>}<span className="ml-2 text-slate-400">{l.result?.summary}</span>{(l.redacted || l.result?.redacted) && <div className="mt-1 text-[10px] text-amber-300">Query string and credentials were removed before lookup; result describes the shortened URL.</div>}<div className="text-[10px] text-slate-600">{new Date(l.checkedAt || l.checked_at).toLocaleString()}</div></div>)}</div>) : <p className="text-xs text-slate-500">{rows.length ? "No matching indicators." : "No indicators were found in this message."}</p>}
      <p className="mt-4 text-xs text-slate-500">Links are shown as text and are never opened or fetched by CyberLens.</p></Section>
    <Section title="Reputation lookup (third-party services)" className="mt-4">
      <div className="space-y-2 text-xs text-slate-300">
        <p>Configured providers: {providers ? (configured.length ? configured.join(", ") : <span className="text-amber-300">none. Set VIRUSTOTAL_API_KEY and/or ABUSEIPDB_API_KEY on the server.</span>) : "checking…"}</p>
        <p className="rounded-lg border border-amber-400/20 bg-amber-400/5 p-3 text-amber-200"><b>Privacy:</b> only the selected indicators are sent: domains, public IPs, SHA-256 hashes, and URLs with query strings, fragments and credentials removed. Email content, subject and addresses are never sent. Private IP addresses are never sent. Providers may log what you query.</p>
        <label className="flex items-start gap-2"><input type="checkbox" checked={confirm} onChange={e => setConfirm(e.target.checked)} className="mt-0.5"/>I confirm that the {picked.size} selected indicator(s) may be sent to the configured third-party providers.</label>
        <Button disabled={busy || !confirm || !picked.size || !configured.length} onClick={lookup}>{busy ? "Checking…" : "Check reputation"}</Button>
        {!result.id && <p className="text-slate-500">This investigation is not saved, so lookup results will not be stored.</p>}
        {error && <p role="alert" className="text-red-300">{error}</p>}
        {out?.rejected?.length > 0 && <ul className="list-disc pl-4 text-amber-300">{out.rejected.map((r, i) => <li key={i}>{r.value.slice(0, 80)}: {r.reason}</li>)}</ul>}
        {out && <p className="text-slate-500">{out.note}</p>}</div></Section></div>;
}
