import React, { useEffect, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { api, setCurrentResult, pendingIntake } from "../lib/api";
import { Badge, Button, Card, PageTitle } from "../components/ui";

const tone = r => (r.score >= 75 ? "red" : r.score >= 50 ? "amber" : r.score >= 25 ? "purple" : "cyan");

export default function History() {
  const nav = useNavigate();
  const [rows, setRows] = useState([]), [total, setTotal] = useState(0), [cases, setCases] = useState([]);
  const [q, setQ] = useState(""), [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true), [error, setError] = useState(""), [busy, setBusy] = useState("");
  const PAGE = 25;
  const load = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const params = new URLSearchParams({ limit: PAGE, offset });
      if (q.trim()) params.set("q", q.trim());
      const [inv, cs] = await Promise.all([api("/investigations?" + params), api("/cases")]);
      setRows(inv.investigations); setTotal(inv.total); setCases(cs.cases);
    } catch (e) { setError(e.message); } finally { setLoading(false); }
  }, [q, offset]);
  useEffect(() => { const t = setTimeout(load, 250); return () => clearTimeout(t); }, [load]);

  const open = async id => {
    setBusy(id); setError("");
    try { const r = await api("/investigations/" + id); pendingIntake.bytes = null; setCurrentResult(r); nav("/result"); }
    catch (e) { setError(e.message); setBusy(""); }
  };
  const remove = async r => {
    if (!window.confirm(`Delete ${r.reference}? The saved analysis, any stored original email, and reputation lookups for it will be permanently removed. The audit log keeps a record of the deletion.`)) return;
    setBusy(r.id); setError("");
    try { await api("/investigations/" + r.id, { method: "DELETE" }); await load(); } catch (e) { setError(e.message); } finally { setBusy(""); }
  };
  const link = async (r, caseId) => {
    setBusy(r.id); setError("");
    try { await api("/investigations/" + r.id, { method: "PATCH", body: JSON.stringify({ caseId: caseId || null }) }); await load(); } catch (e) { setError(e.message); } finally { setBusy(""); }
  };

  return <div className="fade-up">
    <PageTitle eyebrow="Investigation history" title="Saved Investigations" sub="Investigations you chose to save to your account. Only you can see them."/>
    <div className="mb-4 flex gap-2"><input aria-label="Search saved investigations" value={q} onChange={e => { setQ(e.target.value); setOffset(0); }} placeholder="Search by title, reference or SHA-256" className="flex-1 rounded-lg border border-cyber-line bg-cyber-panel p-3 text-sm"/><Button variant="secondary" disabled={loading} onClick={load}>Refresh</Button></div>
    {error && <p role="alert" className="mb-4 text-sm text-red-300">{error}</p>}
    <Card className="overflow-hidden">
      {loading ? <p className="p-4 text-sm text-slate-400">Loading…</p> : !rows.length ? <p className="p-4 text-sm text-slate-400">{q ? "No matching investigations." : "No saved investigations yet. Tick “Save this investigation” when starting one."}</p> :
        rows.map(r => <div key={r.id} className="flex flex-wrap items-center gap-3 border-b border-cyber-line p-4 text-xs">
          <div className="min-w-0 flex-1"><div className="break-all font-bold text-slate-100">{r.title}</div><div className="mt-1 break-all text-[10px] text-slate-500">{r.reference} · SHA-256 {r.original_sha256.slice(0, 16)}… · {new Date(r.created_at).toLocaleString()}</div></div>
          {r.is_sample && <Badge tone="cyan">SAMPLE</Badge>}
          <Badge tone={r.original_stored ? "green" : "slate"}>{r.original_stored ? "Original stored" : "Hash only"}</Badge>
          <Badge tone={tone(r)}>{r.score}/100</Badge>
          <select aria-label={`Case for ${r.reference}`} disabled={busy === r.id} value={r.case_id || ""} onChange={e => link(r, e.target.value)} className="max-w-[10rem] rounded border border-cyber-line bg-cyber-panel p-2"><option value="">No case</option>{cases.map(c => <option key={c.id} value={c.id}>{c.title.slice(0, 40)}</option>)}</select>
          <Button variant="secondary" disabled={busy === r.id} onClick={() => open(r.id)}>Open</Button>
          <Button variant="danger" disabled={busy === r.id} onClick={() => remove(r)}>Delete</Button>
        </div>)}
    </Card>
    <div className="mt-3 flex items-center justify-between text-xs text-slate-500"><span>{total} saved</span><span className="space-x-2"><Button variant="secondary" disabled={offset === 0 || loading} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Previous</Button><Button variant="secondary" disabled={offset + PAGE >= total || loading} onClick={() => setOffset(offset + PAGE)}>Next</Button></span></div>
  </div>;
}
