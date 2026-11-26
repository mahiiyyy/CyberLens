import React, { useEffect, useState, useCallback } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, setCurrentResult, pendingIntake } from "../lib/api";
import { Badge, Button, Card, PageTitle, Section } from "../components/ui";

const PRIORITIES = ["Unclassified", "Low", "Medium", "High", "Critical"];

export default function CaseDetail() {
  const { id } = useParams(); const nav = useNavigate();
  const [data, setData] = useState(null), [error, setError] = useState(""), [notice, setNotice] = useState("");
  const [form, setForm] = useState({ title: "", priority: "Unclassified", notes: "" }), [busy, setBusy] = useState(false);
  const load = useCallback(async () => {
    setError("");
    try { const r = await api("/cases/" + id); setData(r); setForm({ title: r.case.title, priority: r.case.priority, notes: r.case.notes || "" }); }
    catch (e) { setError(e.status === 404 ? "Case not found." : e.message); }
  }, [id]);
  useEffect(() => { load(); }, [load]);
  const patch = async body => { setBusy(true); setError(""); setNotice(""); try { await api("/cases/" + id, { method: "PATCH", body: JSON.stringify(body) }); setNotice("Saved."); await load(); } catch (e) { setError(e.message); } finally { setBusy(false); } };
  const open = async inv => { try { const r = await api("/investigations/" + inv.id); pendingIntake.bytes = null; setCurrentResult(r); nav("/result"); } catch (e) { setError(e.message); } };
  const unlink = async inv => { try { await api("/investigations/" + inv.id, { method: "PATCH", body: JSON.stringify({ caseId: null }) }); await load(); } catch (e) { setError(e.message); } };
  if (!data) return <><PageTitle eyebrow="Case Management" title="Case"/>{error ? <p role="alert" className="text-sm text-red-300">{error} <Link className="text-cyan-300" to="/cases">Back to cases</Link></p> : <p className="text-sm text-slate-400">Loading…</p>}</>;
  const c = data.case;
  return <div className="fade-up"><PageTitle eyebrow={c.case_no} title={c.title} sub={`Created ${new Date(c.created_at).toLocaleString()} · updated ${new Date(c.updated_at).toLocaleString()}`}/>
    {error && <p role="alert" className="mb-4 text-sm text-red-300">{error}</p>}{notice && <p role="status" className="mb-4 text-sm text-emerald-300">{notice}</p>}
    <div className="grid gap-4 lg:grid-cols-2">
      <Section title="Case details"><form className="space-y-3 text-xs" onSubmit={e => { e.preventDefault(); patch(form); }}>
        <label className="block text-slate-400">Title<input value={form.title} maxLength={160} required onChange={e => setForm({ ...form, title: e.target.value })} className="mt-1 w-full rounded-lg border border-cyber-line bg-black/20 p-3 text-sm text-slate-100"/></label>
        <label className="block text-slate-400">Priority<select value={form.priority} onChange={e => setForm({ ...form, priority: e.target.value })} className="mt-1 w-full rounded-lg border border-cyber-line bg-cyber-panel p-3 text-sm text-slate-100">{PRIORITIES.map(p => <option key={p}>{p}</option>)}</select></label>
        <label className="block text-slate-400">Notes (avoid secrets and personal data)<textarea value={form.notes} maxLength={10000} onChange={e => setForm({ ...form, notes: e.target.value })} className="mt-1 h-32 w-full rounded-lg border border-cyber-line bg-black/20 p-3 text-sm text-slate-100"/></label>
        <div className="flex items-center gap-3"><Button type="submit" disabled={busy || !form.title.trim()}>Save changes</Button><Badge tone={c.status === "Closed" ? "green" : "amber"}>{c.status}</Badge><Button variant="secondary" disabled={busy} onClick={() => patch({ status: c.status === "Closed" ? "Open" : "Closed" })}>{c.status === "Closed" ? "Reopen" : "Close case"}</Button></div></form></Section>
      <Section title={`Linked investigations (${data.investigations.length})`}>{data.investigations.length ? data.investigations.map(i => <div key={i.id} className="flex flex-wrap items-center gap-2 border-b border-cyber-line py-3 text-xs last:border-0"><div className="min-w-0 flex-1"><div className="break-all text-slate-200">{i.title}</div><div className="text-[10px] text-slate-500">{i.reference} · {new Date(i.created_at).toLocaleDateString()}</div></div>{i.is_sample && <Badge tone="cyan">SAMPLE</Badge>}<Badge tone={i.score >= 75 ? "red" : i.score >= 50 ? "amber" : "cyan"}>{i.score}/100</Badge><Button variant="secondary" onClick={() => open(i)}>Open</Button><Button variant="ghost" onClick={() => unlink(i)}>Unlink</Button></div>) : <p className="text-xs text-slate-500">No investigations linked. Link one from Saved Investigations.</p>}</Section>
    </div><div className="mt-4"><Button variant="secondary" onClick={() => nav("/cases")}>← All cases</Button></div></div>;
}
