import React, { useEffect, useState, useCallback, useRef } from "react";
import { api, currentResult, downloadBlob, sha256OfBytes } from "../lib/api";
import { Badge, Button, Card, PageTitle, Section } from "../components/ui";

const MAX = 5 * 1024 * 1024;

export default function EvidencePage() {
  const result = currentResult();
  const [rows, setRows] = useState([]), [events, setEvents] = useState([]), [loading, setLoading] = useState(true);
  const [error, setError] = useState(""), [notice, setNotice] = useState(""), [busy, setBusy] = useState("");
  const [local, setLocal] = useState(null);
  const fileRef = useRef(null), cmpRef = useRef(null), cmpTarget = useRef(null);

  const load = useCallback(async () => {
    setLoading(true); setError("");
    try { const [e, a] = await Promise.all([api("/evidence"), api("/audit?limit=50")]); setRows(e.evidence); setEvents(a.events); }
    catch (err) { setError(err.message); } finally { setLoading(false); }
  }, []);
  useEffect(() => { load(); }, [load]);

  const readBytes = async f => { if (!f) return null; if (f.size > MAX) throw new Error("File exceeds 5 MB."); return new Uint8Array(await f.arrayBuffer()); };
  const run = async (key, fn) => { setBusy(key); setError(""); setNotice(""); try { await fn(); } catch (e) { setError(e.message); } finally { setBusy(""); } };

  // Local, offline comparison against the result currently on screen.
  const checkLocal = f => run("local", async () => {
    const bytes = await readBytes(f);
    const hash = await sha256OfBytes(bytes);
    setLocal({ name: f.name, hash, match: hash === result?.integrity?.sha256 });
  });
  const verify = r => run(r.investigation_id, async () => {
    const v = await api(`/evidence/${r.investigation_id}/verify`, { method: "POST" });
    setNotice(v.match ? `${r.reference}: stored original matches its intake hash.` : `${r.reference}: INTEGRITY MISMATCH. The stored bytes no longer match the recorded hash.`);
    await load();
  });
  const compare = (r, f) => run(r.investigation_id, async () => {
    const bytes = await readBytes(f);
    const v = await api(`/evidence/${r.investigation_id}/compare`, { method: "POST", headers: { "Content-Type": "application/octet-stream" }, body: bytes });
    setNotice(v.match ? `${r.reference}: the file you selected matches the recorded hash.` : `${r.reference}: the file you selected does NOT match the recorded hash.`);
    await load();
  });
  const download = r => run(r.investigation_id, () => downloadBlob(`/evidence/${r.investigation_id}/download`, `${r.reference}.eml.bin`).then(load));
  const dropOriginal = r => { if (window.confirm("Delete the stored original email bytes? The hash and analysis are kept.")) run(r.investigation_id, async () => { await api(`/evidence/${r.investigation_id}/original`, { method: "DELETE" }); await load(); }); };

  return <div className="fade-up"><PageTitle eyebrow="Forensic Integrity" title="Evidence & Chain of Custody" sub="SHA-256 fingerprints of original email bytes, integrity verification and an account audit log."/>
    {error && <p role="alert" className="mb-4 text-sm text-red-300">{error}</p>}
    {notice && <p role="status" className="mb-4 text-sm text-cyan-200">{notice}</p>}
    <Section title="Current session result">{result ? <>
      <p className="text-xs text-slate-400">{result.integrity?.source === "original-file-bytes" ? "SHA-256 of the original uploaded file bytes." : "SHA-256 of the pasted text as UTF-8 bytes (no original file existed)."} Computed by the server at intake.</p>
      <div className="mt-3 break-all rounded-lg bg-black/20 p-3 font-mono text-xs text-cyan-300">{result.integrity?.sha256}</div>
      <p className="mt-2 text-xs text-slate-500">{result.integrity?.size} bytes · {result.saved ? "saved" : "not saved"}</p>
      <div className="mt-4 text-xs text-slate-300">Verify a file against this fingerprint (hashed in your browser; nothing is uploaded):
        <input ref={fileRef} type="file" className="hidden" onChange={e => { checkLocal(e.target.files[0]); e.target.value = ""; }}/>
        <Button variant="secondary" className="ml-3" disabled={busy === "local"} onClick={() => fileRef.current?.click()}>Choose file</Button></div>
      {local && <p role="status" className={`mt-3 text-xs ${local.match ? "text-emerald-300" : "text-red-300"}`}>{local.name}: {local.match ? "SHA-256 matches the recorded fingerprint." : "SHA-256 differs from the recorded fingerprint."}</p>}
    </> : <p className="text-sm text-slate-400">No completed investigation in this session. <a className="text-cyan-300" href="/investigate">Start one</a>.</p>}</Section>

    <Section title="Saved evidence records" className="mt-4" action={<Button variant="secondary" disabled={loading} onClick={load}>Refresh</Button>}>
      <input ref={cmpRef} type="file" className="hidden" onChange={e => { const f = e.target.files[0]; e.target.value = ""; if (f && cmpTarget.current) compare(cmpTarget.current, f); }}/>
      {loading ? <p className="text-xs text-slate-500">Loading…</p> : !rows.length ? <p className="text-xs text-slate-500">No saved investigations. Evidence records appear here once you save one.</p> : rows.map(r => <div key={r.investigation_id} className="border-b border-cyber-line py-3 text-xs last:border-0">
        <div className="flex flex-wrap items-center gap-2"><span className="text-cyan-300">{r.reference}</span><span className="flex-1 break-all text-slate-300">{r.title}</span>{r.is_sample && <Badge tone="cyan">SAMPLE</Badge>}<Badge tone={r.original_stored ? "green" : "slate"}>{r.original_stored ? "Original stored" : "Hash only"}</Badge>{r.original_stored && r.last_verified_at && <Badge tone={r.last_verified_ok ? "green" : "red"}>{r.last_verified_ok ? "Verified" : "MISMATCH"}</Badge>}</div>
        <div className="mt-1 break-all font-mono text-[10px] text-slate-500">{r.sha256} · {r.size_bytes} bytes · {r.input_kind === "file" ? "file bytes" : "pasted text"}{r.last_verified_at ? ` · last verified ${new Date(r.last_verified_at).toLocaleString()}` : ""}</div>
        <div className="mt-2 flex flex-wrap gap-2">
          {r.original_stored && <><Button variant="secondary" disabled={busy === r.investigation_id} onClick={() => verify(r)}>Re-verify stored</Button><Button variant="secondary" disabled={busy === r.investigation_id} onClick={() => download(r)}>Download original</Button><Button variant="danger" disabled={busy === r.investigation_id} onClick={() => dropOriginal(r)}>Delete stored original</Button></>}
          <Button variant="secondary" disabled={busy === r.investigation_id} onClick={() => { cmpTarget.current = r; cmpRef.current?.click(); }}>Compare a file</Button></div></div>)}
      <p className="mt-4 text-xs text-slate-500">A matching fingerprint shows the bytes are unchanged since intake; it does not establish authenticity or provenance. Downloads are served as an opaque attachment and are never opened by CyberLens. Treat them as untrusted.</p></Section>

    <Section title="Activity log (your account)" className="mt-4"><div className="max-h-96 overflow-auto">{!events.length ? <p className="text-xs text-slate-500">No recorded events.</p> : events.map(ev => <div key={ev.id} className="flex flex-wrap gap-3 border-b border-cyber-line py-2 text-[11px] last:border-0"><span className="w-44 shrink-0 text-slate-500">{new Date(ev.created_at).toLocaleString()}</span><span className={/MISMATCH|BLOCKED|delete/.test(ev.action) ? "text-amber-300" : "text-slate-200"}>{ev.action}</span><span className="break-all text-slate-600">{ev.entity} {ev.entity_id || ""}</span></div>)}</div><p className="mt-3 text-xs text-slate-500">Append-only from the application: there is no API to edit or remove audit entries. Entries record actions and identifiers, never email content.</p></Section>
  </div>;
}
