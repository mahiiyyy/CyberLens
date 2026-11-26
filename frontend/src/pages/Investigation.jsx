import React, { useState, useRef } from "react";
import { ArrowRight, FileText, UploadCloud, Sparkles } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { Badge, Button, Card, PageTitle, Section } from "../components/ui";
import { api, pendingIntake, setCurrentResult } from "../lib/api";
import { demo } from "../data/demo";

const MAX_BYTES = 5 * 1024 * 1024;

export default function Investigation() {
  const [file, setFile] = useState(null); const [bytes, setBytes] = useState(null); const [text, setText] = useState("");
  const [busy, setBusy] = useState(false); const [error, setError] = useState(""); const nav = useNavigate();
  const [reading, setReading] = useState(false);
  const [sample, setSample] = useState(false);
  const [save, setSave] = useState(false); const [storeOriginal, setStoreOriginal] = useState(false);
  const inputRef = useRef(null);
  const readVersion = useRef(0);
  const readFile = async (files) => {
    if (!files?.length) return;
    const version = ++readVersion.current;
    setError(""); setFile(null); setBytes(null); setText(""); setSample(false); setReading(true);
    try {
      if (files.length !== 1) throw new Error("Choose one email file at a time.");
      const f = files[0];
      if (!/\.eml$/i.test(f.name)) throw new Error("Choose an .eml email file. Outlook .msg is not supported; export the message as .eml.");
      if (!f.size || f.size > MAX_BYTES) throw new Error("Choose a non-empty .eml file up to 5 MB.");
      const buf = new Uint8Array(await f.arrayBuffer()); // original bytes, used for the SHA-256 fingerprint
      if (version === readVersion.current) { setFile(f); setBytes(buf); setText(new TextDecoder("utf-8", { fatal: false }).decode(buf.subarray(0, 20000))); }
    } catch (e) { if (version === readVersion.current) setError(e.message || "Unable to read email file."); }
    finally { if (version === readVersion.current) setReading(false); }
  };
  const loadDemo = () => { ++readVersion.current; setReading(false); setError(""); setBytes(null); setFile(null); setSample(true); setText(`From: ${demo.from}\nReply-To: ${demo.replyTo}\nReturn-Path: ${demo.returnPath}\nSubject: ${demo.subject}\n\n${demo.subject}. Verify your account immediately. Click here: ${demo.url}`); };
  const start = async () => {
    if (reading || busy) return;
    const payload = bytes || new TextEncoder().encode(text);
    if (!text.trim() || !payload.length) { setError("Upload an email file or paste email content first."); return; }
    if (payload.length > MAX_BYTES) { setError("Email content exceeds 5 MB."); return; }
    setError(""); setBusy(true);
    try {
      const kind = bytes ? "file" : "paste";
      const params = new URLSearchParams({ kind });
      if (file) params.set("filename", file.name);
      if (sample) params.set("sample", "1");
      if (save) { params.set("save", "1"); params.set("consent", "1"); if (storeOriginal) params.set("storeOriginal", "1"); }
      const result = await api("/investigations/analyze?" + params, { method: "POST", headers: { "Content-Type": "application/octet-stream" }, body: payload });
      Object.assign(pendingIntake, { bytes: payload, kind, filename: file?.name || "", sample });
      setCurrentResult(result); nav("/analysis");
    } catch (e) { setError(e.message || "Analysis failed"); } finally { setBusy(false); }
  };
  return <div className="fade-up"><PageTitle eyebrow="Evidence Intake" title="New Investigation" sub="Upload or paste an email. CyberLens parses headers and MIME structure on the server, fingerprints the original bytes with SHA-256 and runs heuristic checks."/>
    <div className="grid gap-4 lg:grid-cols-3"><Card className="p-5 lg:col-span-2"><div onDrop={e=>{e.preventDefault();if(!busy) readFile(e.dataTransfer.files)}} onDragOver={e=>e.preventDefault()} className="rounded-xl border border-dashed border-cyan-400/30 bg-cyan-400/[.02] p-12 text-center"><UploadCloud className="mx-auto text-cyber-cyan" size={38}/><div className="mt-3 font-bold text-white">{file ? file.name : "Drop EML evidence here"}</div><p className="mt-2 text-xs text-slate-600">5 MB maximum · .eml files only</p><div className="mt-5"><input ref={inputRef} type="file" accept=".eml,message/rfc822" className="hidden" onChange={e=>{readFile(e.target.files);e.target.value="";}}/><Button variant="secondary" disabled={busy||reading} onClick={()=>inputRef.current?.click()}>{reading?"Reading email…":"Choose evidence"}</Button></div></div>
      <div className="mt-5"><label className="text-xs text-slate-500">{file?"Preview of uploaded file (first 20 KB; the full original is analyzed)":"Paste headers / email content"}</label><textarea value={text} disabled={busy||reading||!!file} onChange={e=>{setText(e.target.value);setSample(false);setError("");}} className="mt-2 h-40 w-full rounded-lg border border-cyber-line bg-black/20 p-3 font-mono text-xs outline-none focus:border-cyan-400" placeholder={"From: security@example.com\nReply-To: security@example.com\nSubject: Your monthly statement\n\nHello, your statement is ready."}/>
      {file&&<button className="mt-1 text-xs text-cyan-300" onClick={()=>{setFile(null);setBytes(null);setText("");}}>Remove uploaded file</button>}
      <fieldset className="mt-4 rounded-lg border border-cyber-line p-3 text-xs text-slate-300"><legend className="px-1 text-[10px] font-bold tracking-widest text-slate-500">STORAGE (OPTIONAL)</legend>
        <label className="flex items-start gap-2"><input type="checkbox" checked={save} onChange={e=>{setSave(e.target.checked);if(!e.target.checked)setStoreOriginal(false);}} className="mt-0.5"/><span>Save this investigation to my account. Stores parsed headers, URLs, attachment hashes, findings and a text excerpt. I consent to this storage and can delete it later.</span></label>
        <label className={`mt-2 flex items-start gap-2 ${save?"":"opacity-40"}`}><input type="checkbox" disabled={!save} checked={storeOriginal} onChange={e=>setStoreOriginal(e.target.checked)} className="mt-0.5"/><span>Also store the original email bytes so integrity can be re-verified later. Attachments inside it are stored but never opened or executed.</span></label>
        <p className="mt-2 text-slate-500">If unchecked, nothing is saved; results exist only in this browser session. The SHA-256 is computed either way.</p></fieldset>
      {error&&<div className="mt-3 rounded-lg border border-red-400/20 bg-red-400/5 p-3 text-xs text-red-300">{error}</div>}<div className="mt-3 flex justify-end"><Button disabled={busy||reading||!text.trim()} onClick={start}>{busy?<><Sparkles className="mr-2 inline animate-pulse" size={15}/>ANALYZING…</>:<>START AI INVESTIGATION <ArrowRight className="ml-2 inline" size={15}/></>}</Button></div></div></Card>
      <Section title="Analysis pipeline">{["MIME and header parsing","Received-header transport path","Reported SPF / DKIM / DMARC results","URL, link and attachment inventory","Original-file SHA-256 fingerprint","Heuristic text analysis","Risk assessment"].map(x=><div key={x} className="flex items-center gap-2 border-b border-cyber-line py-3 text-xs text-slate-300 last:border-0"><span className="text-slate-400">•</span>{x}</div>)}<div className="mt-4 rounded-lg border border-amber-400/20 bg-amber-400/5 p-3 text-[11px] text-amber-200"><FileText size={14} className="mr-1 inline"/> Uploaded files are untrusted evidence. URLs are never visited and attachments are never opened or executed.</div><div className="mt-4"><Badge tone="cyan">SAMPLE DATA</Badge><p className="mt-2 text-[11px] text-slate-500">Built-in fictional email. Results derived from it are marked as sample data.</p><button disabled={busy||reading} onClick={loadDemo} className="mt-2 block text-xs text-cyan-300 hover:underline">Load sample Acme Bank phishing email →</button></div></Section></div></div>;
}
