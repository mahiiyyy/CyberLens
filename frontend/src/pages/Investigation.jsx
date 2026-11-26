import React, { useState, useRef } from "react";
import { ArrowRight, FileText, UploadCloud, Sparkles } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { Badge, Button, Card, PageTitle, Section } from "../components/ui";
import { api } from "../lib/api";
import { demo } from "../data/demo";

export default function Investigation() {
  const [file, setFile] = useState(null); const [text, setText] = useState(""); const [busy, setBusy] = useState(false); const [error, setError] = useState(""); const nav = useNavigate();
  const [reading, setReading] = useState(false);
  const inputRef = useRef(null);
  const readVersion = useRef(0);
  const readFile = async (files) => {
    if (!files?.length) return;
    const version = ++readVersion.current;
    setError(""); setFile(null); setText(""); setReading(true);
    try {
      if (files.length !== 1) throw new Error("Choose one email file at a time.");
      const f = files[0];
      if (!/\.eml$/i.test(f.name)) throw new Error("Choose an .eml email file. Outlook .msg is not yet supported.");
      if (!f.size || f.size > 512 * 1024) throw new Error("Choose a non-empty .eml file up to 512 KB.");
      const raw = await f.text();
      if (!raw.trim() || raw.includes("\0")) throw new Error("This file does not contain readable email text.");
      if (version === readVersion.current) { setFile(f); setText(raw); }
    } catch (e) { if (version === readVersion.current) setError(e.message || "Unable to read email file."); }
    finally { if (version === readVersion.current) setReading(false); }
  };
  const loadDemo = () => { ++readVersion.current; setReading(false); setError(""); setText(`From: ${demo.from}\nReply-To: ${demo.replyTo}\nReturn-Path: ${demo.returnPath}\nSubject: ${demo.subject}\n\n${demo.subject}. Verify your account immediately. Click here: ${demo.url}`); setFile(null); };
  const start = async () => {
    if (reading || busy) return;
    if (!text.trim()) { setError("Upload an email file or paste email content first."); return; }
    if (new TextEncoder().encode(text).length > 512 * 1024) { setError("Email content exceeds 512 KB."); return; }
    setError(""); setBusy(true);
    try {
      const lines = text.split(/\r?\n/); const get = name => lines.find(x => x.toLowerCase().startsWith(name.toLowerCase()+":"))?.split(":").slice(1).join(":").trim() || "";
      const subject = get("Subject") || (file?.name || "Email investigation");
      const sender = get("From"); const reply_to = get("Reply-To"); const return_path = get("Return-Path");
      const urls = [...text.matchAll(/https?:\/\/[^\s<>"')]+/gi)].map(m=>m[0].replace(/[.,;]+$/, ""));
      const header_mismatches = []; if(sender && reply_to && sender.split("@")[1] !== reply_to.split("@")[1]) header_mismatches.push("From domain differs from Reply-To domain");
      const auth = { spf: /spf[^\n]*(pass|fail)/i.test(text) ? (/spf[^\n]*fail/i.test(text)?"FAIL":"PASS") : "UNKNOWN", dkim: /dkim[^\n]*(pass|fail)/i.test(text) ? (/dkim[^\n]*fail/i.test(text)?"FAIL":"PASS") : "UNKNOWN", dmarc: /dmarc[^\n]*(pass|fail)/i.test(text) ? (/dmarc[^\n]*fail/i.test(text)?"FAIL":"PASS") : "UNKNOWN" };
      const result = await api("/investigations/analyze", { method:"POST", body: JSON.stringify({ caseId: `EML-${crypto.randomUUID()}`, subject, body: text, sender, reply_to, return_path, urls, authentication: auth, header_mismatches }) });
      sessionStorage.setItem("cyberlens_result", JSON.stringify(result)); nav("/analysis");
    } catch(e) { setError(e.message || "Analysis failed"); } finally { setBusy(false); }
  };
  return <div className="fade-up"><PageTitle eyebrow="Evidence Intake" title="New Investigation" sub="Upload or paste email evidence. CyberLens runs heuristic checks using the submitted email text."/>
    <div className="grid gap-4 lg:grid-cols-3"><Card className="p-5 lg:col-span-2"><div onDrop={e=>{e.preventDefault();if(!busy) readFile(e.dataTransfer.files)}} onDragOver={e=>e.preventDefault()} className="rounded-xl border border-dashed border-cyan-400/30 bg-cyan-400/[.02] p-12 text-center"><UploadCloud className="mx-auto text-cyber-cyan" size={38}/><div className="mt-3 font-bold text-white">{file ? file.name : "Drop EML evidence here"}</div><p className="mt-2 text-xs text-slate-600">512 KB maximum · .eml text files only</p><div className="mt-5"><input ref={inputRef} type="file" accept=".eml,message/rfc822" className="hidden" onChange={e=>{readFile(e.target.files);e.target.value="";}}/><Button variant="secondary" disabled={busy||reading} onClick={()=>inputRef.current?.click()}>{reading?"Reading email…":"Choose evidence"}</Button></div></div>
      <div className="mt-5"><label className="text-xs text-slate-500">Paste headers / email content</label><textarea value={text} disabled={busy||reading} onChange={e=>{setText(e.target.value);setFile(null);setError("");}} className="mt-2 h-40 w-full rounded-lg border border-cyber-line bg-black/20 p-3 font-mono text-xs outline-none focus:border-cyan-400" placeholder={"From: security@example.com\nReply-To: security@example.com\nSubject: Your monthly statement\n\nHello, your statement is ready."}/>{error&&<div className="mt-3 rounded-lg border border-red-400/20 bg-red-400/5 p-3 text-xs text-red-300">{error}</div>}<div className="mt-3 flex justify-end"><Button disabled={busy||reading||!text.trim()} onClick={start}>{busy?<><Sparkles className="mr-2 inline animate-pulse" size={15}/>ANALYZING…</>:<>START AI INVESTIGATION <ArrowRight className="ml-2 inline" size={15}/></>}</Button></div></div></Card>
      <Section title="Analysis pipeline">{["Basic header intake","Reported authentication indicators","URL references","Heuristic text analysis","Risk assessment"].map(x=><div key={x} className="flex items-center gap-2 border-b border-cyber-line py-3 text-xs text-slate-300 last:border-0"><span className="text-slate-400">•</span>{x}</div>)}<div className="mt-4 rounded-lg border border-amber-400/20 bg-amber-400/5 p-3 text-[11px] text-amber-200"><FileText size={14} className="mr-1 inline"/> Uploaded files are untrusted evidence. Never execute attachments.</div><div className="mt-4"><Badge tone="cyan">DEMO DATA</Badge><button disabled={busy||reading} onClick={loadDemo} className="mt-3 block text-xs text-cyan-300 hover:underline">Load Acme Bank phishing email →</button></div></Section></div></div>;
}
