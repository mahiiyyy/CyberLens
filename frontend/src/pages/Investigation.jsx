import React, { useState } from "react";
import { ArrowRight, FileText, UploadCloud, Sparkles } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { Badge, Button, Card, PageTitle, Section } from "../components/ui";
import { api } from "../lib/api";
import { demo } from "../data/demo";

const MAX_FILE_BYTES = 1_500_000;

export default function Investigation() {
  const [file,setFile]=useState(null);
  const [text,setText]=useState("");
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState("");
  const nav=useNavigate();

  const loadDemo=()=>{
    setText(`From: ${demo.from}\nReply-To: ${demo.replyTo}\nReturn-Path: ${demo.returnPath}\nSubject: ${demo.subject}\n\n${demo.subject}. Verify your account immediately. Click here: ${demo.url}`);
    setFile(null);
  };

  const readFile=async f=>{
    setError("");
    if(!f)return;
    if(f.size>MAX_FILE_BYTES){setFile(null);setError("File is too large. Maximum supported size is 1.5 MB.");return;}
    const ext=f.name.toLowerCase().split(".").pop();
    if(!["eml","txt"].includes(ext)){setFile(null);setError("Only .eml and .txt files are supported currently. Outlook .msg parsing is not implemented yet.");return;}
    try{
      const contents=await f.text();
      if(!contents.trim())throw new Error("The selected file is empty or could not be read as text.");
      setFile(f);setText(contents);
    }catch(e){setFile(null);setError(e.message||"Unable to read this file.");}
  };

  const start=async()=>{
    setError("");
    if(!text.trim()){setError("Paste email content or choose an .eml/.txt file first.");return;}
    if(text.length>MAX_FILE_BYTES){setError("Email content is too large. Maximum supported size is 1.5 MB.");return;}
    setBusy(true);
    try{
      const lines=text.split(/\r?\n/);
      const get=name=>lines.find(x=>x.toLowerCase().startsWith(name.toLowerCase()+":"))?.split(":").slice(1).join(":").trim()||"";
      const subject=get("Subject")||file?.name||"Email investigation";
      const sender=get("From"),reply_to=get("Reply-To"),return_path=get("Return-Path");
      const urls=[...text.matchAll(/https?:\/\/[^\s<>"')]+/gi)].map(m=>m[0].replace(/[.,;]+$/,""));
      const domain=email=>(email.match(/<\s*[^<>\s]+@([^<>\s]+)\s*>|^\s*[^<>\s]+@([^<>\s]+)\s*$/)?.slice(1).find(Boolean)||"").toLowerCase();
      const header_mismatches=[];
      if(sender&&reply_to&&domain(sender)&&domain(reply_to)&&domain(sender)!==domain(reply_to))header_mismatches.push("From domain differs from Reply-To domain");
      const auth={spf:/spf[^\n]*(pass|fail)/i.test(text)?(/spf[^\n]*fail/i.test(text)?"FAIL":"PASS"):"UNKNOWN",dkim:/dkim[^\n]*(pass|fail)/i.test(text)?(/dkim[^\n]*fail/i.test(text)?"FAIL":"PASS"):"UNKNOWN",dmarc:/dmarc[^\n]*(pass|fail)/i.test(text)?(/dmarc[^\n]*fail/i.test(text)?"FAIL":"PASS"):"UNKNOWN"};
      const result=await api("/investigations/analyze",{method:"POST",body:JSON.stringify({subject,body:text,sender,reply_to,return_path,urls,authentication:auth,header_mismatches,filename:file?.name,evidence_type:file?.name.toLowerCase().endsWith(".eml")?"EML":"TEXT"})});
      sessionStorage.setItem("cyberlens_result",JSON.stringify(result));
      nav("/analysis");
    }catch(e){setError(e.message||"Analysis failed");}
    finally{setBusy(false);}
  };

  return <div className="fade-up"><PageTitle eyebrow="Evidence Intake" title="New Investigation" sub="Upload or paste email evidence. The analysis and evidence record are saved to your account."/>
    <div className="grid gap-4 lg:grid-cols-3"><Card className="p-5 lg:col-span-2">
      <div onDrop={e=>{e.preventDefault();void readFile(e.dataTransfer.files?.[0]);}} onDragOver={e=>e.preventDefault()} className="rounded-xl border border-dashed border-cyan-400/30 bg-cyan-400/[.02] p-12 text-center">
        <UploadCloud className="mx-auto text-cyber-cyan" size={38}/><div className="mt-3 font-bold text-white">{file?file.name:"Drop EML / TXT evidence here"}</div>
        <p className="mt-2 text-xs text-slate-600">Maximum 1.5 MB · .eml and .txt supported · .msg not yet supported</p>
        <label className="mt-5 inline-block"><input type="file" accept=".eml,.txt,text/plain,message/rfc822" className="hidden" onChange={e=>void readFile(e.target.files?.[0])}/><Button variant="secondary">Choose evidence</Button></label>
      </div>
      <div className="mt-5"><label className="text-xs text-slate-500">Paste headers / email content</label><textarea value={text} onChange={e=>setText(e.target.value)} className="mt-2 h-40 w-full rounded-lg border border-cyber-line bg-black/20 p-3 font-mono text-xs outline-none focus:border-cyan-400" placeholder={"From: security@example.com\nReply-To: security@example.com\nSubject: Your monthly statement\n\nHello, your statement is ready."}/>
        {error&&<div className="mt-3 rounded-lg border border-red-400/20 bg-red-400/5 p-3 text-xs text-red-300">{error}</div>}
        <div className="mt-3 flex justify-end"><Button disabled={busy} onClick={start}>{busy?<><Sparkles className="mr-2 inline animate-pulse" size={15}/>SAVING & ANALYZING…</>:<>START INVESTIGATION <ArrowRight className="ml-2 inline" size={15}/></>}</Button></div>
      </div></Card>
      <Section title="Analysis pipeline">{["Email text validation","Header and sender checks","SPF / DKIM / DMARC header signals","URL extraction","Local AI service / fallback analysis","Persist case, evidence hash and audit event"].map(x=><div key={x} className="flex items-center gap-2 border-b border-cyber-line py-3 text-xs text-slate-300 last:border-0"><span className="text-emerald-400">•</span>{x}</div>)}<div className="mt-4 rounded-lg border border-amber-400/20 bg-amber-400/5 p-3 text-[11px] text-amber-200"><FileText size={14} className="mr-1 inline"/> Uploaded files are untrusted evidence. Never execute attachments.</div><div className="mt-4"><Badge tone="cyan">DEMO DATA</Badge><button onClick={loadDemo} className="mt-3 block text-xs text-cyan-300 hover:underline">Load Acme Bank phishing email →</button></div></Section>
    </div></div>;
}
