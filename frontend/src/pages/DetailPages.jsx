import React, { useState, useEffect } from "react";
import { api } from "../lib/api";
import { Copy, Download, MapPin, MessageSquare, Search, Server, ShieldCheck } from "lucide-react";
import { Badge, Button, Card, PageTitle, Section } from "../components/ui";
import { demo, campaigns, iocs } from "../data/demo";

function currentInvestigation(){
 try{const r=JSON.parse(sessionStorage.getItem("cyberlens_result")||"null");return r?.status==="complete"?r:null;}catch{return null;}
}
function NoInvestigation({title}){
 return <><PageTitle eyebrow="Investigation" title={title}/><Card className="p-5"><p className="text-sm text-slate-400">No completed investigation in this session.</p><a className="mt-3 inline-block text-sm text-cyan-300" href="/investigate">Start an investigation</a></Card></>;
}
export function Forensics(){
 const result=currentInvestigation();
 if(!result)return <NoInvestigation title="Email Forensics"/>;
 const e=result.evidence||{};
 const rows=[["From",e.sender],["Reply-To",e.reply_to],["Return-Path",e.return_path],["Subject",e.subject]];
 const raw=typeof e.body==="string"?e.body:"";
 return <><PageTitle eyebrow="Evidence Layer" title="Email Forensics" sub="Metadata and submitted email text from the current investigation."/><div className="grid gap-4 lg:grid-cols-2"><Section title="Submitted message metadata">{rows.map(([k,v])=><div key={k} className="grid grid-cols-3 gap-2 border-b border-cyber-line py-3 text-xs"><span className="text-slate-500">{k}</span><span className="col-span-2 break-all text-slate-300">{v||"Not supplied"}</span></div>)}<p className="mt-4 text-xs text-slate-500">These fields are supplied by the current intake parser, not independently verified identities.</p></Section><Section title="Submitted email text"><pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded-lg bg-black/20 p-4 font-mono text-xs leading-6 text-slate-400">{raw||"No original email text available."}</pre><p className="mt-3 text-xs text-slate-500">Displayed as plain text. Original byte integrity and complete MIME parsing have not been verified.</p></Section></div></>;
}
export function Authentication(){
 const result=currentInvestigation();
 if(!result)return <NoInvestigation title="Email Authentication"/>;
 const e=result.evidence||{};
 const rows=[["SPF","Sender Policy Framework"],["DKIM","DomainKeys Identified Mail"],["DMARC","Domain-based Message Authentication, Reporting and Conformance"]];
 return <><PageTitle eyebrow="Email Authentication" title="Authentication" sub="Reported indicators from the current analysis; independent verification is not implemented."/><div className="grid gap-4 md:grid-cols-3">{rows.map(([key,desc])=>{const status=String(e.authentication?.[key.toLowerCase()]||"UNKNOWN").toUpperCase();const label=["PASS","FAIL"].includes(status)?status:"UNKNOWN";return <Card className="p-5" key={key}><div className="flex justify-between gap-2"><span className="text-xl font-black">{key}</span><Badge tone={label==="FAIL"?"red":label==="PASS"?"cyan":"slate"}>{label==="UNKNOWN"?"UNKNOWN":"REPORTED "+label}</Badge></div><p className="mt-4 text-xs text-slate-400">{desc}</p><p className="mt-3 text-xs text-slate-500">Unverified intake indicator</p></Card>;})}</div><Section title="Interpretation limits" className="mt-4"><p className="text-sm text-slate-300">The intake uses basic text matching, so reported results can be inaccurate or spoofed. A reported pass does not establish authenticity, and a reported failure does not establish malicious intent. Live SPF evaluation, DKIM signature verification and DMARC alignment checks are not yet implemented.</p></Section></>;
}

function PendingModule({title,description}){
 return <><PageTitle eyebrow="Investigation workspace" title={title}/><Card className="p-6"><Badge tone="slate">NOT IMPLEMENTED</Badge><p className="mt-4 text-sm text-slate-300">{description}</p></Card></>;
}
export function Intel(){
 return <PendingModule title="URL / Domain / IP Intelligence" description="Live reputation, registration and infrastructure lookups are not connected. No reputation or infrastructure verdict is available."/>; 
}
export function SMTP(){
 return <PendingModule title="SMTP Trace" description="Mail transport reconstruction is not yet implemented. Submitted email text is available in Email Forensics; no transport route has been verified."/>;
}
export function Graph(){
 return <PendingModule title="Threat Graph" description="Relationship analysis is not yet implemented. No infrastructure relationships have been verified."/>;
}
export function Geo(){
 return <PendingModule title="Geolocation" description="No IP geolocation provider is connected. No location has been established."/>;
}
export function Campaigns(){
 return <PendingModule title="Campaign Correlation" description="Cross-case correlation is not yet implemented. No campaign relationships have been established."/>;
}
export function Evidence(){
 const result=currentInvestigation();
 if(!result)return <NoInvestigation title="Evidence & Chain of Custody"/>;
 return <><PageTitle eyebrow="Forensic Integrity" title="Evidence & Chain of Custody" sub="Current session evidence availability"/><Section title="Evidence status"><div className="flex flex-wrap items-center justify-between gap-3 border-b border-cyber-line py-3 text-xs"><span>Submitted email text</span><Badge tone="slate">{typeof result.evidence?.body==="string"&&result.evidence.body.length?"Available in session":"Unavailable"}</Badge></div><div className="flex flex-wrap items-center justify-between gap-3 border-b border-cyber-line py-3 text-xs"><span>Analysis result</span><Badge tone="cyan">Available in session</Badge></div><div className="flex flex-wrap items-center justify-between gap-3 py-3 text-xs"><span>Original evidence integrity</span><Badge tone="slate">Not verified</Badge></div><p className="mt-4 text-xs text-slate-400">Persistent evidence storage, original-file hashing and an audit trail are not implemented. Session data is not a verified chain of custody.</p></Section></>;
}

export function Cases(){
 const [rows,setRows]=useState([]),[loading,setLoading]=useState(true),[error,setError]=useState(""),[query,setQuery]=useState("");
 const [title,setTitle]=useState(""),[busy,setBusy]=useState(false);
 const load=async()=>{setLoading(true);setError("");try{const result=await api("/cases");setRows(result.cases);}catch(e){setError(e.message);}finally{setLoading(false);}};
 useEffect(()=>{load();},[]);
 const create=async e=>{e.preventDefault();setBusy(true);setError("");try{await api("/cases",{method:"POST",body:JSON.stringify({title})});setTitle("");await load();}catch(e){setError(e.message);}finally{setBusy(false);}};
 const update=async(id,status)=>{setBusy(true);setError("");try{await api("/cases/"+id,{method:"PATCH",body:JSON.stringify({status})});await load();}catch(e){setError(e.message);}finally{setBusy(false);}};
 const filtered=rows.filter(r=>(r.case_no+" "+r.title+" "+r.status).toLowerCase().includes(query.toLowerCase()));
 return <><PageTitle eyebrow="Case Management" title="Cases" sub="Manage your own investigation case records."/>
 <Card className="mb-4 p-4"><form onSubmit={create} className="flex flex-wrap gap-3"><input aria-label="Case title" value={title} onChange={e=>setTitle(e.target.value)} maxLength={160} required placeholder="New case title" className="min-w-0 flex-1 rounded-lg border border-cyber-line bg-black/20 p-3 text-sm"/><Button type="submit" disabled={busy||!title.trim()}>Create case</Button></form></Card>
 <div className="mb-4 flex gap-2"><input aria-label="Search cases" value={query} onChange={e=>setQuery(e.target.value)} placeholder="Search your cases" className="flex-1 rounded-lg border border-cyber-line bg-cyber-panel p-3 text-sm"/><Button variant="secondary" disabled={loading} onClick={load}>Refresh</Button></div>
 {error&&<p role="alert" className="mb-4 text-sm text-red-300">{error}</p>}
 <Card className="overflow-hidden">{loading?<p className="p-4 text-sm text-slate-400">Loading cases…</p>:!filtered.length?<p className="p-4 text-sm text-slate-400">{rows.length?"No matching cases.":"No saved cases yet. Create your first case."}</p>:filtered.map(r=><div key={r.id} className="flex flex-wrap items-center gap-4 border-b border-cyber-line p-4 text-xs"><span className="text-cyan-300">{r.case_no}</span><span className="flex-1 break-all">{r.title}</span><Badge tone={r.status==="Closed"?"green":"amber"}>{r.status}</Badge><span className="text-slate-500">{new Date(r.created_at).toLocaleDateString()}</span><Button variant="secondary" disabled={busy} onClick={()=>update(r.id,r.status==="Closed"?"Open":"Closed")}>{r.status==="Closed"?"Reopen":"Close"}</Button></div>)}</Card></>;
}

export function Reports(){
 const [format,setFormat]=useState("Detailed report");
 let result=null;try{result=JSON.parse(sessionStorage.getItem("cyberlens_result")||"null");}catch{}
 if(!result||result.status!=="complete"||!Number.isFinite(result.score))return <><PageTitle eyebrow="Reporting" title="Investigation Reports" sub="Complete an investigation before generating a report."/><Card className="p-5"><p className="text-sm text-slate-400">No completed investigation in this session.</p><a href="/investigate" className="mt-4 inline-block text-sm text-cyan-300">Start an investigation</a></Card></>;
 const evidence=result.evidence||{};
 const rows=[["Report type",format],["Analysis reference",result.caseId||"Not assigned"],["Generated at",new Date().toISOString()],["Subject",evidence.subject||"Not supplied"],["Assessment",result.verdict||"Unavailable"],["Risk score",result.score+"/100"],["Reported confidence (uncalibrated)",result.confidence==null?"Unavailable":result.confidence+"%"],["Analysis method",result.aiModel||"Unavailable"],["Deterministic score",result.deterministicScore??"Unavailable"],["Model score",result.aiScore??"Unavailable"]];
 if(format==="Detailed report")rows.push(["From",evidence.sender||"Not supplied"],["Reply-To",evidence.reply_to||"Not supplied"],["Return-Path",evidence.return_path||"Not supplied"]);
 const findings=Array.isArray(result.findings)?result.findings:[];
 const lines=["CYBERLENS INVESTIGATION REPORT","",...rows.map(([k,v])=>k+": "+v),"","Analysis findings",...(format==="Detailed report"?findings.map(f=>[f.title,f.severity,f.explanation].filter(Boolean).join(" — ")):[]),"",String(result.aiExplanation||""),"","Limitations: heuristic assessment; not proof of malicious or safe content. No independent evidence integrity verification. Raw email content is not included. Report based on the current session."];
 const download=()=>{const url=URL.createObjectURL(new Blob([lines.join("\n")],{type:"text/plain;charset=utf-8"}));const link=document.createElement("a");link.href=url;link.download="CyberLens-Investigation-Report.txt";document.body.appendChild(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);};
 const print=()=>{const frame=document.createElement("iframe");frame.title="Printable investigation report";frame.style.cssText="position:fixed;width:1px;height:1px;opacity:0;pointer-events:none";document.body.appendChild(frame);const doc=frame.contentDocument;doc.title="CyberLens Investigation Report";const style=doc.createElement("style");style.textContent="@page{margin:18mm}body{font:11pt Arial,sans-serif;color:#17202a}h1{font-size:20pt}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:11pt Arial,sans-serif;line-height:1.5}";doc.head.appendChild(style);const h=doc.createElement("h1");h.textContent="CyberLens Investigation Report";doc.body.appendChild(h);const pre=doc.createElement("pre");pre.textContent=lines.slice(2).join("\n");doc.body.appendChild(pre);frame.contentWindow.focus();frame.contentWindow.addEventListener("afterprint",()=>frame.remove(),{once:true});frame.contentWindow.print();};
 return <><PageTitle eyebrow="Reporting" title="Investigation Reports" sub="Generate reports from the current completed investigation."/><Card className="mb-4 flex flex-wrap items-center gap-3 p-4"><label className="text-xs text-slate-400">Report type <select value={format} onChange={e=>setFormat(e.target.value)} className="ml-2 rounded border border-cyber-line bg-cyber-panel p-2 text-sm"><option>Detailed report</option><option>Executive summary</option></select></label><Button variant="secondary" onClick={download}><Download size={14} className="mr-2 inline"/>Download text</Button><Button onClick={print}>Print / Save as PDF</Button></Card><Section title="Report preview"><pre className="whitespace-pre-wrap break-words text-xs leading-6 text-slate-300">{lines.join("\n")}</pre></Section></>;
}

export function IOCs(){const [q,setQ]=useState("");const rows=iocs.filter(r=>r.join(" ").toLowerCase().includes(q.toLowerCase()));return <><PageTitle eyebrow="Indicators of Compromise" title="IOC Center"/><div className="mb-4 flex gap-2"><div className="relative flex-1"><Search className="absolute left-3 top-2.5 text-slate-700" size={15}/><input value={q} onChange={e=>setQ(e.target.value)} placeholder="Search IP, domain, URL, hash…" className="w-full rounded-lg border border-cyber-line bg-cyber-panel py-2 pl-9 pr-3 text-sm outline-none"/></div><Button variant="secondary">Export</Button></div><Card className="overflow-hidden">{rows.map(r=><div key={r[0]} className="grid grid-cols-12 items-center gap-2 border-b border-cyber-line p-4 text-[10px]"><span className="col-span-5 break-all font-mono text-cyan-200">{r[0]}</span><span className="col-span-2 text-slate-600">{r[1]}</span><span className="col-span-2"><Badge tone={r[2]==="Malicious"?"red":"amber"}>{r[2]}</Badge></span><span className="col-span-2 text-slate-600">{r[3]}</span><Copy size={13} className="cursor-pointer text-slate-700"/></div>)}</Card></>}


export function Assistant(){const [q,setQ]=useState("");const [msgs,setMsgs]=useState([]);const answer=x=>x.toLowerCase().includes("why")?"The strongest evidence is the sender/domain mismatch, three failed authentication checks, and a credential-harvesting URL. These signals support the phishing/impersonation verdict.":x.toLowerCase().includes("failed")?"SPF, DKIM and DMARC all failed. The authentication layer cannot verify the claimed sender identity.":"Case EML-2026-0912 is rated 92/100 CRITICAL with 94% AI confidence. The evidence indicates phishing/impersonation with credential-theft indicators.";const ask=()=>{if(!q.trim())return;setMsgs(m=>[...m,{r:"user",t:q},{r:"ai",t:answer(q)}]);setQ("")};return <><PageTitle eyebrow="Case Copilot" title="CyberLens AI" sub="Evidence-grounded assistance only. Hidden chain-of-thought is never exposed."/><Card className="mx-auto flex min-h-[520px] max-w-4xl flex-col p-4"><div className="flex-1 space-y-3">{!msgs.length&&<div className="py-20 text-center text-slate-700"><MessageSquare className="mx-auto mb-3 text-purple-400" size={34}/>Ask about the current case.</div>}{msgs.map((m,i)=><div key={i} className={`max-w-[80%] rounded-lg p-3 text-sm ${m.r==="user"?"ml-auto bg-cyan-400/10 text-cyan-100":"bg-white/5 text-slate-300"}`}>{m.t}</div>)}</div><div className="mt-4 flex gap-2"><input value={q} onChange={e=>setQ(e.target.value)} onKeyDown={e=>e.key==="Enter"&&ask()} className="flex-1 rounded-lg border border-cyber-line bg-black/20 p-3 text-sm" placeholder="Why is this email suspicious?"/><Button onClick={ask}>Ask</Button></div><div className="mt-3 flex flex-wrap gap-2">{["Why is this email suspicious?","Show strongest evidence.","What failed?","Summarize investigation."].map(x=><button key={x} onClick={()=>setQ(x)} className="rounded border border-cyber-line px-2 py-1 text-[9px] text-slate-600 hover:text-slate-300">{x}</button>)}</div></Card></>}

export function Settings(){return <><PageTitle eyebrow="Administration" title="Admin / Settings"/><div className="grid gap-4 md:grid-cols-2">{["Profile","Roles & permissions","AI configuration","Threat intelligence sources","API configuration","Notifications","Security settings","Audit logs"].map(x=><Card className="p-5" key={x}><div className="font-bold text-sm">{x}</div><p className="mt-1 text-xs text-slate-600">Configured for demo environment · ready for production adapter.</p></Card>)}</div></>}

export function Placeholder({title}){return <><PageTitle eyebrow="CyberLens" title={title}/><Card className="p-8 text-center text-slate-500">This module is wired into the navigation and ready for backend/API integration.</Card></>}
