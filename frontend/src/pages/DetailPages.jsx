import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { api, pendingIntake } from "../lib/api";
import { Copy, Download, MapPin, MessageSquare, Search, Server, ShieldCheck } from "lucide-react";
import { Badge, Button, Card, PageTitle, Section } from "../components/ui";

function currentInvestigation(){
 try{const r=JSON.parse(sessionStorage.getItem("cyberlens_result")||"null");return r?.status==="complete"?r:null;}catch{return null;}
}
function NoInvestigation({title}){
 return <><PageTitle eyebrow="Investigation" title={title}/><Card className="p-5"><p className="text-sm text-slate-400">No completed investigation in this session.</p><a className="mt-3 inline-block text-sm text-cyan-300" href="/investigate">Start an investigation</a></Card></>;
}
export function Forensics(){
 const result=currentInvestigation();
 if(!result)return <NoInvestigation title="Email Forensics"/>;
 const e=result.evidence||{},a=result.analysis||{},m=a.metadata||{};
 const list=l=>(l&&l.length?l.map(x=>x.address).join(", "):"");
 const rows=[["From",list(m.from)],["Reply-To",list(m.replyTo)],["Return-Path",m.returnPath],["To",list(m.to)],["Date",m.date],["Message-ID",m.messageId],["Subject",m.subject]];
 const raw=typeof e.body==="string"?e.body:"";
 const hops=[...(a.received||[])].reverse();
 return <><PageTitle eyebrow="Evidence Layer" title="Email Forensics" sub="Headers, transport path, links and attachments parsed from the submitted message."/>
 {a.warnings?.length>0&&<div role="status" className="mb-4 rounded-lg border border-amber-400/20 bg-amber-400/5 p-3 text-xs text-amber-200">{a.warnings.map(w=><div key={w}>{w}</div>)}</div>}
 <div className="grid gap-4 lg:grid-cols-2"><Section title="Message metadata">{rows.map(([k,v])=><div key={k} className="grid grid-cols-3 gap-2 border-b border-cyber-line py-3 text-xs"><span className="text-slate-500">{k}</span><span className="col-span-2 break-all text-slate-300">{v||"Not present in message"}</span></div>)}<p className="mt-4 text-xs text-slate-500">Values are exactly what the message headers claim. They are not independently verified identities.</p></Section>
 <Section title="Message text (plain text excerpt)"><pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded-lg bg-black/20 p-4 font-mono text-xs leading-6 text-slate-400">{raw||"No text body present."}</pre><p className="mt-3 text-xs text-slate-500">Displayed as inert text; HTML is never rendered and links are never opened. The SHA-256 of the original bytes is on the Evidence page.</p></Section></div>
 <Section title="Transport path (Received headers, oldest first)" className="mt-4">{hops.length?hops.map((h,i)=><div key={i} className="border-b border-cyber-line py-3 text-xs last:border-0"><div className="text-slate-300"><span className="text-slate-500">from </span>{h.from||"unknown"} <span className="text-slate-500">by </span>{h.by||"unknown"}{h.protocol?<span className="text-slate-500"> via {h.protocol}</span>:null}</div><div className="mt-1 text-[10px] text-slate-500">{h.timestamp||"no timestamp"}{h.ips.length?" · "+h.ips.map(x=>x.ip+(x.public?"":" (non-public)")).join(", "):""}</div></div>):<p className="text-xs text-slate-500">No Received headers are present, so a transport path cannot be reconstructed.</p>}<p className="mt-3 text-xs text-slate-500">Hops before your own mail server can be forged by the sender. IP addresses are claims in headers; no geolocation or ownership is established.</p></Section>
 <div className="mt-4 grid gap-4 lg:grid-cols-2"><Section title="Links in HTML body">{a.htmlLinks?.length?a.htmlLinks.map((l,i)=><div key={i} className="border-b border-cyber-line py-2 text-xs last:border-0"><div className="break-all font-mono text-slate-300">{l.href}</div><div className="text-[10px] text-slate-500">Displayed as: {l.text||"(no text)"}</div>{l.mismatch&&<Badge tone="red">Text names {l.displayHost}, link goes to {l.hrefHost}</Badge>}</div>):<p className="text-xs text-slate-500">No HTML links.</p>}</Section>
 <Section title="Attachments (hashed, never opened)">{a.attachments?.length?a.attachments.map((x,i)=><div key={i} className="border-b border-cyber-line py-2 text-xs last:border-0"><div className="break-all text-slate-200">{x.filename||"(unnamed)"} <span className="text-slate-500">· {x.size} bytes · declared {x.declaredType||"unknown"}{x.signature?` · content looks like ${x.signature}`:""}</span></div><div className="break-all font-mono text-[10px] text-cyan-300">SHA-256 {x.sha256}</div>{x.flags.map(f=><Badge key={f} tone="red">{f}</Badge>)}</div>):<p className="text-xs text-slate-500">No attachments.</p>}</Section></div></>;
}
export function Authentication(){
 const result=currentInvestigation();
 if(!result)return <NoInvestigation title="Email Authentication"/>;
 const e=result.evidence||{};
 const rows=[["SPF","Sender Policy Framework"],["DKIM","DomainKeys Identified Mail"],["DMARC","Domain-based Message Authentication, Reporting and Conformance"]];
 return <><PageTitle eyebrow="Email Authentication" title="Authentication" sub="Results reported in the message's Authentication-Results / Received-SPF headers. CyberLens does not re-verify them."/><div className="grid gap-4 md:grid-cols-3">{rows.map(([key,desc])=>{const status=String(e.authentication?.[key.toLowerCase()]||"UNKNOWN").toUpperCase();const label=["PASS","FAIL"].includes(status)?status:"UNKNOWN";return <Card className="p-5" key={key}><div className="flex justify-between gap-2"><span className="text-xl font-black">{key}</span><Badge tone={label==="FAIL"?"red":label==="PASS"?"cyan":"slate"}>{label==="UNKNOWN"?"UNKNOWN":"REPORTED "+label}</Badge></div><p className="mt-4 text-xs text-slate-400">{desc}</p><p className="mt-3 text-xs text-slate-500">Reported by the receiving mail server header</p></Card>;})}</div><Section title="Interpretation limits" className="mt-4"><p className="text-sm text-slate-300">These results are read from headers inside the message. Headers added by a sender can be forged; only those added by your own receiving server are trustworthy, and CyberLens cannot tell which are which. A reported pass does not establish authenticity, and a reported failure does not establish malicious intent. Live SPF evaluation, DKIM signature verification and DMARC alignment checks are not implemented.</p></Section></>;
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
export function Geo(){
 return <PendingModule title="Geolocation" description="No IP geolocation provider is connected. No location has been established."/>;
}
export function Campaigns(){
 return <PendingModule title="Campaign Correlation" description="Cross-case correlation is not yet implemented. No campaign relationships have been established."/>;
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
 <Card className="overflow-hidden">{loading?<p className="p-4 text-sm text-slate-400">Loading cases…</p>:!filtered.length?<p className="p-4 text-sm text-slate-400">{rows.length?"No matching cases.":"No saved cases yet. Create your first case."}</p>:filtered.map(r=><div key={r.id} className="flex flex-wrap items-center gap-4 border-b border-cyber-line p-4 text-xs"><Link to={"/cases/"+r.id} className="text-cyan-300 hover:underline">{r.case_no}</Link><span className="flex-1 break-all">{r.title}</span><Badge tone={r.status==="Closed"?"green":"amber"}>{r.status}</Badge><span className="text-slate-500">{new Date(r.created_at).toLocaleDateString()}</span><Button variant="secondary" disabled={busy} onClick={()=>update(r.id,r.status==="Closed"?"Open":"Closed")}>{r.status==="Closed"?"Reopen":"Close"}</Button></div>)}</Card></>;
}

export function Settings(){
 const [profile,setProfile]=useState(null),[error,setError]=useState(""),[loading,setLoading]=useState(true),[cleared,setCleared]=useState(false);
 const load=async()=>{setLoading(true);setError("");try{const r=await api("/auth/me");setProfile(r.user);}catch(e){setError(e.message);}finally{setLoading(false);}};
 useEffect(()=>{load();},[]);
 return <><PageTitle eyebrow="Account" title="Settings" sub="Manage your current account and browser session."/><div className="grid gap-4 md:grid-cols-2"><Section title="Account profile" action={<Button variant="secondary" disabled={loading} onClick={load}>Refresh</Button>}>{loading?<p className="text-xs text-slate-400">Loading profile…</p>:error?<p role="alert" className="text-xs text-red-300">{error}</p>:<div className="space-y-4 text-sm"><div><p className="text-xs text-slate-500">Email</p><p className="break-all">{profile?.email||"Unavailable"}</p></div><div><p className="text-xs text-slate-500">Account role</p><Badge tone="cyan">{profile?.role||"Unknown"}</Badge></div></div>}</Section><Section title="Session privacy"><p className="text-sm text-slate-400">Remove the current analysis and submitted email from this browser session. Saved cases, investigations and stored evidence in PostgreSQL are not deleted; remove those from Saved Investigations and Evidence.</p><Button variant="secondary" className="mt-4" onClick={()=>{pendingIntake.bytes=null;sessionStorage.removeItem("cyberlens_result");sessionStorage.removeItem("cyberlens_history");setCleared(true);}}>Clear local investigation</Button>{cleared&&<p role="status" className="mt-3 text-xs text-emerald-300">Local investigation cleared.</p>}</Section><Section title="Capabilities"><div className="space-y-3 text-xs text-slate-400"><p>Account authentication: available</p><p>Case records: database-backed</p><p>Saved investigations and stored evidence: database-backed, only when you consent</p><p>Audit log: available on the Evidence page</p><p>Reputation lookups: only when a provider key is configured and you confirm each lookup</p><p>Geolocation, SMTP verification and campaign correlation: not implemented</p></div></Section></div></>;
}

export function Placeholder({title}){return <><PageTitle eyebrow="CyberLens" title={title}/><Card className="p-8 text-center text-slate-500">This module is wired into the navigation and ready for backend/API integration.</Card></>}
