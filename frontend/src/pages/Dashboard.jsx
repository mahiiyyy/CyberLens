import React, { useEffect, useState } from "react";
import { AlertTriangle, ArrowUpRight, RefreshCw } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { AreaChart, Area, ResponsiveContainer, PieChart, Pie, Cell, Tooltip, XAxis } from "recharts";
import { Badge, Button, Card, PageTitle, Section } from "../components/ui";
import { api } from "../lib/api";

export default function Dashboard() {
  const nav=useNavigate();
  const [data,setData]=useState(null);
  const [error,setError]=useState("");
  const [loading,setLoading]=useState(true);
  const load=async()=>{setLoading(true);setError("");try{setData(await api("/investigations/dashboard/summary"));}catch(e){setError(e.message||"Unable to load dashboard");}finally{setLoading(false);}};
  useEffect(()=>{load();},[]);
  const totals=data?.totals||{};
  const dist=(data?.priority||[]).map(x=>({name:x.priority,value:x.count}));
  const colors={CRITICAL:"#f87171",HIGH:"#fb923c",MEDIUM:"#fbbf24",LOW:"#22d3ee"};
  return <div className="fade-up">
    <PageTitle eyebrow="Security Operations Center" title="Investigation Command" sub="Live metrics from investigations saved to your account."/>
    <div className="mb-4 flex justify-end"><Button variant="secondary" disabled={loading} onClick={load}><RefreshCw size={13} className="mr-2 inline"/>Refresh</Button></div>
    {error&&<div className="mb-4 rounded-lg border border-red-400/20 bg-red-400/5 p-3 text-xs text-red-300">{error}</div>}
    <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
      {[[totals.total??"—","Total Cases"],[totals.active??"—","Active Cases"],[totals.critical??"—","Critical Cases"],[totals.today??"—","Created Today"],[data?.iocs?.total??"—","Extracted IOCs"],[data?.iocs?.malicious??"—","Malicious IOCs"]].map(([v,l])=><Card className="p-4" key={l}><div className="text-2xl font-black text-white">{loading?"…":v}</div><div className="mt-1 text-[10px] text-slate-600">{l}</div></Card>)}
    </div>
    <div className="mt-4 grid gap-4 lg:grid-cols-3">
      <Section title="Investigations over time" className="lg:col-span-2"><div className="h-56">{data?.activity?.length?<ResponsiveContainer width="100%" height="100%"><AreaChart data={data.activity}><defs><linearGradient id="liveActivity" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#22d3ee" stopOpacity=".25"/><stop offset="100%" stopColor="#22d3ee" stopOpacity="0"/></linearGradient></defs><XAxis dataKey="hour" tickFormatter={v=>new Date(v).toLocaleTimeString([],{hour:"2-digit"})} tick={{fontSize:9,fill:"#64748b"}}/><Area type="monotone" dataKey="count" stroke="#22d3ee" fill="url(#liveActivity)" strokeWidth={2}/><Tooltip/></AreaChart></ResponsiveContainer>:<div className="flex h-full items-center justify-center text-xs text-slate-600">No investigation activity in the last 24 hours.</div>}</div></Section>
      <Section title="Case priority"><div className="h-56">{dist.length?<ResponsiveContainer><PieChart><Pie data={dist} dataKey="value" nameKey="name" innerRadius={52} outerRadius={82}>{dist.map(x=><Cell key={x.name} fill={colors[x.name]||"#94a3b8"}/>)}</Pie><Tooltip/></PieChart></ResponsiveContainer>:<div className="flex h-full items-center justify-center text-xs text-slate-600">No cases recorded yet.</div>}</div><div className="flex flex-wrap justify-center gap-2">{dist.map(x=><Badge key={x.name}>{x.name}: {x.value}</Badge>)}</div></Section>
    </div>
    <div className="mt-4 grid gap-4 lg:grid-cols-3"><Section title="High-priority cases">{(data?.recent||[]).filter(x=>["CRITICAL","HIGH"].includes(x.priority)).slice(0,5).map(x=><div key={x.case_no} className="border-b border-cyber-line py-3 text-xs"><div className="flex justify-between gap-2"><b>{x.case_no}</b><Badge tone={x.priority==="CRITICAL"?"red":"amber"}>{x.priority}</Badge></div><div className="mt-1 text-slate-400">{x.title}</div></div>)}{!data?.recent?.some(x=>["CRITICAL","HIGH"].includes(x.priority))&&<p className="text-xs text-slate-600">No high-priority cases yet.</p>}<Button variant="ghost" className="mt-2 w-full" onClick={()=>nav("/alerts")}>View alerts</Button></Section>
      <Section title="Recent investigations" className="lg:col-span-2"><div className="flex justify-end"><Button onClick={()=>nav("/investigate")}>+ New Investigation</Button></div>{(data?.recent||[]).map(x=><button key={x.case_no} onClick={()=>nav("/result")} className="grid w-full grid-cols-12 gap-2 border-t border-cyber-line p-3 text-left text-xs hover:bg-white/[.02]"><span className="col-span-4 text-cyan-300">{x.case_no}</span><span className="col-span-5 truncate text-slate-300">{x.title}</span><span className="col-span-3"><Badge tone={x.priority==="CRITICAL"?"red":"amber"}>{x.priority}</Badge></span></button>)}{!data?.recent?.length&&<p className="py-8 text-center text-xs text-slate-600">No investigations yet. Create your first case.</p>}</Section>
    </div>
    <div className="mt-4 flex justify-end"><Button onClick={()=>nav("/investigate")}>New Investigation <ArrowUpRight className="ml-2 inline" size={13}/></Button></div>
  </div>;
}
