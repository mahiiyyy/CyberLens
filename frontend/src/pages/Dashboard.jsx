import React from "react";
import { AlertTriangle, ArrowUpRight, ChevronRight } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { AreaChart, Area, ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from "recharts";
import { Badge, Button, Card, PageTitle, Section } from "../components/ui";
import { investigations } from "../data/demo";

const activity = [42,58,38,76,55,88,71,93,64,80,92,68].map((v,i)=>({h:`${i}:00`,v}));
const dist = [{name:"Critical",value:31},{name:"AI signals",value:42},{name:"Auth",value:27}];

export default function Dashboard() {
  const nav = useNavigate();
  return <div className="fade-up">
    <PageTitle eyebrow="Security Operations Center" title="Investigation Command" sub="Demo telemetry · deterministic checks + evidence-grounded AI"/>
    <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
      {[["24","Active Cases"],["7","Critical Threats","red"],["1,284","Emails Analyzed"],["346","Threats Detected"],["92","Suspicious Infra"],["48","Investigations Today"]].map(([v,l,c])=><Card className="p-4" key={l}><div className={`text-2xl font-black ${c==="red"?"text-red-300":"text-white"}`}>{v}</div><div className="mt-1 text-[10px] text-slate-600">{l}</div></Card>)}
    </div>
    <div className="mt-4 grid gap-4 lg:grid-cols-3">
      <Section title="Threat activity" className="lg:col-span-2">
        <div className="h-56"><ResponsiveContainer width="100%" height="100%"><AreaChart data={activity}><defs><linearGradient id="cy" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#22d3ee" stopOpacity=".25"/><stop offset="100%" stopColor="#22d3ee" stopOpacity="0"/></linearGradient></defs><Area type="monotone" dataKey="v" stroke="#22d3ee" fill="url(#cy)" strokeWidth={2}/><Tooltip contentStyle={{background:"#0d1422",border:"1px solid #1d2b3f",fontSize:11}}/></AreaChart></ResponsiveContainer></div>
      </Section>
      <Section title="Threat distribution">
        <div className="h-56"><ResponsiveContainer><PieChart><Pie data={dist} dataKey="value" innerRadius={55} outerRadius={82} stroke="none">{dist.map((_,i)=><Cell key={i} fill={["#f87171","#a78bfa","#fbbf24"][i]}/>)}</Pie><Tooltip contentStyle={{background:"#0d1422",border:"1px solid #1d2b3f",fontSize:11}}/></PieChart></ResponsiveContainer></div>
        <div className="text-center text-[10px] text-slate-500">346 detections · critical 31%</div>
      </Section>
    </div>
    <div className="mt-4 grid gap-4 lg:grid-cols-3">
      <Section title="Critical alerts">
        {["DMARC failure spike","Lookalike domain cluster","Credential lure detected"].map((x,i)=><div className="flex items-center gap-3 border-b border-cyber-line py-3 last:border-0" key={x}><AlertTriangle size={15} className={i===0?"text-red-400":"text-amber-400"}/><span className="flex-1 text-xs">{x}</span><Badge tone={i===0?"red":"amber"}>{i===0?"CRITICAL":"HIGH"}</Badge></div>)}
        <Button variant="ghost" className="mt-2 w-full" onClick={()=>nav("/alerts")}>View all alerts</Button>
      </Section>
      <Section title="Primary case" className="lg:col-span-2" action={<Badge tone="red">CRITICAL</Badge>}>
        <div className="flex flex-col gap-4 md:flex-row md:items-center">
          <div className="flex-1"><div className="font-bold text-white">EML-2026-0912 · Acme Bank Security Alert</div><p className="mt-1 text-xs text-slate-500">Phishing / impersonation · credential theft indicators</p></div>
          <div className="text-right"><div className="text-3xl font-black text-red-300">92<span className="text-sm text-slate-600">/100</span></div><Button onClick={()=>nav("/result")} className="mt-2">Open Case <ArrowUpRight className="ml-1 inline" size={13}/></Button></div>
        </div>
      </Section>
    </div>
    <Card className="mt-4 overflow-hidden">
      <div className="flex items-center justify-between p-4"><h2 className="text-sm font-bold">Recent investigations</h2><Button onClick={()=>nav("/investigate")}>+ New Investigation</Button></div>
      {investigations.map(r=><button key={r[0]} onClick={()=>nav("/result")} className="grid w-full grid-cols-12 gap-2 border-t border-cyber-line p-4 text-left text-xs hover:bg-white/[.02]">
        <span className="col-span-3 text-cyan-300 md:col-span-2">{r[0]}</span><span className="col-span-5 text-slate-300 md:col-span-5">{r[1]}</span><span className="col-span-2"><Badge tone={r[2]==="CRITICAL"?"red":"amber"}>{r[2]}</Badge></span><span className="hidden text-slate-600 md:col-span-2 md:block">{r[3]}</span><ChevronRight size={15}/>
      </button>)}
    </Card>
  </div>;
}
