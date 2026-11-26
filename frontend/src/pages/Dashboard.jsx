import React,{useEffect,useState} from "react";
import {useNavigate} from "react-router-dom";
import {AreaChart,Area,ResponsiveContainer,PieChart,Pie,Cell,Tooltip,XAxis,YAxis} from "recharts";
import {Badge,Button,Card,PageTitle,Section} from "../components/ui";
import {api} from "../lib/api";

export default function Dashboard(){
 const nav=useNavigate();
 const [data,setData]=useState(null),[error,setError]=useState(""),[loading,setLoading]=useState(true);
 const load=async()=>{setLoading(true);setError("");try{setData(await api("/cases/stats"));}catch(e){setError(e.message);}finally{setLoading(false);}};
 useEffect(()=>{load();},[]);
 const stats=data?.stats;
 const dist=stats?[{name:"Open",value:stats.open},{name:"Closed",value:stats.closed}]:[];
 const tooltip={background:"#0d1422",border:"1px solid #1d2b3f",fontSize:11};
 return <div className="fade-up">
 <PageTitle eyebrow="Security Operations Center" title="Investigation Command" sub="Your saved case activity and current case status."/>
 <div className="mb-4 flex flex-wrap gap-2"><Button onClick={()=>nav("/investigate")}>+ New Investigation</Button><Button variant="secondary" onClick={()=>nav("/cases")}>Manage Cases</Button><Button variant="secondary" disabled={loading} onClick={load}>Refresh</Button></div>
 {error&&<p role="alert" className="mb-4 text-sm text-red-300">{error}</p>}
 <div className="grid grid-cols-2 gap-3 md:grid-cols-4">{[["Total cases",stats?.total],["Open cases",stats?.open],["Closed cases",stats?.closed],["Created today (UTC)",stats?.today]].map(([label,value])=><Card key={label} className="p-4"><div className="text-2xl font-black text-white">{loading?"…":value??"—"}</div><div className="mt-1 text-xs text-slate-400">{label}</div></Card>)}</div>
 <div className="mt-4 grid gap-4 lg:grid-cols-3">
 <Section title="Cases created · last 7 UTC days" className="lg:col-span-2">{data?<div className="h-56"><ResponsiveContainer width="100%" height="100%"><AreaChart data={data.activity}><XAxis dataKey="day" tick={{fontSize:10}}/><YAxis allowDecimals={false} tick={{fontSize:10}}/><Tooltip contentStyle={tooltip}/><Area type="monotone" dataKey="count" name="Cases created" stroke="#22d3ee" fill="#164e63" strokeWidth={2}/></AreaChart></ResponsiveContainer></div>:<p className="p-4 text-xs text-slate-500">No statistics loaded.</p>}</Section>
 <Section title="Case status distribution">{stats?.total>0?<div className="h-56"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={dist} dataKey="value" nameKey="name" innerRadius={55} outerRadius={82} stroke="none">{dist.map((r,i)=><Cell key={r.name} fill={["#22d3ee","#34d399"][i]}/>)}</Pie><Tooltip contentStyle={tooltip}/></PieChart></ResponsiveContainer></div>:<p className="p-4 text-xs text-slate-500">No case distribution available.</p>}<div className="flex justify-center gap-4 text-xs text-slate-400"><span>Open: {stats?.open??"—"}</span><span>Closed: {stats?.closed??"—"}</span></div></Section>
 </div>
 <Section title="Recent saved cases" className="mt-4" action={<Button variant="secondary" onClick={()=>nav("/cases")}>All cases</Button>}>{loading?<p className="text-xs text-slate-500">Loading…</p>:data?.recent?.length?data.recent.map(r=><div key={r.id} className="flex flex-wrap items-center gap-3 border-b border-cyber-line py-3 text-xs"><span className="flex-1 break-all text-slate-200">{r.title}</span><Badge tone={r.status==="Closed"?"green":"amber"}>{r.status}</Badge><span className="text-slate-500">{new Date(r.created_at).toLocaleDateString()}</span></div>):<p className="text-xs text-slate-500">{error?"Unable to load cases.":"No saved cases yet."}</p>}</Section>
 <p className="mt-4 text-xs text-slate-500">Statistics reflect saved case records, not email analysis totals. Threat statistics will be available after investigation persistence is implemented.</p>
 </div>;
}
