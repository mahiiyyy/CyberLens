import React, {useEffect,useState} from "react";
import {api,clearAuth} from "../lib/api";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  Activity, BrainCircuit, Database, FileCheck2, FileSearch, Globe2,
  Hash, LayoutDashboard, LockKeyhole, Mail, Map, Menu, Network, Server, Settings,
  ShieldAlert, SlidersHorizontal, Workflow
} from "lucide-react";

const operations = [
  ["/dashboard", "SOC Dashboard", LayoutDashboard],
  ["/investigate", "New Investigation", FileSearch],
  ["/cases", "Cases", Database],
  ["/iocs", "IOC Center", Hash],
  ["/campaigns", "Campaign Correlation", Workflow],
  ["/reports", "Reports", FileCheck2]
];

const investigation = [
  ["/result", "Investigation Result", Activity],
  ["/forensics", "Email Forensics", Mail],
  ["/authentication", "Authentication", ShieldAlert],
  ["/intel", "URL / Domain / IP", Globe2],
  ["/smtp", "SMTP Trace", Server],
  ["/graph", "Threat Graph", Network],
  ["/geo", "Geolocation", Map],
  ["/evidence", "Evidence & Custody", LockKeyhole],
  ["/assistant", "CyberLens AI", BrainCircuit],
  ["/settings", "Admin / Settings", SlidersHorizontal]
];

function Item({ item }) {
  const [path, label, Icon] = item;
  return <NavLink to={path} className={({isActive}) => `flex items-center gap-3 rounded-lg border px-2.5 py-2 text-xs transition ${isActive ? "border-cyan-400/10 bg-cyan-400/10 text-cyan-200" : "border-transparent text-slate-500 hover:bg-white/5 hover:text-slate-200"}`}>
    <Icon size={15}/>{label}
  </NavLink>;
}

export default function Layout() {
  const nav = useNavigate();
  const [user,setUser]=useState(null),[error,setError]=useState("");
  useEffect(()=>{let active=true;const expired=()=>{clearAuth();nav("/login",{replace:true});};window.addEventListener("cyberlens-auth-expired",expired);api("/auth/me").then(r=>{if(active)setUser(r.user);}).catch(e=>{if(active){if(e.status===401)expired();else setError(e.message);}});return()=>{active=false;window.removeEventListener("cyberlens-auth-expired",expired);};},[nav]);
  const logout=async()=>{try{await api("/auth/logout",{method:"POST"});clearAuth();nav("/login",{replace:true});}catch(e){setError(e.message);}};
  if(error)return <div className="p-8 text-slate-300">{error}<button className="ml-3 text-cyan-300" onClick={()=>window.location.reload()}>Retry</button></div>;
  if(!user)return <div className="p-8 text-slate-300">Checking session...</div>;
  return <div className="min-h-screen grid-bg">
    <header className="sticky top-0 z-50 flex h-16 items-center justify-between border-b border-cyber-line bg-[#080d18]/95 px-4 backdrop-blur">
      <div className="flex items-center gap-3">
        <button className="rounded-lg p-2 hover:bg-white/5"><Menu size={18}/></button>
        <button onClick={() => nav("/dashboard")} className="font-black tracking-tight text-white"><span className="text-cyber-cyan">CYBER</span>LENS <span className="ml-2 text-[9px] font-bold tracking-widest text-slate-600">SOC / FORENSICS</span></button>
      </div>
      <div className="flex items-center gap-4">
        <span className="hidden items-center gap-2 text-[10px] text-slate-500 md:flex"><i className="h-2 w-2 rounded-full bg-emerald-400"/><span>DEMO ENVIRONMENT</span></span>
        <span className="hidden text-xs text-slate-300 sm:block">{user.email}</span><button onClick={logout} className="rounded-lg border border-cyber-line px-3 py-2 text-xs text-cyan-300">Log out</button>
      </div>
    </header>
    <div className="flex">
      <aside className="sticky top-16 hidden h-[calc(100vh-4rem)] w-60 shrink-0 overflow-y-auto border-r border-cyber-line bg-[#090f1b] p-3 lg:block">
        <p className="mb-2 px-2 text-[9px] font-bold tracking-[.2em] text-slate-700">OPERATIONS</p>
        <div className="space-y-1">{operations.map(x => <Item key={x[0]} item={x}/>)}</div>
        <p className="mb-2 mt-6 px-2 text-[9px] font-bold tracking-[.2em] text-slate-700">INVESTIGATION</p>
        <div className="space-y-1">{investigation.map(x => <Item key={x[0]} item={x}/>)}</div>
      </aside>
      <main className="min-w-0 flex-1 p-4 md:p-6"><Outlet/></main>
    </div>
  </div>;
}
