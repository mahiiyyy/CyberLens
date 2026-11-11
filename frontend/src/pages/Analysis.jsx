import React, { useEffect, useState } from "react";
import { CheckCircle2, Loader2, BrainCircuit } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { Card } from "../components/ui";

const stages=["Evidence received","Header and URL checks completed","Analysis result received","Case and evidence saved"];
export default function Analysis(){
  const [p,setP]=useState(0);
  const [result,setResult]=useState(null);
  const [error,setError]=useState("");
  const nav=useNavigate();
  useEffect(()=>{
    let parsed=null;
    try{const raw=sessionStorage.getItem("cyberlens_result");parsed=raw?JSON.parse(raw):null;}catch{parsed=null;}
    if(!parsed){setError("No analysis result was found. Please start a new investigation.");return;}
    setResult(parsed);
    const started=Date.now();
    const timer=setInterval(()=>{
      const next=Math.min(100,Math.floor(((Date.now()-started)/900)*100));
      setP(next);
      if(next===100){clearInterval(timer);setTimeout(()=>nav("/result"),250);}
    },80);
    return()=>clearInterval(timer);
  },[nav]);
  const complete=Math.floor(p/100*stages.length);
  return <div className="mx-auto max-w-3xl pt-10 fade-up"><div className="text-center"><div className="text-[10px] font-bold tracking-[.22em] text-purple-300"><BrainCircuit className="mr-1 inline" size={12}/> CYBERLENS ANALYSIS</div><h1 className="mt-3 text-3xl font-black text-white">{error?"Analysis unavailable":"Saving investigation…"}</h1><p className="mt-2 text-sm text-slate-500">{error||"The API has completed analysis and persisted the case and evidence record."}</p></div><Card className="mt-10 p-6"><div className="flex justify-between text-xs"><span className="text-cyan-300">RESULT STATUS</span><span>{p}%</span></div><div className="mt-2 h-2 overflow-hidden rounded-full bg-black/30"><div className="scan-line relative h-full bg-cyan-400" style={{width:`${p}%`}}/></div><div className="mt-7 space-y-3">{stages.map((s,i)=><div className="flex items-center gap-3" key={s}><div className={`flex h-6 w-6 items-center justify-center rounded-full border text-[10px] ${i<complete?"border-emerald-400/40 bg-emerald-400/10 text-emerald-300":"border-cyber-line text-slate-700"}`}>{i<complete?<CheckCircle2 size={14}/>:i===complete?<Loader2 className="animate-spin" size={13}/>:i+1}</div><span className={i<complete?"text-slate-200":"text-slate-600"}>{s}</span>{i<complete&&<span className="ml-auto text-[9px] text-emerald-400">COMPLETE</span>}</div>)}</div>{result&&<div className="mt-6 rounded-lg border border-purple-400/20 bg-purple-400/5 p-3 text-xs text-purple-200">Case: <b>{result.caseId}</b> · engine: <b>{result.aiModel}</b> · mode: {result.aiMode}</div>}{error&&<button onClick={()=>nav("/investigation")} className="mt-4 text-sm text-cyan-300">Start a new investigation →</button>}</Card></div>;
}
