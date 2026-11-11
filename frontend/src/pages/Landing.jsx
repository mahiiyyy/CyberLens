import React from "react";
import { ArrowRight, BrainCircuit, FileSearch, Globe2, Network, Shield, ShieldCheck } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { Badge, Button, Card } from "../components/ui";

export default function Landing() {
  const nav = useNavigate();
  const features = [
    ["Email Forensics", FileSearch, "Headers, identity mismatches and raw evidence."],
    ["Explainable AI", BrainCircuit, "Evidence-grounded classification and explanations."],
    ["Threat Intelligence", Shield, "Domain, URL and infrastructure enrichment."],
    ["Threat Graph", Network, "Connect entities across the investigation."],
    ["Geolocation", Globe2, "Map infrastructure with confidence caveats."],
    ["Evidence Integrity", ShieldCheck, "Hash, audit and chain-of-custody workflow."]
  ];
  return <div className="min-h-screen grid-bg p-6">
    <div className="mx-auto max-w-6xl">
      <nav className="flex items-center justify-between py-3">
        <div className="text-xl font-black text-white"><span className="text-cyber-cyan">CYBER</span>LENS</div>
        <Button variant="ghost" onClick={() => nav("/login")}>Analyst Login</Button>
      </nav>
      <section className="max-w-4xl pb-20 pt-24">
        <Badge tone="purple">AI-ASSISTED DIGITAL FORENSICS</Badge>
        <h1 className="mt-6 text-5xl font-black leading-[.95] tracking-tight text-white md:text-7xl">Turn suspicious emails into <span className="text-cyber-cyan">actionable intelligence.</span></h1>
        <p className="mt-6 max-w-2xl text-lg text-slate-400">We don't just detect malicious emails. <strong className="text-slate-200">We investigate them.</strong> Trace infrastructure, explain every signal, correlate campaigns and preserve evidence.</p>
        <div className="mt-8 flex flex-wrap gap-3">
          <Button onClick={() => nav("/login")}>START INVESTIGATION <ArrowRight className="ml-2 inline" size={15}/></Button>
          <Button variant="secondary" onClick={() => nav("/dashboard")}>VIEW DEMO</Button>
        </div>
      </section>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-6">
        {features.map(([name, Icon, desc], i) => <Card key={name} className="p-4">
          <Icon size={18} className="text-cyber-cyan"/>
          <div className="mt-4 text-xs font-bold text-slate-200">{name}</div>
          <div className="mt-2 text-[10px] leading-4 text-slate-600">{desc}</div>
        </Card>)}
      </div>
    </div>
  </div>;
}
