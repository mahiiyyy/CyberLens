import React from "react";

export function Card({ children, className = "" }) {
  return <div className={`rounded-xl border border-cyber-line bg-cyber-panel ${className}`}>{children}</div>;
}

const tones = {
  red: "border-red-400/25 bg-red-400/10 text-red-300",
  amber: "border-amber-400/25 bg-amber-400/10 text-amber-300",
  green: "border-emerald-400/25 bg-emerald-400/10 text-emerald-300",
  cyan: "border-cyan-400/25 bg-cyan-400/10 text-cyan-300",
  purple: "border-purple-400/25 bg-purple-400/10 text-purple-300",
  slate: "border-slate-500/20 bg-slate-500/10 text-slate-300"
};

export function Badge({ children, tone = "slate" }) {
  return <span className={`inline-flex items-center rounded-md border px-2 py-1 text-[10px] font-bold tracking-wide ${tones[tone] || tones.slate}`}>{children}</span>;
}

export function Button({ children, onClick, type = "button", variant = "primary", className = "", disabled = false }) {
  const styles = {
    primary: "bg-cyber-cyan text-slate-950 border-cyan-300 hover:bg-cyan-300",
    secondary: "bg-white/5 text-slate-200 border-cyber-line hover:bg-white/10",
    danger: "bg-red-500/10 text-red-300 border-red-500/25 hover:bg-red-500/20",
    ghost: "bg-transparent text-slate-400 border-transparent hover:bg-white/5 hover:text-slate-200"
  };
  return <button type={type} disabled={disabled} onClick={onClick} className={`rounded-lg border px-4 py-2 text-sm font-semibold transition disabled:opacity-50 ${styles[variant]} ${className}`}>{children}</button>;
}

export function PageTitle({ eyebrow, title, sub }) {
  return <div className="mb-6 fade-up">
    <div className="text-[10px] font-bold uppercase tracking-[.22em] text-cyber-cyan">{eyebrow}</div>
    <h1 className="mt-1 text-2xl font-black text-white md:text-3xl">{title}</h1>
    {sub && <p className="mt-1 text-sm text-slate-500">{sub}</p>}
  </div>;
}

export function Section({ title, action, children, className = "" }) {
  return <Card className={`p-4 ${className}`}>
    <div className="mb-4 flex items-center justify-between gap-3"><h2 className="text-sm font-bold text-slate-100">{title}</h2>{action}</div>
    {children}
  </Card>;
}
