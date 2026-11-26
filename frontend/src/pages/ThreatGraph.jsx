import React, { useMemo, useState } from "react";
import { currentResult } from "../lib/api";
import { Badge, Card, PageTitle, Section } from "../components/ui";

const COLORS = { message: "#22d3ee", address: "#a78bfa", domain: "#f59e0b", ip: "#f472b6", url: "#60a5fa", attachment: "#f87171" };
const LABELS = { message: "Message", address: "Address", domain: "Domain / host", ip: "IP address", url: "URL", attachment: "Attachment" };

/** Radial layout by hop distance from the message node. Deterministic; positions carry no meaning beyond distance. */
function layout(graph, hidden) {
  const nodes = graph.nodes.filter(n => !hidden.has(n.type));
  const ids = new Set(nodes.map(n => n.id));
  const adj = new Map(nodes.map(n => [n.id, []]));
  for (const e of graph.edges) if (ids.has(e.source) && ids.has(e.target)) { adj.get(e.source).push(e.target); adj.get(e.target).push(e.source); }
  const root = nodes.find(n => n.type === "message")?.id ?? nodes[0]?.id;
  const depth = new Map(), parent = new Map();
  if (root) { depth.set(root, 0); const q = [root]; while (q.length) { const u = q.shift(); for (const v of adj.get(u)) if (!depth.has(v)) { depth.set(v, depth.get(u) + 1); parent.set(v, u); q.push(v); } } }
  const maxD = Math.max(0, ...depth.values());
  for (const n of nodes) if (!depth.has(n.id)) depth.set(n.id, maxD + 1);
  const pos = new Map(), rings = new Map();
  for (const n of nodes) { const d = depth.get(n.id); rings.set(d, [...(rings.get(d) || []), n]); }
  const R = 150, ang = new Map();
  [...rings.keys()].sort((a, b) => a - b).forEach(d => {
    const list = rings.get(d).sort((a, b) => (ang.get(parent.get(a.id)) ?? 0) - (ang.get(parent.get(b.id)) ?? 0) || a.id.localeCompare(b.id));
    list.forEach((n, i) => { const t = d === 0 ? 0 : (2 * Math.PI * i) / list.length - Math.PI / 2; ang.set(n.id, t); pos.set(n.id, { x: d * R * Math.cos(t), y: d * R * Math.sin(t) }); });
  });
  const extent = (Math.max(...depth.values(), 1) + 0.6) * R;
  return { nodes, pos, extent };
}

export default function ThreatGraph() {
  const result = currentResult();
  const [selected, setSelected] = useState(null), [hidden, setHidden] = useState(new Set());
  const graph = result?.graph;
  const L = useMemo(() => (graph ? layout(graph, hidden) : null), [graph, hidden]);
  if (!result || !graph) return <><PageTitle eyebrow="Investigation" title="Threat Graph"/><Card className="p-5"><p className="text-sm text-slate-400">No completed investigation in this session.</p><a className="mt-3 inline-block text-sm text-cyan-300" href="/investigate">Start an investigation</a></Card></>;
  const sel = graph.nodes.find(n => n.id === selected);
  const rels = sel ? graph.edges.filter(e => e.source === sel.id || e.target === sel.id) : [];
  const byId = Object.fromEntries(graph.nodes.map(n => [n.id, n]));
  const toggle = t => setHidden(h => { const n = new Set(h); n.has(t) ? n.delete(t) : n.add(t); return n; });
  return <div className="fade-up"><PageTitle eyebrow="Relationships" title="Threat Graph" sub="Relationships observed in this message, generated from parsed headers, links and attachments."/>
    <div className="mb-3 flex flex-wrap items-center gap-2">{Object.entries(LABELS).map(([t, label]) => <button key={t} onClick={() => toggle(t)} aria-pressed={!hidden.has(t)} className={`flex items-center gap-2 rounded-lg border border-cyber-line px-3 py-1.5 text-xs ${hidden.has(t) ? "opacity-40" : ""}`}><i className="h-2.5 w-2.5 rounded-full" style={{ background: COLORS[t] }}/>{label}</button>)}</div>
    <div className="grid gap-4 lg:grid-cols-3">
      <Card className="overflow-hidden lg:col-span-2"><svg role="img" aria-label="Relationship graph" viewBox={`${-L.extent} ${-L.extent} ${L.extent * 2} ${L.extent * 2}`} className="h-[34rem] w-full">
        {graph.edges.filter(e => L.pos.has(e.source) && L.pos.has(e.target)).map((e, i) => { const a = L.pos.get(e.source), b = L.pos.get(e.target); const active = sel && (e.source === sel.id || e.target === sel.id); return <g key={i}><line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={active ? "#22d3ee" : "#334155"} strokeWidth={active ? 2 : 1}><title>{`${e.relation} (${e.evidence})`}</title></line></g>; })}
        {L.nodes.map(n => { const p = L.pos.get(n.id); const flagged = n.reputation?.flagged; return <g key={n.id} transform={`translate(${p.x},${p.y})`} onClick={() => setSelected(n.id)} onKeyDown={e => (e.key === "Enter" || e.key === " ") && setSelected(n.id)} tabIndex={0} role="button" aria-label={`${LABELS[n.type]} ${n.label}`} className="cursor-pointer outline-none">
          <circle r={n.type === "message" ? 16 : 11} fill={COLORS[n.type]} fillOpacity={0.85} stroke={flagged ? "#ef4444" : n.id === selected ? "#fff" : "none"} strokeWidth={3}/>
          <text y={n.type === "message" ? 30 : 24} textAnchor="middle" fontSize="10" fill="#cbd5e1">{n.label.length > 26 ? n.label.slice(0, 24) + "…" : n.label}</text></g>; })}
      </svg></Card>
      <Section title={sel ? "Node details" : "Select a node"}>{sel ? <div className="space-y-2 text-xs text-slate-300"><Badge tone="slate">{LABELS[sel.type]}</Badge><div className="break-all font-mono">{sel.value}</div>{sel.detail && <div className="text-slate-500">{sel.detail}</div>}{sel.flags?.length > 0 && <div className="text-amber-300">Static flags: {sel.flags.join(", ")}</div>}
        {sel.reputation ? <div className="rounded-lg bg-black/20 p-2"><div className="text-[10px] text-slate-500">{sel.reputation.provider} · {sel.reputation.status}</div>{sel.reputation.summary}</div> : <div className="text-slate-500">No reputation lookup recorded.</div>}
        <div className="pt-2 text-[10px] font-bold tracking-widest text-slate-600">OBSERVED RELATIONSHIPS</div>{rels.map((e, i) => <div key={i} className="border-b border-cyber-line pb-2"><span className="text-cyan-300">{byId[e.source]?.label}</span> → <b>{e.relation}</b> → <span className="text-cyan-300">{byId[e.target]?.label}</span><div className="text-[10px] text-slate-500">Source: {e.evidence}</div></div>)}</div> : <p className="text-xs text-slate-500">Click a node to see where each relationship was observed in the message.</p>}</Section>
    </div>
    <p className="mt-3 text-xs text-slate-500">{graph.basis} {graph.truncated ? "The graph was truncated at 150 nodes. " : ""}Position shows hop distance from the message only. A red ring means a configured reputation provider flagged the indicator; its absence is not a safety signal. Nothing shown here was visited or resolved.</p></div>;
}
