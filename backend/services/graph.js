import { emailDomain, isIp } from "./indicators.js";

const MAX_NODES = 150;

/**
 * Build a relationship graph strictly from fields parsed out of the message.
 * Every edge carries the header/body location it was observed in. Edges describe what the
 * message *claims or contains*; they are not attribution or verified infrastructure ownership.
 * @param {object} analysis parsed analysis (metadata, received, urls, attachments)
 * @param {Array} lookups optional reputation lookups [{indicator, provider, status, result}]
 */
export function buildGraph(analysis, lookups = []) {
  const nodes = new Map(), edges = [], seen = new Set();
  const node = (type, value, label, extra = {}) => {
    const id = `${type}:${value}`;
    if (!nodes.has(id)) {
      if (nodes.size >= MAX_NODES) return null;
      nodes.set(id, { id, type, label: label ?? value, value, ...extra });
    }
    return id;
  };
  const edge = (a, b, relation, evidence) => {
    if (!a || !b) return;
    const key = `${a}|${b}|${relation}`;
    if (seen.has(key)) return;
    seen.add(key);
    edges.push({ source: a, target: b, relation, evidence });
  };
  const m = analysis.metadata || {};
  const msg = node("message", m.messageId || "message", m.subject || "(no subject)", { detail: m.date || null });

  const addr = (a, relation, ref) => {
    const id = node("address", a.address, a.address, { detail: a.name || null });
    edge(msg, id, relation, ref);
    const d = emailDomain(a.address);
    if (d) edge(id, node("domain", d), "belongs-to-domain", ref);
  };
  (m.from || []).forEach(a => addr(a, "from", "From header"));
  (m.replyTo || []).forEach(a => addr(a, "reply-to", "Reply-To header"));
  if (m.returnPath) addr({ address: m.returnPath }, "return-path", "Return-Path header");

  const hops = [...(analysis.received || [])].reverse(); // chronological: origin first
  let prev = null;
  hops.forEach(h => {
    const host = h.by || h.from;
    if (!host) return;
    const hostId = node(isIp(host) ? "ip" : "domain", host.toLowerCase(), host, { detail: h.timestamp ? `Received ${h.timestamp}` : null });
    if (prev) edge(prev, hostId, "relayed-to", `Received header #${h.index + 1}`);
    if (h.from && h.from !== host) edge(node(isIp(h.from) ? "ip" : "domain", h.from.toLowerCase()), hostId, "relayed-to", `Received header #${h.index + 1}`);
    for (const ip of h.ips) edge(hostId, node("ip", ip.ip, ip.ip, { public: ip.public, detail: ip.public ? "Public IP (claimed in Received header)" : "Non-public address" }), "reported-ip", `Received header #${h.index + 1}`);
    prev = hostId;
  });
  if (prev) edge(prev, msg, "handed-message-to-mailbox", "Received header #1");

  for (const u of analysis.urls || []) {
    const id = node("url", u.url, u.url.length > 60 ? u.url.slice(0, 57) + "..." : u.url, { detail: `Found in ${u.source}` });
    edge(msg, id, "contains-url", u.source);
    if (u.host) edge(id, node(isIp(u.host) ? "ip" : "domain", u.host), "points-to-host", "URL host");
  }
  for (const l of analysis.htmlLinks || []) {
    if (l.mismatch && l.displayHost) edge(node("domain", l.displayHost), node("domain", l.hrefHost), "displayed-as-but-links-to", "HTML anchor");
  }
  for (const a of analysis.attachments || []) {
    edge(msg, node("attachment", a.sha256, a.filename || a.sha256.slice(0, 12), { detail: `${a.size} bytes, SHA-256 ${a.sha256}`, flags: a.flags }), "has-attachment", "MIME part");
  }

  const rep = new Map();
  for (const l of lookups) {
    const r = l.result || {};
    const flagged = (r.malicious ?? 0) + (r.suspicious ?? 0) > 0 || (r.abuseConfidenceScore ?? 0) >= 25;
    const prev = rep.get(l.indicator);
    rep.set(l.indicator, prev ? { ...prev, flagged: prev.flagged || flagged, summary: `${prev.summary} | ${l.provider}: ${r.summary ?? l.status}` } : { provider: l.provider, status: l.status, summary: r.summary ?? null, flagged });
  }
  for (const n of nodes.values()) {
    const r = rep.get(n.value);
    if (r) n.reputation = r;
  }
  return { nodes: [...nodes.values()], edges, truncated: nodes.size >= MAX_NODES, basis: "Relationships observed in the submitted message only; not verified infrastructure attribution." };
}
