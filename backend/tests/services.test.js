import test from "node:test";
import assert from "node:assert/strict";
import { parseEmail } from "../services/emailParser.js";
import { deterministicAnalysis, scoreVerdict } from "../services/scoring.js";
import { buildGraph } from "../services/graph.js";
import { normalizeIndicator, lookupIndicator, IndicatorError, providerStatus } from "../services/reputation.js";
import { buildFacts, ruleBasedSummary, aiSummary } from "../services/summary.js";
import { buildReport } from "../services/report.js";
import { sha256Hex } from "../services/hash.js";
import { FIXTURE } from "./fixtures.js";

const raw = Buffer.from(FIXTURE);
async function investigation() {
  const parsed = await parseEmail(raw);
  const det = deterministicAnalysis(parsed);
  const { text, ...rest } = parsed;
  const score = det.score;
  return {
    reference: "EML-test", verdict: scoreVerdict(score), score, is_sample: false, created_at: new Date("2026-01-01T00:00:00Z"),
    original_sha256: sha256Hex(raw), original_size: raw.length, input_kind: "file", ai_summary: null,
    analysis: { ...rest, textExcerpt: text, deterministicScore: det.score, aiScore: 11, aiModel: "test-model", aiMode: "test", factors: det.factors,
      findings: det.factors.map(([title, contribution, explanation]) => ({ title, severity: "HIGH", contribution, explanation })) },
  };
}

test("scoring uses parsed evidence only and cites sources", async () => {
  const inv = await investigation();
  const titles = inv.analysis.factors.map(f => f[0]);
  for (const t of ["Sender anomaly", "Return-Path anomaly", "SPF failure", "DMARC failure", "Deceptive link text", "Risky attachment", "URL risk"]) assert.ok(titles.includes(t), t);
  assert.ok(!titles.includes("DKIM failure"));
  assert.ok(inv.analysis.factors.every(f => typeof f[3] === "string"));
  assert.equal(deterministicAnalysis(await parseEmail(Buffer.from("From: a@x.example\r\nSubject: Lunch\r\n\r\nSee you at noon."))).score, 0);
});

test("graph contains only observed relationships, each with provenance", async () => {
  const inv = await investigation();
  const g = buildGraph(inv.analysis, [{ indicator: "login.phish.example", provider: "virustotal", status: "ok", result: { summary: "x" } }]);
  const ids = new Set(g.nodes.map(n => n.id));
  assert.ok(ids.has("domain:sender.example") && ids.has("domain:elsewhere.example") && ids.has("domain:login.phish.example"));
  assert.ok(g.nodes.some(n => n.type === "attachment"));
  assert.ok(g.edges.every(e => ids.has(e.source) && ids.has(e.target) && e.evidence));
  assert.equal(g.nodes.find(n => n.id === "domain:login.phish.example").reputation.status, "ok");
  assert.equal(g.nodes.find(n => n.id === "domain:sender.example").reputation, undefined);
  assert.ok(g.edges.some(e => e.relation === "displayed-as-but-links-to"));
});

test("indicator normalisation strips URL secrets and refuses private targets", () => {
  const n = normalizeIndicator({ type: "url", value: "https://user:pw@Login.Phish.example/verify?token=SECRET#frag" });
  assert.equal(n.sent, "https://login.phish.example/verify");
  assert.equal(n.redacted, true);
  for (const bad of [{ type: "ip", value: "10.0.0.1" }, { type: "ip", value: "127.0.0.1" }, { type: "url", value: "http://192.168.1.1/x" }, { type: "url", value: "javascript:alert(1)" }, { type: "sha256", value: "abc" }, { type: "domain", value: "not a domain" }])
    assert.throws(() => normalizeIndicator(bad), IndicatorError, JSON.stringify(bad));
});

test("reputation: not-configured is explicit, results never claim safety, errors are surfaced", async () => {
  const ind = normalizeIndicator({ type: "domain", value: "example.org" });
  delete process.env.VIRUSTOTAL_API_KEY; delete process.env.ABUSEIPDB_API_KEY;
  assert.equal(providerStatus().virustotal.configured, false);
  assert.equal((await lookupIndicator(ind))[0].status, "not_configured");

  process.env.VIRUSTOTAL_API_KEY = "test-key";
  const calls = [];
  const mk = (status, json) => async (url, opts) => { calls.push({ url, key: opts.headers["x-apikey"] }); return { status, ok: status < 300, json: async () => json }; };
  let r = (await lookupIndicator(ind, { fetchImpl: mk(200, { data: { attributes: { last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 60, undetected: 10 }, reputation: 3, last_analysis_date: 1700000000 } } }) }))[0];
  assert.equal(r.status, "ok");
  assert.match(r.result.summary, /not proof of safety/);
  assert.equal(calls[0].url, "https://www.virustotal.com/api/v3/domains/example.org");
  assert.equal(calls[0].key, "test-key");
  r = (await lookupIndicator(ind, { fetchImpl: mk(404, {}) }))[0];
  assert.equal(r.status, "not_found");
  assert.match(r.result.summary, /does not mean it is safe/);
  assert.equal((await lookupIndicator(ind, { fetchImpl: mk(429, {}) }))[0].status, "rate_limited");
  assert.equal((await lookupIndicator(ind, { fetchImpl: mk(401, {}) }))[0].status, "error");
  assert.equal((await lookupIndicator(ind, { fetchImpl: async () => { throw new Error("net"); } }))[0].status, "error");
  const url = normalizeIndicator({ type: "url", value: "https://a.example/p?x=1" });
  await lookupIndicator(url, { fetchImpl: mk(404, {}), providers: ["virustotal"] });
  assert.ok(calls.at(-1).url.endsWith(Buffer.from("https://a.example/p").toString("base64").replace(/=+$/, "")), "sends the stripped URL id only");
  delete process.env.VIRUSTOTAL_API_KEY;
});

test("report is built only from stored data and states absences and limitations", async () => {
  const inv = await investigation();
  const detailed = buildReport(inv, { lookups: [], events: [{ action: "investigation.create", created_at: new Date() }], now: new Date("2026-02-01T00:00:00Z") }).text;
  assert.match(detailed, new RegExp(inv.original_sha256));
  assert.match(detailed, /No reputation lookups were performed/);
  assert.match(detailed, /hxxps:\/\/login\[\.\]phish\[\.\]example/);
  assert.match(detailed, /No summary has been generated/);
  assert.match(detailed, /Original stored on server: No/);
  assert.match(detailed, /not re-verified|not independently verified/);
  const exec = buildReport(inv, { format: "executive" }).text;
  assert.ok(!/AUDIT TRAIL/.test(exec) && /KEY FINDINGS/.test(exec));
  assert.match(buildReport({ ...inv, is_sample: true }).text, /SAMPLE DATA/);
});

test("summary: rule-based statements all cite real facts", async () => {
  const inv = await investigation();
  const facts = buildFacts(inv, []);
  assert.ok(!facts.some(f => /Sign in at/.test(f.text)), "message body must not be part of the facts");
  const s = ruleBasedSummary(facts);
  const ids = new Set(facts.map(f => f.id));
  assert.equal(s.mode, "rule-based");
  assert.ok(s.statements.length > 0 && s.statements.every(x => x.evidence.length && x.evidence.every(i => ids.has(i))));
});

test("summary: AI output is validated against the evidence; uncited or invented citations are dropped", async () => {
  const facts = buildFacts(await investigation(), []);
  delete process.env.ANTHROPIC_API_KEY;
  await assert.rejects(aiSummary(facts), /not configured/);
  process.env.ANTHROPIC_API_KEY = "test-key";
  let sent;
  const reply = obj => async (_u, opts) => { sent = JSON.parse(opts.body); return { ok: true, json: async () => ({ content: [{ type: "text", text: "```json\n" + JSON.stringify(obj) + "\n```" }] }) }; };
  const out = await aiSummary(facts, { fetchImpl: reply({ statements: [{ statement: "Grounded.", evidence: ["E1", "E999"] }, { statement: "Invented.", evidence: ["E999"] }, { statement: "No cite.", evidence: [] }] }) });
  assert.deepEqual(out.statements, [{ statement: "Grounded.", evidence: ["E1"] }]);
  assert.equal(out.mode, "ai");
  assert.ok(!JSON.stringify(sent).includes("Sign in at"), "no body text sent to the provider");
  await assert.rejects(aiSummary(facts, { fetchImpl: reply({ statements: [{ statement: "x", evidence: [] }] }) }), /no evidence-cited/);
  delete process.env.ANTHROPIC_API_KEY;
});

test("analysis pipeline produces the response shape the UI consumes (AI service unreachable -> labelled fallback)", async () => {
  process.env.AI_SERVICE_URL = "http://127.0.0.1:9";
  const { buildAnalysis, toView } = await import("../routes/investigations.js");
  const { verdict, score, analysis } = await buildAnalysis(raw);
  const view = toView({ reference: "EML-x", title: "t", verdict, score, is_sample: false, original_sha256: sha256Hex(raw), original_size: raw.length, input_kind: "file", analysis, ai_summary: null });
  assert.equal(view.saved, false);
  assert.equal(view.aiMode, "local-fallback");
  assert.equal(view.integrity.sha256, sha256Hex(raw));
  assert.equal(view.integrity.source, "original-file-bytes");
  assert.equal(view.evidence.sender, "security@sender.example");
  assert.equal(view.evidence.authentication.spf, "FAIL");
  assert.ok(view.factors.every(f => f.length === 3) && view.findings.length >= view.factors.length);
  assert.ok(view.graph.nodes.length > 5);
  assert.ok(view.score >= 25 && view.score <= 100);
  assert.equal(JSON.stringify(view).includes("MZ-not-a-real-binary"), false, "attachment bytes must never be returned");
  const { pool } = await import("../db/pool.js"); await pool.end();
});
