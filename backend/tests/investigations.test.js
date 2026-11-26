import test from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { randomUUID } from "node:crypto";
import auth from "../routes/auth.js";
import cases from "../routes/cases.js";
import investigations from "../routes/investigations.js";
import evidence from "../routes/evidence.js";
import reputation from "../routes/reputation.js";
import auditRoutes from "../routes/audit.js";
import { pool } from "../db/pool.js";
import { sha256Hex } from "../services/hash.js";
import { FIXTURE } from "./fixtures.js";

test("investigation persistence, consent, evidence integrity, isolation and audit", async () => {
  assert.equal(process.env.CYBERLENS_TEST_DB, "1");
  delete process.env.VIRUSTOTAL_API_KEY; delete process.env.ABUSEIPDB_API_KEY; delete process.env.ANTHROPIC_API_KEY;
  process.env.AI_SERVICE_URL = "http://127.0.0.1:9"; // nothing listens: exercises the honest local fallback
  const app = express();
  app.use(express.json());
  app.use("/auth", auth); app.use("/cases", cases); app.use("/investigations", investigations);
  app.use("/evidence", evidence); app.use("/reputation", reputation); app.use("/audit", auditRoutes);
  app.use((err, req, res, next) => res.status(err.status >= 400 && err.status < 500 ? err.status : 500).json({ error: "Test server error", detail: String(err.message) }));
  const server = app.listen(0, "127.0.0.1");
  await new Promise(r => server.once("listening", r));
  const base = "http://127.0.0.1:" + server.address().port;
  const emails = [randomUUID() + "@example.invalid", randomUUID() + "@example.invalid"];
  const call = (path, { method = "GET", json, bytes, cookie } = {}) => fetch(base + path, {
    method, headers: { ...(cookie ? { Cookie: cookie } : {}), ...(json !== undefined ? { "Content-Type": "application/json" } : bytes ? { "Content-Type": "application/octet-stream" } : {}) },
    ...(json !== undefined ? { body: JSON.stringify(json) } : bytes ? { body: bytes } : {}),
  });
  const register = async email => (await call("/auth/register", { method: "POST", json: { email, password: "Test-only-password-729" } })).headers.get("set-cookie").split(";")[0];
  const eml = Buffer.from(FIXTURE);
  const expectedHash = sha256Hex(eml);
  try {
    // --- authentication required everywhere
    for (const p of ["/investigations", "/evidence", "/audit", "/reputation/providers"]) assert.equal((await call(p)).status, 401, p);
    const A = await register(emails[0]), B = await register(emails[1]);

    // --- analysis without saving stores nothing
    let r = await call("/investigations/analyze?kind=file", { method: "POST", bytes: eml, cookie: A });
    assert.equal(r.status, 200);
    let view = await r.json();
    assert.equal(view.saved, false);
    assert.equal(view.integrity.sha256, expectedHash);
    assert.equal(view.evidence.sender, "security@sender.example");
    assert.equal(view.evidence.authentication.spf, "FAIL");
    assert.equal((await (await call("/investigations", { cookie: A })).json()).total, 0);

    // --- invalid input
    assert.equal((await call("/investigations/analyze", { method: "POST", bytes: Buffer.from("no headers here"), cookie: A })).status, 422);
    assert.equal((await call("/investigations/analyze", { method: "POST", cookie: A })).status, 400);
    // --- saving requires explicit consent
    assert.equal((await call("/investigations/analyze?save=1", { method: "POST", bytes: eml, cookie: A })).status, 400);
    assert.equal((await call("/investigations/analyze?storeOriginal=1&consent=1", { method: "POST", bytes: eml, cookie: A })).status, 400);
    assert.equal((await (await call("/investigations", { cookie: A })).json()).total, 0);

    // --- save with consent; original bytes only with the extra opt-in
    r = await call("/investigations/analyze?save=1&consent=1&kind=file&filename=a.eml&storeOriginal=1", { method: "POST", bytes: eml, cookie: A });
    assert.equal(r.status, 201);
    view = await r.json();
    assert.equal(view.saved, true);
    const id = view.id;
    r = await call("/investigations/analyze?save=1&consent=1&kind=paste", { method: "POST", bytes: eml, cookie: A });
    const hashOnly = (await r.json()).id;

    // --- retrieval, search and account isolation
    const list = await (await call("/investigations", { cookie: A })).json();
    assert.equal(list.total, 2);
    assert.equal(list.investigations.find(i => i.id === id).original_stored, true);
    assert.equal(list.investigations.find(i => i.id === hashOnly).original_stored, false);
    assert.equal((await (await call("/investigations?q=" + expectedHash.slice(0, 12), { cookie: A })).json()).total, 2);
    assert.equal((await (await call("/investigations", { cookie: B })).json()).total, 0);
    const got = await (await call("/investigations/" + id, { cookie: A })).json();
    assert.equal(got.integrity.sha256, expectedHash);
    assert.equal(got.analysis.attachments[0].flags.includes("double-extension"), true);
    for (const [m, p] of [["GET", ""], ["GET", "/graph"], ["GET", "/report"], ["GET", "/audit"], ["POST", "/summary"], ["DELETE", ""]])
      assert.equal((await call(`/investigations/${id}${p}`, { method: m, cookie: B, ...(m === "POST" ? { json: {} } : {}) })).status, 404, m + p);
    assert.equal((await call("/investigations/not-a-uuid", { cookie: A })).status, 400);
    assert.equal((await call("/investigations/" + id, { method: "PATCH", json: { title: "x" }, cookie: B })).status, 404);

    // --- evidence: verify, compare, download, tamper detection, isolation
    let v = await (await call(`/evidence/${id}/verify`, { method: "POST", cookie: A })).json();
    assert.equal(v.match, true);
    assert.equal((await call(`/evidence/${hashOnly}/verify`, { method: "POST", cookie: A })).status, 409);
    assert.equal((await call(`/evidence/${id}/verify`, { method: "POST", cookie: B })).status, 409);
    assert.equal((await call(`/evidence/${id}/download`, { cookie: B })).status, 404);
    assert.equal((await (await call(`/evidence/${hashOnly}/compare`, { method: "POST", bytes: eml, cookie: A })).json()).match, true);
    assert.equal((await (await call(`/evidence/${hashOnly}/compare`, { method: "POST", bytes: Buffer.from(FIXTURE + "x"), cookie: A })).json()).match, false);
    const dl = await call(`/evidence/${id}/download`, { cookie: A });
    assert.equal(dl.status, 200);
    assert.equal(dl.headers.get("content-type"), "application/octet-stream");
    assert.match(dl.headers.get("content-disposition"), /^attachment/);
    assert.equal(sha256Hex(Buffer.from(await dl.arrayBuffer())), expectedHash);
    const ev = await (await call("/evidence", { cookie: A })).json();
    assert.equal(ev.evidence.length, 2);
    await pool.query("UPDATE evidence SET content=$1 WHERE investigation_id=$2", [Buffer.from("tampered"), id]);
    v = await (await call(`/evidence/${id}/verify`, { method: "POST", cookie: A })).json();
    assert.equal(v.match, false);
    assert.equal((await call(`/evidence/${id}/download`, { cookie: A })).status, 409);

    // --- reputation: confirmation, scope, honest "not configured", no persistence of non-answers
    assert.equal((await call("/reputation/lookup", { method: "POST", json: { indicators: [{ type: "domain", value: "sender.example" }] }, cookie: A })).status, 400);
    assert.equal((await call("/reputation/lookup", { method: "POST", json: { indicators: [{ type: "domain", value: "sender.example" }], investigationId: id, confirm: true }, cookie: B })).status, 404);
    let rep = await (await call("/reputation/lookup", { method: "POST", cookie: A, json: { investigationId: id, confirm: true, indicators: [{ type: "domain", value: "login.phish.example" }, { type: "domain", value: "unrelated.example" }, { type: "ip", value: "10.0.0.1" }] } })).json();
    assert.equal(rep.results.length, 1);
    assert.equal(rep.results[0].status, "not_configured");
    assert.equal(rep.rejected.length, 2);
    assert.equal((await pool.query("SELECT count(*)::int AS n FROM reputation_lookups WHERE investigation_id=$1", [id])).rows[0].n, 0);

    // --- graph, summary, report
    const { graph } = await (await call(`/investigations/${id}/graph`, { cookie: A })).json();
    assert.ok(graph.nodes.some(n => n.id === "domain:login.phish.example"));
    assert.equal((await call(`/investigations/${id}/summary`, { method: "POST", json: { mode: "ai" }, cookie: A })).status, 400);
    assert.equal((await call(`/investigations/${id}/summary`, { method: "POST", json: { mode: "ai", confirm: true }, cookie: A })).status, 501);
    const { summary } = await (await call(`/investigations/${id}/summary`, { method: "POST", json: { mode: "rule" }, cookie: A })).json();
    assert.equal(summary.mode, "rule-based");
    const { report } = await (await call(`/investigations/${id}/report?format=detailed`, { cookie: A })).json();
    assert.match(report.text, new RegExp(expectedHash));
    assert.match(report.text, /rule-based \(not AI\)/);
    assert.match(report.text, /evidence\.verify\.MISMATCH/);

    // --- case linking
    const c = (await (await call("/cases", { method: "POST", json: { title: "Linked case" }, cookie: A })).json()).case;
    assert.equal((await call(`/investigations/${id}`, { method: "PATCH", json: { caseId: c.id }, cookie: B })).status, 404);
    assert.equal((await call(`/investigations/${id}`, { method: "PATCH", json: { caseId: c.id }, cookie: A })).status, 200);
    const detail = await (await call(`/cases/${c.id}`, { cookie: A })).json();
    assert.equal(detail.investigations.length, 1);
    assert.equal((await call(`/cases/${c.id}`, { cookie: B })).status, 404);
    assert.equal((await call(`/cases/${c.id}`, { method: "PATCH", json: { priority: "High", notes: "n", title: "Renamed" }, cookie: A })).status, 200);
    assert.equal((await call(`/cases/${c.id}`, { method: "PATCH", json: { priority: "Bogus" }, cookie: A })).status, 400);
    assert.equal((await (await call("/cases/stats", { cookie: A })).json()).investigations.total, 2);

    // --- audit trail is complete, scoped to the account, and free of email content
    const events = (await (await call("/audit?limit=200", { cookie: A })).json()).events;
    const actions = new Set(events.map(e => e.action));
    for (const a of ["investigation.create", "evidence.store", "evidence.verify.match", "evidence.verify.MISMATCH", "evidence.download.BLOCKED_INTEGRITY", "reputation.lookup", "summary.rule", "report.generate", "case.create", "case.update", "investigation.update"]) assert.ok(actions.has(a), a);
    assert.equal((await (await call("/audit", { cookie: B })).json()).events.length, 0);
    assert.ok(!JSON.stringify(events).includes("phish.example/verify"), "audit metadata must not contain message content");

    // --- deletion removes stored evidence and is audited
    assert.equal((await call(`/investigations/${id}`, { method: "DELETE", cookie: A })).status, 200);
    assert.equal((await pool.query("SELECT count(*)::int AS n FROM evidence WHERE investigation_id=$1", [id])).rows[0].n, 0);
    assert.equal((await call(`/investigations/${id}`, { cookie: A })).status, 404);
    assert.ok((await (await call("/audit?entity=investigation&limit=200", { cookie: A })).json()).events.some(e => e.action === "investigation.delete"));
  } finally {
    try {
      await pool.query("DELETE FROM audit_logs WHERE user_id IN (SELECT id FROM users WHERE email=ANY($1::text[]))", [emails]);
      await pool.query("DELETE FROM cases WHERE investigator_id IN (SELECT id FROM users WHERE email=ANY($1::text[]))", [emails]);
      await pool.query("DELETE FROM users WHERE email=ANY($1::text[])", [emails]);
    } finally { await new Promise(r => server.close(r)); await pool.end(); }
  }
});
