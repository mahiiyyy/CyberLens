import { Router, raw } from "express";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { pool } from "../db/pool.js";
import { requireAuth } from "../middleware/auth.js";
import { audit } from "../services/audit.js";
import { parseEmail, ParseError, MAX_EML_BYTES } from "../services/emailParser.js";
import { sha256Hex } from "../services/hash.js";
import { deterministicAnalysis, scoreVerdict, labelFor } from "../services/scoring.js";
import { runAI, aiStatus } from "../services/aiClient.js";
import { buildGraph } from "../services/graph.js";
import { buildReport } from "../services/report.js";
import { buildFacts, ruleBasedSummary, aiSummary } from "../services/summary.js";

const router = Router();
router.use(requireAuth);

const uuid = z.string().uuid();
const flag = v => v === "1" || v === "true";
const TEXT_EXCERPT = 20_000;

/** One consistent response shape for fresh and stored investigations. Legacy top-level keys are kept for existing pages. */
export function toView(row, extras = {}) {
  const a = row.analysis;
  return {
    status: "complete",
    id: row.id ?? null, saved: !!row.id, reference: row.reference, caseId: row.reference, caseLinkId: row.case_id ?? null,
    title: row.title, isSample: !!row.is_sample, createdAt: row.created_at ?? null,
    verdict: row.verdict, label: a.label, score: row.score, confidence: a.confidence,
    aiScore: a.aiScore, aiModel: a.aiModel, aiMode: a.aiMode, aiExplanation: a.aiExplanation, deterministicScore: a.deterministicScore,
    factors: a.factors.map(f => [f[0], f[1], f[2]]), findings: a.findings,
    integrity: { algorithm: "SHA-256", sha256: row.original_sha256, size: row.original_size, source: row.input_kind === "file" ? "original-file-bytes" : "pasted-text-utf8-bytes" },
    evidence: {
      subject: a.metadata.subject, sender: a.metadata.from[0]?.address ?? "", reply_to: a.metadata.replyTo[0]?.address ?? "", return_path: a.metadata.returnPath ?? "",
      body: a.textExcerpt, urls: a.urls.map(u => u.url), authentication: Object.fromEntries(["spf", "dkim", "dmarc"].map(k => [k, a.authentication[k]])),
    },
    analysis: a, summary: row.ai_summary ?? null, graph: buildGraph(a, extras.reputation ?? []), ...extras,
  };
}

export async function buildAnalysis(buf) {
  const parsed = await parseEmail(buf);
  const det = deterministicAnalysis(parsed);
  const m = parsed.metadata;
  const ai = await runAI({
    subject: m.subject || "", body: parsed.text, sender: m.from[0]?.address || "", reply_to: m.replyTo[0]?.address || "", return_path: m.returnPath || "",
    urls: parsed.urls.map(u => u.url), authentication: Object.fromEntries(["spf", "dkim", "dmarc"].map(k => [k, parsed.authentication[k]])),
    header_mismatches: det.factors.filter(f => f[3]?.startsWith("header:")).map(f => f[2]), deterministic_score: det.score,
  });
  // Deterministic evidence has priority; the text model alone cannot turn a clean message into phishing.
  const score = Math.min(100, Math.round(det.score * 0.65 + ai.ai_score * 0.35));
  const verdict = scoreVerdict(score);
  const findings = [
    ...det.factors.map(([title, contribution, explanation, ref]) => ({ title, severity: contribution >= 15 ? "CRITICAL" : contribution >= 10 ? "HIGH" : "MEDIUM", contribution, confidence: 94, evidence: explanation, explanation, source: ref })),
    ...(ai.findings || []).map(f => ({ ...f, contribution: 0 })),
  ];
  const { text, ...rest } = parsed;
  return {
    verdict, score,
    analysis: {
      ...rest, textExcerpt: text.slice(0, TEXT_EXCERPT), label: labelFor(verdict), confidence: ai.confidence,
      aiScore: ai.ai_score, aiModel: ai.model, aiMode: ai.mode, aiExplanation: ai.explanation, deterministicScore: det.score,
      factors: det.factors, findings,
    },
  };
}

const INTAKE_PARSER = raw({ type: () => true, limit: MAX_EML_BYTES });

router.get("/ai-status", async (_req, res) => {
  const s = await aiStatus();
  res.status(s.connected ? 200 : 503).json(s);
});

/**
 * Analyze an email (raw bytes in the request body). Nothing is persisted unless the caller passes
 * save=1 AND consent=1; the original bytes are only stored with an additional storeOriginal=1.
 */
router.post("/analyze", INTAKE_PARSER, async (req, res, next) => {
  const q = z.object({
    save: z.string().optional(), consent: z.string().optional(), storeOriginal: z.string().optional(), sample: z.string().optional(),
    filename: z.string().max(255).optional(), title: z.string().trim().max(160).optional(), kind: z.enum(["file", "paste"]).optional(),
  }).safeParse(req.query);
  if (!q.success) return res.status(400).json({ error: "Invalid request options." });
  const o = q.data;
  const buf = req.body;
  if (!Buffer.isBuffer(buf) || !buf.length) return res.status(400).json({ error: "Send the email as the raw request body (.eml bytes or pasted text)." });
  if (flag(o.save) && !flag(o.consent)) return res.status(400).json({ error: "Explicit consent is required to save an investigation to your account." });
  if (flag(o.storeOriginal) && !flag(o.save)) return res.status(400).json({ error: "storeOriginal requires saving the investigation." });
  try {
    const { verdict, score, analysis } = await buildAnalysis(buf);
    const sha = sha256Hex(buf);
    const reference = "EML-" + randomUUID();
    const row = {
      reference, title: o.title || analysis.metadata.subject || "Email investigation", verdict, score, is_sample: flag(o.sample),
      original_sha256: sha, original_size: buf.length, input_kind: o.kind === "file" ? "file" : "paste", analysis, ai_summary: null,
    };
    if (!flag(o.save)) return res.set("Cache-Control", "no-store").json(toView(row));

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const ins = await client.query(
        "INSERT INTO investigations(user_id,reference,title,verdict,score,is_sample,original_sha256,original_size,input_kind,analysis,consent_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW()) RETURNING id,created_at,case_id",
        [req.user.id, row.reference, row.title, verdict, score, row.is_sample, sha, buf.length, row.input_kind, JSON.stringify(analysis)]);
      Object.assign(row, ins.rows[0]);
      await audit(req.user.id, "investigation.create", "investigation", row.id, { reference, sha256: sha, size: buf.length, sample: row.is_sample, storedOriginal: flag(o.storeOriginal) }, client);
      if (flag(o.storeOriginal)) {
        const ev = await client.query(
          "INSERT INTO evidence(user_id,investigation_id,sha256,source,evidence_type,integrity,file_name,size_bytes,content) VALUES($1,$2,$3,$4,'email-original','sha256-recorded-at-intake',$5,$6,$7) RETURNING id",
          [req.user.id, row.id, sha, row.input_kind, o.filename ? o.filename.replace(/[\u0000-\u001f\\/]+/g, "_") : null, buf.length, buf]);
        await audit(req.user.id, "evidence.store", "evidence", ev.rows[0].id, { investigationId: row.id, sha256: sha }, client);
      }
      await client.query("COMMIT");
    } catch (e) { await client.query("ROLLBACK").catch(() => {}); throw e; } finally { client.release(); }
    res.status(201).set("Cache-Control", "no-store").json(toView(row, { storedOriginal: flag(o.storeOriginal) }));
  } catch (e) {
    if (e instanceof ParseError) return res.status(422).json({ error: e.message });
    next(e);
  }
});

const COLUMNS = "id,case_id,reference,title,verdict,score,is_sample,original_sha256,original_size,input_kind,analysis,ai_summary,created_at";
async function owned(id, userId) {
  const r = await pool.query(`SELECT ${COLUMNS} FROM investigations WHERE id=$1 AND user_id=$2`, [id, userId]);
  return r.rows[0] ?? null;
}
const lookupsFor = async (id, userId) =>
  (await pool.query("SELECT indicator,kind,provider,status,result,checked_at FROM reputation_lookups WHERE investigation_id=$1 AND user_id=$2 ORDER BY checked_at DESC", [id, userId])).rows;

router.get("/", async (req, res, next) => {
  const q = z.object({ q: z.string().trim().max(100).optional(), limit: z.coerce.number().int().min(1).max(100).default(25), offset: z.coerce.number().int().min(0).default(0), caseId: uuid.optional() }).safeParse(req.query);
  if (!q.success) return res.status(400).json({ error: "Invalid query." });
  try {
    const { q: term, limit, offset, caseId } = q.data;
    const like = term ? `%${term.replace(/[\\%_]/g, "\\$&")}%` : null;
    const r = await pool.query(
      `SELECT i.id,i.case_id,i.reference,i.title,i.verdict,i.score,i.is_sample,i.original_sha256,i.created_at,
              EXISTS(SELECT 1 FROM evidence e WHERE e.investigation_id=i.id AND e.content IS NOT NULL) AS original_stored,
              count(*) OVER()::int AS total
       FROM investigations i WHERE i.user_id=$1
         AND ($2::text IS NULL OR i.title ILIKE $2 OR i.reference ILIKE $2 OR i.original_sha256 ILIKE $2)
         AND ($3::uuid IS NULL OR i.case_id=$3)
       ORDER BY i.created_at DESC LIMIT $4 OFFSET $5`, [req.user.id, like, caseId ?? null, limit, offset]);
    res.set("Cache-Control", "no-store").json({ investigations: r.rows.map(({ total, ...x }) => x), total: r.rows[0]?.total ?? 0 });
  } catch (e) { next(e); }
});

router.get("/:id", async (req, res, next) => {
  const id = uuid.safeParse(req.params.id);
  if (!id.success) return res.status(400).json({ error: "Invalid investigation id." });
  try {
    const row = await owned(id.data, req.user.id);
    if (!row) return res.status(404).json({ error: "Investigation not found" });
    const [lookups, ev] = await Promise.all([lookupsFor(row.id, req.user.id),
      pool.query("SELECT id,file_name,size_bytes,last_verified_at,last_verified_ok,(content IS NOT NULL) AS stored FROM evidence WHERE investigation_id=$1 AND user_id=$2", [row.id, req.user.id])]);
    await audit(req.user.id, "investigation.view", "investigation", row.id, { reference: row.reference });
    res.set("Cache-Control", "no-store").json(toView(row, { reputation: lookups, evidenceRecords: ev.rows }));
  } catch (e) { next(e); }
});

router.patch("/:id", async (req, res, next) => {
  const id = uuid.safeParse(req.params.id);
  const body = z.object({ title: z.string().trim().min(1).max(160).optional(), caseId: uuid.nullable().optional() }).refine(b => b.title !== undefined || b.caseId !== undefined).safeParse(req.body);
  if (!id.success || !body.success) return res.status(400).json({ error: "Invalid update." });
  try {
    if (body.data.caseId) {
      const c = await pool.query("SELECT 1 FROM cases WHERE id=$1 AND investigator_id=$2", [body.data.caseId, req.user.id]);
      if (!c.rowCount) return res.status(404).json({ error: "Case not found" });
    }
    const r = await pool.query(
      "UPDATE investigations SET title=COALESCE($1,title), case_id=CASE WHEN $2::boolean THEN $3::uuid ELSE case_id END, updated_at=NOW() WHERE id=$4 AND user_id=$5 RETURNING id,title,case_id",
      [body.data.title ?? null, body.data.caseId !== undefined, body.data.caseId ?? null, id.data, req.user.id]);
    if (!r.rowCount) return res.status(404).json({ error: "Investigation not found" });
    await audit(req.user.id, "investigation.update", "investigation", id.data, { renamed: body.data.title !== undefined, caseId: body.data.caseId });
    res.json({ investigation: r.rows[0] });
  } catch (e) { next(e); }
});

router.delete("/:id", async (req, res, next) => {
  const id = uuid.safeParse(req.params.id);
  if (!id.success) return res.status(400).json({ error: "Invalid investigation id." });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const r = await client.query("DELETE FROM investigations WHERE id=$1 AND user_id=$2 RETURNING reference,original_sha256", [id.data, req.user.id]);
    if (!r.rowCount) { await client.query("ROLLBACK"); return res.status(404).json({ error: "Investigation not found" }); }
    await audit(req.user.id, "investigation.delete", "investigation", id.data, { reference: r.rows[0].reference, sha256: r.rows[0].original_sha256 }, client);
    await client.query("COMMIT");
    res.json({ ok: true });
  } catch (e) { await client.query("ROLLBACK").catch(() => {}); next(e); } finally { client.release(); }
});

router.get("/:id/graph", async (req, res, next) => {
  const id = uuid.safeParse(req.params.id);
  if (!id.success) return res.status(400).json({ error: "Invalid investigation id." });
  try {
    const row = await owned(id.data, req.user.id);
    if (!row) return res.status(404).json({ error: "Investigation not found" });
    res.set("Cache-Control", "no-store").json({ graph: buildGraph(row.analysis, await lookupsFor(row.id, req.user.id)) });
  } catch (e) { next(e); }
});

router.post("/:id/summary", async (req, res, next) => {
  const id = uuid.safeParse(req.params.id);
  const body = z.object({ mode: z.enum(["rule", "ai"]).default("rule"), confirm: z.boolean().optional() }).safeParse(req.body ?? {});
  if (!id.success || !body.success) return res.status(400).json({ error: "Invalid request." });
  if (body.data.mode === "ai" && body.data.confirm !== true) return res.status(400).json({ error: "Confirm that the evidence facts (no email body or attachment content) may be sent to the AI provider." });
  try {
    const row = await owned(id.data, req.user.id);
    if (!row) return res.status(404).json({ error: "Investigation not found" });
    const facts = buildFacts(row, await lookupsFor(row.id, req.user.id));
    const summary = body.data.mode === "ai" ? await aiSummary(facts) : ruleBasedSummary(facts);
    await pool.query("UPDATE investigations SET ai_summary=$1,updated_at=NOW() WHERE id=$2 AND user_id=$3", [JSON.stringify(summary), row.id, req.user.id]);
    await audit(req.user.id, body.data.mode === "ai" ? "summary.ai" : "summary.rule", "investigation", row.id, { model: summary.model, statements: summary.statements.length });
    res.json({ summary });
  } catch (e) {
    if (e.status && e.status !== 500) return res.status(e.status).json({ error: e.message });
    next(e);
  }
});

router.get("/:id/report", async (req, res, next) => {
  const id = uuid.safeParse(req.params.id);
  const fmt = z.enum(["detailed", "executive"]).default("detailed").safeParse(req.query.format ?? undefined);
  if (!id.success || !fmt.success) return res.status(400).json({ error: "Invalid request." });
  try {
    const row = await owned(id.data, req.user.id);
    if (!row) return res.status(404).json({ error: "Investigation not found" });
    const [lookups, events, ev] = await Promise.all([
      lookupsFor(row.id, req.user.id),
      pool.query("SELECT action,created_at FROM audit_logs WHERE user_id=$1 AND ((entity='investigation' AND entity_id=$2) OR (entity='evidence' AND metadata->>'investigationId'=$2)) ORDER BY created_at ASC LIMIT 200", [req.user.id, row.id]),
      pool.query("SELECT last_verified_at,last_verified_ok FROM evidence WHERE investigation_id=$1 AND user_id=$2 AND content IS NOT NULL", [row.id, req.user.id]),
    ]);
    const report = buildReport(row, { lookups, events: events.rows, storedEvidence: ev.rows[0] ?? null, format: fmt.data });
    await audit(req.user.id, "report.generate", "investigation", row.id, { format: fmt.data });
    res.set("Cache-Control", "no-store").json({ report });
  } catch (e) { next(e); }
});

router.get("/:id/audit", async (req, res, next) => {
  const id = uuid.safeParse(req.params.id);
  if (!id.success) return res.status(400).json({ error: "Invalid investigation id." });
  try {
    const r = await pool.query("SELECT id,action,entity,entity_id,metadata,created_at FROM audit_logs WHERE user_id=$1 AND ((entity='investigation' AND entity_id=$2) OR (entity='evidence' AND metadata->>'investigationId'=$2)) ORDER BY created_at DESC LIMIT 200", [req.user.id, id.data]);
    res.set("Cache-Control", "no-store").json({ events: r.rows });
  } catch (e) { next(e); }
});

export default router;
