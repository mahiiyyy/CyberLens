import { Router, raw } from "express";
import { timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { pool } from "../db/pool.js";
import { requireAuth } from "../middleware/auth.js";
import { audit } from "../services/audit.js";
import { sha256Hex } from "../services/hash.js";
import { MAX_EML_BYTES } from "../services/emailParser.js";

const router = Router();
router.use(requireAuth);
const uuid = z.string().uuid();
const same = (a, b) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

/** Evidence records for every saved investigation: recorded hash, and whether the original bytes are stored. */
router.get("/", async (req, res, next) => {
  try {
    const r = await pool.query(
      `SELECT i.id AS investigation_id,i.reference,i.title,i.original_sha256 AS sha256,i.original_size AS size_bytes,i.input_kind,i.created_at,i.is_sample,
              e.id AS evidence_id,e.file_name,(e.content IS NOT NULL) AS original_stored,e.last_verified_at,e.last_verified_ok
       FROM investigations i LEFT JOIN evidence e ON e.investigation_id=i.id AND e.user_id=i.user_id
       WHERE i.user_id=$1 ORDER BY i.created_at DESC LIMIT 200`, [req.user.id]);
    res.set("Cache-Control", "no-store").json({ evidence: r.rows });
  } catch (e) { next(e); }
});

async function stored(investigationId, userId) {
  const r = await pool.query(
    "SELECT e.id,e.file_name,e.content,e.sha256 AS evidence_sha256,i.original_sha256,i.reference FROM evidence e JOIN investigations i ON i.id=e.investigation_id WHERE e.investigation_id=$1 AND e.user_id=$2 AND i.user_id=$2 AND e.content IS NOT NULL",
    [investigationId, userId]);
  return r.rows[0] ?? null;
}

/** Re-hash the stored original and compare with the hash recorded at intake. */
router.post("/:investigationId/verify", async (req, res, next) => {
  const id = uuid.safeParse(req.params.investigationId);
  if (!id.success) return res.status(400).json({ error: "Invalid investigation id." });
  try {
    const ev = await stored(id.data, req.user.id);
    if (!ev) return res.status(409).json({ error: "The original file was not stored for this investigation, so it cannot be re-verified." });
    const current = sha256Hex(ev.content);
    const ok = same(current, ev.original_sha256) && same(current, ev.evidence_sha256);
    await pool.query("UPDATE evidence SET last_verified_at=NOW(),last_verified_ok=$1 WHERE id=$2 AND user_id=$3", [ok, ev.id, req.user.id]);
    await audit(req.user.id, ok ? "evidence.verify.match" : "evidence.verify.MISMATCH", "evidence", ev.id, { investigationId: id.data, recorded: ev.original_sha256, current });
    res.json({ match: ok, recordedSha256: ev.original_sha256, currentSha256: current, verifiedAt: new Date().toISOString() });
  } catch (e) { next(e); }
});

/** Hash a file supplied now and compare with the recorded intake hash (works even if the original was not stored). */
router.post("/:investigationId/compare", raw({ type: () => true, limit: MAX_EML_BYTES }), async (req, res, next) => {
  const id = uuid.safeParse(req.params.investigationId);
  if (!id.success) return res.status(400).json({ error: "Invalid investigation id." });
  if (!Buffer.isBuffer(req.body) || !req.body.length) return res.status(400).json({ error: "Send the file bytes as the request body." });
  try {
    const r = await pool.query("SELECT original_sha256 FROM investigations WHERE id=$1 AND user_id=$2", [id.data, req.user.id]);
    if (!r.rowCount) return res.status(404).json({ error: "Investigation not found" });
    const current = sha256Hex(req.body);
    const ok = same(current, r.rows[0].original_sha256);
    await audit(req.user.id, ok ? "evidence.compare.match" : "evidence.compare.mismatch", "evidence", id.data, { investigationId: id.data, recorded: r.rows[0].original_sha256, provided: current });
    res.json({ match: ok, recordedSha256: r.rows[0].original_sha256, providedSha256: current, size: req.body.length });
  } catch (e) { next(e); }
});

/** Download the stored original. It is integrity-checked first and always served as an opaque attachment. */
router.get("/:investigationId/download", async (req, res, next) => {
  const id = uuid.safeParse(req.params.investigationId);
  if (!id.success) return res.status(400).json({ error: "Invalid investigation id." });
  try {
    const ev = await stored(id.data, req.user.id);
    if (!ev) return res.status(404).json({ error: "No stored original for this investigation." });
    if (!same(sha256Hex(ev.content), ev.original_sha256)) {
      await audit(req.user.id, "evidence.download.BLOCKED_INTEGRITY", "evidence", ev.id, { investigationId: id.data });
      return res.status(409).json({ error: "Stored evidence failed its integrity check and was not released." });
    }
    await audit(req.user.id, "evidence.download", "evidence", ev.id, { investigationId: id.data, sha256: ev.original_sha256 });
    res.set({ "Content-Type": "application/octet-stream", "Content-Disposition": `attachment; filename="${ev.reference}.eml.bin"`, "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store" }).send(ev.content);
  } catch (e) { next(e); }
});

/** Remove only the stored bytes; the recorded hash and analysis remain. */
router.delete("/:investigationId/original", async (req, res, next) => {
  const id = uuid.safeParse(req.params.investigationId);
  if (!id.success) return res.status(400).json({ error: "Invalid investigation id." });
  try {
    const r = await pool.query("DELETE FROM evidence WHERE investigation_id=$1 AND user_id=$2 RETURNING id", [id.data, req.user.id]);
    if (!r.rowCount) return res.status(404).json({ error: "No stored original for this investigation." });
    await audit(req.user.id, "evidence.delete", "evidence", r.rows[0].id, { investigationId: id.data });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

export default router;
