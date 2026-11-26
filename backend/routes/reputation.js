import { Router } from "express";
import rateLimit from "express-rate-limit";
import { z } from "zod";
import { pool } from "../db/pool.js";
import { requireAuth } from "../middleware/auth.js";
import { audit } from "../services/audit.js";
import { PROVIDERS, providerStatus, normalizeIndicator, lookupIndicator, IndicatorError } from "../services/reputation.js";
import { emailDomain } from "../services/indicators.js";

const router = Router();
router.use(requireAuth);
const CACHE_HOURS = 24;

// Third-party quota protection, keyed per account (requireAuth has already run).
const limiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false, keyGenerator: req => req.user.id, message: { error: "Reputation lookup limit reached. Try again later." } });

router.get("/providers", (_req, res) => res.json({ providers: providerStatus() }));

/** Indicators that actually occur in a saved investigation. Lookups for a saved case are restricted to these. */
function allowedIndicators(row) {
  const a = row.analysis, set = new Set([row.original_sha256]);
  for (const u of a.urls) { set.add(u.url); if (u.host) set.add(u.host); }
  for (const x of [...a.metadata.from, ...a.metadata.replyTo]) set.add(emailDomain(x.address));
  if (a.metadata.returnPath) set.add(emailDomain(a.metadata.returnPath));
  for (const h of a.received) { for (const i of h.ips) if (i.public) set.add(i.ip); }
  for (const at of a.attachments) set.add(at.sha256);
  for (const l of a.htmlLinks) if (l.hrefHost) set.add(l.hrefHost);
  return set;
}

const body = z.object({
  indicators: z.array(z.object({ type: z.enum(["url", "domain", "ip", "sha256"]), value: z.string().max(2048) })).min(1).max(10),
  investigationId: z.string().uuid().optional(),
  confirm: z.literal(true, { errorMap: () => ({ message: "Explicit confirmation is required before indicators are sent to third-party services." }) }),
});

router.post("/lookup", limiter, async (req, res, next) => {
  const parsed = body.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message || "Invalid lookup request." });
  const { indicators, investigationId } = parsed.data;
  try {
    let allowed = null;
    if (investigationId) {
      const r = await pool.query("SELECT original_sha256,analysis FROM investigations WHERE id=$1 AND user_id=$2", [investigationId, req.user.id]);
      if (!r.rowCount) return res.status(404).json({ error: "Investigation not found" });
      allowed = allowedIndicators(r.rows[0]);
    }
    const out = [], rejected = [];
    for (const raw of indicators) {
      let ind;
      try { ind = normalizeIndicator(raw); } catch (e) { if (e instanceof IndicatorError) { rejected.push({ ...raw, reason: e.message }); continue; } throw e; }
      if (allowed && !allowed.has(ind.value)) { rejected.push({ ...raw, reason: "Indicator does not occur in this investigation." }); continue; }
      const cached = investigationId ? (await pool.query(
        `SELECT DISTINCT ON (provider) indicator,kind,provider,status,result,checked_at FROM reputation_lookups
         WHERE user_id=$1 AND indicator=$2 AND kind=$3 AND status IN ('ok','not_found') AND checked_at > NOW() - make_interval(hours => $4)
         ORDER BY provider,checked_at DESC`, [req.user.id, ind.value, ind.kind, CACHE_HOURS])).rows : [];
      const have = new Set(cached.map(c => c.provider));
      for (const c of cached) out.push({ indicator: c.indicator, kind: c.kind, provider: c.provider, status: c.status, result: c.result, checkedAt: c.checked_at, cached: true });
      out.push(...await lookupIndicator(ind, { providers: Object.keys(PROVIDERS).filter(p => !have.has(p)) }));
    }
    // Persist only for a saved investigation (the user already consented to storing it) and only real provider answers.
    if (investigationId) {
      for (const r of out) {
        if (r.cached || !["ok", "not_found"].includes(r.status)) continue;
        await pool.query("INSERT INTO reputation_lookups(user_id,investigation_id,indicator,kind,provider,status,result,checked_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
          [req.user.id, investigationId, r.indicator, r.kind, r.provider, r.status, JSON.stringify({ ...r.result, sent: r.sent, redacted: r.redacted }), r.checkedAt]);
      }
    }
    await audit(req.user.id, "reputation.lookup", "investigation", investigationId ?? null, {
      requested: indicators.length, kinds: [...new Set(out.map(r => r.kind))], providers: [...new Set(out.filter(r => !r.cached && r.status !== "not_configured").map(r => r.provider))], persisted: !!investigationId, rejected: rejected.length });
    res.set("Cache-Control", "no-store").json({ results: out, rejected, note: "Third-party opinions. 'No detections' or 'not found' is not proof an indicator is safe. Indicators were queried by value only and never visited." });
  } catch (e) { next(e); }
});

export default router;
