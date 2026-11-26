import { Router } from "express";
import { z } from "zod";
import { pool } from "../db/pool.js";
import { requireAuth } from "../middleware/auth.js";

const router = Router();
router.use(requireAuth);

/** The caller's own audit trail only. Append-only from the API: there is no write or delete endpoint. */
router.get("/", async (req, res, next) => {
  const q = z.object({ limit: z.coerce.number().int().min(1).max(200).default(50), offset: z.coerce.number().int().min(0).default(0), entity: z.enum(["investigation", "evidence", "case"]).optional() }).safeParse(req.query);
  if (!q.success) return res.status(400).json({ error: "Invalid query." });
  try {
    const r = await pool.query(
      "SELECT id,action,entity,entity_id,metadata,created_at FROM audit_logs WHERE user_id=$1 AND ($2::text IS NULL OR entity=$2) ORDER BY created_at DESC, id LIMIT $3 OFFSET $4",
      [req.user.id, q.data.entity ?? null, q.data.limit, q.data.offset]);
    res.set("Cache-Control", "no-store").json({ events: r.rows });
  } catch (e) { next(e); }
});
export default router;
