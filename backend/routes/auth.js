import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { z } from "zod";
import { pool } from "../db/pool.js";

const router = Router();
const loginSchema = z.object({
  email: z.string().trim().email().max(254),
  password: z.string().min(8).max(128),
});

router.post("/login", async (req, res, next) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "Enter a valid email and password (8–128 characters)." });
  }

  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
    return res.status(503).json({ error: "Authentication is not configured. Contact the administrator." });
  }

  try {
    const email = parsed.data.email.toLowerCase();
    const result = await pool.query(
      "SELECT id, email, password_hash, role FROM users WHERE email = $1 LIMIT 1",
      [email]
    );
    const user = result.rows[0];
    const valid = user ? await bcrypt.compare(parsed.data.password, user.password_hash) : false;

    // Use the same response for unknown users and incorrect passwords.
    if (!valid) return res.status(401).json({ error: "Invalid email or password." });

    const token = jwt.sign(
      { sub: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "2h", issuer: "cyberlens-api", audience: "cyberlens-client" }
    );

    await pool.query(
      "INSERT INTO audit_logs (user_id, action, entity, entity_id, metadata) VALUES ($1, $2, $3, $4, $5)",
      [user.id, "LOGIN", "USER", user.id, JSON.stringify({ email: user.email })]
    );

    res.json({
      token,
      user: { id: user.id, email: user.email, role: user.role },
    });
  } catch (err) {
    next(err);
  }
});

export default router;
