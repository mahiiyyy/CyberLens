import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { z } from "zod";
const router = Router();

const loginSchema = z.object({ email: z.string().email(), password: z.string().min(6) });

router.post("/login", async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Invalid credentials format" });

  // Prototype auth: replace with PostgreSQL user lookup in production.
  const token = jwt.sign({ sub: "demo-user", email: parsed.data.email, role: "ANALYST" }, process.env.JWT_SECRET, { expiresIn: "2h" });
  res.json({ token, user: { email: parsed.data.email, role: "ANALYST" } });
});

export default router;
