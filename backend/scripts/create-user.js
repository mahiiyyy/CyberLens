import "dotenv/config";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { pool } from "../db/pool.js";

const args = process.argv.slice(2);
const input = z.object({
  email: z.string().trim().email().max(254),
  password: z.string().min(12).max(128),
  role: z.enum(["ADMIN", "ANALYST", "INVESTIGATOR"]).default("ADMIN"),
}).safeParse({ email: args[0], password: args[1], role: args[2] || "ADMIN" });

if (!input.success) {
  console.error("Usage: npm run create-user -- <email> <password-at-least-12-chars> [ADMIN|ANALYST|INVESTIGATOR]");
  process.exit(1);
}

try {
  const { email, password, role } = input.data;
  const passwordHash = await bcrypt.hash(password, 12);
  const result = await pool.query(
    "INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) ON CONFLICT (email) DO NOTHING RETURNING id",
    [email.toLowerCase(), passwordHash, role]
  );
  if (!result.rowCount) {
    console.error("That email is already registered; no account was changed.");
    process.exitCode = 1;
  } else {
    console.log("User account created.");
  }
} catch (error) {
  console.error("Could not create user:", error.message);
  process.exitCode = 1;
} finally {
  await pool.end();
}
