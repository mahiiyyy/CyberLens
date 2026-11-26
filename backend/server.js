import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { readFile } from "node:fs/promises";
import { pool } from "./db/pool.js";

import authRoutes from "./routes/auth.js";
import investigationRoutes from "./routes/investigations.js";

const app = express();

/* =========================
   CORS
========================= */

const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:5174",
  process.env.CLIENT_ORIGIN,
  process.env.RENDER_EXTERNAL_URL,
];

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests without an origin
      // such as curl/Postman/server-to-server
      if (!origin) {
        return callback(null, true);
      }

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error(`CORS blocked origin: ${origin}`));
    },
    credentials: true,
  })
);

/* =========================
   SECURITY
========================= */

app.set("trust proxy", 1);
app.use(helmet());

/* =========================
   BODY PARSER
========================= */

app.use(
  express.json({
    limit: "2mb",
  })
);

/* =========================
   RATE LIMIT
========================= */

app.use(
  rateLimit({
    windowMs: 60 * 1000,
    limit: 120,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

/* =========================
   HEALTH CHECK
========================= */

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    service: "CyberLens API",
    stack: "PERN + JavaScript",
  });
});

/* =========================
   API ROUTES
========================= */

app.use("/api/auth", authRoutes);

app.use("/api/investigations", investigationRoutes);

if (process.env.NODE_ENV === "production") {
  const dist = fileURLToPath(new URL("../frontend/dist/", import.meta.url));
  app.use(express.static(dist));
  app.get("*", (req, res, next) => {
    if (req.path.startsWith("/api/")) return next();
    res.sendFile(path.join(dist, "index.html"));
  });
}

/* =========================
   ERROR HANDLER
========================= */

app.use((err, _req, res, _next) => {
  console.error("SERVER ERROR:", err);

  if (err.message?.startsWith("CORS blocked")) {
    return res.status(403).json({
      error: "CORS blocked",
      message: err.message,
    });
  }

  res.status(500).json({
    error: "Internal server error",
  });
});

/* =========================
   START SERVER
========================= */

const port = process.env.PORT || 4000;

if (!process.env.DATABASE_URL || !process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) { throw new Error("DATABASE_URL and a strong JWT_SECRET are required"); }
if (process.env.DATABASE_URL) {
  await pool.query(await readFile(new URL("./db/schema.sql", import.meta.url), "utf8"));
}

app.listen(port, "0.0.0.0", () => {
  console.log(`
╔══════════════════════════════════════════╗
║          CYBERLENS API SERVER            ║
╠══════════════════════════════════════════╣
║  API:       http://localhost:${port}       ║
║  Frontend:  http://localhost:5174        ║
║  Status:    RUNNING                      ║
╚══════════════════════════════════════════╝
`);
});