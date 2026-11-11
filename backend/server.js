import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

import authRoutes from "./routes/auth.js";
import investigationRoutes from "./routes/investigations.js";

const app = express();

/* =========================
   CORS
========================= */

const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:5174",
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

app.listen(port, () => {
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