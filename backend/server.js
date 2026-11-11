import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

import authRoutes from "./routes/auth.js";
import investigationRoutes from "./routes/investigations.js";

const app = express();
const port = Number(process.env.PORT || 4000);

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is required");
}
if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must be set to at least 32 characters");
}

const allowedOrigins = (process.env.CLIENT_ORIGIN || "http://localhost:5173")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    // Requests without Origin are commonly server-to-server/CLI requests.
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(null, new Error("CORS origin not allowed"));
  },
  credentials: true,
}));
app.use(helmet());
app.use(express.json({ limit: "2mb" }));

app.use("/api/auth", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
}), authRoutes);

app.use("/api", rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: "draft-7",
  legacyHeaders: false,
}));

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, service: "CyberLens API" });
});

app.use("/api/investigations", investigationRoutes);

app.use((req, res) => res.status(404).json({ error: "Route not found" }));

app.use((err, _req, res, _next) => {
  console.error("SERVER ERROR:", err);
  if (err.message === "CORS origin not allowed") {
    return res.status(403).json({ error: "Origin not allowed" });
  }
  res.status(500).json({ error: "Internal server error" });
});

app.listen(port, () => {
  console.log(`CyberLens API listening on port ${port}`);
});
