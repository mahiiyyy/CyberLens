import jwt from "jsonwebtoken";

export function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Authentication required" });

  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
    return res.status(503).json({ error: "Authentication is not configured" });
  }

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET, {
      issuer: "cyberlens-api",
      audience: "cyberlens-client",
      algorithms: ["HS256"],
    });
    if (!req.user.sub || !req.user.role) {
      return res.status(401).json({ error: "Invalid token claims" });
    }
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

export function requireRole(...roles) {
  return (req, res, next) =>
    roles.includes(req.user?.role)
      ? next()
      : res.status(403).json({ error: "Insufficient role" });
}
