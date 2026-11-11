import { Router } from "express";
import { requireAuth } from "../middleware/auth.js";

const router = Router();
const AI_URL = process.env.AI_SERVICE_URL || "http://127.0.0.1:8000";

const demo = {
  caseId: "EML-2026-0912",
  subject: "Urgent: Acme Bank Security Alert — Verify Your Account",
  body: "Your account has unusual activity. Verify your account immediately to avoid suspension. Click here to sign in and confirm your credentials.",
  sender: "security@acme-bank-alert.example",
  reply_to: "verify@acme-support.example",
  return_path: "bounce@mx-acme-alert.example",
  urls: ["https://acme-bank-verify.example/login?session=7f92a"],
  authentication: { spf: "FAIL", dkim: "FAIL", dmarc: "FAIL" },
  header_mismatches: ["From domain differs from Reply-To domain", "From domain does not match claimed Acme Bank identity"],
};

const extractUrls = (text = "") => [...text.matchAll(/https?:\/\/[^\s<>"')]+/gi)].map(m => m[0].replace(/[.,;]+$/, ""));
const domainOf = (email = "") => email.includes("@") ? email.split("@")[1].toLowerCase() : "";
const scoreVerdict = score => score >= 75 ? "PHISHING / IMPERSONATION" : score >= 50 ? "SUSPICIOUS" : score >= 25 ? "NEEDS REVIEW" : "BENIGN / LEGITIMATE";

function deterministicAnalysis(e) {
  const fromDomain = domainOf(e.sender);
  const replyDomain = domainOf(e.reply_to);
  const returnDomain = domainOf(e.return_path);
  const urls = e.urls?.length ? e.urls : extractUrls(`${e.subject}\n${e.body}`);
  const text = `${e.subject} ${e.body}`.toLowerCase();
  let score = 0;
  const factors = [];

  if (fromDomain && replyDomain && fromDomain !== replyDomain) { score += 18; factors.push(["Sender anomaly", 18, "Reply-To domain differs from visible sender domain."]); }
  if (fromDomain && returnDomain && fromDomain !== returnDomain) { score += 8; factors.push(["Return-Path anomaly", 8, "Return-Path domain differs from sender domain."]); }
  for (const [key, label, pts] of [["spf","SPF",12],["dkim","DKIM",10],["dmarc","DMARC",12]]) {
    if (String(e.authentication?.[key] || "").toUpperCase() === "FAIL") { score += pts; factors.push([`${label} failure`, pts, `${label} authentication reported FAIL.`]); }
  }
  if (urls.length) {
    const suspicious = urls.filter(u => /\/(login|verify|signin|password|account|secure)/i.test(u));
    if (suspicious.length) { score += 16; factors.push(["URL risk", 16, "URL contains an authentication or credential-oriented path."]); }
  }
  const urgency = ["urgent", "immediately", "suspend", "suspended", "verify", "confirm your account", "unusual activity", "password", "credential"].filter(x => text.includes(x)).length;
  if (urgency) { const pts = Math.min(16, urgency * 2); score += pts; factors.push(["Social engineering", pts, `Detected ${urgency} urgency/account-pressure indicator(s).`]); }
  return { score: Math.min(100, score), factors, urls, fromDomain, replyDomain };
}

async function runAI(evidence) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2500);
    const r = await fetch(`${AI_URL}/analyze`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(evidence), signal: controller.signal });
    clearTimeout(timer);
    if (!r.ok) throw new Error(`AI service ${r.status}`);
    return await r.json();
  } catch {
    // Local fallback keeps the prototype functional if Python is not running.
    const text = `${evidence.subject} ${evidence.body}`.toLowerCase();
    const hits = ["urgent","verify","password","credential","suspend","login","click here","unusual activity"].filter(x => text.includes(x));
    const aiScore = Math.min(100, hits.length * 11);
    return {
      model: "CyberLens Local Fallback NLP",
      mode: "local-fallback",
      verdict: scoreVerdict(aiScore),
      label: aiScore >= 75 ? "malicious" : aiScore >= 50 ? "suspicious" : aiScore >= 25 ? "review" : "benign",
      confidence: 70 + Math.min(25, hits.length * 3), ai_score: aiScore,
      findings: [{ title: hits.length ? "Semantic phishing indicators" : "No strong phishing language detected", severity: hits.length >= 4 ? "HIGH" : "LOW", confidence: 78, evidence: hits.join(", ") || "none", explanation: "Fallback local NLP was used because the FastAPI AI service was unavailable." }],
      explanation: `Fallback local NLP detected ${hits.length} high-weight semantic indicator(s).`
    };
  }
}

router.get("/demo", requireAuth, (_req, res) => res.json({ ...demo, status: "ready" }));

router.get("/ai-status", requireAuth, async (_req, res) => {
  try {
    const r = await fetch(`${AI_URL}/health`);
    const data = await r.json();
    res.json({ connected: r.ok, ...data });
  } catch {
    res.status(503).json({ connected: false, error: "AI service unavailable" });
  }
});

router.post("/analyze", requireAuth, async (req, res, next) => {
  try {
    const input = { ...req.body };
    const deterministic = deterministicAnalysis(input);
    const evidence = { ...input, urls: deterministic.urls, header_mismatches: input.header_mismatches || [] };
    const ai = await runAI(evidence);

    // Correlation rule: deterministic evidence has priority. AI can raise confidence,
    // but it cannot turn a clean email into phishing on semantic language alone.
    const finalScore = Math.min(100, Math.round(deterministic.score * 0.65 + ai.ai_score * 0.35));
    const verdict = scoreVerdict(finalScore);
    const combinedFindings = [
      ...deterministic.factors.map(([title, contribution, explanation]) => ({ title, severity: contribution >= 15 ? "CRITICAL" : contribution >= 10 ? "HIGH" : "MEDIUM", contribution, confidence: 94, evidence: explanation, explanation })),
      ...ai.findings.map(f => ({ ...f, contribution: 0 }))
    ];

    res.json({
      caseId: input.caseId || `EML-${Date.now()}`,
      status: "complete",
      verdict,
      label: verdict.startsWith("BENIGN") ? "benign" : verdict.startsWith("PHISHING") ? "malicious" : verdict === "SUSPICIOUS" ? "suspicious" : "review",
      score: finalScore,
      confidence: ai.confidence,
      aiScore: ai.ai_score,
      aiModel: ai.model,
      aiMode: ai.mode,
      deterministicScore: deterministic.score,
      factors: deterministic.factors,
      findings: combinedFindings,
      evidence: { ...input, urls: deterministic.urls },
      aiExplanation: ai.explanation,
    });
  } catch (err) { next(err); }
});

export default router;
