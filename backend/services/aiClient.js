import { scoreVerdict } from "./scoring.js";

const AI_URL = () => process.env.AI_SERVICE_URL || "http://127.0.0.1:8000";

/** Local text-heuristic model (FastAPI) with an honest local fallback. Sends nothing off-machine by default. */
export async function runAI(evidence) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2500);
    const r = await fetch(`${AI_URL()}/analyze`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(evidence), signal: controller.signal });
    clearTimeout(timer);
    if (!r.ok) throw new Error(`AI service ${r.status}`);
    return await r.json();
  } catch {
    const text = `${evidence.subject} ${evidence.body}`.toLowerCase();
    const hits = ["urgent", "verify", "password", "credential", "suspend", "login", "click here", "unusual activity"].filter(x => text.includes(x));
    const aiScore = Math.min(100, hits.length * 11);
    return {
      model: "CyberLens Local Fallback NLP", mode: "local-fallback",
      verdict: scoreVerdict(aiScore), confidence: 70 + Math.min(25, hits.length * 3), ai_score: aiScore,
      findings: [{ title: hits.length ? "Semantic phishing indicators" : "No strong phishing language detected", severity: hits.length >= 4 ? "HIGH" : "LOW", confidence: 78, evidence: hits.join(", ") || "none", explanation: "Keyword fallback was used because the FastAPI AI service was unavailable." }],
      explanation: `Fallback keyword analysis matched ${hits.length} indicator(s).`,
    };
  }
}

export async function aiStatus() {
  try {
    const r = await fetch(`${AI_URL()}/health`, { signal: AbortSignal.timeout(2500) });
    return { connected: r.ok, ...(await r.json()) };
  } catch { return { connected: false, error: "AI service unavailable" }; }
}
