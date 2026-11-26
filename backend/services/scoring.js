import { emailDomain } from "./indicators.js";

export const scoreVerdict = score =>
  score >= 75 ? "PHISHING / IMPERSONATION" : score >= 50 ? "SUSPICIOUS" : score >= 25 ? "NEEDS REVIEW" : "BENIGN / LEGITIMATE";

export const labelFor = verdict =>
  verdict.startsWith("BENIGN") ? "benign" : verdict.startsWith("PHISHING") ? "malicious" : verdict === "SUSPICIOUS" ? "suspicious" : "review";

const URGENCY = ["urgent", "immediately", "suspend", "suspended", "verify", "confirm your account", "unusual activity", "password", "credential"];

/**
 * Deterministic heuristics over *parsed* message data. Every factor cites the evidence it came from.
 * Returns factors as [title, points, explanation, evidenceRef] tuples (first three keep the legacy shape).
 */
export function deterministicAnalysis(parsed) {
  const m = parsed.metadata;
  const fromDomain = emailDomain(m.from[0]?.address);
  const replyDomain = emailDomain(m.replyTo[0]?.address);
  const returnDomain = emailDomain(m.returnPath);
  const auth = parsed.authentication;
  const factors = [];
  const add = (title, pts, explanation, ref) => factors.push([title, pts, explanation, ref]);

  if (fromDomain && replyDomain && fromDomain !== replyDomain) add("Sender anomaly", 18, `Reply-To domain (${replyDomain}) differs from From domain (${fromDomain}).`, "header:reply-to");
  if (fromDomain && returnDomain && fromDomain !== returnDomain) add("Return-Path anomaly", 8, `Return-Path domain (${returnDomain}) differs from From domain (${fromDomain}).`, "header:return-path");
  for (const [key, label, pts] of [["spf", "SPF", 12], ["dkim", "DKIM", 10], ["dmarc", "DMARC", 12]]) {
    if (auth[key] === "FAIL" || auth[key] === "HARDFAIL") add(`${label} failure`, pts, `${label} reported ${auth[key]} in Authentication-Results (reported by the receiving server, not re-verified).`, `header:authentication-results:${key}`);
  }
  const loginPath = parsed.urls.filter(u => /\/(login|verify|signin|password|account|secure)/i.test(u.url));
  if (loginPath.length) add("URL risk", 16, `${loginPath.length} URL(s) contain an authentication or credential-oriented path.`, "urls");
  const mismatches = parsed.htmlLinks.filter(l => l.mismatch);
  if (mismatches.length) add("Deceptive link text", 16, `${mismatches.length} HTML link(s) display one host but point to another (e.g. shown ${mismatches[0].displayHost}, actual ${mismatches[0].hrefHost}).`, "html-links");
  const badAtt = parsed.attachments.filter(a => a.flags.length);
  if (badAtt.length) add("Risky attachment", 18, `${badAtt.length} attachment(s) flagged by static checks (${[...new Set(badAtt.flatMap(a => a.flags))].join(", ")}). Not opened or executed.`, "attachments");
  const text = `${m.subject || ""} ${parsed.text}`.toLowerCase();
  const urgency = URGENCY.filter(x => text.includes(x)).length;
  if (urgency) add("Social engineering", Math.min(16, urgency * 2), `Detected ${urgency} urgency/account-pressure indicator(s) in the subject/body.`, "body-text");

  const score = Math.min(100, factors.reduce((s, f) => s + f[1], 0));
  return { score, factors, fromDomain, replyDomain };
}
