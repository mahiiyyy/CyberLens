import { safeUrl, isIp, isPublicIp, isDomain } from "./indicators.js";

/**
 * Defensive reputation lookups against third-party threat-intelligence APIs.
 * Privacy rules enforced here:
 *  - only an indicator (URL host/path, domain, public IP, SHA-256) is ever sent; never email content
 *  - URL userinfo, query string and fragment are stripped before sending (they can carry tokens/PII)
 *  - private/reserved IPs are rejected and never leave the server
 *  - indicators are only ever *queried by value*; they are never fetched or visited
 * Provider results are third-party opinions. "Not found" / "no detections" is never reported as safe.
 */
export const PROVIDERS = {
  virustotal: { label: "VirusTotal", env: "VIRUSTOTAL_API_KEY", kinds: ["url", "domain", "ip", "sha256"] },
  abuseipdb: { label: "AbuseIPDB", env: "ABUSEIPDB_API_KEY", kinds: ["ip"] },
};
const TIMEOUT_MS = 8000;

export const providerStatus = () =>
  Object.fromEntries(Object.entries(PROVIDERS).map(([k, p]) => [k, { label: p.label, configured: !!process.env[p.env], kinds: p.kinds }]));

export class IndicatorError extends Error {}

/** Validate and minimise an indicator for third-party submission. */
export function normalizeIndicator({ type, value }) {
  const v = String(value ?? "").trim();
  switch (type) {
    case "url": {
      const u = safeUrl(v);
      if (!u) throw new IndicatorError("Invalid URL (http/https only).");
      if (isIp(u.hostname.replace(/^\[|\]$/g, "")) && !isPublicIp(u.hostname.replace(/^\[|\]$/g, ""))) throw new IndicatorError("URL points to a non-public address; it is not sent to third parties.");
      const sent = new URL(u.origin + u.pathname).href;
      return { kind: "url", value: v, sent, redacted: !!(u.search || u.hash || u.username || u.password) };
    }
    case "domain": {
      const d = v.toLowerCase().replace(/\.$/, "");
      if (!isDomain(d)) throw new IndicatorError("Invalid domain.");
      return { kind: "domain", value: d, sent: d, redacted: false };
    }
    case "ip":
      if (!isIp(v)) throw new IndicatorError("Invalid IP address.");
      if (!isPublicIp(v)) throw new IndicatorError("Private or reserved IP addresses are never sent to third parties.");
      return { kind: "ip", value: v, sent: v, redacted: false };
    case "sha256":
      if (!/^[a-f0-9]{64}$/i.test(v)) throw new IndicatorError("Invalid SHA-256.");
      return { kind: "sha256", value: v.toLowerCase(), sent: v.toLowerCase(), redacted: false };
    default:
      throw new IndicatorError("Unsupported indicator type.");
  }
}

const b64url = s => Buffer.from(s).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

function vtPath(ind) {
  switch (ind.kind) {
    case "url": return `/urls/${b64url(ind.sent)}`;
    case "domain": return `/domains/${encodeURIComponent(ind.sent)}`;
    case "ip": return `/ip_addresses/${encodeURIComponent(ind.sent)}`;
    default: return `/files/${ind.sent}`;
  }
}

async function call(fetchImpl, url, headers) {
  try {
    const r = await fetchImpl(url, { headers: { Accept: "application/json", ...headers }, signal: AbortSignal.timeout(TIMEOUT_MS), redirect: "error" });
    return { r };
  } catch (e) {
    return { error: e?.name === "TimeoutError" ? "Provider timed out." : "Provider request failed." };
  }
}

const base = (ind, provider) => ({ indicator: ind.value, kind: ind.kind, provider, sent: ind.sent, redacted: ind.redacted, checkedAt: new Date().toISOString() });

async function queryVirusTotal(ind, fetchImpl) {
  const out = base(ind, "virustotal");
  const { r, error } = await call(fetchImpl, `https://www.virustotal.com/api/v3${vtPath(ind)}`, { "x-apikey": process.env.VIRUSTOTAL_API_KEY });
  if (error) return { ...out, status: "error", result: { summary: error } };
  if (r.status === 404) return { ...out, status: "not_found", result: { summary: "VirusTotal has no existing report for this indicator. This does not mean it is safe." } };
  if (r.status === 429) return { ...out, status: "rate_limited", result: { summary: "Provider rate limit reached. Try again later." } };
  if (r.status === 401 || r.status === 403) return { ...out, status: "error", result: { summary: "Provider rejected the configured API key." } };
  if (!r.ok) return { ...out, status: "error", result: { summary: `Provider returned HTTP ${r.status}.` } };
  const attrs = (await r.json().catch(() => null))?.data?.attributes;
  const s = attrs?.last_analysis_stats;
  if (!s) return { ...out, status: "error", result: { summary: "Unexpected provider response." } };
  const flagged = (s.malicious ?? 0) + (s.suspicious ?? 0);
  const total = Object.values(s).reduce((a, b) => a + (Number(b) || 0), 0);
  return {
    ...out, status: "ok",
    result: {
      malicious: s.malicious ?? 0, suspicious: s.suspicious ?? 0, harmless: s.harmless ?? 0, undetected: s.undetected ?? 0, engines: total,
      reputation: Number.isFinite(attrs.reputation) ? attrs.reputation : null,
      lastAnalysisDate: attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : null,
      summary: flagged ? `${flagged} of ${total} engines flagged this indicator as malicious or suspicious.` : `No engine flagged this indicator in the provider's latest analysis (${total} engines). This is not proof of safety.`,
    },
  };
}

async function queryAbuseIpdb(ind, fetchImpl) {
  const out = base(ind, "abuseipdb");
  const { r, error } = await call(fetchImpl, `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ind.sent)}&maxAgeInDays=90`, { Key: process.env.ABUSEIPDB_API_KEY });
  if (error) return { ...out, status: "error", result: { summary: error } };
  if (r.status === 429) return { ...out, status: "rate_limited", result: { summary: "Provider rate limit reached. Try again later." } };
  if (r.status === 401 || r.status === 403) return { ...out, status: "error", result: { summary: "Provider rejected the configured API key." } };
  if (!r.ok) return { ...out, status: "error", result: { summary: `Provider returned HTTP ${r.status}.` } };
  const d = (await r.json().catch(() => null))?.data;
  if (!d || !Number.isFinite(d.abuseConfidenceScore)) return { ...out, status: "error", result: { summary: "Unexpected provider response." } };
  return {
    ...out, status: "ok",
    result: {
      abuseConfidenceScore: d.abuseConfidenceScore, totalReports: d.totalReports ?? 0, countryCode: d.countryCode ?? null,
      isp: d.isp ?? null, usageType: d.usageType ?? null, lastReportedAt: d.lastReportedAt ?? null,
      summary: `${d.totalReports ?? 0} community report(s) in the last 90 days; abuse confidence ${d.abuseConfidenceScore}%. Community-sourced and not verified by CyberLens.`,
    },
  };
}

const RUNNERS = { virustotal: queryVirusTotal, abuseipdb: queryAbuseIpdb };

/** Query every configured, applicable provider for one normalised indicator. */
export async function lookupIndicator(ind, { fetchImpl = fetch, providers = Object.keys(PROVIDERS) } = {}) {
  const results = [];
  for (const name of providers) {
    const p = PROVIDERS[name];
    if (!p?.kinds.includes(ind.kind)) continue;
    if (!process.env[p.env]) { results.push({ ...base(ind, name), status: "not_configured", result: { summary: `${p.label} is not configured (set ${p.env}).` } }); continue; }
    results.push(await RUNNERS[name](ind, fetchImpl));
  }
  return results;
}
