import net from "node:net";

/** Extract http(s) URLs from plain text. Trailing punctuation is trimmed. Never fetched. */
export function extractUrls(text = "") {
  const out = [];
  for (const m of String(text).matchAll(/https?:\/\/[^\s<>"'`\)\]]+/gi)) out.push(m[0].replace(/[.,;:!?]+$/, ""));
  return out;
}

export function safeUrl(value) {
  try {
    const u = new URL(value);
    return u.protocol === "http:" || u.protocol === "https:" ? u : null;
  } catch { return null; }
}

export function hostOf(value) {
  const u = safeUrl(value);
  if (!u) return null;
  return u.hostname.replace(/^\[|\]$/g, "").toLowerCase().replace(/\.$/, "");
}

export function emailDomain(address = "") {
  const at = String(address).lastIndexOf("@");
  return at === -1 ? "" : String(address).slice(at + 1).trim().toLowerCase().replace(/[>\s]+$/, "");
}

/** True only for globally routable IPv4/IPv6 addresses (never private/loopback/link-local/etc). */
export function isPublicIp(ip) {
  const v = net.isIP(ip);
  if (v === 4) {
    const [a, b] = ip.split(".").map(Number);
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 192 && b === 0) return false;
    if (a === 198 && (b === 18 || b === 19)) return false;
    if ((a === 192 && b === 88) || (a === 198 && b === 51) || (a === 203 && b === 0)) return false;
    return true;
  }
  if (v === 6) {
    const s = ip.toLowerCase();
    if (s === "::" || s === "::1" || s.startsWith("fe8") || s.startsWith("fe9") || s.startsWith("fea") || s.startsWith("feb")) return false;
    if (/^f[cd]/.test(s) || s.startsWith("ff") || s.startsWith("2001:db8") || s.startsWith("::ffff:")) return false;
    return true;
  }
  return false;
}

export const isIp = value => net.isIP(String(value)) !== 0;

/** Display form that cannot be clicked accidentally. */
export const defang = value => String(value).replace(/^http/i, "hxxp").replace(/\./g, "[.]");

const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
export const isDomain = value => DOMAIN_RE.test(String(value).toLowerCase());
