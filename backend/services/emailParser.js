import { simpleParser } from "mailparser";
import { sha256Hex } from "./hash.js";
import { extractUrls, safeUrl, hostOf, isIp, isPublicIp } from "./indicators.js";

export const MAX_EML_BYTES = 5 * 1024 * 1024;
const MAX_TEXT_CHARS = 100_000;
const MAX_URLS = 200;
const RISKY_EXT = new Set(["exe", "scr", "js", "jse", "vbs", "vbe", "wsf", "bat", "cmd", "com", "pif", "lnk", "jar", "msi", "ps1", "hta", "iso", "img", "docm", "xlsm", "pptm", "dll", "reg"]);

export class ParseError extends Error {
  constructor(message) { super(message); this.status = 422; }
}

const clean = (s, max = 500) => String(s ?? "").replace(/[\u0000-\u001f\u007f]+/g, " ").trim().slice(0, max);
const addrList = list => (list?.value || []).map(a => ({ name: clean(a.name, 200), address: clean(a.address, 320).toLowerCase() })).filter(a => a.address);

function rawHeaders(parsed, name) {
  const key = name.toLowerCase();
  return (parsed.headerLines || []).filter(h => h.key === key)
    .map(h => h.line.replace(/^[^:]*:/, "").replace(/\r?\n[ \t]+/g, " ").replace(/\s+/g, " ").trim());
}

/** Parse Received headers into hops. Values are exactly what the headers claim; none are verified. */
export function parseReceived(values) {
  return values.map((value, i) => {
    const [main, ...rest] = value.split(";");
    const date = rest.length ? new Date(rest.join(";").trim()) : null;
    const from = /\bfrom\s+(\S+)/i.exec(main)?.[1] ?? null;
    const by = /\bby\s+(\S+)/i.exec(main)?.[1] ?? null;
    const ips = [...new Set([...main.matchAll(/[\[(]\s*(?:IPv6:)?([0-9a-f:.]{3,45})\s*[\])]/gi)].map(m => m[1]).filter(isIp))];
    return {
      index: i, // 0 = most recent hop (top of the header block)
      from: from && clean(from, 255),
      by: by && clean(by, 255),
      protocol: clean(/\bwith\s+(\S+)/i.exec(main)?.[1] ?? "", 40) || null,
      ips: ips.map(ip => ({ ip, public: isPublicIp(ip) })),
      timestamp: date && !Number.isNaN(date.getTime()) ? date.toISOString() : null,
      raw: clean(value, 1000),
    };
  });
}

const RESULT = /^(pass|fail|softfail|neutral|none|temperror|permerror|policy|hardfail|bestguesspass)$/i;

/** Collect SPF/DKIM/DMARC results *reported* in Authentication-Results / Received-SPF headers. */
export function parseAuthentication(parsed) {
  const out = { spf: "UNKNOWN", dkim: "UNKNOWN", dmarc: "UNKNOWN", dkimSignatures: [], servers: [], source: "reported-in-headers", verified: false };
  for (const v of rawHeaders(parsed, "authentication-results")) {
    const server = v.split(";")[0].trim();
    if (server) out.servers.push(clean(server, 255));
    for (const m of v.matchAll(/\b(spf|dkim|dmarc)\s*=\s*([a-z]+)([^;]*)/gi)) {
      const k = m[1].toLowerCase();
      if (!RESULT.test(m[2])) continue;
      const status = m[2].toUpperCase();
      if (k === "dkim") {
        out.dkimSignatures.push({ result: status, domain: /header\.d=([^\s;]+)/i.exec(m[3])?.[1]?.toLowerCase() ?? null });
        if (out.dkim === "UNKNOWN" || (out.dkim !== "PASS" && status === "PASS")) out.dkim = status;
      } else if (out[k] === "UNKNOWN") out[k] = status; // topmost header = added last by the receiving server
    }
  }
  if (out.spf === "UNKNOWN") {
    const r = /^\s*([a-z]+)/i.exec(rawHeaders(parsed, "received-spf")[0] ?? "")?.[1];
    if (r && RESULT.test(r)) out.spf = r.toUpperCase();
  }
  return out;
}

function sniff(buf) {
  const h = buf.subarray(0, 8);
  if (h[0] === 0x4d && h[1] === 0x5a) return "windows-executable";
  if (h[0] === 0x7f && h[1] === 0x45 && h[2] === 0x4c && h[3] === 0x46) return "elf-executable";
  if (h.subarray(0, 4).toString("latin1") === "%PDF") return "pdf";
  if (h[0] === 0x50 && h[1] === 0x4b) return "zip-container";
  if (h[0] === 0xd0 && h[1] === 0xcf && h[2] === 0x11 && h[3] === 0xe0) return "ole2-legacy-office";
  return null;
}

function describeAttachment(a) {
  const filename = clean((a.filename || "").split(/[\\/]/).pop(), 255) || null;
  const parts = (filename || "").toLowerCase().split(".");
  const ext = parts.length > 1 ? parts.pop() : null;
  const risky = !!(ext && RISKY_EXT.has(ext));
  const flags = [];
  if (risky) flags.push("risky-extension");
  if (risky && parts.length > 1 && /^(pdf|docx?|xlsx?|pptx?|txt|jpe?g|png|zip)$/.test(parts.at(-1))) flags.push("double-extension");
  const content = Buffer.isBuffer(a.content) ? a.content : Buffer.alloc(0);
  const signature = sniff(content);
  if (signature?.endsWith("executable") && !risky) flags.push("executable-content-disguised");
  return {
    filename, extension: ext, declaredType: clean(a.contentType, 120) || null, signature,
    size: content.length, sha256: sha256Hex(content), disposition: clean(a.contentDisposition, 20) || null,
    flags, // static analysis only; the attachment is hashed, never opened or executed
  };
}

/** Anchor tags whose visible text names a different host than the real href (a common phishing tell). */
function htmlLinks(html) {
  const links = [];
  if (typeof html !== "string") return links;
  for (const m of html.slice(0, 2_000_000).matchAll(/<a\b[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)')[^>]*>([\s\S]*?)<\/a>/gi)) {
    const href = (m[1] ?? m[2] ?? "").trim().replace(/&amp;/g, "&");
    if (!safeUrl(href)) continue;
    const text = m[3].replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
    const shown = extractUrls(text)[0] ?? (/^[a-z0-9.-]+\.[a-z]{2,}(\/\S*)?$/i.test(text) ? "http://" + text : null);
    const displayHost = shown ? hostOf(shown) : null;
    const hrefHost = hostOf(href);
    links.push({ href, text: clean(text, 200), displayHost, hrefHost, mismatch: !!(displayHost && displayHost !== hrefHost) });
    if (links.length >= MAX_URLS) break;
  }
  return links;
}

/**
 * Parse raw RFC 822 bytes. Pure: no network access, no execution of content.
 * @param {Buffer} raw original bytes exactly as received
 */
export async function parseEmail(raw) {
  if (!Buffer.isBuffer(raw) || !raw.length) throw new ParseError("The email is empty.");
  if (raw.length > MAX_EML_BYTES) throw new ParseError("Email exceeds the 5 MB limit.");
  if (raw.subarray(0, 8).equals(Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]))) throw new ParseError("Outlook .msg files are not supported. Export the message as .eml.");
  let parsed;
  try { parsed = await simpleParser(raw, { skipImageLinks: true, skipTextToHtml: true, maxHtmlLengthToParse: 2_000_000 }); }
  catch { throw new ParseError("The message could not be parsed as an RFC 822 email."); }
  const hdrs = new Set((parsed.headerLines || []).map(h => h.key));
  if (!hdrs.has("from") && !hdrs.has("subject") && !hdrs.has("received") && !hdrs.has("message-id")) {
    throw new ParseError("No email headers were found. Provide a full message including headers (From, Subject, ...).");
  }
  const warnings = [];
  for (const h of ["from", "date", "message-id"]) if (!hdrs.has(h)) warnings.push(`Missing ${h} header.`);
  if (!hdrs.has("received")) warnings.push("No Received headers: transport path cannot be reconstructed.");
  if ((parsed.headerLines || []).filter(h => h.key === "from").length > 1) warnings.push("Multiple From headers present.");

  const returnPath = /<([^>]*)>|(\S+@\S+)/.exec(rawHeaders(parsed, "return-path")[0] ?? "");
  const text = typeof parsed.text === "string" ? parsed.text : "";
  const links = htmlLinks(parsed.html);
  const urlSet = new Map();
  for (const u of extractUrls(text)) urlSet.set(u, "body-text");
  for (const l of links) urlSet.set(l.href, "html-link");
  const urls = [...urlSet].slice(0, MAX_URLS).map(([url, source]) => ({ url, host: hostOf(url), source }));

  return {
    metadata: {
      subject: clean(parsed.subject, 998) || null,
      from: addrList(parsed.from), replyTo: addrList(parsed.replyTo), to: addrList(parsed.to), cc: addrList(parsed.cc),
      returnPath: clean(returnPath?.[1] ?? returnPath?.[2] ?? "", 320).toLowerCase() || null,
      date: parsed.date && !Number.isNaN(parsed.date.getTime()) ? parsed.date.toISOString() : null,
      messageId: clean(parsed.messageId, 998) || null,
    },
    received: parseReceived(rawHeaders(parsed, "received")),
    authentication: parseAuthentication(parsed),
    urls, htmlLinks: links,
    attachments: (parsed.attachments || []).slice(0, 100).map(describeAttachment),
    text: text.slice(0, MAX_TEXT_CHARS), textTruncated: text.length > MAX_TEXT_CHARS,
    hasHtml: typeof parsed.html === "string",
    warnings,
  };
}
