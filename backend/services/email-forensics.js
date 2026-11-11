import { simpleParser } from "mailparser";
import { isIP } from "node:net";

const clean = value => String(value || "").replace(/[\r\n\t]+/g, " ").trim();
const firstAddress = value => {
  if (!value) return "";
  if (typeof value === "string") return clean(value);
  if (Array.isArray(value.value)) return clean(value.value[0]?.address || "");
  return clean(value.value?.[0]?.address || "");
};
const domainOf = value => {
  const match = clean(value).match(/<\s*[^<>\s]+@([^<>\s]+)\s*>|^\s*[^<>\s]+@([^<>\s]+)\s*$/);
  return (match?.[1] || match?.[2] || "").toLowerCase().replace(/\.$/, "");
};
const extractUrls = text => {
  const found = new Set();
  for (const match of String(text || "").matchAll(/https?:\/\/[^\s<>"')]+/gi)) {
    const candidate = match[0].replace(/[.,;]+$/, "");
    try {
      const parsed = new URL(candidate);
      if (["http:", "https:"].includes(parsed.protocol)) found.add(parsed.href);
    } catch {}
  }
  return [...found].slice(0, 500);
};
const parseAuth = headers => {
  const header = headers.get("authentication-results");
  const values = (Array.isArray(header) ? header : header ? [header] : []).map(item => typeof item === "string" ? item : String(item.value || item.text || ""));
  const joined = values.join(" ");
  const read = name => {
    const matches = [...joined.matchAll(new RegExp("(?:^|[;\\s])" + name + "\\s*=\\s*(pass|fail|softfail|neutral|none|temperror|permerror)", "gi"))];
    if (!matches.length) return "UNKNOWN";
    const status = matches[matches.length - 1][1].toLowerCase();
    return status === "pass" ? "PASS" : ["fail", "softfail", "permerror"].includes(status) ? "FAIL" : "UNKNOWN";
  };
  return { spf: read("spf"), dkim: read("dkim"), dmarc: read("dmarc"), source: values.length ? "Authentication-Results header" : "not present" };
};

export async function parseEmailEvidence(raw, supplied = {}) {
  const parsed = await simpleParser(raw, { skipHtmlToText: false, skipTextToHtml: true });
  const sender = firstAddress(parsed.from) || clean(supplied.sender);
  const replyTo = firstAddress(parsed.replyTo) || clean(supplied.reply_to);
  const returnPath = clean(parsed.headers.get("return-path")?.text || parsed.headers.get("return-path") || supplied.return_path);
  const subject = clean(parsed.subject || supplied.subject || "Untitled email investigation");
  const textBody = parsed.text || parsed.html || String(raw);
  const urls = extractUrls([textBody, parsed.html || ""].join("\n")).concat(supplied.urls || []);
  const uniqueUrls = [...new Set(urls)].slice(0, 500);
  const authentication = parseAuth(parsed.headers);
  const mismatches = [];
  const fromDomain = domainOf(sender);
  const replyDomain = domainOf(replyTo);
  const returnDomain = domainOf(returnPath);
  if (fromDomain && replyDomain && fromDomain !== replyDomain) mismatches.push("From domain differs from Reply-To domain");
  if (fromDomain && returnDomain && fromDomain !== returnDomain) mismatches.push("From domain differs from Return-Path domain");
  if (!parsed.messageId) mismatches.push("Message-ID header is missing");
  if (!parsed.date) mismatches.push("Date header is missing");

  const iocs = [];
  for (const value of uniqueUrls) {
    try {
      const hostname = new URL(value).hostname.toLowerCase();
      iocs.push({ value, kind: "URL" });
      const bareHost = hostname.replace(/^\[|\]$/g, "");
      if (isIP(bareHost)) iocs.push({ value: bareHost, kind: "IP" });
      else if (bareHost.includes(".")) iocs.push({ value: bareHost, kind: "DOMAIN" });
    } catch {}
  }
  for (const address of [sender, replyTo, returnPath]) {
    const domain = domainOf(address);
    if (domain && domain.includes(".")) iocs.push({ value: domain, kind: "DOMAIN" });
  }

  return {
    subject, body: String(textBody).slice(0, 1_500_000), sender, reply_to: replyTo,
    return_path: returnPath, urls: uniqueUrls,
    authentication: { spf: authentication.spf, dkim: authentication.dkim, dmarc: authentication.dmarc },
    authenticationSource: authentication.source,
    header_mismatches: [...new Set([...(supplied.header_mismatches || []), ...mismatches])],
    parsedHeaders: {
      messageId: clean(parsed.messageId),
      date: parsed.date ? parsed.date.toISOString() : null,
      contentType: clean(parsed.headers.get("content-type")?.text),
      transferEncoding: clean(parsed.headers.get("content-transfer-encoding")?.text),
      attachmentCount: parsed.attachments.length,
      attachments: parsed.attachments.map(file => ({ filename: clean(file.filename), contentType: clean(file.contentType), size: Number(file.size) || 0 })),
    },
    iocs: [...new Map(iocs.map(item => [item.kind + ":" + item.value, item])).values()],
  };
}
