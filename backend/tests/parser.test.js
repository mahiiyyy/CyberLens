import test from "node:test";
import assert from "node:assert/strict";
import { parseEmail, ParseError } from "../services/emailParser.js";
import { sha256Hex } from "../services/hash.js";
import { FIXTURE } from "./fixtures.js";
import { isPublicIp, extractUrls, defang } from "../services/indicators.js";

test("parses headers, received chain, reported authentication and links", async () => {
  const p = await parseEmail(Buffer.from(FIXTURE));
  assert.equal(p.metadata.subject, "Urgent: verify your account");
  assert.equal(p.metadata.from[0].address, "security@sender.example");
  assert.equal(p.metadata.replyTo[0].address, "verify@elsewhere.example");
  assert.equal(p.metadata.returnPath, "bounce@other.example");
  assert.equal(p.metadata.messageId, "<abc@sender.example>");
  assert.equal(p.received.length, 2);
  assert.equal(p.received[0].by, "mx.victim.example");
  assert.deepEqual(p.received[0].ips, [{ ip: "203.0.113.7", public: false }]); // documentation range is not routable
  assert.equal(p.received[1].ips[0].public, false);
  assert.equal(p.authentication.spf, "FAIL");
  assert.equal(p.authentication.dkim, "PASS");
  assert.equal(p.authentication.dmarc, "FAIL");
  assert.equal(p.authentication.verified, false);
  assert.ok(p.urls.some(u => u.url === "https://login.phish.example/verify?id=1"));
  assert.equal(p.htmlLinks[0].mismatch, true);
  assert.equal(p.htmlLinks[0].displayHost, "www.bank.example");
});

test("hashes attachments without exposing content and flags risky files", async () => {
  const p = await parseEmail(Buffer.from(FIXTURE));
  assert.equal(p.attachments.length, 1);
  const a = p.attachments[0];
  assert.equal(a.filename, "invoice.pdf.exe");
  assert.equal(a.sha256, sha256Hex(Buffer.from("MZ-not-a-real-binary")));
  assert.equal(a.signature, "windows-executable");
  assert.ok(a.flags.includes("double-extension") && a.flags.includes("risky-extension"));
  assert.equal("content" in a, false);
});

test("rejects empty, header-less, oversized and OLE .msg input", async () => {
  await assert.rejects(parseEmail(Buffer.alloc(0)), ParseError);
  await assert.rejects(parseEmail(Buffer.from("just some words with no headers at all")), ParseError);
  await assert.rejects(parseEmail(Buffer.alloc(5 * 1024 * 1024 + 1, 65)), /5 MB/);
  await assert.rejects(parseEmail(Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, 0, 0])), /\.msg/);
});

test("warns about missing headers instead of inventing values", async () => {
  const p = await parseEmail(Buffer.from("Subject: hi\r\n\r\nbody"));
  assert.equal(p.metadata.from.length, 0);
  assert.equal(p.metadata.messageId, null);
  assert.equal(p.authentication.spf, "UNKNOWN");
  assert.ok(p.warnings.some(w => /Missing from/.test(w)));
});

test("indicator helpers", () => {
  assert.equal(isPublicIp("8.8.8.8"), true);
  for (const ip of ["10.1.1.1", "127.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.1.1", "::1", "fd00::1"]) assert.equal(isPublicIp(ip), false, ip);
  assert.deepEqual(extractUrls("see https://a.example/x, and http://b.example."), ["https://a.example/x", "http://b.example"]);
  assert.equal(defang("https://a.example"), "hxxps://a[.]example");
});
