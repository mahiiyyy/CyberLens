export const demo = {
  caseId: "EML-2026-0912",
  subject: "Urgent: Acme Bank Security Alert — Verify Your Account",
  from: "security@acme-bank-alert.example",
  to: "analyst@cyberlens.local",
  replyTo: "verify@acme-support.example",
  returnPath: "bounce@mx-acme-alert.example",
  date: "09 Sep 2026 09:42:18 +0530",
  messageId: "<7f92a.demo@mx-acme-alert.example>",
  score: 92,
  confidence: 94,
  verdict: "PHISHING / IMPERSONATION",
  tags: ["Phishing", "Impersonation", "Credential Theft"],
  url: "https://acme-bank-verify.example/login?session=7f92a",
  domain: "acme-bank-verify.example",
  ip: "198.51.100.42"
};

export const findings = [
  { title: "Sender identity mismatch", severity: "CRITICAL", contribution: 24, confidence: 97, evidence: "Visible sender uses acme-bank-alert.example while the claimed brand is Acme Bank.", explanation: "The sender domain is a lookalike/demo infrastructure domain and does not match the trusted identity." },
  { title: "Authentication failure", severity: "HIGH", contribution: 20, confidence: 99, evidence: "SPF: FAIL · DKIM: FAIL · DMARC: FAIL", explanation: "The sending infrastructure cannot be authenticated as an authorized source for the claimed identity." },
  { title: "Credential-harvesting URL", severity: "CRITICAL", contribution: 22, confidence: 95, evidence: "/login?session=7f92a on a newly observed lookalike domain.", explanation: "The account-verification lure and login path strongly indicate credential collection intent." },
  { title: "Social engineering language", severity: "HIGH", contribution: 12, confidence: 93, evidence: "Urgency + account restriction threat + verification request.", explanation: "Time pressure and fear are used to push the recipient toward unsafe action." },
  { title: "Infrastructure risk", severity: "HIGH", contribution: 14, confidence: 91, evidence: "198.51.100.42 · AS-DEMO-64500 · proxy indicator.", explanation: "The demo infrastructure has characteristics associated with anonymized hosting." }
];

export const iocs = [
  ["198.51.100.42", "IP", "Malicious", "Infrastructure"],
  ["acme-bank-verify.example", "Domain", "Malicious", "Phishing"],
  ["acme-support.example", "Domain", "Suspicious", "Impersonation"],
  ["https://acme-bank-verify.example/login?session=7f92a", "URL", "Malicious", "Credential theft"],
  ["7f92a-demo-sha256", "SHA-256", "Unknown", "Evidence hash"],
  ["security@acme-bank-alert.example", "Email", "Suspicious", "Sender"]
];

export const campaigns = [
  ["CMP-031", "Acme Verification Wave", "4 emails", "3 domains", "2 IPs"],
  ["CMP-027", "Payroll Portal Lure", "3 emails", "2 domains", "1 IP"],
  ["CMP-019", "Document Review Bait", "3 emails", "4 domains", "2 IPs"]
];

export const investigations = [
  ["EML-2026-0912", "Acme Bank Security Alert", "CRITICAL", "Investigating", "Investigator 01", 92],
  ["EML-2026-0910", "Invoice access verification", "HIGH", "Under Review", "Investigator 02", 78],
  ["EML-2026-0908", "Payroll document review", "HIGH", "Investigating", "Investigator 03", 84],
  ["EML-2026-0906", "Microsoft account notice", "MEDIUM", "Resolved", "Investigator 01", 61],
  ["EML-2026-0904", "Shared document alert", "HIGH", "New", "Investigator 02", 73]
];
