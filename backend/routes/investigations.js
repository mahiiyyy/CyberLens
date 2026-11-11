import { Router } from "express";
import { createHash, randomUUID } from "node:crypto";
import { z } from "zod";
import { requireAuth } from "../middleware/auth.js";
import { pool } from "../db/pool.js";
import { parseEmailEvidence } from "../services/email-forensics.js";
import { enrichCaseIocs } from "../services/threat-intel.js";
import { enrichCaseDomains } from "../services/domain-intel.js";

const router = Router();
const AI_URL = process.env.AI_SERVICE_URL || "http://127.0.0.1:8000";
const MAX_EMAIL_CHARS = 1_500_000;

const inputSchema = z.object({
  subject: z.string().max(998).default("Untitled email investigation"),
  body: z.string().min(1).max(MAX_EMAIL_CHARS),
  sender: z.string().max(320).default(""),
  reply_to: z.string().max(320).default(""),
  return_path: z.string().max(320).default(""),
  urls: z.array(z.string().url()).max(500).optional().default([]),
  authentication: z.object({
    spf: z.enum(["PASS","FAIL","UNKNOWN"]).default("UNKNOWN"),
    dkim: z.enum(["PASS","FAIL","UNKNOWN"]).default("UNKNOWN"),
    dmarc: z.enum(["PASS","FAIL","UNKNOWN"]).default("UNKNOWN"),
  }).default({}),
  header_mismatches: z.array(z.string().max(500)).max(50).default([]),
  filename: z.string().max(255).optional(),
  evidence_type: z.enum(["EML","TEXT"]).default("TEXT"),
});

const domainOf = (email = "") => {
  const match = String(email).match(/<\s*[^<>\s]+@([^<>\s]+)\s*>|^\s*[^<>\s]+@([^<>\s]+)\s*$/);
  return (match?.[1] || match?.[2] || "").toLowerCase();
};
const extractUrls = (text = "") => [...text.matchAll(/https?:\/\/[^\s<>"')]+/gi)].map(m => m[0].replace(/[.,;]+$/, ""));
const scoreVerdict = score => score >= 75 ? "PHISHING / IMPERSONATION" : score >= 50 ? "SUSPICIOUS" : score >= 25 ? "NEEDS REVIEW" : "BENIGN / LEGITIMATE";

function deterministicAnalysis(e) {
  const fromDomain = domainOf(e.sender);
  const replyDomain = domainOf(e.reply_to);
  const returnDomain = domainOf(e.return_path);
  const urls = e.urls.length ? e.urls : extractUrls(`${e.subject}\n${e.body}`);
  const text = `${e.subject} ${e.body}`.toLowerCase();
  let score = 0;
  const factors = [];
  if (fromDomain && replyDomain && fromDomain !== replyDomain) { score += 18; factors.push(["Sender anomaly",18,"Reply-To domain differs from visible sender domain."]); }
  if (fromDomain && returnDomain && fromDomain !== returnDomain) { score += 8; factors.push(["Return-Path anomaly",8,"Return-Path domain differs from sender domain."]); }
  for (const [key,label,pts] of [["spf","SPF",12],["dkim","DKIM",10],["dmarc","DMARC",12]]) {
    if (e.authentication[key] === "FAIL") { score += pts; factors.push([`${label} failure`,pts,`${label} authentication reported FAIL.`]); }
  }
  const suspicious = urls.filter(u => /\/(login|verify|signin|password|account|secure)/i.test(new URL(u).pathname));
  if (suspicious.length) { score += 16; factors.push(["URL risk",16,"URL contains an authentication or credential-oriented path."]); }
  const urgency = ["urgent","immediately","suspend","suspended","verify","confirm your account","unusual activity","password","credential"].filter(x => text.includes(x)).length;
  if (urgency) { const pts = Math.min(16,urgency*2); score += pts; factors.push(["Social engineering",pts,`Detected ${urgency} urgency/account-pressure indicator(s).`]); }
  return { score:Math.min(100,score), factors, urls, fromDomain, replyDomain };
}

async function runAI(evidence) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 3500);
  try {
    const response = await fetch(`${AI_URL}/analyze`, {
      method:"POST", headers:{"Content-Type":"application/json"},
      body:JSON.stringify(evidence), signal:controller.signal,
    });
    if (!response.ok) throw new Error(`AI service ${response.status}`);
    const data = await response.json();
    if (!Number.isFinite(Number(data.ai_score))) throw new Error("AI response missing a numeric score");
    return data;
  } catch {
    const text = `${evidence.subject} ${evidence.body}`.toLowerCase();
    const hits = ["urgent","verify","password","credential","suspend","login","click here","unusual activity"].filter(x=>text.includes(x));
    const aiScore = Math.min(100,hits.length*11);
    return {
      model:"CyberLens Local Fallback NLP", mode:"local-fallback",
      confidence:70+Math.min(25,hits.length*3), ai_score:aiScore,
      findings:[{title:hits.length?"Semantic phishing indicators":"No strong phishing language detected",severity:hits.length>=4?"HIGH":"LOW",confidence:78,evidence:hits.join(", ")||"none",explanation:"Fallback keyword analysis was used because the AI service was unavailable."}],
      explanation:`Fallback analysis detected ${hits.length} high-weight language indicator(s).`,
    };
  } finally {
    clearTimeout(timer);
  }
}

function buildResult(input, deterministic, ai, caseNo) {
  const finalScore = Math.min(100,Math.round(deterministic.score*0.65+Number(ai.ai_score)*0.35));
  const verdict = scoreVerdict(finalScore);
  const findings = [
    ...deterministic.factors.map(([title,contribution,explanation])=>({title,severity:contribution>=15?"CRITICAL":contribution>=10?"HIGH":"MEDIUM",contribution,confidence:94,evidence:explanation,explanation})),
    ...(Array.isArray(ai.findings)?ai.findings:[]).map(f=>({...f,contribution:0})),
  ];
  return {
    caseId:caseNo, status:"complete", subject:input.subject, verdict,
    label:verdict.startsWith("BENIGN")?"benign":verdict.startsWith("PHISHING")?"malicious":verdict==="SUSPICIOUS"?"suspicious":"review",
    score:finalScore, confidence:Number(ai.confidence)||0, aiScore:Number(ai.ai_score),
    aiModel:ai.model||"Unknown model", aiMode:ai.mode||"unknown",
    deterministicScore:deterministic.score, factors:deterministic.factors, findings,
    evidence:{...input,urls:deterministic.urls}, aiExplanation:ai.explanation||"",
  };
}

router.get("/demo", requireAuth, (_req,res)=>res.status(410).json({error:"Demo endpoint is disabled. Submit evidence to create a real investigation."}));

router.get("/ai-status", requireAuth, async (_req,res)=>{
  try { const r=await fetch(`${AI_URL}/health`,{signal:AbortSignal.timeout(2500)}); const data=await r.json(); res.json({connected:r.ok,...data}); }
  catch { res.status(503).json({connected:false,error:"AI service unavailable"}); }
});

router.post("/analyze", requireAuth, async (req,res,next)=>{
  const parsed=inputSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({error:"Invalid evidence payload",details:parsed.error.flatten().fieldErrors});
  const rawInput=parsed.data;
  let input;
  try {
    const forensic=await parseEmailEvidence(rawInput.body,rawInput);
    input={...rawInput,...forensic,filename:rawInput.filename,evidence_type:rawInput.evidence_type};
  } catch (error) {
    return res.status(422).json({error:"Unable to parse email evidence",details:error.message});
  }
  const client=await pool.connect();
  try {
    const deterministic=deterministicAnalysis(input);
    const ai=await runAI({...input,urls:deterministic.urls});
    const caseNo=`CL-${new Date().toISOString().slice(0,10).replaceAll("-","")}-${randomUUID().slice(0,8).toUpperCase()}`;
    const result=buildResult(input,deterministic,ai,caseNo);
    const sha256=createHash("sha256").update(rawInput.body,"utf8").digest("hex");
    await client.query("BEGIN");
    const inserted=await client.query(
      "INSERT INTO cases (case_no,title,priority,status,investigator_id,result) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id",
      [caseNo,input.subject||"Untitled email investigation",result.score>=75?"CRITICAL":result.score>=50?"HIGH":result.score>=25?"MEDIUM":"LOW","ANALYZED",req.user.sub,JSON.stringify(result)]
    );
    const caseId=inserted.rows[0].id;
    await client.query(
      "INSERT INTO evidence (case_id,sha256,source,evidence_type,integrity,raw_storage_key,processed_analysis,original_filename,content_text) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
      [caseId,sha256,"USER_UPLOAD",input.evidence_type,"SHA256_RECORDED",`postgres-evidence:${sha256}`,JSON.stringify(result),input.filename||null,rawInput.body]
    );
    for (const ioc of input.iocs) {
      await client.query("INSERT INTO iocs (case_id,value,kind,verdict,confidence) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (case_id,value,kind) DO NOTHING", [caseId,ioc.value,ioc.kind,"UNVERIFIED",null]);
    }
    await client.query(
      "INSERT INTO audit_logs (user_id,action,entity,entity_id,metadata) VALUES ($1,$2,$3,$4,$5)",
      [req.user.sub,"INVESTIGATION_CREATED","CASE",caseId,JSON.stringify({caseNo,sha256,score:result.score})]
    );
    await client.query("COMMIT");
    let threatIntel = {provider:"VirusTotal",configured:Boolean(process.env.VIRUSTOTAL_API_KEY),results:[],message:"Threat intelligence enrichment unavailable."};
    let domainIntel = {lookedUp:0,results:[]};
    try { threatIntel = await enrichCaseIocs(caseId); } catch { /* Keep the saved investigation available if the provider/cache is down. */ }
    try { domainIntel = await enrichCaseDomains(caseId); } catch { /* DNS/RDAP is supplemental and must not fail case creation. */ }
    res.status(201).json({...result,caseUuid:caseId,evidenceSha256:sha256,threatIntel,domainIntel});
  } catch(err) {
    await client.query("ROLLBACK").catch(()=>{});
    next(err);
  } finally { client.release(); }
});

router.get("/dashboard/summary", requireAuth, async (req,res,next)=>{
  try {
    const [totals,priority,recent,activity,iocCount]=await Promise.all([
      pool.query("SELECT COUNT(*)::int AS total, COUNT(*) FILTER (WHERE status NOT IN ('CLOSED','RESOLVED'))::int AS active, COUNT(*) FILTER (WHERE priority='CRITICAL')::int AS critical, COUNT(*) FILTER (WHERE created_at >= NOW()-INTERVAL '24 hours')::int AS today FROM cases WHERE investigator_id=$1",[req.user.sub]),
      pool.query("SELECT priority,COUNT(*)::int AS count FROM cases WHERE investigator_id=$1 GROUP BY priority",[req.user.sub]),
      pool.query("SELECT case_no,title,priority,status,created_at,result->>'score' AS score FROM cases WHERE investigator_id=$1 ORDER BY created_at DESC LIMIT 8",[req.user.sub]),
      pool.query("SELECT date_trunc('hour',created_at) AS hour,COUNT(*)::int AS count FROM cases WHERE investigator_id=$1 AND created_at >= NOW()-INTERVAL '24 hours' GROUP BY 1 ORDER BY 1",[req.user.sub]),
      pool.query("SELECT COUNT(*)::int AS total,COUNT(*) FILTER (WHERE verdict='MALICIOUS')::int AS malicious FROM iocs i JOIN cases c ON c.id=i.case_id WHERE c.investigator_id=$1",[req.user.sub])
    ]);
    res.json({totals:totals.rows[0],priority:priority.rows,recent:recent.rows,activity:activity.rows,iocs:iocCount.rows[0]});
  } catch(err) { next(err); }
});

router.get("/iocs", requireAuth, async (req,res,next)=>{
  try {
    const result=await pool.query(
      "SELECT i.id,i.value,i.kind,i.verdict,i.confidence,i.created_at,c.case_no,c.title FROM iocs i JOIN cases c ON c.id=i.case_id WHERE c.investigator_id=$1 ORDER BY i.created_at DESC LIMIT 500",
      [req.user.sub]
    );
    res.json({iocs:result.rows});
  } catch(err) { next(err); }
});

router.get("/alerts", requireAuth, async (req,res,next)=>{
  try {
    const result=await pool.query(
      "SELECT c.case_no,c.title,c.priority,c.status,c.created_at,c.result->>'score' AS score FROM cases c WHERE c.investigator_id=$1 AND c.priority IN ('CRITICAL','HIGH') ORDER BY c.created_at DESC LIMIT 100",
      [req.user.sub]
    );
    res.json({alerts:result.rows});
  } catch(err) { next(err); }
});

router.get("/", requireAuth, async (req,res,next)=>{
  try {
    const result=await pool.query(
      "SELECT c.id,c.case_no,c.title,c.priority,c.status,c.created_at,c.updated_at,u.email AS investigator_email FROM cases c LEFT JOIN users u ON u.id=c.investigator_id WHERE c.investigator_id=$1 ORDER BY c.created_at DESC LIMIT 100",
      [req.user.sub]
    );
    res.json({cases:result.rows});
  } catch(err) { next(err); }
});

router.get("/:caseNo/threat-intel", requireAuth, async (req,res,next)=>{
  try {
    const owned=await pool.query("SELECT id FROM cases WHERE case_no=$1 AND investigator_id=$2",[req.params.caseNo,req.user.sub]);
    if(!owned.rowCount) return res.status(404).json({error:"Investigation not found"});
    const threatIntel=await enrichCaseIocs(owned.rows[0].id);
    res.json(threatIntel);
  } catch(err) { next(err); }
});

router.get("/:caseNo/domain-intel", requireAuth, async (req,res,next)=>{
  try {
    const owned=await pool.query("SELECT id FROM cases WHERE case_no=$1 AND investigator_id=$2",[req.params.caseNo,req.user.sub]);
    if(!owned.rowCount) return res.status(404).json({error:"Investigation not found"});
    res.json(await enrichCaseDomains(owned.rows[0].id));
  } catch(err) { next(err); }
});

router.get("/:caseNo/graph", requireAuth, async (req,res,next)=>{
  try {
    const found=await pool.query("SELECT c.id,c.case_no,c.title,c.result FROM cases c WHERE c.case_no=$1 AND c.investigator_id=$2",[req.params.caseNo,req.user.sub]);
    if(!found.rowCount)return res.status(404).json({error:"Investigation not found"});
    const row=found.rows[0];
    const [iocRows,evidenceRows]=await Promise.all([
      pool.query("SELECT value,kind,verdict FROM iocs WHERE case_id=$1 ORDER BY kind,value LIMIT 100",[row.id]),
      pool.query("SELECT processed_analysis FROM evidence WHERE case_id=$1 ORDER BY created_at DESC LIMIT 1",[row.id])
    ]);
    const result=row.result||{};
    const evidence=evidenceRows.rows[0]?.processed_analysis?.evidence||result.evidence||{};
    const nodes=[{id:"case",type:"CASE",label:row.case_no,detail:row.title}];
    const edges=[];
    const add=(id,type,label,detail="")=>{if(!nodes.some(n=>n.id===id)){nodes.push({id,type,label,detail});edges.push({source:"case",target:id,relation:"CONTAINED_IN"});}};
    const sender=String(evidence.sender||"");
    if(sender)add("sender:"+sender,"SENDER",sender,"Parsed From address");
    for(const ioc of iocRows.rows){
      const id=ioc.kind.toLowerCase()+":"+ioc.value;
      add(id,ioc.kind,ioc.value,ioc.verdict);
    }
    const trace=evidence.parsedHeaders?.smtpTrace||[];
    for(const hop of trace){
      if(hop.from)add("host:"+hop.from,"SMTP_HOST",hop.from,"Received header hop "+hop.hop);
      if(hop.by)add("host:"+hop.by,"SMTP_HOST",hop.by,"Received header hop "+hop.hop);
      for(const ip of hop.ips||[])add("ip:"+ip,"IP",ip,"Observed in Received header");
    }
    for(const attachment of evidence.parsedHeaders?.attachments||[]){
      if(attachment.sha256)add("attachment:"+attachment.sha256,"ATTACHMENT",attachment.filename||attachment.sha256,attachment.sha256);
    }
    res.json({case:{caseNo:row.case_no,title:row.title},nodes,edges,trace});
  } catch(err){next(err);}
});

router.get("/:caseNo/evidence", requireAuth, async (req,res,next)=>{
  try {
    const owned=await pool.query(
      "SELECT e.id,e.sha256,e.source,e.evidence_type,e.integrity,e.original_filename,e.created_at,e.processed_analysis,c.case_no FROM evidence e JOIN cases c ON c.id=e.case_id WHERE c.case_no=$1 AND c.investigator_id=$2 ORDER BY e.created_at DESC",
      [req.params.caseNo,req.user.sub]
    );
    if(!owned.rowCount)return res.status(404).json({error:"Investigation not found"});
    const audit=await pool.query("SELECT action,entity,metadata,created_at FROM audit_logs WHERE entity_id=(SELECT id::text FROM cases WHERE case_no=$1 AND investigator_id=$2) ORDER BY created_at ASC",[req.params.caseNo,req.user.sub]);
    res.json({caseNo:req.params.caseNo,evidence:owned.rows.map(row=>({id:row.id,sha256:row.sha256,source:row.source,type:row.evidence_type,integrity:row.integrity,filename:row.original_filename,createdAt:row.created_at,analysis:row.processed_analysis})),audit:audit.rows});
  } catch(err){next(err);}
});

router.get("/:caseNo/report", requireAuth, async (req,res,next)=>{
  try {
    const found=await pool.query(
      "SELECT c.case_no,c.title,c.priority,c.status,c.result,c.created_at,e.sha256,e.evidence_type,e.original_filename FROM cases c LEFT JOIN LATERAL (SELECT sha256,evidence_type,original_filename FROM evidence WHERE case_id=c.id ORDER BY created_at DESC LIMIT 1) e ON TRUE WHERE c.case_no=$1 AND c.investigator_id=$2",
      [req.params.caseNo,req.user.sub]
    );
    if(!found.rowCount)return res.status(404).json({error:"Investigation not found"});
    const row=found.rows[0];
    const iocRows=await pool.query("SELECT value,kind,verdict,confidence FROM iocs WHERE case_id=(SELECT id FROM cases WHERE case_no=$1) ORDER BY kind,value",[req.params.caseNo]);
    const result=row.result||{};
    res.json({generatedAt:new Date().toISOString(),case:{caseNo:row.case_no,title:row.title,priority:row.priority,status:row.status,createdAt:row.created_at},analysis:{verdict:result.verdict||"UNAVAILABLE",score:result.score??null,confidence:result.confidence??null,model:result.aiModel||"Unknown",mode:result.aiMode||"unknown",findings:result.findings||[],explanation:result.aiExplanation||""},evidence:{sha256:row.sha256||null,type:row.evidence_type||null,filename:row.original_filename||null},indicators:iocRows.rows,limitations:["This report reflects stored automated analysis and is not a certification of sender identity.","SPF/DKIM/DMARC values may be reported by the submitted message and are not independently verified unless explicitly stated.","Third-party intelligence and antivirus results may be unavailable or stale."]});
  } catch(err){next(err);}
});

router.get("/:caseNo", requireAuth, async (req,res,next)=>{
  try {
    const result=await pool.query(
      "SELECT c.id,c.case_no,c.title,c.priority,c.status,c.result,c.created_at,c.updated_at,e.sha256,e.evidence_type,e.original_filename,e.content_text,e.created_at AS evidence_created_at FROM cases c LEFT JOIN evidence e ON e.case_id=c.id WHERE c.case_no=$1 AND c.investigator_id=$2 ORDER BY e.created_at DESC LIMIT 1",
      [req.params.caseNo,req.user.sub]
    );
    if (!result.rowCount) return res.status(404).json({error:"Investigation not found"});
    const row=result.rows[0];
    res.json({case:{id:row.id,caseId:row.case_no,title:row.title,priority:row.priority,status:row.status,createdAt:row.created_at,updatedAt:row.updated_at},result:row.result,evidence:{sha256:row.sha256,type:row.evidence_type,filename:row.original_filename,content:row.content_text}});
  } catch(err) { next(err); }
});

export default router;
