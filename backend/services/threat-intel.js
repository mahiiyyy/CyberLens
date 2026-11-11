import { Buffer } from "node:buffer";
import { pool } from "../db/pool.js";

const VT_BASE = "https://www.virustotal.com/api/v3";
const CACHE_HOURS = 24;
const MAX_LOOKUPS = 20;

function vtPath(kind,value) {
  if (kind === "URL") return `/urls/${Buffer.from(value).toString("base64url").replace(/=+$/,"")}`;
  if (kind === "IP") return `/ip_addresses/${encodeURIComponent(value)}`;
  if (kind === "DOMAIN") return `/domains/${encodeURIComponent(value)}`;
  return null;
}

function summarize(data,kind,value) {
  const attributes=data?.data?.attributes || {};
  const stats=attributes.last_analysis_stats || {};
  const malicious=Number(stats.malicious)||0;
  const suspicious=Number(stats.suspicious)||0;
  const harmless=Number(stats.harmless)||0;
  const undetected=Number(stats.undetected)||0;
  const total=malicious+suspicious+harmless+undetected;
  return {
    provider:"VirusTotal",kind,value,
    reputation:Number(attributes.reputation)||0,
    stats:{malicious,suspicious,harmless,undetected,total},
    verdict:malicious>0?"MALICIOUS":suspicious>0?"SUSPICIOUS":total>0?"NO_MALICIOUS_DETECTIONS":"UNKNOWN",
    lastAnalysisDate:attributes.last_analysis_date ? new Date(attributes.last_analysis_date*1000).toISOString() : null,
    permalink:kind==="URL"?`https://www.virustotal.com/gui/url/${Buffer.from(value).toString("base64url").replace(/=+$/,"")}`:null,
    checkedAt:new Date().toISOString(),
  };
}

async function cachedLookup(ioc) {
  const cached=await pool.query(
    "SELECT provider,result,checked_at FROM ioc_intel_cache WHERE kind=$1 AND value=$2 AND checked_at > NOW() - ($3::int * INTERVAL '1 hour')",
    [ioc.kind,ioc.value,CACHE_HOURS]
  );
  if(cached.rowCount) return {...cached.rows[0].result,cached:true,checkedAt:cached.rows[0].checked_at};

  const apiKey=process.env.VIRUSTOTAL_API_KEY;
  if(!apiKey) return {provider:"VirusTotal",kind:ioc.kind,value:ioc.value,verdict:"NOT_CONFIGURED",message:"Set VIRUSTOTAL_API_KEY to enable live reputation checks.",cached:false};

  const path=vtPath(ioc.kind,ioc.value);
  if(!path) return {provider:"VirusTotal",kind:ioc.kind,value:ioc.value,verdict:"UNSUPPORTED_TYPE",cached:false};
  const response=await fetch(VT_BASE+path,{headers:{"x-apikey":apiKey},signal:AbortSignal.timeout(7000)});
  if(response.status===404) return {provider:"VirusTotal",kind:ioc.kind,value:ioc.value,verdict:"NO_RECORD",message:"No VirusTotal record was found.",cached:false};
  if(response.status===429) return {provider:"VirusTotal",kind:ioc.kind,value:ioc.value,verdict:"RATE_LIMITED",message:"Provider rate limit reached. Retry later.",cached:false};
  if(!response.ok) return {provider:"VirusTotal",kind:ioc.kind,value:ioc.value,verdict:"PROVIDER_ERROR",message:`Provider returned HTTP ${response.status}.`,cached:false};
  const data=await response.json();
  const result=summarize(data,ioc.kind,ioc.value);
  await pool.query(
    "INSERT INTO ioc_intel_cache (kind,value,provider,result,checked_at) VALUES ($1,$2,$3,$4,NOW()) ON CONFLICT (kind,value,provider) DO UPDATE SET result=EXCLUDED.result,checked_at=NOW()",
    [ioc.kind,ioc.value,"VirusTotal",JSON.stringify(result)]
  );
  return {...result,cached:false};
}

export async function enrichCaseIocs(caseUuid) {
  const found=await pool.query("SELECT id,value,kind FROM iocs WHERE case_id=$1 ORDER BY kind,value LIMIT $2",[caseUuid,MAX_LOOKUPS]);
  const results=[];
  for(const ioc of found.rows) {
    try {
      const result=await cachedLookup(ioc);
      results.push(result);
      await pool.query("UPDATE iocs SET verdict=$1,confidence=$2 WHERE id=$3",[
        result.verdict,
        result.stats?.total ? Math.round((result.stats.malicious+result.stats.suspicious)/result.stats.total*100) : null,
        ioc.id
      ]);
    } catch {
      results.push({provider:"VirusTotal",kind:ioc.kind,value:ioc.value,verdict:"LOOKUP_FAILED",message:"Reputation lookup failed or timed out.",cached:false});
    }
  }
  return {provider:"VirusTotal",configured:Boolean(process.env.VIRUSTOTAL_API_KEY),lookedUp:results.length,limit:MAX_LOOKUPS,results};
}
