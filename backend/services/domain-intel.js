import dns from "node:dns/promises";
import { isIP } from "node:net";

const timeout = ms => AbortSignal.timeout(ms);
const validDomain = value => {
  const domain=String(value||"").toLowerCase().replace(/\.$/,"");
  return domain.length<=253 && domain.includes(".") && !isIP(domain) &&
    domain.split(".").every(label=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
};
async function safeDns(method,domain) {
  try { return await Promise.race([dns[method](domain),new Promise((_,reject)=>setTimeout(()=>reject(new Error("DNS timeout")),3500))]); }
  catch(error) { return {error:error.code||error.message||"DNS_LOOKUP_FAILED"}; }
}
async function rdap(domain) {
  try {
    const response=await fetch("https://rdap.org/domain/"+encodeURIComponent(domain),{signal:timeout(5000),headers:{accept:"application/rdap+json"}});
    if(response.status===404)return {status:"NOT_FOUND"};
    if(!response.ok)return {status:"UNAVAILABLE",httpStatus:response.status};
    const data=await response.json();
    const events=(data.events||[]).map(e=>({action:e.eventAction,date:e.eventDate})).filter(e=>["registration","expiration","last changed"].includes(e.action));
    return {status:"AVAILABLE",ldhName:data.ldhName||domain,handle:data.handle||null,registrar:(data.entities||[]).flatMap(e=>e.vcardArray?.[1]||[]).find(v=>v[0]==="fn")?.[3]||null,events,nameservers:(data.nameservers||[]).map(n=>n.ldhName).filter(Boolean)};
  } catch { return {status:"UNAVAILABLE"}; }
}
export async function inspectDomain(domain) {
  if(!validDomain(domain))return {domain,status:"INVALID_DOMAIN"};
  const [a,aaaa,mx,ns,txt,rdapData]=await Promise.all([
    safeDns("resolve4",domain),safeDns("resolve6",domain),safeDns("resolveMx",domain),
    safeDns("resolveNs",domain),safeDns("resolveTxt",domain),rdap(domain),
  ]);
  const txtRows=Array.isArray(txt)?txt.map(row=>row.join("")):[];
  const spf=txtRows.filter(row=>/^v=spf1\b/i.test(row));
  const dmarcRaw=await safeDns("resolveTxt","_dmarc."+domain);
  const dmarcRows=Array.isArray(dmarcRaw)?dmarcRaw.map(row=>row.join("")).filter(row=>/^v=DMARC1\b/i.test(row)):[];
  return {
    domain,status:"LOOKED_UP",
    dns:{
      a:Array.isArray(a)?a:[],aaaa:Array.isArray(aaaa)?aaaa:[],
      mx:Array.isArray(mx)?mx.map(x=>({exchange:x.exchange,priority:x.priority})):[],
      ns:Array.isArray(ns)?ns:[],
      spfRecords:spf,dmarcRecords:dmarcRows,
      errors:{a:a?.error||null,aaaa:aaaa?.error||null,mx:mx?.error||null,ns:ns?.error||null,txt:txt?.error||null,dmarc:dmarcRaw?.error||null}
    },
    rdap:rdapData,
    checkedAt:new Date().toISOString(),
    notes:["DNS records and RDAP registration data are informational signals, not proof of maliciousness.","SPF and DMARC records are published DNS policy; this lookup does not authenticate the message."]
  };
}
export async function enrichCaseDomains(caseUuid) {
  const rows=await poolQuery(caseUuid);
  const results=[];
  for(const row of rows) {
    try {
      const cached=await cacheGet(row.value);
      if(cached){results.push({...cached,cached:true});continue;}
      const result=await inspectDomain(row.value);
      if(result.status==="LOOKED_UP")await cachePut(row.value,result);
      results.push({...result,cached:false});
    } catch { results.push({domain:row.value,status:"LOOKUP_FAILED"}); }
  }
  return {lookedUp:results.length,results};
}
import { pool } from "../db/pool.js";
async function poolQuery(caseUuid) {
  const r=await pool.query("SELECT DISTINCT value FROM iocs WHERE case_id=$1 AND kind='DOMAIN' ORDER BY value LIMIT 15",[caseUuid]);
  return r.rows;
}
async function cacheGet(domain) {
  const r=await pool.query("SELECT result FROM domain_intel_cache WHERE domain=$1 AND checked_at>NOW()-INTERVAL '24 hours'",[domain]);
  return r.rowCount? r.rows[0].result:null;
}
async function cachePut(domain,result) {
  await pool.query("INSERT INTO domain_intel_cache (domain,result,checked_at) VALUES ($1,$2,NOW()) ON CONFLICT (domain) DO UPDATE SET result=EXCLUDED.result,checked_at=NOW()",[domain,JSON.stringify(result)]);
}
