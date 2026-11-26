import test from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { randomUUID } from "node:crypto";
import auth from "../routes/auth.js";
import cases from "../routes/cases.js";
import { pool } from "../db/pool.js";

test("case lifecycle and dashboard counts are isolated per account", async () => {
 assert.equal(process.env.CYBERLENS_TEST_DB,"1");
 const app=express();
 app.use(express.json());
 app.use("/auth",auth);
 app.use("/cases",cases);
 app.use((err,req,res,next)=>res.status(500).json({error:"Test server error"}));
 const server=app.listen(0,"127.0.0.1");
 await new Promise(resolve=>server.once("listening",resolve));
 const base="http://127.0.0.1:"+server.address().port;
 const emails=[randomUUID()+"@example.invalid",randomUUID()+"@example.invalid"];
 const request=(path,method="GET",body,cookie)=>fetch(base+path,{method,headers:{"Content-Type":"application/json",...(cookie?{Cookie:cookie}:{})},...(body===undefined?{}:{body:JSON.stringify(body)})});
 const register=async email=>{
 const r=await request("/auth/register","POST",{email,password:"Test-only-password-729"});
 assert.equal(r.status,200);
 return r.headers.get("set-cookie").split(";")[0];
 };
 try{
 assert.equal((await request("/cases")).status,401);
 const first=await register(emails[0]),second=await register(emails[1]);
 assert.equal((await request("/cases","POST",{title:"   "},first)).status,400);
 const create=await request("/cases","POST",{title:"Sample test case"},first);
 assert.equal(create.status,201);
 const {case:record}=await create.json();
 assert.equal(record.status,"Open");
 const list=await (await request("/cases","GET",undefined,first)).json();
 assert.equal(list.cases.length,1);
 assert.equal(list.cases[0].id,record.id);
 const other=await (await request("/cases","GET",undefined,second)).json();
 assert.equal(other.cases.length,0);
 assert.equal((await request("/cases/"+record.id,"PATCH",{status:"Closed"},second)).status,404);
 const statsResponse=await request("/cases/stats","GET",undefined,first);
 assert.equal(statsResponse.status,200);
 const stats=await statsResponse.json();
 assert.equal(stats.stats.total,1);
 assert.equal(stats.stats.open,1);
 assert.equal(stats.stats.closed,0);
 assert.equal(stats.activity.length,7);
 assert.equal(stats.activity.reduce((sum,d)=>sum+d.count,0),1);
 assert.equal(stats.recent[0].id,record.id);
 const otherStats=await (await request("/cases/stats","GET",undefined,second)).json();
 assert.equal(otherStats.stats.total,0);
 assert.equal(otherStats.recent.length,0);
 assert.equal((await request("/cases/"+record.id,"PATCH",{status:"Invalid"},first)).status,400);
 assert.equal((await request("/cases/"+record.id,"PATCH",{status:"Closed"},first)).status,200);
 const closed=await (await request("/cases/stats","GET",undefined,first)).json();
 assert.equal(closed.stats.closed,1);
 assert.equal(closed.stats.open,0);
 assert.equal((await request("/cases/"+record.id,"PATCH",{status:"Open"},first)).status,200);
 }finally{
 try{await pool.query("DELETE FROM cases WHERE investigator_id IN (SELECT id FROM users WHERE email=ANY($1::text[]))",[emails]);await pool.query("DELETE FROM users WHERE email=ANY($1::text[])",[emails]);}finally{await new Promise(resolve=>server.close(resolve));await pool.end();}
 }
});
