import { Router } from "express";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { pool } from "../db/pool.js";
import { requireAuth } from "../middleware/auth.js";
import { audit } from "../services/audit.js";

const router = Router();
router.use(requireAuth);
const createSchema=z.object({title:z.string().trim().min(1).max(160)});
const updateSchema=z.object({status:z.enum(["Open","Closed"]).optional(),title:z.string().trim().min(1).max(160).optional(),priority:z.enum(["Unclassified","Low","Medium","High","Critical"]).optional(),notes:z.string().max(10000).optional()}).refine(b=>Object.values(b).some(v=>v!==undefined));
router.get("/",async(req,res,next)=>{
 try{
 const result=await pool.query("SELECT id,case_no,title,priority,status,created_at,updated_at FROM cases WHERE investigator_id=$1 ORDER BY created_at DESC LIMIT 200",[req.user.id]);
 res.set("Cache-Control","no-store").json({cases:result.rows});
 }catch(e){next(e);}
});
router.get("/stats",async(req,res,next)=>{
 try{
 const uid=req.user.id;
 const [totals,activity,recent,inv]=await Promise.all([
 pool.query("SELECT count(*)::int AS total, count(*) FILTER (WHERE status='Open')::int AS open, count(*) FILTER (WHERE status='Closed')::int AS closed, count(*) FILTER (WHERE (created_at AT TIME ZONE 'UTC')::date=(NOW() AT TIME ZONE 'UTC')::date)::int AS today FROM cases WHERE investigator_id=$1",[uid]),
 pool.query("WITH days AS (SELECT generate_series((NOW() AT TIME ZONE 'UTC')::date-6,(NOW() AT TIME ZONE 'UTC')::date,'1 day'::interval)::date AS day) SELECT to_char(d.day,'YYYY-MM-DD') AS day,count(c.id)::int AS count FROM days d LEFT JOIN cases c ON c.investigator_id=$1 AND (c.created_at AT TIME ZONE 'UTC')::date=d.day GROUP BY d.day ORDER BY d.day",[uid]),
 pool.query("SELECT id,title,status,created_at FROM cases WHERE investigator_id=$1 ORDER BY created_at DESC LIMIT 8",[uid]),
 pool.query("SELECT count(*)::int AS total, count(*) FILTER (WHERE score>=75)::int AS high_risk, count(*) FILTER (WHERE score>=50 AND score<75)::int AS suspicious, count(*) FILTER (WHERE score<50)::int AS lower_risk FROM investigations WHERE user_id=$1 AND NOT is_sample",[uid])
 ]);
 res.set("Cache-Control","no-store").json({stats:totals.rows[0],activity:activity.rows,recent:recent.rows,investigations:inv.rows[0]});
 }catch(e){next(e);}
});
router.post("/",async(req,res,next)=>{
 const parsed=createSchema.safeParse(req.body);
 if(!parsed.success)return res.status(400).json({error:"Enter a case title between 1 and 160 characters."});
 try{
 const result=await pool.query("INSERT INTO cases(case_no,title,priority,status,investigator_id) VALUES($1,$2,'Unclassified','Open',$3) RETURNING id,case_no,title,priority,status,created_at,updated_at",["CASE-"+randomUUID(),parsed.data.title,req.user.id]);
 await audit(req.user.id,"case.create","case",result.rows[0].id,{caseNo:result.rows[0].case_no});
 res.status(201).json({case:result.rows[0]});
 }catch(e){next(e);}
});
router.get("/:id",async(req,res,next)=>{
 const id=z.string().uuid().safeParse(req.params.id);
 if(!id.success)return res.status(400).json({error:"Invalid case"});
 try{
 const c=await pool.query("SELECT id,case_no,title,priority,status,notes,created_at,updated_at FROM cases WHERE id=$1 AND investigator_id=$2",[id.data,req.user.id]);
 if(!c.rowCount)return res.status(404).json({error:"Case not found"});
 const inv=await pool.query("SELECT id,reference,title,verdict,score,is_sample,original_sha256,created_at FROM investigations WHERE case_id=$1 AND user_id=$2 ORDER BY created_at DESC",[id.data,req.user.id]);
 res.set("Cache-Control","no-store").json({case:c.rows[0],investigations:inv.rows});
 }catch(e){next(e);}
});
router.patch("/:id",async(req,res,next)=>{
 const id=z.string().uuid().safeParse(req.params.id);
 const parsed=updateSchema.safeParse(req.body);
 if(!id.success||!parsed.success)return res.status(400).json({error:"Invalid case update"});
 const b=parsed.data;
 try{
 const result=await pool.query("UPDATE cases SET status=COALESCE($1,status),title=COALESCE($2,title),priority=COALESCE($3,priority),notes=COALESCE($4,notes),updated_at=NOW() WHERE id=$5 AND investigator_id=$6 RETURNING id,case_no,title,priority,status,notes,created_at,updated_at",[b.status??null,b.title??null,b.priority??null,b.notes??null,id.data,req.user.id]);
 if(!result.rowCount)return res.status(404).json({error:"Case not found"});
 await audit(req.user.id,"case.update","case",id.data,{fields:Object.keys(b)});
 res.json({case:result.rows[0]});
 }catch(e){next(e);}
});
export default router;
