import { Router } from "express";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { pool } from "../db/pool.js";
import { requireAuth } from "../middleware/auth.js";

const router = Router();
router.use(requireAuth);
const createSchema=z.object({title:z.string().trim().min(1).max(160)});
const updateSchema=z.object({status:z.enum(["Open","Closed"])});
router.get("/",async(req,res,next)=>{
 try{
 const result=await pool.query("SELECT id,case_no,title,priority,status,created_at,updated_at FROM cases WHERE investigator_id=$1 ORDER BY created_at DESC LIMIT 200",[req.user.id]);
 res.set("Cache-Control","no-store").json({cases:result.rows});
 }catch(e){next(e);}
});
router.get("/stats",async(req,res,next)=>{
 try{
 const uid=req.user.id;
 const [totals,activity,recent]=await Promise.all([
 pool.query("SELECT count(*)::int AS total, count(*) FILTER (WHERE status='Open')::int AS open, count(*) FILTER (WHERE status='Closed')::int AS closed, count(*) FILTER (WHERE (created_at AT TIME ZONE 'UTC')::date=(NOW() AT TIME ZONE 'UTC')::date)::int AS today FROM cases WHERE investigator_id=$1",[uid]),
 pool.query("WITH days AS (SELECT generate_series((NOW() AT TIME ZONE 'UTC')::date-6,(NOW() AT TIME ZONE 'UTC')::date,'1 day'::interval)::date AS day) SELECT to_char(d.day,'YYYY-MM-DD') AS day,count(c.id)::int AS count FROM days d LEFT JOIN cases c ON c.investigator_id=$1 AND (c.created_at AT TIME ZONE 'UTC')::date=d.day GROUP BY d.day ORDER BY d.day",[uid]),
 pool.query("SELECT id,title,status,created_at FROM cases WHERE investigator_id=$1 ORDER BY created_at DESC LIMIT 8",[uid])
 ]);
 res.set("Cache-Control","no-store").json({stats:totals.rows[0],activity:activity.rows,recent:recent.rows});
 }catch(e){next(e);}
});
router.post("/",async(req,res,next)=>{
 const parsed=createSchema.safeParse(req.body);
 if(!parsed.success)return res.status(400).json({error:"Enter a case title between 1 and 160 characters."});
 try{
 const result=await pool.query("INSERT INTO cases(case_no,title,priority,status,investigator_id) VALUES($1,$2,'Unclassified','Open',$3) RETURNING id,case_no,title,priority,status,created_at,updated_at",["CASE-"+randomUUID(),parsed.data.title,req.user.id]);
 res.status(201).json({case:result.rows[0]});
 }catch(e){next(e);}
});
router.patch("/:id",async(req,res,next)=>{
 const id=z.string().uuid().safeParse(req.params.id);
 const parsed=updateSchema.safeParse(req.body);
 if(!id.success||!parsed.success)return res.status(400).json({error:"Invalid case or status"});
 try{
 const result=await pool.query("UPDATE cases SET status=$1,updated_at=NOW() WHERE id=$2 AND investigator_id=$3 RETURNING id,case_no,title,priority,status,created_at,updated_at",[parsed.data.status,id.data,req.user.id]);
 if(!result.rowCount)return res.status(404).json({error:"Case not found"});
 res.json({case:result.rows[0]});
 }catch(e){next(e);}
});
export default router;
