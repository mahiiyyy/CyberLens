import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import { z } from "zod";
import { pool } from "../db/pool.js";
import { requireAuth } from "../middleware/auth.js";
const router=Router();
const schema=z.object({email:z.string().trim().email().max(254).transform(s=>s.toLowerCase()),password:z.string().min(8).refine(s=>Buffer.byteLength(s,"utf8")<=72),remember:z.boolean().optional()});
const limit=rateLimit({windowMs:15*60*1000,limit:20,standardHeaders:true,legacyHeaders:false,message:{error:"Too many attempts. Try again later."}});
const cookie={httpOnly:true,secure:process.env.NODE_ENV==="production",sameSite:"lax",path:"/"};
function issue(res,user,remember){
 const token=jwt.sign({sub:user.id},process.env.JWT_SECRET,{algorithm:"HS256",issuer:"cyberlens-account",expiresIn:remember?"7d":"2h"});
 res.cookie("cyberlens_session",token,{...cookie,...(remember?{maxAge:604800000}:{})});
 return res.set("Cache-Control","no-store").json({user:{id:user.id,email:user.email,role:user.role}});
}
router.post("/register",limit,async(req,res,next)=>{
 try{
 const parsed=schema.safeParse(req.body);
 if(!parsed.success)return res.status(400).json({error:"Enter a valid email and password of at least 8 characters (maximum 72 bytes)."});
 const {email,password,remember}=parsed.data;
 const hash=await bcrypt.hash(password,12);
 const result=await pool.query("INSERT INTO users(email,password_hash,role) VALUES($1,$2,'ANALYST') ON CONFLICT(email) DO NOTHING RETURNING id,email,role",[email,hash]);
 if(!result.rowCount)return res.status(409).json({error:"Unable to create account. Try signing in."});
 return issue(res,result.rows[0],remember);
 }catch(e){next(e);}
});
router.post("/login",limit,async(req,res,next)=>{
 try{
 const parsed=schema.safeParse(req.body);
 if(!parsed.success)return res.status(401).json({error:"Invalid email or password"});
 const {email,password,remember}=parsed.data;
 const result=await pool.query("SELECT id,email,role,password_hash FROM users WHERE email=$1",[email]);
 const user=result.rows[0];
 if(!user||!(await bcrypt.compare(password,user.password_hash)))return res.status(401).json({error:"Invalid email or password"});
 return issue(res,user,remember);
 }catch(e){next(e);}
});
router.get("/me",requireAuth,(req,res)=>res.set("Cache-Control","no-store").json({user:req.user}));
router.post("/logout",(req,res)=>res.clearCookie("cyberlens_session",cookie).json({ok:true}));
export default router;
