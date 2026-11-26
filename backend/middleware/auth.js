import jwt from "jsonwebtoken";
import {pool} from "../db/pool.js";
export async function requireAuth(req,res,next){
 const token=(req.headers.cookie||"").split(";").map(s=>s.trim()).find(s=>s.startsWith("cyberlens_session="))?.slice("cyberlens_session=".length);
 if(!token)return res.status(401).json({error:"Authentication required"});
 let claims;
 try{claims=jwt.verify(token,process.env.JWT_SECRET,{algorithms:["HS256"],issuer:"cyberlens-account"});}catch{return res.status(401).json({error:"Invalid or expired session"});}
 try{
 const result=await pool.query("SELECT id,email,role FROM users WHERE id=$1",[claims.sub]);
 if(!result.rowCount)return res.status(401).json({error:"Account not found"});
 req.user={...result.rows[0],sub:result.rows[0].id};next();
 }catch(e){next(e);}
}
export function requireRole(...roles){return(req,res,next)=>roles.includes(req.user?.role)?next():res.status(403).json({error:"Insufficient role"});}
