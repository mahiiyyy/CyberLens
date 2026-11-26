import React,{useState} from "react";
import {ArrowRight,LockKeyhole,Loader2} from "lucide-react";
import {useNavigate} from "react-router-dom";
import {Button,Card} from "../components/ui";
import {api,clearAuth} from "../lib/api";
export default function Login(){
 const nav=useNavigate();
 const [register,setRegister]=useState(false),[email,setEmail]=useState(""),[password,setPassword]=useState(""),[confirm,setConfirm]=useState(""),[remember,setRemember]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState("");
 const submit=async e=>{
 e.preventDefault();setError("");
 if(register&&password!==confirm){setError("Passwords do not match.");return;}
 setBusy(true);
 try{await api(register?"/auth/register":"/auth/login",{method:"POST",body:JSON.stringify({email,password,remember})});clearAuth();nav("/dashboard",{replace:true});}
 catch(e){setError(e.message);}finally{setBusy(false);}
 };
 const field="mt-1 w-full rounded-lg border border-cyber-line bg-black/20 p-3 text-sm outline-none focus:border-cyber-cyan";
 return <div className="min-h-screen grid-bg flex items-center justify-center p-5"><Card className="w-full max-w-md p-7 shadow-glow">
 <div className="text-center"><div className="text-xl font-black text-white"><span className="text-cyber-cyan">CYBER</span>LENS</div><p className="mt-2 text-sm text-slate-400">{register?"Create your analyst account":"Sign in to your analyst workspace"}</p></div>
 <form onSubmit={submit} className="mt-8 space-y-4">
 <label className="block text-xs text-slate-400">Email<input className={field} type="email" autoComplete="email" required value={email} onChange={e=>setEmail(e.target.value)}/></label>
 <label className="block text-xs text-slate-400">Password<input className={field} type="password" minLength={8} autoComplete={register?"new-password":"current-password"} required value={password} onChange={e=>setPassword(e.target.value)}/></label>
 {register&&<label className="block text-xs text-slate-400">Confirm password<input className={field} type="password" autoComplete="new-password" required value={confirm} onChange={e=>setConfirm(e.target.value)}/></label>}
 <label className="flex items-center gap-2 text-xs text-slate-400"><input type="checkbox" checked={remember} onChange={e=>setRemember(e.target.checked)}/>Remember me</label>
 {error&&<div role="alert" className="rounded-lg border border-red-400/20 bg-red-400/5 p-3 text-xs text-red-300">{error}</div>}
 <Button type="submit" disabled={busy} className="w-full">{busy?<Loader2 className="mx-auto animate-spin" size={16}/>:<>{register?"CREATE ACCOUNT":"SIGN IN"}<ArrowRight className="ml-2 inline" size={15}/></>}</Button>
 </form><button type="button" disabled={busy} onClick={()=>{setRegister(!register);setError("");setPassword("");setConfirm("");}} className="mt-6 w-full text-center text-xs text-cyan-300">{register?"Already registered? Sign in":"New to CyberLens? Create account"}</button>
 <div className="mt-5 flex items-center justify-center gap-2 text-xs text-emerald-400"><LockKeyhole size={12}/>Account authentication</div>
 </Card></div>;
}
