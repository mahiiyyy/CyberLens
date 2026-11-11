import React, { useState } from "react";
import { ArrowRight, LockKeyhole, Loader2 } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { Button, Card } from "../components/ui";
import { api } from "../lib/api";

export default function Login() {
  const nav = useNavigate();
  const [email, setEmail] = useState("analyst@cyberlens.local");
  const [password, setPassword] = useState("demo-password");
  const [remember, setRemember] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    setBusy(true);

    try {
      const data = await api("/auth/login", {
        method: "POST",
        body: JSON.stringify({ email, password }),
      });

      const storage = remember ? localStorage : sessionStorage;
      storage.setItem("cyberlens_token", data.token);
      storage.setItem("cyberlens_user", JSON.stringify(data.user));
      nav("/dashboard", { replace: true });
    } catch (err) {
      setError(err.message || "Unable to sign in");
    } finally {
      setBusy(false);
    }
  };

  return <div className="min-h-screen grid-bg flex items-center justify-center p-5">
    <Card className="w-full max-w-md p-7 shadow-glow">
      <div className="text-center">
        <div className="text-xl font-black text-white"><span className="text-cyber-cyan">CYBER</span>LENS</div>
        <p className="mt-2 text-xs text-slate-500">Secure analyst workspace</p>
      </div>

      <form onSubmit={submit} className="mt-8 space-y-4">
        <div>
          <label className="text-xs text-slate-500">Email</label>
          <input value={email} onChange={e => setEmail(e.target.value)} type="email" autoComplete="username" required className="mt-1 w-full rounded-lg border border-cyber-line bg-black/20 p-3 text-sm outline-none focus:border-cyber-cyan" />
        </div>
        <div>
          <label className="text-xs text-slate-500">Password</label>
          <input value={password} onChange={e => setPassword(e.target.value)} type="password" autoComplete="current-password" required className="mt-1 w-full rounded-lg border border-cyber-line bg-black/20 p-3 text-sm outline-none focus:border-cyber-cyan" />
        </div>
        <label className="flex items-center gap-2 text-xs text-slate-500">
          <input type="checkbox" checked={remember} onChange={e => setRemember(e.target.checked)} /> Remember me
        </label>

        {error && <div className="rounded-lg border border-red-400/20 bg-red-400/5 p-3 text-xs text-red-300">{error}</div>}

        <Button type="submit" disabled={busy} className="w-full">
          {busy ? <><Loader2 className="mr-2 inline animate-spin" size={15}/>SIGNING IN…</> : <>SIGN IN <ArrowRight className="ml-2 inline" size={15}/></>}
        </Button>
      </form>

      <div className="mt-6 border-t border-cyber-line pt-5 text-center text-[10px] text-slate-600">
        Demo account: analyst@cyberlens.local · demo-password
      </div>
      <div className="mt-4 flex items-center justify-center gap-2 text-[10px] text-emerald-400"><LockKeyhole size={12}/> JWT authentication enabled</div>
    </Card>
  </div>;
}
