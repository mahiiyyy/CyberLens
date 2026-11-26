const API=import.meta.env.VITE_API_URL||(import.meta.env.PROD?"/api":"http://localhost:4000/api");
export async function api(path,options={}){
 const res=await fetch(API+path,{...options,credentials:"include",headers:{"Content-Type":"application/json",...options.headers}});
 const data=await res.json().catch(()=>({}));
 if(res.status===401&&!path.startsWith("/auth/"))window.dispatchEvent(new Event("cyberlens-auth-expired"));
 if(!res.ok){const e=new Error(data.error||"API request failed");e.status=res.status;throw e;}
 return data;
}
export function clearAuth(){
 for(const storage of [localStorage,sessionStorage])for(const key of ["cyberlens_token","cyberlens_user","cyberlens_result","cyberlens_history"])storage.removeItem(key);
}

/** Bytes held in memory only (never storage) so a result can be saved later with explicit consent. */
export const pendingIntake = { bytes: null, kind: "paste", filename: "", sample: false };

export function currentResult(){
 try{const r=JSON.parse(sessionStorage.getItem("cyberlens_result")||"null");return r?.status==="complete"&&Number.isFinite(r.score)?r:null;}catch{return null;}
}
export function setCurrentResult(result){sessionStorage.setItem("cyberlens_result",JSON.stringify(result));}

export const toHex=buffer=>Array.from(new Uint8Array(buffer),x=>x.toString(16).padStart(2,"0")).join("");
export async function sha256OfBytes(bytes){
 if(!globalThis.crypto?.subtle)throw new Error("SHA-256 requires a secure browser context.");
 return toHex(await crypto.subtle.digest("SHA-256",bytes));
}
export async function downloadBlob(path,filename){
 const res=await fetch(API+path,{credentials:"include"});
 if(!res.ok){const d=await res.json().catch(()=>({}));throw new Error(d.error||"Download failed");}
 const url=URL.createObjectURL(await res.blob());
 const a=document.createElement("a");a.href=url;a.download=filename;document.body.appendChild(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(url),1000);
}
