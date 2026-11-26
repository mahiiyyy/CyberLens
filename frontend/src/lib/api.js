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
