import net from "node:net";

const MAX_SCAN_BYTES = 20 * 1024 * 1024;

function scanBuffer(buffer) {
  return new Promise((resolve,reject)=>{
    const host=process.env.CLAMAV_HOST || "127.0.0.1";
    const port=Number(process.env.CLAMAV_PORT || 3310);
    const socket=net.createConnection({host,port});
    let response="";
    let settled=false;
    const finish=(error,value)=>{
      if(settled)return;
      settled=true;
      socket.destroy();
      error?reject(error):resolve(value);
    };
    const timer=setTimeout(()=>finish(new Error("ClamAV scan timed out")),10000);
    socket.setTimeout(10000,()=>finish(new Error("ClamAV socket timed out")));
    socket.on("connect",()=>{
      socket.write("zINSTREAM\0");
      const chunkSize=64*1024;
      for(let offset=0;offset<buffer.length;offset+=chunkSize){
        const chunk=buffer.subarray(offset,Math.min(offset+chunkSize,buffer.length));
        const size=Buffer.alloc(4);
        size.writeUInt32BE(chunk.length,0);
        socket.write(size);
        socket.write(chunk);
      }
      socket.write(Buffer.alloc(4));
    });
    socket.on("data",chunk=>{
      response+=chunk.toString("utf8");
      if(response.length>4096)return finish(new Error("Unexpected ClamAV response"));
      if(response.includes("\0") || /\b(?:OK|FOUND|ERROR)\s*$/.test(response.trim())){
        const value=response.replace(/\0/g,"").trim();
        clearTimeout(timer);
        if(value.endsWith(" OK")) finish(null,{status:"CLEAN",engine:"ClamAV",detail:value});
        else if(value.endsWith(" FOUND")) finish(null,{status:"INFECTED",engine:"ClamAV",detail:value});
        else finish(new Error(value || "ClamAV scan failed"));
      }
    });
    socket.on("error",error=>{clearTimeout(timer);finish(error);});
    socket.on("close",()=>{clearTimeout(timer);if(!settled)finish(new Error("ClamAV closed connection before returning a result"));});
  });
}

export async function scanAttachment(buffer) {
  if(!Buffer.isBuffer(buffer)) return {status:"NOT_SCANNED",reason:"Attachment content unavailable."};
  if(buffer.length>MAX_SCAN_BYTES) return {status:"NOT_SCANNED",reason:"Attachment exceeds the 20 MB antivirus scan limit."};
  try { return await scanBuffer(buffer); }
  catch(error) {
    return {status:"SCAN_UNAVAILABLE",engine:"ClamAV",reason:error.message};
  }
}
