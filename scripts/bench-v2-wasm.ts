// Real Chrome, eight-thread WASM, synthetic local TLS fixture.
// See docs/v2-presentation-optimizations.md for fixture generation and usage.
import {resolve} from 'node:path';
const variant=process.argv[2] ?? 'baseline';
const modulePath=variant==='baseline'? '/.zkf/v2-profile/wasm-baseline/zkf.js':'/packages/wasm/pkg-threads/zkf.js';
const fixturePath=process.env.ZKF_V2_PROFILE_FIXTURE ?? '/private/tmp/zkf-v2-profile-fixture.json';
const fixture=await Bun.file(fixturePath).json();
fixture.options.maxAgeSecs=null;
fixture.request.parameters=process.env.ZKF_V2_PARAMETERS ?? "fast";
const html=`<!doctype html><script type="module">
import init,* as w from '${modulePath}';
window.result=(async()=>{
 await init();await w.initThreadPool(8);
 const f=await fetch('/fixture').then(r=>r.json());const rows=[];
 for(let i=0;i<4;i++){
  w.setV2Profiling(true);let at=performance.now();
  const proof=w.presentV2(f.attestation,f.secrets,JSON.stringify(f.request));
  const proveMs=performance.now()-at;const proveProfile=JSON.parse(w.takeV2Profile());
  w.setV2Profiling(true);at=performance.now();
  const verified=JSON.parse(w.verifyV2(proof,JSON.stringify(f.options)));
  const verifyMs=performance.now()-at;const verifyProfile=JSON.parse(w.takeV2Profile());
  rows.push({round:i,proveMs,verifyMs,proofBytes:atob(proof).length,verified:!!verified.serverName,proveProfile,verifyProfile});
 }
 return rows;
})();
</script>`;
const server=Bun.serve({hostname:'127.0.0.1',port:9239,fetch(req){
 const path=new URL(req.url).pathname;let body:any;
 if(path==='/')body=html;
 else if(path==='/fixture')body=JSON.stringify(fixture);
 else if(path.startsWith('/packages/wasm/pkg-threads/') || path.startsWith('/.zkf/v2-profile/wasm-baseline/'))body=Bun.file(resolve('.'+path));
 else return new Response('',{status:404});
 return new Response(body,{headers:{'Cross-Origin-Opener-Policy':'same-origin','Cross-Origin-Embedder-Policy':'require-corp',...(path==='/'?{'Content-Type':'text/html'}:{})}});
}});
const chrome=Bun.spawn([process.env.CHROME_BINARY ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome','--headless=new','--no-first-run','--remote-debugging-port=9240','--user-data-dir=/private/tmp/zkf-v2-profile-chrome','about:blank'],{stdout:'ignore',stderr:'ignore'});
let socket:WebSocket|undefined;
try{
 let tabs:any;for(let i=0;i<100;i++){try{tabs=await fetch('http://127.0.0.1:9240/json').then(r=>r.json());break;}catch{}await Bun.sleep(100);}
 socket=new WebSocket(tabs[0].webSocketDebuggerUrl);await new Promise((r,j)=>{socket!.onopen=r;socket!.onerror=j;});
 let id=0;const pending=new Map();socket.onmessage=e=>{const data=JSON.parse(String(e.data));if(pending.has(data.id)){const p=pending.get(data.id);pending.delete(data.id);data.error?p.j(data.error):p.r(data.result);}};
 const call=(method:string,params:any={})=>new Promise<any>((r,j)=>{const next=++id;pending.set(next,{r,j});socket!.send(JSON.stringify({id:next,method,params}));});
 await call('Page.navigate',{url:'http://127.0.0.1:9239/'});for(let i=0;i<100;i++){const check=await call('Runtime.evaluate',{expression:'!!window.result',returnByValue:true});if(check.result.value)break;await Bun.sleep(200);}
 const r=await call('Runtime.evaluate',{expression:'window.result',awaitPromise:true,returnByValue:true});
 if(r.exceptionDetails || !Array.isArray(r.result.value))throw new Error(JSON.stringify(r));
 const report={variant,parameters:fixture.request.parameters,threads:8,client:'real-headless-Chrome',samples:r.result.value};
 if(report.samples.some((r:any)=>!r.verified))throw new Error('Proof did not verify');
 await Bun.write(`docs/benchmarks/d1-d3-baseline/wasm-profile-${variant}-2026-10-10.json`,JSON.stringify(report,null,2)+'\n');
 console.log(JSON.stringify(report));
}finally{socket?.close();chrome.kill();await chrome.exited;server.stop(true);}
