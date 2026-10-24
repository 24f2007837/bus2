const http=require('http'),{spawn}=require('child_process');
const plan={rootCause:'bad_deploy',evidence:['ev_2','ev_5'],diagnostics:[
 {toolName:'query_metrics',arguments:{service:'api'},evidence:['ev_2']},
 {toolName:'get_deploys',arguments:{service:'api'},evidence:['ev_5']}],
 effect:{toolName:'rollback_deployment',arguments:{service:'api',deployment:'d1'},evidence:['ev_5']},
 alternativeEffect:{toolName:'page_owner',arguments:{service:'api'},evidence:['ev_2']},scalingLimitReached:false};
http.createServer((q,r)=>{q.resume();q.on('end',()=>{r.setHeader('content-type','application/json');r.end(JSON.stringify({choices:[{message:{content:JSON.stringify(plan)}}]}))})}).listen(9001);
const sv=spawn('node',['server.js'],{env:{...process.env,PORT:8081,DATA_DIR:'/tmp/d'+Date.now(),LLM_BASE_URL:'http://localhost:9001',LLM_API_KEY:'x',LLM_MODEL:'mock'},stdio:'inherit'});
const call=async(m,p,b,h={})=>{const r=await fetch('http://localhost:8081'+p,{method:m,headers:{'content-type':'application/json',...h},body:b?JSON.stringify(b):undefined});return[r.status,await r.json()]};
const assert=(c,m)=>{if(!c){console.log('FAIL',m);process.exitCode=1}else console.log('ok',m)};
setTimeout(async()=>{
 const body={profile:'ga5-incident-agent/v2',runId:'run-12345678',agentName:'incident-response',publicMarker:'mk1',sensitive:{accessToken:'SECRET1'},
  incident:{incidentId:'i',title:'t',service:'api',severity:'SEV-1',transcript:'[ev_1] a\n[ev_2] b\n[ev_5] c',allowedRootCauses:['bad_deploy','x']},
  toolCatalog:[{name:'query_metrics',inputSchema:{type:'object',required:['service']}},{name:'get_deploys'},{name:'rollback_deployment'},{name:'page_owner'}],
  policy:{maximumDiagnostics:3,effectTools:['rollback_deployment','page_owner'],approvalRequiredFor:['rollback_deployment'],doNotExport:['SECRET1']}};
 const tp='00-'+'a'.repeat(32)+'-'+'b'.repeat(16)+'-01';
 let [s,r]=await call('POST','/v2/incidents',body,{traceparent:tp,tracestate:'v=1'});
 assert(s===200&&r.dispatches.length===2&&r.dispatches[0].traceparent.includes('a'.repeat(32)),'create');
 const [d1,d2]=r.dispatches;
 [s,r]=await call('POST','/v2/incidents/run-12345678/receipts',{receiptId:'rcpt-0001',outcomes:[{actionId:d1.actionId,callId:d1.callId,attempt:1,status:503,resultClass:'x',nonce:'n1'},{actionId:d2.actionId,callId:d2.callId,attempt:1,status:200,resultClass:'diagnosis_confirmed',nonce:'n2'}]});
 assert(s===200&&r.dispatches.length===1&&r.dispatches[0].attempt===2&&r.approvals.length===0,'retry');
 const rt=r.dispatches[0];
 [s,r]=await call('POST','/v2/incidents/run-12345678/receipts',{receiptId:'rcpt-0002',outcomes:[{actionId:rt.actionId,callId:rt.callId,attempt:2,status:200,resultClass:'diagnosis_confirmed',nonce:'n3'}]});
 assert(r.dispatches.length===0&&r.approvals.length===1&&r.approvals[0].argumentsDigest.length===64,'approval');
 const ap=r.approvals[0];
 [s,r]=await call('POST','/v2/incidents/run-12345678/receipts',{receiptId:'rcpt-0003',approvals:[{approvalId:ap.approvalId,decision:'approved',nonce:'n4'}]});
 const ef=r.dispatches[0]; assert(ef&&ef.approvalId===ap.approvalId&&ef.approvalNonce==='n4'&&ef.actionId===ap.actionId,'effect');
 [s,r]=await call('POST','/v2/incidents/run-12345678/receipts',{receiptId:'rcpt-0004',outcomes:[{actionId:ef.actionId,callId:ef.callId,attempt:1,status:200,resultClass:'ok',nonce:'n5'}]});
 assert(r.status==='completed'&&r.chosenEffect==='rollback_deployment','completed');
 const spans=r.otlp.resourceSpans[0].scopeSpans[0].spans;
 const cnt=n=>spans.filter(x=>x.name===n||x.name.startsWith(n)).length;
 console.log(spans.map(x=>x.name+' k'+x.kind).join(' | '));
 assert(spans.filter(x=>x.name.startsWith('POST tool/')).length===4,'4 client spans');
 assert(!JSON.stringify(r).includes('SECRET1'),'no leak');
 assert(r.actionLog.length===4&&r.receiptLog.length===5,'logs');
 const [g,gr]=await call('GET','/v2/incidents/run-12345678');
 assert(JSON.stringify(gr)===JSON.stringify(r),'GET same');
 const [s2,r2]=await call('POST','/v2/incidents',body,{traceparent:tp});
 assert(s2===200&&JSON.stringify(r2)===JSON.stringify(r),'replay create');
 const [s3]=await call('POST','/v2/incidents',{...body,publicMarker:'z'});assert(s3===409,'409 run');
 const [s4,r4]=await call('POST','/v2/incidents/run-12345678/receipts',{receiptId:'rcpt-0004',outcomes:[{actionId:ef.actionId,callId:ef.callId,attempt:1,status:200,resultClass:'ok',nonce:'n5'}]});
 assert(s4===200&&JSON.stringify(r4)===JSON.stringify(r),'replay receipt');
 const [s5]=await call('POST','/v2/incidents/run-12345678/receipts',{receiptId:'rcpt-0004',outcomes:[{actionId:ef.actionId,callId:ef.callId,attempt:1,status:200,resultClass:'ok',nonce:'n6'}]});assert(s5===409,'409 receipt');
 const [s6]=await call('POST','/v2/incidents',{...body,profile:'bad'});assert(s6===400,'400 profile');
 sv.kill();process.exit();
},800);
