import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { randomBytes,createHash } from 'node:crypto';
import { createGateway } from './gateway.mjs';

test('OAuth PKCE, consent, audience, refresh, persistence, and MCP isolation',async()=>{
 const dir=mkdtempSync(path.join(tmpdir(),'or-gateway-test-'));const appUrl='https://replay.example.test';
 const backendJwt='test-backend-credential';let workers=0;
 const options={appUrl,dataDir:dir,verifyBackend:async jwt=>{assert.equal(jwt,backendJwt);return Math.floor(Date.now()/1000)+600;},workerFactory:async()=>{
  workers++;return {close:async()=>{},client:{listTools:async()=>({tools:[{name:'list_projects',inputSchema:{type:'object'}},{name:'configure_backend',inputSchema:{type:'object'}},{name:'fetch_chart_data',inputSchema:{type:'object'}}]}),callTool:async()=>({content:[{type:'text',text:'verified fixture'}]}),listResources:async()=>({resources:[]})}};
 }};
 const gateway=createGateway(options),server=gateway.app.listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));
 const base='http://127.0.0.1:'+server.address().port;
 const json=async(url,body,headers={})=>fetch(base+url,{method:'POST',headers:{'content-type':'application/json',...headers},body:JSON.stringify(body)});
 const form=async(body)=>fetch(base+'/mcp-auth/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams(body)});
 async function register(){const r=await json('/mcp-auth/register',{client_name:'Test Client',redirect_uris:['http://127.0.0.1:17001/callback'],token_endpoint_auth_method:'none',grant_types:['authorization_code','refresh_token'],response_types:['code']});assert.equal(r.status,201);return r.json();}
 async function authorize(client,extra={}){
  const verifier=randomBytes(32).toString('base64url'),challenge=createHash('sha256').update(verifier).digest('base64url');
  const params=new URLSearchParams({client_id:client.client_id,redirect_uri:client.redirect_uris[0],response_type:'code',scope:'openreplay:read',state:'test-state',code_challenge:challenge,code_challenge_method:'S256',resource:appUrl+'/mcp',...extra});
  const response=await fetch(base+'/mcp-auth/authorize?'+params,{redirect:'manual'});return {response,verifier};
 }
 async function grant(client){const {response,verifier}=await authorize(client);assert.equal(response.status,200);const html=await response.text();assert.ok(!html.includes(backendJwt));const id=html.match(/requestId:"([^"]+)"/)[1];
  const denied=await json('/mcp-auth/approve',{requestId:id,jwt:backendJwt},{origin:'https://evil.example'});assert.equal(denied.status,403);
  const approved=await json('/mcp-auth/approve',{requestId:id,jwt:backendJwt},{origin:appUrl});assert.equal(approved.status,200);const redirect=new URL((await approved.json()).redirect);assert.equal(redirect.searchParams.get('state'),'test-state');
  return {grant_type:'authorization_code',client_id:client.client_id,code:redirect.searchParams.get('code'),code_verifier:verifier,redirect_uri:client.redirect_uris[0],resource:appUrl+'/mcp'};
 }
 try{
  let r=await json('/mcp',{jsonrpc:'2.0',id:1,method:'initialize'});assert.equal(r.status,401);assert.match(r.headers.get('www-authenticate'),/oauth-protected-resource/);
  const meta=await(await fetch(base+'/.well-known/oauth-protected-resource/mcp')).json();assert.equal(meta.resource,appUrl+'/mcp');
  const client=await register(),other=await register();
  const wrongScope=await authorize(client,{scope:'admin'});assert.notEqual(wrongScope.response.status,200);
  const wrongAudience=await authorize(client,{resource:'https://other.example/mcp'});assert.notEqual(wrongAudience.response.status,200);
  const g=await grant(client);
  r=await form({...g,code_verifier:'incorrect'});assert.equal(r.status,400);
  r=await form({...g,client_id:other.client_id});assert.equal(r.status,400);
  r=await form({...g,redirect_uri:'http://127.0.0.1:9999/callback'});assert.equal(r.status,400);
  r=await form(g);assert.equal(r.status,200);const tokens=await r.json();
  r=await form(g);assert.equal(r.status,400);
  assert.ok(!readFileSync(path.join(dir,'grants.enc')).includes(Buffer.from(backendJwt)));
  const headers={Authorization:'Bearer '+tokens.access_token,Accept:'application/json, text/event-stream'};
  r=await json('/mcp',{jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-03-26',capabilities:{},clientInfo:{name:'test',version:'1'}}},headers);assert.equal(r.status,200);const session=r.headers.get('mcp-session-id');assert.ok(session);assert.equal((await r.json()).result.serverInfo.name,'openreplay-mcp-app');
  const h={...headers,'mcp-session-id':session};
  r=await json('/mcp',{jsonrpc:'2.0',method:'notifications/initialized'},h);assert.equal(r.status,202);
  r=await json('/mcp',{jsonrpc:'2.0',id:2,method:'tools/list',params:{}},h);const tools=(await r.json()).result.tools;assert.deepEqual(tools.map(t=>t.name),['list_projects']);
  r=await json('/mcp',{jsonrpc:'2.0',id:3,method:'tools/call',params:{name:'configure_backend',arguments:{}}},h);assert.equal((await r.json()).result.isError,true);
  r=await json('/mcp',{jsonrpc:'2.0',id:4,method:'tools/call',params:{name:'list_projects',arguments:{}}},h);assert.equal((await r.json()).result.content[0].text,'verified fixture');
  const second=await(await form(await grant(other))).json();r=await json('/mcp',{jsonrpc:'2.0',id:2,method:'tools/list',params:{}},{...h,Authorization:'Bearer '+second.access_token});assert.equal(r.status,404);assert.equal(workers,1);
  r=await form({grant_type:'refresh_token',client_id:other.client_id,refresh_token:tokens.refresh_token});assert.equal(r.status,400);
  r=await form({grant_type:'refresh_token',client_id:client.client_id,refresh_token:tokens.refresh_token,scope:'admin'});assert.equal(r.status,400);
  r=await form({grant_type:'refresh_token',client_id:client.client_id,refresh_token:tokens.refresh_token});assert.equal(r.status,200);const renewed=await r.json();
  r=await form({grant_type:'refresh_token',client_id:client.client_id,refresh_token:tokens.refresh_token});assert.equal(r.status,400);
  const reload=createGateway(options);assert.equal((await reload.provider.verifyAccessToken(renewed.access_token)).clientId,client.client_id);await reload.close();
  r=await fetch(base+'/mcp-auth/revoke',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({client_id:client.client_id,token:renewed.refresh_token})});assert.equal(r.status,200);
  r=await json('/mcp',{jsonrpc:'2.0',id:5,method:'tools/list',params:{}},h);assert.equal(r.status,401);
 }finally{await gateway.close();await new Promise(r=>server.close(r));rmSync(dir,{recursive:true,force:true});}
});
