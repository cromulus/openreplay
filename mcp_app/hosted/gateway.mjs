import express from 'express';
import { randomBytes, createHash, createCipheriv, createDecipheriv } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, renameSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { authorizationHandler } from '@modelcontextprotocol/sdk/server/auth/handlers/authorize.js';
import { tokenHandler } from '@modelcontextprotocol/sdk/server/auth/handlers/token.js';
import { clientRegistrationHandler } from '@modelcontextprotocol/sdk/server/auth/handlers/register.js';
import { revocationHandler } from '@modelcontextprotocol/sdk/server/auth/handlers/revoke.js';
import { mcpAuthMetadataRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { InvalidGrantError, InvalidTokenError, InvalidScopeError, InvalidTargetError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { ListToolsRequestSchema, CallToolRequestSchema, ListResourcesRequestSchema, ReadResourceRequestSchema, isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';

const random = () => randomBytes(32).toString('base64url');
const hash = value => createHash('sha256').update(value).digest('hex');
const now = () => Math.floor(Date.now() / 1000);
const esc = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
// Deliberately omit authentication/configuration tools and the arbitrary API proxy.
const ALLOWED = new Set(['view_recent_sessions','view_chart','view_user_journey','view_web_vitals','view_table_chart','view_funnel','view_session_replay','list_projects','get_project_id','fetch_sessions','get_session_replay','get_session_details','get_available_filters','get_auth_status','_refresh_replay_urls','_fetch_mob_file','_fetch_css','fetch_events','fetch_users','fetch_event_properties']);

export function createGateway({ appUrl, dataDir, verifyBackend, workerFactory } = {}) {
  appUrl ||= process.env.OPENREPLAY_URL;
  if (!appUrl || new URL(appUrl).protocol !== 'https:') throw new Error('OPENREPLAY_URL must be HTTPS');
  appUrl = new URL(appUrl).origin;
  const resource = appUrl + '/mcp';
  dataDir ||= process.env.MCP_DATA_DIR || '/var/lib/openreplay-mcp';
  mkdirSync(dataDir, { recursive:true, mode:0o700 });
  const keyFile = path.join(dataDir, 'key');
  if (!existsSync(keyFile)) writeFileSync(keyFile, randomBytes(32), {mode:0o600, flag:'wx'});
  const key = readFileSync(keyFile);
  const storeFile = path.join(dataDir, 'grants.enc');
  let store = { clients:{}, tokens:{}, refresh:{} };
  if (existsSync(storeFile)) {
    const blob = readFileSync(storeFile); const cipher = createDecipheriv('aes-256-gcm',key,blob.subarray(0,12));
    cipher.setAuthTag(blob.subarray(12,28));
    store = JSON.parse(Buffer.concat([cipher.update(blob.subarray(28)),cipher.final()]).toString());
  }
  function save() {
    const iv=randomBytes(12), cipher=createCipheriv('aes-256-gcm',key,iv);
    const body=Buffer.concat([cipher.update(JSON.stringify(store)),cipher.final()]);
    writeFileSync(storeFile+'.tmp', Buffer.concat([iv,cipher.getAuthTag(),body]), {mode:0o600});
    renameSync(storeFile+'.tmp',storeFile);
  }
  const pending=new Map(), codes=new Map(), sessions=new Map();
  let creating=0;
  verifyBackend ||= async jwt => {
    const response=await fetch(appUrl+'/api/projects',{headers:{Authorization:'Bearer '+jwt},signal:AbortSignal.timeout(15000),redirect:'error'});
    if (!response.ok) throw new InvalidTokenError('Sign in to OpenReplay again.');
    const body=await response.json();
    if (!Array.isArray(body.data)) throw new InvalidTokenError('OpenReplay did not confirm access.');
    const payload=JSON.parse(Buffer.from(jwt.split('.')[1],'base64url').toString());
    if (!Number.isFinite(payload.exp) || payload.exp <= now()+30) throw new InvalidTokenError('OpenReplay session expired.');
    return Math.min(payload.exp,now()+86400);
  };
  function validateScope(scopes) { if ((scopes||[]).some(s=>s!=='openreplay:read')) throw new InvalidScopeError('Only openreplay:read is supported.'); }
  function validateResource(url) { if (url && url.toString()!==resource) throw new InvalidTargetError('Wrong resource.'); }
  function codeFor(client,code) {
    const value=codes.get(hash(code));
    if (!value || value.clientId!==client.client_id || value.expires<=now()) throw new InvalidGrantError('Invalid or expired code.');
    return value;
  }
  function issue(grant) {
    const access=random(), refresh=random();
    store.tokens[hash(access)]={...grant,expires:Math.min(now()+3600,grant.backendExpires)};
    store.refresh[hash(refresh)]={...grant,expires:grant.backendExpires}; save();
    return {access_token:access,refresh_token:refresh,token_type:'Bearer',expires_in:store.tokens[hash(access)].expires-now(),scope:'openreplay:read'};
  }
  const provider={
    clientsStore:{
      getClient: id=>store.clients[id],
      registerClient: async client=>{
        if (Object.keys(store.clients).length>=500) throw new Error('Client limit reached');
        for (const uri of client.redirect_uris) {
          const u=new URL(uri);
          if (u.hash || u.username || u.password || !(u.protocol==='https:' || (u.protocol==='http:' && ['localhost','127.0.0.1','[::1]'].includes(u.hostname)))) throw new Error('Invalid redirect URI');
        }
        const entry={...client,client_id:client.client_id||random(),client_id_issued_at:now()};
        store.clients[entry.client_id]=entry; save(); return entry;
      }
    },
    authorize: async (client,params,res)=>{
      validateScope(params.scopes);validateResource(params.resource);
      if(pending.size>=500) throw new Error('Too many pending authorizations');
      const id=random();pending.set(id,{clientId:client.client_id,params,expires:now()+600});
      const nonce=random();
      res.set({'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY',
        'Content-Security-Policy':`default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`});
      res.type('html').send(`<!doctype html><html lang="en"><meta name="viewport" content="width=device-width"><title>Connect OpenReplay</title><style nonce="${nonce}">body{font:18px system-ui;max-width:620px;margin:12vh auto;padding:24px;color:#142034;background:#f8fafc}button,a{font:inherit}button{padding:12px 22px;background:#394eff;color:white;border:0;border-radius:8px;cursor:pointer}small{overflow-wrap:anywhere;color:#555}p{line-height:1.5}</style><h1>Connect OpenReplay</h1><p><strong>${esc(client.client_name||'MCP client')}</strong> is requesting read access to the projects, analytics and session recordings available to your OpenReplay account.</p><p><small>Client: ${esc(client.client_id)}<br>Callback: ${esc(params.redirectUri)}</small></p><p>Sign in to <a href="/" target="_blank" rel="noopener">OpenReplay</a> first, then return here to approve access. Access ends when this OpenReplay session expires, or after 24 hours.</p><button id="approve">Approve read access</button><p id="status" role="status"></p><script nonce="${nonce}">document.getElementById('approve').onclick=async()=>{const status=document.getElementById('status');try{const jwt=JSON.parse(localStorage.getItem('UserStore')||'{}').jwt;if(!jwt)throw Error('Please sign in to OpenReplay in the linked tab, then try again.');const r=await fetch('/mcp-auth/approve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({requestId:${JSON.stringify(id)},jwt})});const b=await r.json();if(!r.ok)throw Error(b.error||'Authorization failed');location.assign(b.redirect);}catch(e){status.textContent=e.message;}};</script></html>`);
    },
    challengeForAuthorizationCode:async(client,code)=>codeFor(client,code).params.codeChallenge,
    exchangeAuthorizationCode:async(client,code,_verifier,redirectUri,url)=>{
      const value=codeFor(client,code);validateResource(url);
      if (redirectUri!==value.params.redirectUri) throw new InvalidGrantError('Redirect URI mismatch.');
      codes.delete(hash(code));
      return issue({clientId:client.client_id,jwt:value.jwt,backendExpires:value.backendExpires,grantId:random()});
    },
    exchangeRefreshToken:async(client,token,scopes,url)=>{
      validateScope(scopes);validateResource(url);
      const value=store.refresh[hash(token)];
      if (!value || value.clientId!==client.client_id || value.expires<=now()) throw new InvalidGrantError('Refresh expired; sign in again.');
      await verifyBackend(value.jwt);
      delete store.refresh[hash(token)];
      return issue(value);
    },
    verifyAccessToken:async token=>{
      const value=store.tokens[hash(token)];
      if(!value || value.expires<=now() || value.backendExpires<=now()) throw new InvalidTokenError('Invalid or expired token.');
      return {token,clientId:value.clientId,scopes:['openreplay:read'],expiresAt:value.expires,resource:new URL(resource),extra:{grantId:value.grantId}};
    },
    revokeToken:async(client,request)=>{
      const value=store.tokens[hash(request.token)]||store.refresh[hash(request.token)];
      if (value?.clientId!==client.client_id) return;
      for (const map of [store.tokens,store.refresh]) for(const [k,g] of Object.entries(map)) if(g.grantId===value.grantId) delete map[k];
      for(const [id,s] of sessions) if(s.grantId===value.grantId) {sessions.delete(id);await s.close();}
      save();
    }
  };
  const app=express(); app.disable('x-powered-by'); app.set('trust proxy',1);
  app.use(express.json({limit:'256kb'}));
  app.use((req,res,next)=>{res.set('Cache-Control','no-store');next();});
  const oauthMetadata={issuer:appUrl,authorization_endpoint:appUrl+'/mcp-auth/authorize',token_endpoint:appUrl+'/mcp-auth/token',registration_endpoint:appUrl+'/mcp-auth/register',revocation_endpoint:appUrl+'/mcp-auth/revoke',response_types_supported:['code'],grant_types_supported:['authorization_code','refresh_token'],token_endpoint_auth_methods_supported:['none','client_secret_post'],code_challenge_methods_supported:['S256'],scopes_supported:['openreplay:read']};
  app.use(mcpAuthMetadataRouter({oauthMetadata,resourceServerUrl:new URL(resource),scopesSupported:['openreplay:read'],resourceName:'NMC OpenReplay'}));
  app.use('/mcp-auth/authorize',authorizationHandler({provider}));
  app.use('/mcp-auth/token',tokenHandler({provider}));
  app.use('/mcp-auth/register',clientRegistrationHandler({clientsStore:provider.clientsStore}));
  app.use('/mcp-auth/revoke',revocationHandler({provider}));
  app.post('/mcp-auth/approve',async(req,res)=>{
    if(req.get('origin')!==appUrl) return res.status(403).json({error:'Invalid origin.'});
    const {requestId,jwt}=req.body||{}; const request=pending.get(requestId);
    if(!request || request.expires<=now() || typeof jwt!=='string' || jwt.length>16000) return res.status(400).json({error:'Authorization expired. Restart the connection.'});
    // Consume before awaiting backend verification to prevent concurrent approval.
    pending.delete(requestId);
    try {
      const backendExpires=await verifyBackend(jwt), code=random();
      codes.set(hash(code),{...request,jwt,backendExpires,expires:now()+120});
      const redirect=new URL(request.params.redirectUri);redirect.searchParams.set('code',code);
      if(request.params.state)redirect.searchParams.set('state',request.params.state);
      res.json({redirect:redirect.toString()});
    }catch{res.status(401).json({error:'OpenReplay could not confirm your session. Sign in and restart the connection.'});}
  });
  app.get('/mcp-health',(_req,res)=>res.json({status:'ok',version:'1.0.6',transport:'streamable-http',authentication:'oauth-pkce'}));
  async function makeWorker(jwt) {
    const dir=mkdtempSync(path.join(tmpdir(),'openreplay-mcp-'));
    writeFileSync(path.join(dir,'config.json'),JSON.stringify({appUrl,jwt,clientId:random()}),{mode:0o600});
    const child=new StdioClientTransport({command:process.execPath,args:[path.resolve(import.meta.dirname,'../dist-server/server.mjs')],env:{PATH:process.env.PATH||'/usr/bin:/bin',OPENREPLAY_URL:appUrl,OPENREPLAY_CONFIG_DIR:dir},stderr:'ignore'});
    const client=new Client({name:'openreplay-hosted-gateway',version:'1.0.0'});
    try {await client.connect(child);return {client,close:async()=>{await client.close();rmSync(dir,{recursive:true,force:true});}};}
    catch(e){await child.close();rmSync(dir,{recursive:true,force:true});throw e;}
  }
  app.all('/mcp',async(req,res)=>{
    let initializing=false, newWorker;
    try {
      const token=req.get('authorization')?.match(/^Bearer (.+)$/i)?.[1]||'';
      const auth=await provider.verifyAccessToken(token);req.auth=auth;
      if(req.get('origin') && req.get('origin')!==appUrl) return res.status(403).json({error:'Invalid origin'});
      const sessionId=req.get('mcp-session-id');let session=sessions.get(sessionId);
      if(sessionId && (!session || session.grantId!==auth.extra.grantId)) return res.status(404).json({error:'Unknown session'});
      if(!session) {
        if(req.method!=='POST' || !isInitializeRequest(req.body)) return res.status(400).json({error:'Initialize a new MCP session'});
        if(sessions.size+creating>=12) return res.status(503).json({error:'Connection capacity reached'});
        initializing=true;creating++;
        const grant=store.tokens[hash(token)];await verifyBackend(grant.jwt);
        const worker=await (workerFactory||makeWorker)(grant.jwt);newWorker=worker;
        const server=new Server({name:'openreplay-mcp-app',version:'1.0.6'},{capabilities:{tools:{},resources:{}}});
        const tools=(await worker.client.listTools()).tools.filter(t=>ALLOWED.has(t.name));const names=new Set(tools.map(t=>t.name));
        server.setRequestHandler(ListToolsRequestSchema,async()=>({tools}));
        server.setRequestHandler(CallToolRequestSchema,async request=>{
          if(!names.has(request.params.name))return {isError:true,content:[{type:'text',text:'This tool is not available on the hosted read-only endpoint.'}]};
          return worker.client.callTool(request.params);
        });
        server.setRequestHandler(ListResourcesRequestSchema,async()=>worker.client.listResources());
        server.setRequestHandler(ReadResourceRequestSchema,async request=>{
          if(request.params.uri!=='ui://openreplay/app')throw new Error('Unknown resource');
          return worker.client.readResource(request.params);
        });
        let closed=false;
        session={grantId:auth.extra.grantId,lastUsed:Date.now(),close:async()=>{if(closed)return;closed=true;await worker.close();await server.close();}};
        const transport=new StreamableHTTPServerTransport({sessionIdGenerator:random,enableJsonResponse:true,onsessioninitialized:id=>sessions.set(id,session)});
        session.transport=transport;transport.onclose=()=>{sessions.delete(transport.sessionId);void session.close();};
        await server.connect(transport);newWorker=undefined;
      }
      session.lastUsed=Date.now();await session.transport.handleRequest(req,res,req.body);
    }catch(error){
      if(newWorker)await newWorker.close();
      if(res.headersSent)return;
      if(error instanceof InvalidTokenError) {res.set('WWW-Authenticate',`Bearer resource_metadata="${appUrl}/.well-known/oauth-protected-resource/mcp", scope="openreplay:read"`);return res.status(401).json({error:'Authentication required'});}
      console.error('MCP request failed:',error.name);res.status(500).json({error:'MCP request failed'});
    }finally{if(initializing)creating--;}
  });
  const timer=setInterval(()=>{
    for(const map of [pending,codes])for(const [id,v]of map)if(v.expires<=now())map.delete(id);
    for(const [id,s]of sessions)if(Date.now()-s.lastUsed>600000){sessions.delete(id);void s.close();}
    for(const map of [store.tokens,store.refresh])for(const [id,v]of Object.entries(map))if(v.expires<=now())delete map[id];
  },60000);timer.unref();
  return {app,provider,close:async()=>{clearInterval(timer);for(const s of sessions.values())await s.close();save();}};
}
if(process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  const gateway=createGateway();const server=gateway.app.listen(Number(process.env.PORT||3100),'0.0.0.0',()=>console.log('OpenReplay MCP listening'));
  const stop=()=>server.close(async()=>{await gateway.close();process.exit(0);});process.on('SIGTERM',stop);process.on('SIGINT',stop);
}
