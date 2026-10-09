/* OAuth 2.0 Authorization Code + PKCE. Token stays in volatile memory.
   The provider MUST be configured for public-client PKCE + CORS + API audience,
   and issue access tokens with auth_time and amr/acr for privileged actions. */
const utf8=new TextEncoder();
const randomString=()=>Array.from(crypto.getRandomValues(new Uint8Array(32))).map(x=>x.toString(16).padStart(2,'0')).join('');
const base64url=bytes=>btoa(String.fromCharCode(...bytes)).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'');
const sha256=async text=>base64url(new Uint8Array(await crypto.subtle.digest('SHA-256',utf8.encode(text))));
const qs=id=>document.getElementById(id);
const Identity={config:null,token:null,expiry:0,tenant:null,roles:[],
  headers(){if(!this.config?.enabled)return{};if(!this.token||Date.now()>this.expiry*1000){this.token=null;throw new Error('Session expired. Sign in again.')}if(!this.tenant)throw new Error('Select an authorized organization.');return{'Authorization':`Bearer ${this.token}`,'X-Bahar-Tenant':this.tenant}},
  hasRole(role){return this.roles.includes(role)},
  allowedEndpoints:[],
  async beginLogin(fresh=false){
    if(!this.config?.enabled)throw new Error('Identity provider is not configured.');
    if(!globalThis.crypto?.subtle)throw new Error('A secure browser context (HTTPS or localhost) is required.');
    const verifier=randomString(),state=randomString();
    sessionStorage.setItem('bahar-oidc-pkce',JSON.stringify({verifier,state,issued_at:Date.now()}));
    const auth=new URL(this.config.authorize_url);
    auth.searchParams.set('response_type','code');auth.searchParams.set('client_id',this.config.client_id);
    auth.searchParams.set('redirect_uri',this.config.redirect_uri);
    auth.searchParams.set('scope','openid profile');
    auth.searchParams.set('audience',this.config.audience);
    auth.searchParams.set('state',state);auth.searchParams.set('code_challenge_method','S256');
    auth.searchParams.set('code_challenge',await sha256(verifier));
    if(fresh){auth.searchParams.set('prompt','login');auth.searchParams.set('max_age','0')}
    location.assign(auth.toString());
  },
  async finishLogin(){
    const params=new URL(location.href).searchParams;
    if(!params.has('code')&&!params.has('error'))return;
    // Remove the one-time code from the visible URL before any further work.
    const code=params.get('code'),receivedState=params.get('state'),error=params.get('error');
    history.replaceState(null,'',location.pathname+location.hash);
    const raw=sessionStorage.getItem('bahar-oidc-pkce');sessionStorage.removeItem('bahar-oidc-pkce');
    if(error)throw new Error('Identity provider rejected sign-in: '+error);
    const attempt=raw?JSON.parse(raw):null;
    if(!attempt||attempt.state!==receivedState||Date.now()-attempt.issued_at>300000)throw new Error('OIDC state or PKCE session expired');
    const body=new URLSearchParams({grant_type:'authorization_code',client_id:this.config.client_id,
      redirect_uri:this.config.redirect_uri,code,code_verifier:attempt.verifier});
    const response=await fetch(this.config.token_url,{method:'POST',mode:'cors',credentials:'omit',
      headers:{'Content-Type':'application/x-www-form-urlencoded'},body});
    if(!response.ok)throw new Error('OIDC code exchange failed. Verify provider CORS, API audience and PKCE settings.');
    const output=await response.json();
    if(typeof output.access_token!=='string'||output.token_type?.toLowerCase()!=='bearer'||output.expires_in<=0)
      throw new Error('OIDC provider did not issue a valid bearer access token');
    // Never use an ID token in place of an API access token.
    this.token=output.access_token;this.expiry=Math.floor(Date.now()/1000)+Number(output.expires_in)-20;
  },
  async loadTenants(){
    const response=await fetch('/api/auth/tenants',{headers:{'Authorization':`Bearer ${this.token}`,'Accept':'application/json'}});
    if(!response.ok)throw new Error('Identity has no valid tenant appointments, or the access token is not accepted by the API');
    const data=await response.json();
    const select=qs('identity-tenant');select.replaceChildren();
    for(const tenant of data.tenants||[]){const option=document.createElement('option');option.value=tenant.organization_id;
      option.textContent=tenant.organization_id+' · '+tenant.roles.join(', ');select.append(option)}
    if(!select.options.length)throw new Error('No organization-wide membership is assigned to this identity.');
    this.tenant=select.value;await this.refresh();
  },
  async refresh(){
    const resp=await fetch('/api/auth/me',{headers:{...this.headers(),'Accept':'application/json'}});
    if(!resp.ok)throw new Error('Current tenant membership is no longer authorized');
    const body=await resp.json();this.roles=body.roles||[];
    this.allowedEndpoints=body.allowed_post_routes||[];
    qs('identity-status').textContent='Signed in · '+body.principal_id.slice(0,8)+'… · '+this.roles.join(', ');
    qs('identity-tenant').hidden=false;qs('identity-login').hidden=true;
    qs('identity-logout').hidden=false;qs('identity-fresh').hidden=false;
    document.body.dataset.authenticated='true';
    document.querySelector('.environment').textContent='GOVERNED SSO';
    document.querySelectorAll('[data-required-role]').forEach(element=>{element.hidden=!this.hasRole(element.dataset.requiredRole)});
    document.querySelectorAll('form[data-endpoint]').forEach(form=>{
      const allowed=this.allowedEndpoints.includes(form.dataset.endpoint);
      form.querySelectorAll('button[type="submit"],button:not([type])').forEach(button=>{
        button.disabled=!allowed;button.title=allowed?'':'An organization appointment with this action is required';
      });
    });
    const documentForm=qs('document-form');if(documentForm){
      const button=documentForm.querySelector('button');if(button){button.disabled=!this.hasRole('analyst');}
    }
  },
  signOut(){this.token=null;this.expiry=0;this.tenant=null;this.roles=[];sessionStorage.removeItem('bahar-oidc-pkce');
    qs('identity-status').textContent='Signed out';qs('identity-login').hidden=false;qs('identity-logout').hidden=true;
    qs('identity-fresh').hidden=true;qs('identity-tenant').hidden=true;document.body.dataset.authenticated='false';
    document.querySelectorAll('[data-required-role]').forEach(element=>{element.hidden=true});
  },
  async init(){const result=await fetch('/api/auth/config',{headers:{Accept:'application/json'}});
    if(!result.ok)throw new Error('Authentication configuration unavailable');
    this.config=await result.json();if(!this.config.enabled){qs('identity-status').textContent='Local demonstration · no user login';
      document.querySelector('.environment').textContent='LOCAL DEMO';
      qs('identity-login').hidden=true;return}
    try{await this.finishLogin();if(this.token)await this.loadTenants();else this.signOut()}
    catch(error){this.signOut();qs('identity-status').textContent=error.message}
  }
};
qs('identity-login').addEventListener('click',()=>Identity.beginLogin().catch(e=>alert(e.message)));
qs('identity-fresh').addEventListener('click',()=>Identity.beginLogin(true).catch(e=>alert(e.message)));
qs('identity-logout').addEventListener('click',()=>Identity.signOut());
qs('identity-tenant').addEventListener('change',async event=>{Identity.tenant=event.target.value;
  try{await Identity.refresh()}catch(error){Identity.signOut();qs('identity-status').textContent=error.message}});
window.BaharIdentity=Identity;
