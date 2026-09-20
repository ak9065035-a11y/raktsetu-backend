const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');

const PORT = process.env.PORT || 5500;
const HOST = process.env.HOST || '127.0.0.1';
const DATA = path.join(__dirname, 'data.json');
const PUBLIC = path.join(__dirname, 'public');
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

function load(){
  if(!fs.existsSync(DATA)){
    const seed={users:[],donors:[],requests:[]}; fs.writeFileSync(DATA,JSON.stringify(seed,null,2)); return seed;
  }
  try{return JSON.parse(fs.readFileSync(DATA,'utf8'))}catch{return {users:[],donors:[],requests:[]}}
}
let db=load();
function save(){const tmp=DATA+'.tmp';fs.writeFileSync(tmp,JSON.stringify(db,null,2));fs.renameSync(tmp,DATA)}
function id(){return crypto.randomUUID()}
function now(){return new Date().toISOString()}
function clean(s,max=160){return String(s??'').trim().slice(0,max)}
function normalizeContact(s){return clean(s,120).toLowerCase()}
function hashPassword(password){const salt=crypto.randomBytes(16).toString('hex');const hash=crypto.scryptSync(password,salt,64).toString('hex');return `${salt}:${hash}`}
function verifyPassword(password,stored){try{const [salt,hex]=stored.split(':');const got=crypto.scryptSync(password,salt,64).toString('hex');return crypto.timingSafeEqual(Buffer.from(got,'hex'),Buffer.from(hex,'hex'))}catch{return false}}
function b64(x){return Buffer.from(x).toString('base64url')}
function sign(payload){const body=b64(JSON.stringify(payload));const sig=crypto.createHmac('sha256',SESSION_SECRET).update(body).digest('base64url');return body+'.'+sig}
function unsign(token){try{const [body,sig]=token.split('.');const expected=crypto.createHmac('sha256',SESSION_SECRET).update(body).digest('base64url');if(!crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(expected)))return null;const p=JSON.parse(Buffer.from(body,'base64url'));if(!p.exp||p.exp<Date.now())return null;return p}catch{return null}}
function cookies(req){return Object.fromEntries((req.headers.cookie||'').split(';').filter(Boolean).map(x=>{const i=x.indexOf('=');return [x.slice(0,i).trim(),decodeURIComponent(x.slice(i+1))]}))}
function userFrom(req){const t=cookies(req).raktsetu_session;const p=t&&unsign(t);return p?db.users.find(u=>u.id===p.uid)||null:null}
function send(res,status,data,extra={}){const body=JSON.stringify(data);res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...extra});res.end(body)}
function readBody(req){return new Promise((resolve,reject)=>{let raw='';req.on('data',c=>{raw+=c;if(raw.length>1e6){req.destroy();reject(new Error('body too large'))}});req.on('end',()=>{try{resolve(raw?JSON.parse(raw):{})}catch{reject(new Error('invalid json'))}});req.on('error',reject)})}
function safeUser(u){const d=db.donors.find(x=>x.userId===u.id);return {id:u.id,name:u.name,contact:u.contact,city:u.city,group:u.group,donorId:d?.id||null,available:d?.available??false,createdAt:u.createdAt}}
function safeDonor(d){return {id:d.id,name:d.name,group:d.group,city:d.city,available:d.available,createdAt:d.createdAt}}
function safeRequest(r,viewer){const viewerDonor=db.donors.find(d=>d.userId===viewer.id);const out={id:r.id,patient:r.patient,group:r.group,city:r.city,units:r.units,hospital:r.hospital,urgency:r.urgency,status:r.status,createdAt:r.createdAt,donorId:r.donorId||null};if(r.requesterId===viewer.id)out.contact=r.contact;if(r.status==='accepted'&&r.donorId===viewerDonor?.id)out.contact=r.contact;if(r.status==='accepted'&&r.requesterId===viewer.id&&r.donorId){const d=db.donors.find(x=>x.id===r.donorId);if(d)out.donor={name:d.name,contact:d.contact,city:d.city}}out.canClaim=Boolean(viewerDonor&&viewerDonor.available&&r.status==='open'&&r.group===viewerDonor.group&&r.city.toLowerCase()===viewerDonor.city.toLowerCase()&&r.requesterId!==viewer.id);return out}

const bloodGroups=new Set(['A+','A-','B+','B-','AB+','AB-','O+','O-']);
async function api(req,res,pathname,q){
  const method=req.method;
  if(pathname==='/api/health'&&method==='GET')return send(res,200,{ok:true,time:now()});
  if(pathname==='/api/register'&&method==='POST'){
    const b=await readBody(req);const name=clean(b.name,80),contact=normalizeContact(b.contact),city=clean(b.city,80),group=clean(b.group,4),password=String(b.password||'');
    if(name.length<2||!contact||city.length<2||!bloodGroups.has(group)||password.length<8)return send(res,400,{error:'Enter valid name, contact, city, blood group and an 8+ character password.'});
    if(db.users.some(u=>u.contact===contact))return send(res,409,{error:'An account with this email/mobile already exists.'});
    const u={id:id(),name,contact,city,group,passwordHash:hashPassword(password),createdAt:now()};db.users.push(u);
    db.donors.push({id:id(),userId:u.id,name,contact,group,city,available:true,createdAt:now()});save();
    const token=sign({uid:u.id,exp:Date.now()+1000*60*60*24*30});return send(res,201,{user:safeUser(u)},{'Set-Cookie':`raktsetu_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000`});
  }
  if(pathname==='/api/login'&&method==='POST'){
    const b=await readBody(req),contact=normalizeContact(b.contact),password=String(b.password||''),u=db.users.find(x=>x.contact===contact);
    if(!u||!verifyPassword(password,u.passwordHash))return send(res,401,{error:'Invalid email/mobile or password.'});
    const token=sign({uid:u.id,exp:Date.now()+1000*60*60*24*30});return send(res,200,{user:safeUser(u)},{'Set-Cookie':`raktsetu_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000`});
  }
  if(pathname==='/api/logout'&&method==='POST')return send(res,200,{ok:true},{'Set-Cookie':'raktsetu_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'});
  if(pathname==='/api/me'&&method==='GET'){const u=userFrom(req);return u?send(res,200,{user:safeUser(u)}):send(res,401,{error:'Not signed in'});}
  const user=userFrom(req);
  if(!user)return send(res,401,{error:'Please sign in first.'});

  if(pathname==='/api/donors'&&method==='GET'){
    const group=clean(q.group,4),city=clean(q.city,80).toLowerCase();let list=db.donors.filter(d=>d.available);
    if(group)list=list.filter(d=>d.group===group);if(city)list=list.filter(d=>d.city.toLowerCase().includes(city));
    return send(res,200,{donors:list.map(safeDonor)});
  }
  if(pathname==='/api/me/donor'&&method==='PATCH'){
    const d=db.donors.find(x=>x.userId===user.id);if(!d)return send(res,404,{error:'Donor profile not found'});const b=await readBody(req);if(typeof b.available==='boolean')d.available=b.available;save();return send(res,200,{donor:safeDonor(d)});
  }
  if(pathname==='/api/requests'&&method==='POST'){
    const b=await readBody(req),patient=clean(b.patient,80),group=clean(b.group,4),city=clean(b.city,80),hospital=clean(b.hospital,160),contact=clean(b.contact,30),urgency=clean(b.urgency,20),units=Number(b.units),donorId=clean(b.donorId,80)||null;
    if(!patient||!bloodGroups.has(group)||!city||!hospital||!/^[0-9+ -]{8,18}$/.test(contact)||!Number.isInteger(units)||units<1||units>20)return send(res,400,{error:'Please enter valid request details.'});
    if(donorId&&!db.donors.some(d=>d.id===donorId&&d.available))return send(res,400,{error:'Selected donor is no longer available.'});
    const r={id:id(),requesterId:user.id,patient,group,city,units,hospital,contact,urgency:urgency||'Urgent',donorId,status:donorId?'pending':'open',createdAt:now()};db.requests.push(r);save();return send(res,201,{request:safeRequest(r,user)});
  }
  if(pathname==='/api/requests'&&method==='GET'){
    const myDonor=db.donors.find(d=>d.userId===user.id);const list=db.requests.filter(r=>r.requesterId===user.id||(r.donorId&&myDonor&&r.donorId===myDonor.id)||(r.status==='open'&&myDonor&&myDonor.available&&r.group===myDonor.group&&r.city.toLowerCase()===myDonor.city.toLowerCase()&&r.requesterId!==user.id));return send(res,200,{requests:list.sort((a,b)=>b.createdAt.localeCompare(a.createdAt)).map(r=>safeRequest(r,user))});
  }
  const claim=pathname.match(/^\/api\/requests\/([^/]+)\/claim$/);
  if(claim&&method==='POST'){
    const r=db.requests.find(x=>x.id===claim[1]),d=db.donors.find(x=>x.userId===user.id);
    if(!r||!d)return send(res,404,{error:'Request or donor profile not found'});
    if(!d.available||r.status!=='open'||r.group!==d.group||r.city.toLowerCase()!==d.city.toLowerCase())return send(res,409,{error:'This request is not available for your donor profile.'});
    r.donorId=d.id;r.status='pending';save();return send(res,200,{request:safeRequest(r,user)});
  }
  const m=pathname.match(/^\/api\/requests\/([^/]+)$/);
  if(m&&method==='PATCH'){
    const r=db.requests.find(x=>x.id===m[1]);if(!r)return send(res,404,{error:'Request not found'});const d=db.donors.find(x=>x.id===r.donorId);const isDonor=d&&d.userId===user.id;const isOwner=r.requesterId===user.id;if(!isDonor&&!isOwner)return send(res,403,{error:'Not allowed'});
    const b=await readBody(req),status=clean(b.status,20);if(!['pending','accepted','rejected','completed','cancelled'].includes(status))return send(res,400,{error:'Invalid status'});if(isDonor&&!['accepted','rejected','completed'].includes(status))return send(res,403,{error:'Donor can accept, reject or complete a request.'});if(isOwner&&!['cancelled','completed'].includes(status))return send(res,403,{error:'Requester can cancel or complete a request.'});r.status=status;save();return send(res,200,{request:safeRequest(r,user)});
  }
  return send(res,404,{error:'API route not found'});
}

const mime={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.json':'application/json; charset=utf-8','.png':'image/png','.jpg':'image/jpeg','.svg':'image/svg+xml','.ico':'image/x-icon'};
const server=http.createServer(async(req,res)=>{
  const u=url.parse(req.url,true);try{
    if(u.pathname.startsWith('/api/'))return await api(req,res,u.pathname,u.query);
    let p=path.normalize(path.join(PUBLIC,u.pathname==='/'?'index.html':u.pathname));if(!p.startsWith(PUBLIC))return send(res,403,{error:'Forbidden'});if(!fs.existsSync(p)||fs.statSync(p).isDirectory())p=path.join(PUBLIC,'index.html');res.writeHead(200,{'Content-Type':mime[path.extname(p)]||'application/octet-stream'});fs.createReadStream(p).pipe(res);
  }catch(e){console.error(e);if(!res.headersSent)send(res,500,{error:'Server error'});}
});
server.listen(process.env.PORT || PORT, () => console.log("RaktSetu is LIVE on cloud!"));
