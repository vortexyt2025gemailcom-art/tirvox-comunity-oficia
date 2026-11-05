// Tirvox APK · servidor que RECIBE y REPARTE APK. Sin dependencias (Node 18+).
const http=require("http"),fs=require("fs"),path=require("path"),crypto=require("crypto");
const DIR=process.env.DATA_DIR||path.join(__dirname,"data"),PORT=process.env.PORT||3000,OWNER=(process.env.OWNER_HASH||"").trim().toLowerCase();
const FD=path.join(DIR,"files"),DBF=path.join(DIR,"db.json");fs.mkdirSync(FD,{recursive:true});
let DB={users:{},docs:{},files:{}};try{DB={...DB,...JSON.parse(fs.readFileSync(DBF,"utf8"))}}catch(e){}
let tw;const save=()=>{clearTimeout(tw);tw=setTimeout(()=>fs.writeFile(DBF,JSON.stringify(DB),()=>{}),300)};
const SECRET=process.env.SECRET||(DB.secret=DB.secret||crypto.randomBytes(32).toString("hex"));
const sig=s=>crypto.createHmac("sha256",SECRET).update(s).digest("hex"),hs=(p,s)=>crypto.scryptSync(p,s,32).toString("hex");
const who=q=>{const[u,s]=(q.headers.authorization||"").replace("Bearer ","").split(".");return u&&s&&DB.users[u]&&s===sig(u)?u:null};
const own=u=>!!u&&!!OWNER&&!!DB.docs["owners/"+u]&&DB.docs["owners/"+u].h==OWNER;
const H={"Access-Control-Allow-Origin":"*","Access-Control-Allow-Headers":"authorization,content-type,x-ct,x-cd","Access-Control-Allow-Methods":"GET,PUT,POST,PATCH,DELETE,OPTIONS"};
const out=(r,c,o)=>{r.writeHead(c,{...H,"content-type":"application/json"});r.end(JSON.stringify(o))},bad=(r,c,k,m)=>out(r,c,{code:k,error:m||k});
const body=q=>new Promise(ok=>{let b="";q.on("data",d=>{b+=d;if(b.length>1e6)q.destroy()});q.on("end",()=>{try{ok(JSON.parse(b||"{}"))}catch(e){ok({})}})});
const segs=p=>p.split("/"),good=s=>s.every(x=>/^[\w.-]+$/.test(x)&&x!=".."&&x!==".");
const diff=(a,b,keys)=>[...new Set([...Object.keys(a),...Object.keys(b)])].filter(k=>JSON.stringify(a[k])!==JSON.stringify(b[k])).every(k=>keys.includes(k));
const merge=(old,d)=>{const n={...old};for(const k in d){const v=d[k];n[k]=v&&v.__inc!==undefined?(old[k]||0)+v.__inc:v&&v.__rm?(old[k]||[]).filter(x=>!v.__rm.includes(x)):v}return n};
// Permisos (iguales a las reglas de la versión Firebase)
function allow(op,p,u,old,nu){const s=segs(p),c=s[0];
if(c=="usernames")return s.length==2&&(op=="get"||(op=="create"&&!!u&&nu.uid==u));
if(c=="users")return s.length==2&&(op=="get"||u==s[1]);
if(c=="owners")return s.length==2&&u==s[1]&&(op=="get"||(op!="delete"&&!!OWNER&&nu.h==OWNER));
if(c!="apps")return false;
if(s.length==2){if(op=="get")return true;if(op=="create")return!!u&&nu.uid==u;
if(op=="update")return(!!u&&(old.uid==u||own(u)||diff(old,nu,["likes"])))||diff(old,nu,["views"]);
return!!u&&(old.uid==u||own(u))}
if(s.length==4&&s[2]=="likes")return op=="get"||u==s[3];
if(s.length==4&&s[2]=="comments")return op=="get"||(op=="create"&&!!u&&nu.uid==u)||(op=="delete"&&!!u&&(old.uid==u||own(u)));
return false}
function apply(ops,u){const plan=[];
for(const o of ops){const s=segs(String(o.path||""));if(!good(s)||s.length%2)throw[400,"bad/path"];
const old=DB.docs[o.path],kind=o.op=="delete"?"delete":o.op=="update"?"update":old?"update":"create";
if(kind=="delete"&&!old)continue;if(kind=="update"&&!old)throw[404,"not-found"];
const nu=kind=="delete"?null:(o.op=="set"&&!o.merge)?(o.data||{}):merge(old||{},o.data||{});
if(!allow(kind,o.path,u,old||{},nu))throw[403,"permission-denied"];plan.push([o.path,nu])}
for(const[p,n]of plan){if(n===null){delete DB.docs[p];if(segs(p).length==2)for(const k in DB.docs)if(k.startsWith(p+"/"))delete DB.docs[k]}else DB.docs[p]=n}save()}
// Solo APK real: firma ZIP + AndroidManifest.xml
const chk=async(f,n)=>{const fd=await fs.promises.open(f,"r");try{const h=Buffer.alloc(4);await fd.read(h,0,4,0);if(h.toString("hex")!="504b0304")return false;const L=Math.min(n,4<<20),t=Buffer.alloc(L);await fd.read(t,0,L,n-L);return t.includes("AndroidManifest.xml")}finally{await fd.close()}};
http.createServer(async(q,r)=>{try{
if(q.method=="OPTIONS"){r.writeHead(204,H);return r.end()}
const url=new URL(q.url,"http://x"),p=decodeURIComponent(url.pathname),u=who(q);
if(p=="/")return out(r,200,{ok:"Tirvox server funcionando"});
if(p=="/auth/signup"||p=="/auth/login"){const b=await body(q),e=String(b.email||"").trim().toLowerCase(),pw=String(b.password||""),ex=Object.entries(DB.users).find(([,x])=>x.email==e);
if(p.endsWith("signup")){if(!/^\S+@\S+\.\S+$/.test(e))return bad(r,400,"auth/invalid-email");if(pw.length<6)return bad(r,400,"auth/weak-password");if(ex)return bad(r,400,"auth/email-already-in-use");
const id=crypto.randomUUID(),salt=crypto.randomBytes(16).toString("hex");DB.users[id]={email:e,salt,hash:hs(pw,salt)};save();return out(r,200,{uid:id,token:id+"."+sig(id)})}
if(!ex||hs(pw,ex[1].salt)!=ex[1].hash)return bad(r,400,"auth/invalid-credential");return out(r,200,{uid:ex[0],token:ex[0]+"."+sig(ex[0])})}
if(p=="/auth/me"){if(!u)return bad(r,401,"auth/unauthenticated");if(q.method=="DELETE"){delete DB.users[u];save();return out(r,200,{})}return out(r,200,{uid:u,email:DB.users[u].email})}
if(p.startsWith("/doc/")){const dp=p.slice(5),s=segs(dp);if(!good(s)||s.length%2)return bad(r,400,"bad/path");
if(q.method=="GET"){if(!allow("get",dp,u,{},{}))return bad(r,403,"permission-denied");const d=DB.docs[dp];return out(r,200,{exists:!!d,data:d||null})}
const op={PUT:"set",PATCH:"update",DELETE:"delete"}[q.method];if(!op)return bad(r,405,"method");const b=await body(q);apply([{op,path:dp,data:b.data,merge:b.merge}],u);return out(r,200,{})}
if(p=="/batch"){apply((await body(q)).ops||[],u);return out(r,200,{})}
if(p.startsWith("/col/")){const cp=p.slice(5),s=segs(cp);if(!good(s)||!((s.length==1&&s[0]=="apps")||(s.length==3&&s[0]=="apps"&&(s[2]=="comments"||s[2]=="likes"))))return bad(r,403,"permission-denied");
const o=url.searchParams.get("order"),d=url.searchParams.get("dir")=="desc"?-1:1;
const docs=Object.keys(DB.docs).filter(k=>k.startsWith(cp+"/")&&segs(k).length==s.length+1).map(k=>({id:k.split("/").pop(),data:DB.docs[k]}));
if(o)docs.sort((a,b)=>(a.data[o]>b.data[o]?1:a.data[o]<b.data[o]?-1:0)*d);return out(r,200,{docs})}
if(p.startsWith("/file/")){const fp=p.slice(6),s=segs(fp);
if(!good(s)||!((["apks","imgs","vids"].includes(s[0])&&s.length==4)||(s[0]=="profiles"&&s.length==2)))return bad(r,400,"bad/path");
const full=path.join(FD,...s);
if(q.method=="GET"){const m=DB.files[fp];if(!m||!fs.existsSync(full))return bad(r,404,"not-found");
const z=fs.statSync(full).size,h={...H,"content-type":m.ct,"accept-ranges":"bytes","cache-control":"public,max-age=3600"};if(m.cd)h["content-disposition"]=m.cd;
const rg=/bytes=(\d*)-(\d*)/.exec(q.headers.range||"");let a=0,b=z-1,c=200;
if(rg){a=rg[1]?+rg[1]:Math.max(0,z-+rg[2]);b=rg[1]&&rg[2]?Math.min(+rg[2],b):b;c=206;h["content-range"]=`bytes ${a}-${b}/${z}`}
h["content-length"]=b-a+1;r.writeHead(c,h);return fs.createReadStream(full,{start:a,end:b}).pipe(r)}
if(!u)return bad(r,401,"auth/unauthenticated");
if(q.method=="DELETE"){if(s[1]!=u&&!own(u))return bad(r,403,"permission-denied");fs.rm(full,{force:true},()=>{});delete DB.files[fp];save();return out(r,200,{})}
if(q.method=="PUT"){if(s[1]!=u)return bad(r,403,"permission-denied");
const ct=String(q.headers["x-ct"]||q.headers["content-type"]||""),k=s[0],lim={apks:1e9,imgs:1e7,vids:2e8,profiles:5e6}[k];
if(!(k=="apks"?ct=="application/vnd.android.package-archive":ct.startsWith(k=="vids"?"video/":"image/")))return bad(r,415,"upload/tipo","Tipo de archivo no permitido");
fs.mkdirSync(path.dirname(full),{recursive:true});const tmp=full+".tmp",w=fs.createWriteStream(tmp);let n=0,dead=0;
q.on("data",d=>{n+=d.length;if(n>lim&&!dead){dead=1;q.unpipe(w);w.destroy();fs.rm(tmp,{force:true},()=>{});bad(r,413,"upload/grande","Archivo demasiado grande")}});
q.pipe(w);
w.on("close",async()=>{if(dead)return;try{if(k=="apks"&&!(await chk(tmp,n))){fs.rm(tmp,{force:true},()=>{});return bad(r,415,"upload/apk","No es un APK válido")}
fs.renameSync(tmp,full);DB.files[fp]={ct,cd:String(q.headers["x-cd"]||"")};save();out(r,200,{})}catch(e){bad(r,500,"server")}});return}}
return bad(r,404,"not-found")
}catch(e){if(Array.isArray(e))return bad(r,e[0],e[1]);console.error(e);if(!r.headersSent)bad(r,500,"server")}
}).listen(PORT,()=>console.log("Tirvox server en puerto "+PORT));
