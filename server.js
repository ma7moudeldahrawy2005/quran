// سيرفر ورد القرآن - Node.js بدون أي مكتبات خارجية (Node 16 أو أحدث)
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PORT=25567,TZ='Africa/Cairo',VISIBLE_DAYS=5,JUZ_PTS=10;
const DATA=path.join(__dirname,'data.json'),ADM=path.join(__dirname,'admins.json'),PUB=path.join(__dirname,'public');
const ST=[0,2,50,77,106,128,151,177,187,208,221,235,249,255,262,267,282,293,305,312,322,332,342,350,359,367,377,385,396,404,411,415,418,428,434,440,446,453,458,467,477,483,489,496,499,502,507,511,515,518,520,523,526,528,531,534,537,542,545,549,551,553,554,556,558,560,562,564,566,568,570,572,574,575,577,578,580,582];
const SH=[1.5,1.4,1,.8,.6,1.5,1,.8,.5,.6,.8,1.3,.7,.5,.6,.4,.3,.4,.6,.3,.8,.5,.6,.5,.4,.2,.4,.3,.3,.3,.2,.4,.3,.3,.25,.3,1/3];
const pg=i=>i<77?ST[i+1]-ST[i]:SH[i-77],pts=i=>pg(i)/2;
const hex=s=>Buffer.from(s.trim().toLowerCase().replace(/\s+/g,' ')).toString('hex');
const norm=t=>t.toLowerCase().replace(/[\u064B-\u0652\u0640]/g,'').replace(/[أإآ]/g,'ا').replace(/ى/g,'ي').replace(/ة/g,'ه').replace(/\s+/g,' ').trim();
if(!fs.existsSync(ADM))fs.writeFileSync(ADM,JSON.stringify({admins:['محمود اشرف الدهراوي']},null,2));
const adminNames=()=>{try{const a=JSON.parse(fs.readFileSync(ADM,'utf8')).admins;if(Array.isArray(a))return a.filter(x=>typeof x=='string')}catch(e){}return[]};
const isAdmin=id=>adminNames().some(n=>hex(n)==id);
let db={users:{},logs:{},sessions:{}};
try{db=Object.assign(db,JSON.parse(fs.readFileSync(DATA,'utf8')))}catch(e){}
let timer=null;
const flush=()=>{clearTimeout(timer);const t=DATA+'.tmp';fs.writeFileSync(t,JSON.stringify(db));fs.renameSync(t,DATA)};
const save=()=>{clearTimeout(timer);timer=setTimeout(flush,200)};
['SIGINT','SIGTERM'].forEach(s=>process.on(s,()=>{flush();process.exit(0)}));
const today=()=>new Date().toLocaleDateString('sv-SE',{timeZone:TZ});
/* الوقت المتبقي (بالمللي ثانية) على الساعة 12 بليل بتوقيت القاهرة = بداية اليوم الجديد */
const msToMidnight=()=>{const n=new Date(),p=new Intl.DateTimeFormat('en-GB',{timeZone:TZ,hour:'2-digit',minute:'2-digit',second:'2-digit',hourCycle:'h23'}).formatToParts(n).reduce((o,x)=>(o[x.type]=+x.value,o),{});return Math.max(0,(86400-(p.hour*3600+p.minute*60+p.second))*1000-n.getMilliseconds())};
const hash=(pw,salt)=>crypto.scryptSync(pw,salt,32).toString('hex');
const same=(a,b)=>a.length==b.length&&crypto.timingSafeEqual(Buffer.from(a),Buffer.from(b));
const fails={};
const ipOf=r=>String(r.headers['x-forwarded-for']||r.socket.remoteAddress).split(',')[0].trim();
const blocked=ip=>(fails[ip]||[]).filter(t=>Date.now()-t<9e5).length>=10;
const send=(res,code,obj)=>{res.writeHead(code,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(obj))};
const authUid=req=>{const m=(req.headers.authorization||'').match(/^Bearer (\w+)$/);const u=m&&db.sessions[m[1]];return u&&db.users[u]?u:null};
const body=req=>new Promise((ok,no)=>{let b='';req.on('data',c=>{b+=c;if(b.length>3e5){no(new Error('big'));req.destroy()}});req.on('end',()=>{try{ok(JSON.parse(b||'{}'))}catch(e){ok({})}});req.on('error',no)});
const newSession=uid=>{const t=crypto.randomBytes(24).toString('hex');db.sessions[t]=uid;save();return t};
const ints=(v,max)=>Math.max(0,Math.min(max,Math.floor(+v||0)));

async function api(req,res,url){
  const uid=authUid(req);
  if(req.method=='GET'&&url=='/api/state'){
    const adm=uid&&isAdmin(uid);
    const users=Object.values(db.users).sort((a,b)=>a.created-b.created).map(u=>({id:u.id,name:u.name,photo:u.photo}));
    let logs=[];
    if(adm)logs=Object.values(db.logs).sort((a,b)=>b.ts-a.ts);
    else if(uid){logs=Object.values(db.logs).filter(l=>l.uid==uid).sort((a,b)=>b.ts-a.ts).map((l,i)=>i<VISIBLE_DAYS?l:{id:l.id,uid:l.uid,name:l.name,date:l.date,ts:l.ts,points:null})}
    const u=uid&&db.users[uid];
    const done=users.filter(x=>db.logs[x.id+'_'+today()]).map(x=>x.id);
    return send(res,200,{today:today(),left:msToMidnight(),done,users,logs,me:u?{id:u.id,name:u.name,photo:u.photo,admin:!!adm}:null,admins:adm?adminNames():null});
  }
  if(req.method!='POST')return send(res,404,{error:'not found'});
  const b=await body(req);
  if(url=='/api/register'){
    const name=String(b.name||'').trim().replace(/\s+/g,' '),pw=String(b.password||''),photo=String(b.photo||'');
    if(name.length<2||name.length>40)return send(res,400,{error:'الاسم لازم يكون من ٢ إلى ٤٠ حرف'});
    if(pw.length<4||pw.length>60)return send(res,400,{error:'كلمة السر لازم تكون ٤ حروف على الأقل'});
    if(!/^data:image\/(jpeg|png|webp);base64,/.test(photo)||photo.length>120000)return send(res,400,{error:'لازم تختار صورة صحيحة'});
    const id=hex(name);
    if(db.users[id]||Object.values(db.users).some(u=>norm(u.name)==norm(name)))return send(res,409,{error:'الاسم ده مستخدم قبل كده'});
    const salt=crypto.randomBytes(12).toString('hex');
    db.users[id]={id,name,photo,salt,ph:hash(pw,salt),created:Date.now()};
    return send(res,200,{token:newSession(id)});
  }
  if(url=='/api/login'){
    const ip=ipOf(req);if(blocked(ip))return send(res,429,{error:'محاولات كتير، حاول بعد شوية'});
    const u=db.users[hex(String(b.name||''))];
    if(!u)return send(res,404,{error:'الحساب ده مش موجود، اعمل حساب جديد'});
    if(!same(hash(String(b.password||''),u.salt),u.ph)){(fails[ip]=fails[ip]||[]).push(Date.now());return send(res,401,{error:'كلمة السر غلط'})}
    return send(res,200,{token:newSession(u.id)});
  }
  if(url=='/api/logout'){const m=(req.headers.authorization||'').match(/^Bearer (\w+)$/);if(m){delete db.sessions[m[1]];save()}return send(res,200,{})}
  if(!uid)return send(res,401,{error:'سجّل دخولك الأول'});
  if(url=='/api/log'){
    const day=today(),id=uid+'_'+day;
    if(db.logs[id])return send(res,409,{error:'سجلت ورد النهاردة قبل كده'});
    const nw=ints(b.nw,99),tath=ints(b.tath,99),tahd=ints(b.tahd,99);
    const rev=[...new Set((Array.isArray(b.rev)?b.rev:[]).map(Number))].filter(i=>Number.isInteger(i)&&i>=1&&i<=113);
    const juz=[...new Set((Array.isArray(b.juz)?b.juz:[]).map(Number))].filter(i=>Number.isInteger(i)&&i>=0&&i<=29);
    if(rev.length&&juz.length)return send(res,400,{error:'اختار مراجعة بالسورة أو بالجزء مش الاتنين'});
    const points=+(nw+tath+tahd+rev.reduce((t,i)=>t+pts(i),0)+juz.length*JUZ_PTS).toFixed(2);
    if(!points)return send(res,400,{error:'اختار حاجة الأول'});
    db.logs[id]={id,uid,name:db.users[uid].name,date:day,ts:Date.now(),points,nw,tath,tahd,rev,juz:juz.map(i=>i+1)};
    save();return send(res,200,db.logs[id]);
  }
  if(url=='/api/admin/admins'){
    if(!isAdmin(uid))return send(res,403,{error:'مش مسموح'});
    const names=[],seen=new Set();
    for(const n of Array.isArray(b.names)?b.names:[]){const t=String(n).trim().replace(/\s+/g,' ');if(t.length>=2&&t.length<=40&&!seen.has(hex(t))){seen.add(hex(t));names.push(t)}}
    if(!names.length)return send(res,400,{error:'لازم يفضل أدمن واحد على الأقل'});
    /* مينفعش حذف أدمن عنده حساب (نفسك أو أدمن تاني) */
    const keep=new Set(names.map(hex));
    if(adminNames().some(n=>!keep.has(hex(n))&&db.users[hex(n)]))return send(res,403,{error:'مينفعش تحذف أدمن عنده حساب'});
    fs.writeFileSync(ADM,JSON.stringify({admins:names},null,2));return send(res,200,{});
  }
  if(url=='/api/admin/reset-points'){
    if(!isAdmin(uid))return send(res,403,{error:'مش مسموح'});
    const id=String(b.id||'');
    if(!db.users[id])return send(res,404,{error:'العضو ده مش موجود'});
    /* تصفير النقاط: بيمسح كل سجلات الورد بس، والحساب يفضل زي ما هو */
    for(const k of Object.keys(db.logs))if(db.logs[k].uid==id)delete db.logs[k];
    flush();return send(res,200,{});
  }
  if(url=='/api/admin/change-password'){
    if(!isAdmin(uid))return send(res,403,{error:'مش مسموح'});
    const id=String(b.id||''),pw=String(b.password||'');
    const u=db.users[id];
    if(!u)return send(res,404,{error:'العضو ده مش موجود'});
    if(id!=uid&&isAdmin(id))return send(res,403,{error:'مينفعش تغيّر كلمة سر أدمن تاني'});
    if(pw.length<4||pw.length>60)return send(res,400,{error:'كلمة السر لازم تكون ٤ حروف على الأقل'});
    u.salt=crypto.randomBytes(12).toString('hex');u.ph=hash(pw,u.salt);
    /* نخرّج العضو من كل الأجهزة عشان يدخل بالباسورد الجديد */
    for(const t of Object.keys(db.sessions))if(db.sessions[t]==id&&id!=uid)delete db.sessions[t];
    flush();return send(res,200,{});
  }
  if(url=='/api/admin/delete-user'){
    if(!isAdmin(uid))return send(res,403,{error:'مش مسموح'});
    const id=String(b.id||'');
    if(!db.users[id])return send(res,404,{error:'العضو ده مش موجود'});
    if(id==uid)return send(res,403,{error:'مينفعش تمسح حسابك'});
    if(isAdmin(id))return send(res,403,{error:'مينفعش تمسح حساب أدمن'});
    /* مسح العضو بكل بياناته: الحساب + كل الورد + كل الجلسات */
    delete db.users[id];
    for(const k of Object.keys(db.logs))if(db.logs[k].uid==id)delete db.logs[k];
    for(const t of Object.keys(db.sessions))if(db.sessions[t]==id)delete db.sessions[t];
    flush();return send(res,200,{});
  }
  send(res,404,{error:'not found'});
}
const TYPES={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.png':'image/png','.ico':'image/x-icon','.svg':'image/svg+xml'};
http.createServer(async(req,res)=>{
  try{
    const url=decodeURIComponent(req.url.split('?')[0]);
    if(url.startsWith('/api/'))return await api(req,res,url);
    const f=path.normalize(path.join(PUB,url=='/'?'index.html':url));
    if(!f.startsWith(PUB)||!fs.existsSync(f)||fs.statSync(f).isDirectory()){res.writeHead(404);return res.end('Not found')}
    res.writeHead(200,{'Content-Type':TYPES[path.extname(f)]||'application/octet-stream','X-Content-Type-Options':'nosniff'});
    fs.createReadStream(f).pipe(res);
  }catch(e){try{send(res,500,{error:'خطأ في السيرفر'})}catch(_){}}
}).listen(PORT,"0.0.0.0",()=>console.log('Wird server on port '+PORT));
