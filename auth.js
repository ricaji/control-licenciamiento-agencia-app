/* Autenticación, roles y datos con Firebase (Auth + Firestore). Módulo compartido. */
import {initializeApp,deleteApp} from 'https://www.gstatic.com/firebasejs/11.0.2/firebase-app.js';
import {getAuth,onAuthStateChanged,signInWithEmailAndPassword,createUserWithEmailAndPassword,signOut,
  sendPasswordResetEmail,verifyPasswordResetCode,confirmPasswordReset,deleteUser}
  from 'https://www.gstatic.com/firebasejs/11.0.2/firebase-auth.js';
import {getFirestore,doc,getDoc,getDocs,setDoc,updateDoc,deleteDoc,collection,writeBatch}
  from 'https://www.gstatic.com/firebasejs/11.0.2/firebase-firestore.js';
import {firebaseConfig} from './firebase-config.js';

const app=initializeApp(firebaseConfig),auth=getAuth(app),db=getFirestore(app);

const ROLES={
  admin:{n:'Administrador',p:['lic','usr_ver','usr_crear','usr_rol','usr_estado','usr_clave','usr_clave_admin']},
  supervisor:{n:'Supervisor',p:['lic','usr_ver','usr_clave']},
  consulta:{n:'Consulta',p:[]}
};
const checks={
  len:p=>p.length===8,up:p=>/[A-Z]/.test(p),lo:p=>/[a-z]/.test(p),
  nu:p=>/[0-9]/.test(p),sp:p=>/[^A-Za-z0-9]/.test(p)
};
const pwOk=p=>Object.values(checks).every(f=>f(p));
const ccOk=u=>/^\d{6,10}$/.test(u);
const emailOk=e=>/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);

function genPass(){
  const r=n=>crypto.getRandomValues(new Uint32Array(1))[0]%n;
  const pick=s=>s[r(s.length)];
  const A='ABCDEFGHJKLMNPQRSTUVWXYZ',a='abcdefghijkmnpqrstuvwxyz',N='23456789',X='!@#$%&*?';
  const c=[pick(A),pick(a),pick(N),pick(X)];
  while(c.length<8)c.push(pick(A+a+N+X));
  for(let i=c.length-1;i>0;i--){const j=r(i+1);[c[i],c[j]]=[c[j],c[i]]}
  return c.join('');
}

let ME=null;
async function loadProfile(u){
  try{
    const s=await getDoc(doc(db,'usuarios',u.uid));
    if(s.exists()&&s.data().activo!==false){
      const d=s.data();
      ME={uid:u.uid,cc:d.cc,nombre:d.nombre||'',email:d.email,rol:ROLES[d.rol]?d.rol:'consulta'};
      return ME;
    }
  }catch(e){}
  ME=null;await signOut(auth);return null;
}
const ready=new Promise(res=>{
  const off=onAuthStateChanged(auth,async u=>{off();res(u?await loadProfile(u):null)});
});

const can=p=>!!ME&&ROLES[ME.rol].p.includes(p);
async function guard(perm){
  const m=await ready;
  if(!m||(perm&&!can(perm))){location.replace(m?'index.html':'login.html');return null}
  return m;
}
async function initialized(){return (await getDoc(doc(db,'config','init'))).exists()}

async function login(cc,pw){
  const c=await getDoc(doc(db,'cedulas',cc));
  if(!c.exists())throw new Error('cred');
  await signInWithEmailAndPassword(auth,c.data().email,pw);
  const p=await loadProfile(auth.currentUser);
  if(!p)throw new Error('sinperfil');
  return p;
}
const logout=async()=>{await signOut(auth);location.href='login.html'};

async function bootstrap(cc,email,nombre,pw){
  const cred=await createUserWithEmailAndPassword(auth,email,pw);
  try{
    const b=writeBatch(db),uid=cred.user.uid;
    b.set(doc(db,'usuarios',uid),{cc,nombre,email,rol:'admin',activo:true,creado:Date.now()});
    b.set(doc(db,'cedulas',cc),{email,uid});
    b.set(doc(db,'config','init'),{por:uid,fecha:Date.now()});
    await b.commit();
  }catch(e){try{await deleteUser(cred.user)}catch(x){}throw e}
  return loadProfile(cred.user);
}

// El administrador crea la cuenta y a la persona le llega un correo para elegir su contraseña.
async function createUser({cc,email,nombre,rol}){
  if(!can('usr_crear'))throw new Error('permiso');
  if((await getDoc(doc(db,'cedulas',cc))).exists())throw new Error('cc-existe');
  const sec=initializeApp(firebaseConfig,'sec'+Date.now()),sa=getAuth(sec);
  let uid;
  try{
    const c=await createUserWithEmailAndPassword(sa,email,genPass());
    uid=c.user.uid;await signOut(sa);
  }finally{await deleteApp(sec)}
  const b=writeBatch(db);
  b.set(doc(db,'usuarios',uid),{cc,nombre,email,rol,activo:true,creado:Date.now()});
  b.set(doc(db,'cedulas',cc),{email,uid});
  await b.commit();
  await sendPasswordResetEmail(auth,email);
}
async function sendReset(cc){
  const c=await getDoc(doc(db,'cedulas',cc));
  if(!c.exists())throw new Error('cred');
  await sendPasswordResetEmail(auth,c.data().email);
}
const verifyReset=code=>verifyPasswordResetCode(auth,code);
const confirmReset=(code,pw)=>confirmPasswordReset(auth,code,pw);

const users={
  async list(){return (await getDocs(collection(db,'usuarios'))).docs.map(d=>({uid:d.id,...d.data()}))},
  update:(uid,patch)=>updateDoc(doc(db,'usuarios',uid),patch)
};
const licencias={
  async list(){return (await getDocs(collection(db,'licencias'))).docs.map(d=>({id:d.id,...d.data()}))},
  save:l=>{const {id,...rest}=l;return setDoc(doc(db,'licencias',id),rest)},
  remove:id=>deleteDoc(doc(db,'licencias',id)),
  async saveMany(arr){
    for(let i=0;i<arr.length;i+=400){
      const b=writeBatch(db);
      arr.slice(i,i+400).forEach(({id,...rest})=>b.set(doc(db,'licencias',id),rest));
      await b.commit();
    }
  }
};

export const Auth={ROLES,checks,pwOk,ccOk,emailOk,genPass,ready,me:()=>ME,can,guard,initialized,
  login,logout,bootstrap,createUser,sendReset,verifyReset,confirmReset,users,licencias};
