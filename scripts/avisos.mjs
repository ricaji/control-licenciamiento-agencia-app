import admin from 'firebase-admin';
import nodemailer from 'nodemailer';

const TO = 'control.licenciamiento@app.gov.co';
const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
admin.initializeApp({ credential: admin.credential.cert(sa) });
const db = admin.firestore();

const ymd = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Bogota' }).format(new Date());
const utc = s => Date.UTC(+s.slice(0, 4), +s.slice(5, 7) - 1, +s.slice(8, 10));
const hoy = utc(ymd);
const dow = new Date(hoy).getUTCDay(); // 1=lun, 3=mie, 5=vie
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const dias = l => (l.vencimiento ? Math.round((utc(l.vencimiento) - hoy) / 864e5) : null);

const snap = await db.collection('licencias').get();
const lics = snap.docs.map(d => ({ id: d.id, ...d.data() }));
const stRef = db.doc('config/notif');
const st = await stRef.get();
const stData = st.exists ? st.data() : null;

// Primera ejecucion: se toma la lista actual como base y no se avisa de las existentes.
const conocidas = new Set(stData?.conocidas || (stData ? [] : lics.map(l => l.id)));
const nuevas = lics.filter(l => !conocidas.has(l.id));

const force = process.env.FORCE === 'true';
const r3 = (force || [1, 3, 5].includes(dow))
  ? lics.filter(l => { const d = dias(l); return d !== null && d >= 0 && d <= 90; }) : [];
const ult = stData?.ultimo180;
const toca15 = force || !ult || (hoy - utc(ult)) / 864e5 >= 15;
const r6 = toca15 ? lics.filter(l => { const d = dias(l); return d !== null && d > 90 && d <= 180; }) : [];

const tabla = (arr, conDias) =>
  '<table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;font-family:Arial;font-size:13px">' +
  '<tr style="background:#eee"><th>Software</th><th>Proveedor</th><th>Contrato</th><th>Vencimiento</th>' + (conDias ? '<th>Días</th>' : '') + '</tr>' +
  arr.sort((a, b) => (dias(a) ?? 9e9) - (dias(b) ?? 9e9)).map(l =>
    '<tr><td>' + esc(l.nombre) + '</td><td>' + esc(l.proveedor) + '</td><td>' + esc(l.contrato) + '</td><td>' + esc(l.vencimiento || 'Sin fecha') + '</td>' +
    (conDias ? '<td>' + dias(l) + '</td>' : '') + '</tr>').join('') + '</table>';

const partes = [];
if (nuevas.length) partes.push('<h3>Licencias nuevas ingresadas (' + nuevas.length + ')</h3>' + tabla(nuevas, true));
if (r3.length) partes.push('<h3 style="color:#b42318">Vencen en menos de 3 meses (' + r3.length + ')</h3>' + tabla(r3, true));
if (r6.length) partes.push('<h3 style="color:#8a6100">Vencen entre 3 y 6 meses (' + r6.length + ')</h3>' + tabla(r6, true));

if (partes.length) {
  const tr = nodemailer.createTransport({
    host: 'smtp.office365.com', port: 587, secure: false, requireTLS: true,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
  const asunto = 'Licenciamiento: ' + [
    nuevas.length && nuevas.length + ' nueva(s)',
    r3.length && r3.length + ' por vencer (<3 meses)',
    r6.length && r6.length + ' por vencer (3-6 meses)'
  ].filter(Boolean).join(', ');
  await tr.sendMail({
    from: process.env.SMTP_USER, to: TO, subject: asunto,
    html: '<div style="font-family:Arial"><p>Señores Agencia APP,</p>' + ((r3.length || r6.length) ? '<p>Actualmente tiene el siguiente licenciamiento a vencer:</p>' : '') + partes.join('<br>') + '<p style="color:#666;font-size:12px">Aviso automatico - Control de Licenciamiento. ' + ymd + '</p></div>'
  });
  console.log('Correo enviado:', asunto);
} else {
  console.log('Nada que avisar hoy.');
}

await stRef.set({
  conocidas: lics.map(l => l.id),
  ultimo180: r6.length ? ymd : (ult || null),
  actualizado: ymd
});
