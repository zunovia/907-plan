// =============================================
// Serial Number Authentication Helpers
// =============================================
async function timingSafeCompare(a, b) {
  const encoder = new TextEncoder();
  const keyA = await crypto.subtle.digest('SHA-256', encoder.encode(String(a)));
  const keyB = await crypto.subtle.digest('SHA-256', encoder.encode(String(b)));
  return crypto.subtle.timingSafeEqual(keyA, keyB);
}

function generateSerial(prefix) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const segCount = 3; // 3 segments of 4 chars
  const bytes = new Uint8Array(segCount * 4);
  crypto.getRandomValues(bytes);
  let body = '';
  for (let i = 0; i < segCount * 4; i++) {
    if (i > 0 && i % 4 === 0) body += '-';
    body += chars[bytes[i] % chars.length];
  }
  return prefix ? prefix + '-' + body : generateSerialLegacy();
}

function generateSerialLegacy() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let serial = '';
  for (let i = 0; i < 16; i++) {
    if (i > 0 && i % 4 === 0) serial += '-';
    serial += chars[bytes[i] % chars.length];
  }
  return serial;
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
    },
  });
}

async function checkRateLimit(ip, env) {
  const key = 'ratelimit:' + ip;
  const raw = await env.RATE_LIMIT_KV.get(key);
  const now = Date.now();
  if (raw) {
    const data = JSON.parse(raw);
    if ((now - data.firstAttempt) < 900000) {
      if (data.attempts >= 5) return { allowed: false, remaining: 0 };
      await env.RATE_LIMIT_KV.put(key, JSON.stringify({
        attempts: data.attempts + 1, firstAttempt: data.firstAttempt
      }), { expirationTtl: 900 });
      return { allowed: true, remaining: 5 - data.attempts - 1 };
    }
  }
  await env.RATE_LIMIT_KV.put(key, JSON.stringify({
    attempts: 1, firstAttempt: now
  }), { expirationTtl: 900 });
  return { allowed: true, remaining: 4 };
}

async function verifyAdmin(request, env) {
  const key = request.headers.get('X-Admin-Key') || '';
  if (!key || !env.ADMIN_API_KEY) return false;
  return timingSafeCompare(key, env.ADMIN_API_KEY);
}

// =============================================
// Spreadsheet Webhook
// =============================================
async function sendWebhook(env, payload) {
  const url = env.SPREADSHEET_WEBHOOK_URL;
  if (!url) return;
  try {
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        timestamp: new Date().toISOString(),
        ...payload,
      }),
    });
  } catch (_) {
    // Webhook failure must not affect main flow
  }
}

// =============================================
// API Handlers
// =============================================
async function handleSerialVerify(request, env, ctx) {
  const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';

  let body;
  try { body = await request.json(); } catch { return jsonResponse({ valid: false, error: 'Invalid request body' }, 400); }
  const rawInput = (body.serial || '').trim();

  // Admin API key bypass — freepass with no expiry, skips rate limit
  if (env.ADMIN_API_KEY && await timingSafeCompare(rawInput, env.ADMIN_API_KEY)) {
    ctx.waitUntil(sendWebhook(env, {
      event: 'VERIFY_SUCCESS', serial: 'ADMIN-FREEPASS', status: 'freepass', ip,
      note: 'Admin freepass authentication',
    }));
    return jsonResponse({ valid: true, freepass: true, expiresAt: null, remainingDays: 9999 });
  }

  const rateCheck = await checkRateLimit(ip, env);
  if (!rateCheck.allowed) {
    ctx.waitUntil(sendWebhook(env, {
      event: 'VERIFY_FAIL', serial: '-', status: 'rate_limited', ip,
      note: 'Rate limit exceeded',
    }));
    return jsonResponse({ valid: false, error: 'Too many attempts. Please try again in 15 minutes.' }, 429);
  }

  const serial = rawInput.toUpperCase();
  // Support both legacy XXXX-XXXX-XXXX-XXXX and new PREFIX-XXXX-XXXX-XXXX formats
  if (!/^([A-Z]{2,4}-)?[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}(-[A-Z0-9]{4})?$/.test(serial)) {
    return jsonResponse({ valid: false, error: 'Invalid serial number format' }, 400);
  }

  const kvKey = 'serial:' + serial;
  const raw = await env.SERIAL_KV.get(kvKey);
  if (!raw) {
    ctx.waitUntil(sendWebhook(env, {
      event: 'VERIFY_FAIL', serial, status: 'not_found', ip,
      note: 'Serial not found. Attempts remaining: ' + rateCheck.remaining,
    }));
    return jsonResponse({ valid: false, error: 'Invalid serial number', attemptsRemaining: rateCheck.remaining }, 401);
  }

  const data = JSON.parse(raw);

  // Cross-app protection: reject if serial was issued for a different app
  const requestedApp = (body.app || '').toLowerCase();
  if (requestedApp && data.app && data.app !== requestedApp) {
    ctx.waitUntil(sendWebhook(env, {
      event: 'VERIFY_FAIL', serial, status: 'wrong_app', ip,
      note: 'Serial issued for ' + data.app + ' but used on ' + requestedApp,
    }));
    return jsonResponse({ valid: false, error: 'Invalid serial number' }, 401);
  }

  if (data.status === 'revoked') {
    ctx.waitUntil(sendWebhook(env, {
      event: 'VERIFY_FAIL', serial, status: 'revoked', ip,
      expiresAt: data.expiresAt || null, note: 'Attempted use of revoked serial',
      app: data.app || null,
    }));
    return jsonResponse({ valid: false, error: 'This serial number has been revoked' }, 401);
  }

  const now = new Date();
  const isNewModel = data.expiresAfterDays != null;
  let expiresAt;

  if (isNewModel) {
    // New model: activation-based expiry
    if (!data.activatedAt) {
      // First use — activate now
      data.activatedAt = now.toISOString();
      data.usedBy = ip;
      data.usedAt = now.toISOString();
      await env.SERIAL_KV.put(kvKey, JSON.stringify(data));
    }
    expiresAt = new Date(new Date(data.activatedAt).getTime() + data.expiresAfterDays * 24 * 60 * 60 * 1000);
  } else {
    // Legacy model: fixed expiresAt
    expiresAt = new Date(data.expiresAt);
  }

  if (now > expiresAt) {
    data.status = 'expired';
    await env.SERIAL_KV.put(kvKey, JSON.stringify(data));
    ctx.waitUntil(sendWebhook(env, {
      event: 'VERIFY_FAIL', serial, status: 'expired', ip,
      expiresAt: expiresAt.toISOString(), note: 'Attempted use of expired serial',
      app: data.app || null,
    }));
    return jsonResponse({ valid: false, error: 'This serial number has expired' }, 401);
  }

  if (!data.usedBy) {
    data.usedBy = ip;
    data.usedAt = now.toISOString();
    await env.SERIAL_KV.put(kvKey, JSON.stringify(data));
  }

  const remainingMs = expiresAt.getTime() - now.getTime();
  const remainingDays = Math.ceil(remainingMs / (1000 * 60 * 60 * 24));
  const computedExpiresAt = expiresAt.toISOString();

  ctx.waitUntil(sendWebhook(env, {
    event: 'VERIFY_SUCCESS', serial, status: 'active', ip,
    expiresAt: computedExpiresAt, remainingDays,
    createdAt: data.createdAt, usedAt: data.usedAt,
    activatedAt: data.activatedAt || null,
    app: data.app || null,
    note: isNewModel ? 'Authentication successful (activation model)' : 'Authentication successful (legacy model)',
  }));

  return jsonResponse({ valid: true, expiresAt: computedExpiresAt, remainingDays });
}

async function handleSerialGenerate(request, env, ctx) {
  if (!await verifyAdmin(request, env)) return jsonResponse({ error: 'Unauthorized' }, 401);

  let body;
  try { body = await request.json(); } catch { body = {}; }
  const count = Math.min(Math.max(parseInt(body.count) || 1, 1), 10);
  const durationDays = parseInt(body.durationDays) || 14;
  const app = (body.app || '').toLowerCase(); // "keiri" or "voice"
  const validApps = ['keiri', 'voice'];
  if (app && !validApps.includes(app)) {
    return jsonResponse({ error: 'Invalid app. Must be "keiri" or "voice"' }, 400);
  }
  const prefixMap = { keiri: 'VOI', voice: 'KOE' };
  const prefix = prefixMap[app] || null;
  const label = body.label || '';

  const serials = [];
  const now = new Date();

  for (let i = 0; i < count; i++) {
    const serial = generateSerial(prefix);
    const data = {
      createdAt: now.toISOString(),
      activatedAt: null,
      expiresAfterDays: durationDays,
      status: 'active',
      usedBy: null,
      usedAt: null,
      app: app || 'keiri',
      label: label,
      source: 'admin',
    };
    await env.SERIAL_KV.put('serial:' + serial, JSON.stringify(data));
    serials.push({ serial, expiresAfterDays: durationDays, app: data.app });
  }

  const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'admin';
  ctx.waitUntil(Promise.all(serials.map(s =>
    sendWebhook(env, {
      event: 'GENERATE', serial: s.serial, status: 'active', ip,
      expiresAfterDays: durationDays,
      createdAt: now.toISOString(),
      app: s.app,
      note: 'Generated with ' + durationDays + '-day validity (from first use)',
    })
  )));

  return jsonResponse({ serials });
}

async function handleSerialList(request, env) {
  if (!await verifyAdmin(request, env)) return jsonResponse({ error: 'Unauthorized' }, 401);

  const url = new URL(request.url);
  const appFilter = url.searchParams.get('app'); // "keiri", "voice", or null for all

  const list = await env.SERIAL_KV.list({ prefix: 'serial:' });
  const serials = [];
  for (const key of list.keys) {
    const raw = await env.SERIAL_KV.get(key.name);
    if (raw) {
      const data = JSON.parse(raw);
      const serial = key.name.replace('serial:', '');

      // App filter
      if (appFilter) {
        const dataApp = data.app || 'keiri'; // legacy serials default to keiri
        if (dataApp !== appFilter) continue;
      }

      const now = new Date();
      const isNewModel = data.expiresAfterDays != null;
      let computedExpiresAt;

      if (isNewModel) {
        if (data.activatedAt) {
          computedExpiresAt = new Date(new Date(data.activatedAt).getTime() + data.expiresAfterDays * 24 * 60 * 60 * 1000);
        } else {
          computedExpiresAt = null; // Not activated yet
        }
      } else {
        computedExpiresAt = data.expiresAt ? new Date(data.expiresAt) : null;
      }

      if (data.status === 'active' && computedExpiresAt && now > computedExpiresAt) {
        data.status = 'expired';
        await env.SERIAL_KV.put(key.name, JSON.stringify(data));
      }

      serials.push({
        serial,
        ...data,
        expiresAt: computedExpiresAt ? computedExpiresAt.toISOString() : null,
        app: data.app || 'keiri',
      });
    }
  }

  serials.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  return jsonResponse({ serials, total: serials.length });
}

async function handleSerialRevoke(request, env, ctx) {
  if (!await verifyAdmin(request, env)) return jsonResponse({ error: 'Unauthorized' }, 401);

  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: 'Invalid request body' }, 400); }
  const serial = (body.serial || '').trim().toUpperCase();
  const kvKey = 'serial:' + serial;
  const raw = await env.SERIAL_KV.get(kvKey);
  if (!raw) return jsonResponse({ error: 'Serial number not found' }, 404);

  const data = JSON.parse(raw);
  data.status = 'revoked';
  await env.SERIAL_KV.put(kvKey, JSON.stringify(data));

  const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'admin';
  ctx.waitUntil(sendWebhook(env, {
    event: 'REVOKE', serial, status: 'revoked', ip,
    expiresAt: data.expiresAt || null, createdAt: data.createdAt,
    app: data.app || 'keiri',
    note: 'Revoked by admin',
  }));

  return jsonResponse({ success: true, serial });
}

// =============================================
// Admin Page HTML
// =============================================
function getAdminHtml() {
  return `<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Serial Number Admin | Sur Communication</title>
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans+JP:wght@400;500;700&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{--ink:#1a1a1a;--ink2:#4a5a6a;--ink3:#888;--bg:#f5f4f0;--sf:#fff;--bd:#dbd8d0;--bd2:#c8c4bc;
  --gn:#1a6040;--gnbg:#e8f5ee;--bl:#1a4a9a;--blbg:#e8effe;--am:#92400e;--ambg:#fef3c7;
  --rd:#880e4f;--rdbg:#fce4ec;--cy:#0078c8;--cybg:#e8f2ff;--r:8px}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Noto Sans JP',sans-serif;background:var(--bg);color:var(--ink);font-size:13px;line-height:1.7}
.hd{background:#1a1a1a;height:54px;display:flex;align-items:center;padding:0 20px;gap:10px;position:sticky;top:0;z-index:300}
.hd-t{font-size:14px;font-weight:700;color:#fff}
.hd-b{font-size:9px;background:rgba(255,255,255,.15);padding:2px 6px;border-radius:3px;color:rgba(255,255,255,.65)}
.wrap{max-width:960px;margin:0 auto;padding:20px}
.card{background:var(--sf);border:.5px solid var(--bd);border-radius:var(--r);overflow:hidden;margin-bottom:14px}
.cardh{padding:10px 14px;display:flex;align-items:center;gap:8px;border-bottom:.5px solid var(--bd);background:#f9f8f5}
.cardt{font-size:13px;font-weight:700;flex:1}
.cardb{padding:14px}
.btn{display:inline-flex;align-items:center;gap:4px;padding:7px 16px;border:none;border-radius:4px;font-size:12px;font-family:inherit;font-weight:700;cursor:pointer;transition:all .12s;white-space:nowrap}
.btn-g{background:var(--gn);color:#fff}.btn-g:hover{background:#237a4e}
.btn-c{background:var(--cy);color:#fff}.btn-c:hover{background:#005fa0}
.btn-r{background:var(--rd);color:#fff;font-size:10px;padding:4px 8px}.btn-r:hover{opacity:.85}
.btn-o{background:var(--sf);border:.5px solid var(--bd2);color:var(--ink)}.btn-o:hover{background:#f5f4f0}
input,select{font-family:'Noto Sans JP',sans-serif;font-size:12px;padding:6px 10px;border:1px solid var(--bd2);border-radius:4px;background:var(--sf);color:var(--ink);outline:none}
input:focus{border-color:var(--cy)}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:6px 10px;background:#f9f8f5;border-bottom:.5px solid var(--bd);font-size:10px;font-weight:700;color:var(--ink3);white-space:nowrap}
td{padding:7px 10px;border-bottom:.5px solid var(--bd);vertical-align:middle}
tr:last-child td{border:none}
tr:hover td{background:#fafaf8}
.chip{font-size:9px;font-weight:700;padding:2px 6px;border-radius:3px}
.c-active{background:var(--gnbg);color:var(--gn)}
.c-expired{background:var(--ambg);color:var(--am)}
.c-revoked{background:var(--rdbg);color:var(--rd)}
.mono{font-family:'DM Mono',monospace;font-size:12px;letter-spacing:.5px}
.notif{position:fixed;bottom:14px;right:14px;background:#1a1a1a;color:#fff;padding:9px 14px;border-radius:var(--r);font-size:12px;box-shadow:0 4px 20px rgba(0,0,0,.2);z-index:999;transform:translateY(60px);opacity:0;transition:all .3s cubic-bezier(.34,1.56,.64,1)}
.notif.on{transform:translateY(0);opacity:1}
.notif.green{background:var(--gn)}
.auth-bar{background:var(--blbg);border:.5px solid rgba(26,74,154,.15);border-radius:var(--r);padding:10px 14px;display:flex;align-items:center;gap:10px;margin-bottom:14px}
.gen-result{margin-top:10px;background:#f9f8f5;border:.5px solid var(--bd);border-radius:var(--r);padding:10px;display:none}
.gen-item{display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:.5px solid var(--bd)}
.gen-item:last-child{border:none}
.copy-btn{background:none;border:1px solid var(--bd2);border-radius:3px;padding:2px 8px;font-size:10px;cursor:pointer;color:var(--ink3)}
.copy-btn:hover{background:var(--bg);color:var(--ink)}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:14px}
.stat-card{background:var(--sf);border:.5px solid var(--bd);border-radius:var(--r);padding:14px;text-align:center}
.stat-num{font-size:24px;font-weight:700;font-family:'DM Mono',monospace}
.stat-lbl{font-size:10px;color:var(--ink3);margin-top:2px}
</style>
</head>
<body>
<div class="hd">
  <span class="hd-t">Serial Number Admin</span>
  <span class="hd-b">MANAGEMENT</span>
</div>
<div class="wrap">
  <div class="auth-bar">
    <span style="font-size:11px;font-weight:700">Admin API Key:</span>
    <input type="password" id="admin-key" placeholder="Enter admin API key..." style="flex:1" value="">
    <button class="btn btn-c" onclick="saveAdminKey()">Save</button>
  </div>

  <div class="stats" id="stats">
    <div class="stat-card"><div class="stat-num" id="stat-total">-</div><div class="stat-lbl">Total</div></div>
    <div class="stat-card"><div class="stat-num" id="stat-active" style="color:var(--gn)">-</div><div class="stat-lbl">Active</div></div>
    <div class="stat-card"><div class="stat-num" id="stat-expired" style="color:var(--am)">-</div><div class="stat-lbl">Expired / Revoked</div></div>
  </div>

  <div class="card">
    <div class="cardh"><span class="cardt">Generate Serial Numbers</span></div>
    <div class="cardb">
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <label style="font-size:11px;font-weight:700">App:</label>
        <select id="gen-app" style="font-size:12px;padding:6px 10px">
          <option value="keiri">経理ツール (VOI-)</option>
          <option value="voice">声のアプリ (KOE-)</option>
        </select>
        <label style="font-size:11px;font-weight:700">Count:</label>
        <input type="number" id="gen-count" value="1" min="1" max="10" style="width:60px">
        <label style="font-size:11px;font-weight:700">Duration (days):</label>
        <input type="number" id="gen-days" value="14" min="1" max="365" style="width:60px">
        <button class="btn btn-g" onclick="generateSerials()">Generate</button>
      </div>
      <div style="font-size:10px;color:var(--ink3);margin-top:6px">Duration starts from first use, not from issuance</div>
      <div class="gen-result" id="gen-result"></div>
    </div>
  </div>

  <div class="card">
    <div class="cardh">
      <span class="cardt">Serial Number List</span>
      <select id="filter-app" onchange="loadSerials()" style="font-size:11px;padding:4px 8px;margin-left:8px">
        <option value="">All Apps</option>
        <option value="keiri">経理ツール (VOI-)</option>
        <option value="voice">声のアプリ (KOE-)</option>
      </select>
      <button class="btn btn-o" onclick="loadSerials()" style="font-size:11px;padding:4px 10px">Refresh</button>
    </div>
    <div id="serial-list" style="overflow-x:auto">
      <table>
        <thead><tr><th>App</th><th>Serial Number</th><th>Status</th><th>Created</th><th>Activated</th><th>Expires</th><th>Remaining</th><th>Used By</th><th>Actions</th></tr></thead>
        <tbody id="serial-tbody"><tr><td colspan="9" style="text-align:center;padding:20px;color:#bbb">Click "Refresh" to load</td></tr></tbody>
      </table>
    </div>
  </div>

  <div class="card">
    <div class="cardh"><span class="cardt">Spreadsheet Webhook</span></div>
    <div class="cardb">
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <span style="font-size:11px;font-weight:700">Status:</span>
        <span id="webhook-status" class="chip" style="background:#f0f0f0;color:#888">Checking...</span>
        <button class="btn btn-o" onclick="testWebhook()" style="font-size:11px;padding:4px 10px">Test Webhook</button>
      </div>
      <div style="margin-top:8px;font-size:11px;color:var(--ink3);line-height:1.6">
        Webhook URL is configured via environment variable <code>SPREADSHEET_WEBHOOK_URL</code>.<br>
        Set it with: <code>wrangler secret put SPREADSHEET_WEBHOOK_URL</code>
      </div>
    </div>
  </div>
</div>
<div class="notif" id="notif"></div>
<script>
var _nt;
function notif(msg,cls){
  var el=document.getElementById('notif');
  el.textContent=msg;el.className='notif on'+(cls?' '+cls:'');
  clearTimeout(_nt);_nt=setTimeout(function(){el.classList.remove('on');},3500);
}
function getKey(){return localStorage.getItem('serial_admin_key')||'';}
function saveAdminKey(){
  var k=document.getElementById('admin-key').value.trim();
  if(!k){notif('Please enter an API key');return;}
  localStorage.setItem('serial_admin_key',k);
  notif('API key saved','green');
  loadSerials();
}
async function apiCall(method,path,body){
  var opts={method:method,headers:{'Content-Type':'application/json','X-Admin-Key':getKey()}};
  if(body)opts.body=JSON.stringify(body);
  var res=await fetch(path,opts);
  return await res.json();
}
async function generateSerials(){
  var count=parseInt(document.getElementById('gen-count').value)||1;
  var days=parseInt(document.getElementById('gen-days').value)||14;
  var app=document.getElementById('gen-app').value||'keiri';
  try{
    var data=await apiCall('POST','/api/admin/serial/generate',{count:count,durationDays:days,app:app});
    if(data.error){notif(data.error);return;}
    var el=document.getElementById('gen-result');
    el.style.display='block';
    el.innerHTML=data.serials.map(function(s){
      return '<div class="gen-item"><span class="mono" style="flex:1">'+s.serial+'</span><span style="font-size:10px;color:var(--ink3)">'+s.expiresAfterDays+'d from first use</span><button class="copy-btn" onclick="copySerial(this,\\''+s.serial+'\\')">Copy</button></div>';
    }).join('');
    notif(data.serials.length+' serial(s) generated for '+(app==='voice'?'Voice':'Keiri'),'green');
    loadSerials();
  }catch(e){notif('Error: '+e.message);}
}
function copySerial(btn,serial){
  navigator.clipboard.writeText(serial).then(function(){
    btn.textContent='Copied!';setTimeout(function(){btn.textContent='Copy';},2000);
  });
}
async function loadSerials(){
  try{
    var appF=document.getElementById('filter-app').value;
    var url='/api/admin/serial/list'+(appF?'?app='+appF:'');
    var data=await apiCall('GET',url);
    if(data.error){notif(data.error);return;}
    var serials=data.serials||[];
    var active=serials.filter(function(s){return s.status==='active';}).length;
    var other=serials.length-active;
    document.getElementById('stat-total').textContent=serials.length;
    document.getElementById('stat-active').textContent=active;
    document.getElementById('stat-expired').textContent=other;
    var tbody=document.getElementById('serial-tbody');
    if(!serials.length){tbody.innerHTML='<tr><td colspan="9" style="text-align:center;padding:20px;color:#bbb">No serial numbers</td></tr>';return;}
    tbody.innerHTML=serials.map(function(s){
      var now=new Date();
      var appLabel=s.app==='voice'?'Voice':'Keiri';
      var appChip=s.app==='voice'?'<span class="chip" style="background:var(--blbg);color:var(--bl)">Voice</span>':'<span class="chip" style="background:var(--gnbg);color:var(--gn)">Keiri</span>';
      var activated=s.activatedAt?new Date(s.activatedAt).toLocaleDateString('ja-JP'):'<span style="color:#bbb">未使用</span>';
      var expText='-',remText='-';
      if(s.expiresAt){
        var exp=new Date(s.expiresAt);
        expText=exp.toLocaleDateString('ja-JP');
        if(s.status==='active'){
          var remDays=Math.max(0,Math.ceil((exp-now)/(1000*60*60*24)));
          remText=remDays+'d';
        }
      } else if(s.status==='active'){
        expText='<span style="color:#bbb">未使用</span>';
        remText=s.expiresAfterDays?s.expiresAfterDays+'d':'14d';
      }
      var chipCls=s.status==='active'?'c-active':s.status==='expired'?'c-expired':'c-revoked';
      var revokeBtn=s.status==='active'?'<button class="btn-r" onclick="revokeSerial(\\''+s.serial+'\\')">Revoke</button>':'';
      return '<tr><td>'+appChip+'</td><td class="mono">'+s.serial+'</td><td><span class="chip '+chipCls+'">'+s.status+'</span></td><td>'+new Date(s.createdAt).toLocaleDateString('ja-JP')+'</td><td>'+activated+'</td><td>'+expText+'</td><td style="text-align:center">'+remText+'</td><td style="font-size:10px;color:var(--ink3)">'+(s.usedBy||'-')+'</td><td>'+revokeBtn+'</td></tr>';
    }).join('');
  }catch(e){notif('Error: '+e.message);}
}
async function revokeSerial(serial){
  if(!confirm('Revoke serial: '+serial+'?'))return;
  try{
    var data=await apiCall('POST','/api/admin/serial/revoke',{serial:serial});
    if(data.error){notif(data.error);return;}
    notif('Serial revoked','green');
    loadSerials();
  }catch(e){notif('Error: '+e.message);}
}
async function checkWebhookStatus(){
  try{
    var data=await apiCall('GET','/api/admin/webhook/status');
    var el=document.getElementById('webhook-status');
    if(data.configured){
      el.className='chip c-active';el.textContent='Configured';
    } else {
      el.className='chip c-expired';el.textContent='Not configured';
    }
  }catch(e){}
}
async function testWebhook(){
  try{
    var data=await apiCall('POST','/api/admin/webhook/test');
    if(data.error){notif(data.error);return;}
    if(data.success) notif('Webhook test sent','green');
    else notif('Webhook not configured');
  }catch(e){notif('Error: '+e.message);}
}
(function(){
  var k=localStorage.getItem('serial_admin_key');
  if(k){document.getElementById('admin-key').value=k;loadSerials();checkWebhookStatus();}
})();
</script>
</body>
</html>`;
}

// =============================================
// Main Worker
// =============================================
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // --- API Routes ---
    if (url.pathname === '/api/serial/verify' && request.method === 'POST') {
      return handleSerialVerify(request, env, ctx);
    }
    if (url.pathname === '/api/admin/serial/generate' && request.method === 'POST') {
      return handleSerialGenerate(request, env, ctx);
    }
    if (url.pathname === '/api/admin/serial/list' && request.method === 'GET') {
      return handleSerialList(request, env);
    }
    if (url.pathname === '/api/admin/serial/revoke' && request.method === 'POST') {
      return handleSerialRevoke(request, env, ctx);
    }
    if (url.pathname === '/api/admin/webhook/status' && request.method === 'GET') {
      if (!await verifyAdmin(request, env)) return jsonResponse({ error: 'Unauthorized' }, 401);
      return jsonResponse({ configured: !!(env.SPREADSHEET_WEBHOOK_URL) });
    }
    if (url.pathname === '/api/admin/webhook/test' && request.method === 'POST') {
      if (!await verifyAdmin(request, env)) return jsonResponse({ error: 'Unauthorized' }, 401);
      if (!env.SPREADSHEET_WEBHOOK_URL) return jsonResponse({ success: false, error: 'Webhook URL not configured' });
      ctx.waitUntil(sendWebhook(env, {
        event: 'TEST', serial: 'TEST-TEST-TEST-TEST', status: 'test',
        ip: 'admin', note: 'Webhook connectivity test',
      }));
      return jsonResponse({ success: true });
    }

    // --- Admin Page ---
    if (url.pathname === '/admin' || url.pathname === '/admin/') {
      return new Response(getAdminHtml(), {
        headers: { 'Content-Type': 'text/html;charset=UTF-8' },
      });
    }

    if (url.pathname === "/tool.html" || url.pathname === "/tool") {
      const toolHtml = `<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI 仕訳インポートツール | Sur Communication</title>
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans+JP:wght@400;500;700&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{--ink:#1a1a1a;--ink2:#4a5a6a;--ink3:#888;--bg:#f5f4f0;--sf:#fff;--bd:#dbd8d0;--bd2:#c8c4bc;
  --gn:#1a6040;--gnbg:#e8f5ee;--bl:#1a4a9a;--blbg:#e8effe;--am:#92400e;--ambg:#fef3c7;
  --rd:#880e4f;--rdbg:#fce4ec;--cy:#0078c8;--cybg:#e8f2ff;--r:8px}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Noto Sans JP',sans-serif;background:var(--bg);color:var(--ink);font-size:13px;line-height:1.7}
.tb{background:#1a1a1a;height:54px;display:flex;align-items:center;padding:0 14px;gap:8px;position:sticky;top:0;z-index:300}
.tb-logo{font-size:13px;font-weight:700;color:#fff}
.tb-badge{font-size:9px;background:rgba(255,255,255,.15);padding:2px 6px;border-radius:3px;color:rgba(255,255,255,.65)}
.tb-sp{flex:1}
.sw-wrap{display:flex;gap:3px;background:rgba(255,255,255,.1);padding:3px;border-radius:5px}
.swb{padding:5px 12px;border:none;border-radius:3px;font-size:11px;font-weight:700;cursor:pointer;font-family:inherit;background:transparent;color:rgba(255,255,255,.6);transition:all .15s}
.swb.on{background:#fff;color:#1a1a1a}
.swb:hover:not(.on){background:rgba(255,255,255,.2);color:#fff}
.tb-stat{font-size:11px;color:rgba(255,255,255,.45);font-family:monospace;margin:0 8px;white-space:nowrap}
.tb-dl{background:var(--cy);color:#fff;border:none;padding:6px 14px;border-radius:4px;font-size:12px;font-weight:700;cursor:pointer;font-family:inherit}
.tb-dl:hover{background:#005fa0}
.app{display:flex;height:calc(100vh - 54px)}
.sb{width:196px;flex-shrink:0;background:var(--sf);border-right:.5px solid var(--bd);overflow-y:auto}
.sbh{padding:10px 12px 3px;font-size:9px;font-weight:700;color:#ccc;letter-spacing:.1em;text-transform:uppercase}
.sbi{display:flex;align-items:center;gap:7px;padding:8px 12px;cursor:pointer;font-size:12px;color:var(--ink2);border-left:2.5px solid transparent}
.sbi:hover{background:#f5f4f0}
.sbi.on{background:#f5f4f0;border-left-color:var(--ink);color:var(--ink);font-weight:600}
.sbd{width:7px;height:7px;border-radius:2px;flex-shrink:0}
.sbdv{height:.5px;background:var(--bd);margin:4px 12px}
.sbtot{margin:8px 10px;background:var(--ink);border-radius:5px;padding:9px 11px}
.sbtl{font-size:9px;color:rgba(255,255,255,.4);margin-bottom:2px}
.sbtv{font-size:16px;font-weight:700;color:#fff;font-family:monospace}
.sbts{font-size:9px;color:rgba(255,255,255,.3);margin-top:1px}
.main{flex:1;overflow-y:auto;padding:16px 18px 60px}
.sec{display:none}.sec.on{display:block}
.shd{display:flex;align-items:flex-end;justify-content:space-between;gap:8px;flex-wrap:wrap;margin-bottom:14px;padding-bottom:10px;border-bottom:1.5px solid var(--bd)}
.stitle{font-size:17px;font-weight:700}
.ssub{font-size:11px;color:var(--ink3);margin-top:1px}
.card{background:var(--sf);border:.5px solid var(--bd);border-radius:var(--r);overflow:hidden;margin-bottom:10px}
.cardh{padding:9px 12px;display:flex;align-items:center;gap:7px;border-bottom:.5px solid var(--bd);background:#f9f8f5}
.cardt{font-size:12px;font-weight:700;flex:1}
.btn{display:inline-flex;align-items:center;gap:4px;padding:6px 13px;border:none;border-radius:4px;font-size:12px;font-family:inherit;font-weight:700;cursor:pointer;transition:all .12s;white-space:nowrap}
.btn-g{background:var(--gn);color:#fff}.btn-g:hover{background:#237a4e}
.btn-o{background:var(--sf);border:.5px solid var(--bd2);color:var(--ink)}.btn-o:hover{background:#f5f4f0}
.btn-sm{padding:4px 10px;font-size:11px}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:5px 8px;background:#f9f8f5;border-bottom:.5px solid var(--bd);font-size:10px;font-weight:700;color:var(--ink3);white-space:nowrap}
td{padding:6px 8px;border-bottom:.5px solid var(--bd);vertical-align:middle}
tr:last-child td{border:none}
tr:hover td{background:#fafaf8}
.ar{text-align:right;font-family:monospace;font-weight:700}
input,select{font-family:'Noto Sans JP',sans-serif;font-size:11px;padding:3px 6px;border:.5px solid var(--bd2);border-radius:3px;background:var(--sf);color:var(--ink);outline:none}
input:focus,select:focus{border-color:#999}
.chip{font-size:9px;font-weight:700;padding:2px 6px;border-radius:3px}
.cg{background:var(--gnbg);color:var(--gn)}.cb{background:var(--blbg);color:var(--bl)}
.ca{background:var(--ambg);color:var(--am)}.cgr{background:#f0f0f0;color:#888}
.jr{background:var(--sf);border:.5px solid var(--bd);border-radius:var(--r);overflow:hidden;margin-bottom:5px}
.jr.dis{opacity:.4}
.dr{background:var(--gnbg);color:var(--gn);padding:1px 4px;border-radius:2px;font-family:monospace;font-size:9px;font-weight:600}
.cr2{background:var(--rdbg);color:var(--rd);padding:1px 4px;border-radius:2px;font-family:monospace;font-size:9px;font-weight:600}
.tog{position:relative;width:32px;height:18px;flex-shrink:0}
.tog input{opacity:0;width:0;height:0;position:absolute}
.togsl{position:absolute;inset:0;background:#ccc;border-radius:9px;cursor:pointer;transition:.2s}
.togsl::before{content:'';position:absolute;width:14px;height:14px;left:2px;top:2px;background:#fff;border-radius:50%;transition:.2s}
.tog input:checked+.togsl{background:var(--gn)}
.tog input:checked+.togsl::before{transform:translateX(14px)}
.drop{border:2px dashed var(--bd2);border-radius:var(--r);padding:20px;text-align:center;cursor:pointer;background:var(--sf);margin-bottom:10px;transition:all .2s}
.drop:hover,.drop.dg{border-color:var(--ink);background:#f9f8f5}
.pills{display:flex;gap:5px;flex-wrap:wrap;margin-bottom:8px}
.pill{display:flex;align-items:center;gap:4px;background:var(--sf);border:.5px solid var(--bd);border-radius:4px;padding:3px 7px;font-size:11px}
.at{font-size:9px;font-weight:700;padding:1px 4px;border-radius:2px;white-space:nowrap}
.at-s{background:#dbeafe;color:#1e40af}.at-p{background:#f3e8ff;color:#6b21a8}.at-b{background:var(--blbg);color:var(--bl)}
.ld{display:none;background:var(--gnbg);border:.5px solid var(--gn);border-radius:var(--r);padding:9px 12px;align-items:center;gap:9px;margin-bottom:10px}
.spin{width:15px;height:15px;border:2px solid var(--gnbg);border-top-color:var(--gn);border-radius:50%;animation:sp .6s linear infinite;flex-shrink:0}
@keyframes sp{to{transform:rotate(360deg)}}
.notif{position:fixed;bottom:14px;right:14px;background:#1a1a1a;color:#fff;padding:9px 14px;border-radius:var(--r);font-size:12px;box-shadow:0 4px 20px rgba(0,0,0,.2);z-index:999;transform:translateY(60px);opacity:0;transition:all .3s cubic-bezier(.34,1.56,.64,1)}
.notif.on{transform:translateY(0);opacity:1}
.notif.green{background:var(--gn)}
.empty{text-align:center;padding:40px;color:#bbb}
.concept{background:linear-gradient(135deg,#1a1a2e,#16213e);border-radius:var(--r);padding:18px 20px;margin-bottom:16px;color:#fff}
.cstep{background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.18);border-radius:5px;padding:5px 10px;font-size:11px;color:rgba(255,255,255,.85)}
.swcards{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:14px}
.swcard{text-align:center;padding:14px 10px;border-radius:8px;border:1px solid var(--bd)}
.swcard.act{border-color:var(--cy);background:var(--cybg)}
.fld{display:flex;flex-direction:column;gap:2px}
.flbl{font-size:9px;font-weight:700;color:var(--ink3);letter-spacing:.04em;text-transform:uppercase}
.detg{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:7px;margin-bottom:8px}
/* AUTH LAYER */
.auth-overlay{position:fixed;inset:0;z-index:9999;background:var(--bg);display:flex;align-items:center;justify-content:center}
.auth-box{background:var(--sf);border:.5px solid var(--bd);border-radius:12px;padding:36px 40px;width:420px;max-width:90vw;box-shadow:0 8px 40px rgba(0,0,0,.08)}
.auth-title{font-size:18px;font-weight:700;text-align:center;margin-bottom:4px}
.auth-sub{font-size:12px;color:var(--ink3);text-align:center;margin-bottom:20px}
.serial-inputs{display:flex;gap:8px;justify-content:center;margin-bottom:16px}
.serial-inputs input{width:72px;text-align:center;font-family:'DM Mono',monospace;font-size:16px;font-weight:700;padding:10px 6px;border:1.5px solid var(--bd2);border-radius:6px;background:var(--sf);color:var(--ink);text-transform:uppercase;letter-spacing:2px}
.serial-inputs input:focus{border-color:var(--cy);box-shadow:0 0 0 3px rgba(0,120,200,.1)}
.serial-sep{display:flex;align-items:center;color:var(--bd2);font-size:18px;font-weight:700}
.auth-btn{width:100%;padding:12px;background:var(--cy);color:#fff;border:none;border-radius:6px;font-size:14px;font-weight:700;cursor:pointer;font-family:inherit;transition:all .15s}
.auth-btn:hover{background:#005fa0}
.auth-btn:disabled{opacity:.5;cursor:not-allowed}
.auth-err{background:var(--rdbg);color:var(--rd);font-size:11px;font-weight:600;padding:8px 12px;border-radius:5px;text-align:center;margin-bottom:12px;display:none}
.auth-spin{display:none;text-align:center;margin-bottom:12px}
.auth-spin .spin{display:inline-block}
.remaining-badge{background:var(--gnbg);color:var(--gn);font-size:10px;font-weight:700;padding:3px 8px;border-radius:3px;margin-left:8px}
.remaining-badge.warn{background:var(--ambg);color:var(--am)}
.remaining-badge.danger{background:var(--rdbg);color:var(--rd)}
</style>
</head>
<body>

<!-- AUTH LAYER -->
<div class="auth-overlay" id="auth-layer">
  <div class="auth-box">
    <div class="auth-title">AI Accounting Import Tool</div>
    <div class="auth-sub">Please enter your serial number to access</div>
    <div class="auth-err" id="auth-err"></div>
    <div class="auth-spin" id="auth-spin"><div class="spin"></div><span style="font-size:12px;color:var(--ink3);margin-left:8px">Verifying...</span></div>
    <div style="margin-bottom:8px">
      <input type="text" id="serial-full" placeholder="VOI-XXXX-XXXX-XXXX or Admin Key" autocomplete="off"
        style="width:100%;text-align:center;font-family:'DM Mono',monospace;font-size:16px;font-weight:700;padding:12px;border:1.5px solid var(--bd2);border-radius:6px;letter-spacing:1px">
    </div>
    <button class="auth-btn" id="auth-btn" onclick="doVerify()">Verify</button>
    <div style="text-align:center;margin-top:12px;font-size:10px;color:var(--ink3)">Serial numbers are valid for 14 days from first use</div>
  </div>
</div>

<!-- APP LAYER -->
<div id="app-layer" style="display:none">
<div class="tb">
  <span class="tb-logo">AI 仕訳インポートツール</span>
  <span class="tb-badge">β</span>
  <span class="remaining-badge" id="remaining-badge" style="display:none"></span>
  <div class="tb-sp"></div>
  <div style="font-size:10px;color:rgba(255,255,255,.4);margin-right:4px">出力ソフト:</div>
  <div class="sw-wrap">
    <button class="swb on"  id="swb-tkc"   onclick="switchSW('tkc')">TKC</button>
    <button class="swb"     id="swb-yayoi" onclick="switchSW('yayoi')">弥生</button>
    <button class="swb"     id="swb-freee" onclick="switchSW('freee')">freee</button>
    <button class="swb"     id="swb-mf"    onclick="switchSW('mf')">MF</button>
  </div>
  <span class="tb-stat" id="tb-stat">0件 / ¥0</span>
  <button class="tb-dl" onclick="downloadAll()">⬇ CSV出力</button>
</div>

<div class="app">
<div class="sb">
  <div class="sbh">メニュー</div>
  <div class="sbi on" onclick="goSec('top',this)"><span class="sbd" style="background:#1a1a1a"></span>はじめに</div>
  <div class="sbi" onclick="goSec('fixed',this)"><span class="sbd" style="background:var(--gn)"></span>月末定型仕訳<span id="sb-f" style="font-size:9px;color:#bbb;margin-left:auto;font-family:monospace"></span></div>
  <div class="sbi" onclick="goSec('bank',this)"><span class="sbd" style="background:var(--bl)"></span>銀行明細→仕訳<span id="sb-b" style="font-size:9px;color:#bbb;margin-left:auto;font-family:monospace"></span></div>
  <div class="sbi" onclick="goSec('cc',this)"><span class="sbd" style="background:#b45309"></span>カード明細AI読取<span id="sb-c" style="font-size:9px;color:#bbb;margin-left:auto;font-family:monospace"></span></div>
  <div class="sbdv"></div>
  <div class="sbh">出力</div>
  <div class="sbi" onclick="goSec('out',this)"><span class="sbd" style="background:var(--am)"></span>CSV出力確認</div>
  <div class="sbdv"></div>
  <div class="sbh">設定</div>
  <div class="sbi" onclick="goSec('api',this)"><span class="sbd" style="background:var(--cy)"></span>🔑 APIキー設定</div>
  <div class="sbdv"></div>
  <div class="sbtot">
    <div class="sbtl">出力予定 合計</div>
    <div class="sbtv" id="sb-total">¥0</div>
    <div class="sbts" id="sb-cnt">0件</div>
  </div>
</div>

<div class="main">

<!-- TOP -->
<div class="sec on" id="sec-top">
  <div class="concept">
    <div style="font-size:14px;font-weight:700;margin-bottom:6px">１次情報をまとめて、会計ソフトにアップロードする</div>
    <div style="font-size:12px;color:rgba(255,255,255,.65);line-height:1.8">銀行・カードの生データをAIが仕訳に変換。上のボタンでソフトを選び、CSVを出力してインポートするだけ。</div>
    <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:10px">
      <span class="cstep">📄 銀行明細</span><span style="color:rgba(255,255,255,.3)">→</span>
      <span class="cstep">💳 カード明細</span><span style="color:rgba(255,255,255,.3)">→</span>
      <span class="cstep">📅 定型仕訳</span><span style="color:rgba(255,255,255,.3)">→</span>
      <span class="cstep" style="background:rgba(0,120,200,.3);border-color:rgba(0,120,200,.5)">⬇ CSV → インポート完了</span>
    </div>
  </div>
  <div class="card">
    <div class="cardh"><span class="cardt">対応会計ソフト（上のボタンで切替）</span></div>
    <div style="padding:14px">
      <div class="swcards">
        <div class="swcard act" id="swc-tkc"><div style="font-size:15px;font-weight:700;color:var(--cy);margin-bottom:3px">TKC</div><div style="font-size:10px;color:#888;margin-bottom:6px">29カラム形式</div><span class="chip cg">✓ 対応済み</span></div>
        <div class="swcard" id="swc-yayoi"><div style="font-size:15px;font-weight:700;color:#e85a10;margin-bottom:3px">弥生</div><div style="font-size:10px;color:#888;margin-bottom:6px">弥生インポート形式</div><span class="chip" style="background:#eee;color:#888;font-size:9px">5月公開予定</span></div>
        <div class="swcard" id="swc-freee"><div style="font-size:15px;font-weight:700;color:#00b894;margin-bottom:3px">freee</div><div style="font-size:10px;color:#888;margin-bottom:6px">取引インポート18列</div><span class="chip cg">✓ 対応済み</span></div>
        <div class="swcard" id="swc-mf"><div style="font-size:15px;font-weight:700;color:#0066cc;margin-bottom:3px">MF</div><div style="font-size:10px;color:#888;margin-bottom:6px">仕訳インポート形式</div><span class="chip" style="background:#eee;color:#888;font-size:9px">5月公開予定</span></div>
      </div>
    </div>
  </div>
  <div class="card">
    <div class="cardh"><span class="cardt">スタートガイド</span></div>
    <div style="padding:14px;display:flex;flex-direction:column;gap:10px">
      <div style="display:flex;gap:10px;align-items:flex-start"><div style="width:22px;height:22px;border-radius:50%;background:var(--cy);color:#fff;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;flex-shrink:0">1</div><div><div style="font-size:12px;font-weight:700">上のボタンで会計ソフトを選択</div><div style="font-size:11px;color:var(--ink3)">TKC・弥生・freee・MF から選ぶと出力CSVが切り替わります</div></div></div>
      <div style="display:flex;gap:10px;align-items:flex-start"><div style="width:22px;height:22px;border-radius:50%;background:var(--cy);color:#fff;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;flex-shrink:0">2</div><div><div style="font-size:12px;font-weight:700">左メニューからデータを入力</div><div style="font-size:11px;color:var(--ink3)">月末定型仕訳・銀行明細・カード明細を入力</div></div></div>
      <div style="display:flex;gap:10px;align-items:flex-start"><div style="width:22px;height:22px;border-radius:50%;background:var(--gn);color:#fff;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;flex-shrink:0">3</div><div><div style="font-size:12px;font-weight:700">「⬇ CSV出力」→ 会計ソフトにインポート</div><div style="font-size:11px;color:var(--ink3)">データが会計ソフトに正確に入力されます</div></div></div>
    </div>
  </div>
</div>

<!-- FIXED -->
<div class="sec" id="sec-fixed">
  <div class="shd">
    <div><div class="stitle">月末定型仕訳</div><div class="ssub">毎月繰り返す固定費を自動生成</div></div>
    <div style="display:flex;gap:6px">
      <button class="btn btn-o btn-sm" onclick="addFixed()">＋ 追加</button>
      <button class="btn btn-o btn-sm" onclick="chkAllFixed(true)">全選択</button>
      <button class="btn btn-o btn-sm" onclick="chkAllFixed(false)">全解除</button>
      <button class="btn btn-g btn-sm" onclick="dlSection('fixed')">⬇ このみ出力</button>
    </div>
  </div>
  <div id="fixed-body"></div>
</div>

<!-- BANK -->
<div class="sec" id="sec-bank">
  <div class="shd">
    <div><div class="stitle">銀行明細 → 仕訳</div><div class="ssub">銀行CSVをドロップ → 仕訳を自動判定</div></div>
    <div style="display:flex;gap:6px">
      <button class="btn btn-o btn-sm" onclick="chkAllBank(true)">全選択</button>
      <button class="btn btn-o btn-sm" onclick="chkAllBank(false)">全解除</button>
      <button class="btn btn-g btn-sm" onclick="dlSection('bank')">⬇ このみ出力</button>
    </div>
  </div>
  <div class="drop" id="drop" ondragover="event.preventDefault();this.classList.add('dg')" ondragleave="this.classList.remove('dg')" ondrop="onDrop(event)" onclick="document.getElementById('finput').click()">
    <input type="file" id="finput" multiple accept=".csv" onchange="onFiles(this.files)" style="display:none">
    <div style="font-size:24px;margin-bottom:4px">🏦</div>
    <div style="font-size:13px;font-weight:700;margin-bottom:2px">銀行CSVをドラッグ＆ドロップ</div>
    <div style="font-size:11px;color:#aaa">UFJ / ゆうちょ対応 / 複数同時OK</div>
  </div>
  <div class="pills" id="pills"></div>
  <div id="bank-wrap" style="display:none">
    <div class="card">
      <div class="cardh"><span class="cardt">仕訳一覧</span><span style="font-size:10px;color:#aaa;margin-left:5px">黄色行 = 要確認</span></div>
      <table><thead><tr><th>日付</th><th>通帳</th><th>科目CD</th><th>取引先</th><th>借方</th><th>借方補助</th><th></th><th>貸方</th><th>貸方補助</th><th class="ar">金額</th><th>摘要</th><th>出力</th></tr></thead>
      <tbody id="bank-tbody"></tbody></table>
    </div>
  </div>
  <div class="empty" id="bank-empty"><div style="font-size:28px;margin-bottom:6px">📂</div><div style="font-weight:600">銀行CSVをドロップしてください</div></div>
</div>

<!-- CC -->
<div class="sec" id="sec-cc">
  <div class="shd">
    <div><div class="stitle">カード明細 AI読取</div><div class="ssub">明細画像・PDFをドロップ → Claude AIが自動読取</div></div>
    <button class="btn btn-g btn-sm" onclick="dlSection('cc')">⬇ このみ出力</button>
  </div>
  <div style="background:var(--ambg);border:.5px solid #f6c97e;border-radius:var(--r);padding:9px 12px;margin-bottom:10px;display:flex;align-items:center;gap:8px;flex-wrap:wrap">
    <span style="font-size:11px;font-weight:700">🔑 Claude APIキー</span>
    <input type="password" id="cc-key" placeholder="sk-ant-api03-..." oninput="saveKey(this.value)" style="flex:1;min-width:200px;font-family:monospace;font-size:11px;padding:5px 8px;border:.5px solid var(--bd2);border-radius:4px">
    <span id="cc-kst" style="font-size:11px;color:var(--gn)"></span>
  </div>
  <div class="drop" id="cc-drop" ondragover="event.preventDefault()" ondrop="ccDrop(event)" style="position:relative;overflow:hidden">
    <input type="file" id="cc-fi" accept="image/*,application/pdf" multiple onchange="ccFiles(this.files)" style="position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%;z-index:1">
    <div style="font-size:22px;margin-bottom:4px">📄</div>
    <div style="font-size:13px;font-weight:700;margin-bottom:2px">明細画像・PDFをドロップ</div>
    <div style="font-size:11px;color:#aaa">JPG / PNG / PDF 対応</div>
  </div>
  <div id="cc-prev" style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px"></div>
  <div class="ld" id="cc-ld"><div class="spin"></div><span>Claude AIで読み取り中...</span></div>
  <div id="cc-cont" style="display:none">
    <div class="card" style="margin-bottom:10px">
      <div class="cardh"><span class="cardt">支払情報</span></div>
      <div style="padding:12px;display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:10px">
        <div class="fld"><span class="flbl">カード会社</span><input type="text" id="cc-co" value="カード会社"></div>
        <div class="fld"><span class="flbl">支払日</span><input type="text" id="cc-pay" value=""></div>
        <div class="fld"><span class="flbl">引落口座</span><select id="cc-acct" onchange="ccAcctChg()"><option value="1113">1113 普通預金</option><option value="1112">1112 郵便貯金</option></select></div>
        <div class="fld"><span class="flbl">補助科目</span><select id="cc-acct-sub" style="font-size:11px"><option value="">--</option><option value="10">10:総務</option><option value="20">20:よしの</option><option value="21">21:あつた</option><option value="22">22:物流</option><option value="23">23:さくら</option><option value="24">24:東海義援</option><option value="25">25:積立</option></select></div>
        <div class="fld"><span class="flbl">事業CD</span><input type="number" id="cc-ji" value="0"></div>
      </div>
    </div>
    <div id="cc-cards"></div>
    <div class="card">
      <div class="cardh"><span class="cardt">仕訳プレビュー（2ステップ）</span><span class="chip" id="cc-bal">—</span></div>
      <div style="padding:12px" id="cc-jnl"></div>
    </div>
  </div>
</div>

<!-- OUTPUT -->
<div class="sec" id="sec-out">
  <div class="shd">
    <div><div class="stitle">CSV出力確認</div><div class="ssub" id="out-lbl">出力形式: TKC 29カラム</div></div>
    <button class="btn btn-g" onclick="downloadAll()">⬇ 全仕訳CSV出力</button>
  </div>
  <div id="out-sums" style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:12px"></div>
  <div class="card">
    <div class="cardh"><span class="cardt">全仕訳一覧</span></div>
    <table><thead><tr><th>区分</th><th>借方</th><th>借方補助</th><th>貸方</th><th>貸方補助</th><th>摘要</th><th class="ar">金額</th><th>課税</th></tr></thead>
    <tbody id="out-tbody"></tbody></table>
  </div>
</div>

<!-- API -->
<div class="sec" id="sec-api">
  <div class="shd"><div><div class="stitle">🔑 APIキー設定</div><div class="ssub">カード明細のAI読取に使用</div></div></div>
  <div style="max-width:500px">
    <div class="card"><div style="padding:18px">
      <div style="font-size:12px;color:var(--ink3);margin-bottom:10px;line-height:1.7"><a href="https://console.anthropic.com" target="_blank" style="color:var(--bl)">console.anthropic.com</a> → API Keys → Create Key</div>
      <input type="password" id="g-key" placeholder="sk-ant-api03-..." style="width:100%;font-family:monospace;font-size:12px;padding:9px 10px;border:1.5px solid var(--bd2);border-radius:6px;background:#fff;margin-bottom:8px">
      <div style="display:flex;gap:7px">
        <button onclick="gSave()" style="flex:1;padding:9px;background:var(--ink);color:#fff;border:none;border-radius:5px;font-size:13px;font-weight:700;cursor:pointer;font-family:inherit">💾 保存</button>
        <button onclick="gClear()" style="padding:9px 14px;background:#fff;color:#888;border:.5px solid var(--bd2);border-radius:5px;font-size:12px;cursor:pointer;font-family:inherit">削除</button>
      </div>
      <div id="g-st" style="display:none;padding:8px 12px;border-radius:5px;font-size:12px;font-weight:600;margin-top:10px"></div>
    </div></div>
    <div style="background:var(--blbg);border:.5px solid rgba(26,74,154,.15);border-radius:var(--r);padding:12px 14px;font-size:12px;line-height:1.8;margin-top:10px">
      🔒 APIキーはブラウザのlocalStorageにのみ保存。外部送信なし。<br>
      💰 カード明細1回の読取 約¥5 / 月1回で年間約¥60
    </div>
  </div>
</div>

</div><!-- /main -->
</div><!-- /app -->
<div class="notif" id="notif"></div>
</div><!-- /app-layer -->

<script>
// =============================================
// AUTH SYSTEM
// =============================================
(function(){
  var el=document.getElementById('serial-full');
  el.addEventListener('input',function(){
    // Allow alphanumeric + hyphen (keep case for admin key)
    this.value=this.value.replace(/[^A-Za-z0-9-]/g,'');
  });
  document.addEventListener('keydown',function(e){
    if(e.key==='Enter'&&document.getElementById('auth-layer').style.display!=='none'){
      doVerify();
    }
  });
})();

function getSerial(){
  return document.getElementById('serial-full').value.trim();
}

function showAuthError(msg){
  var el=document.getElementById('auth-err');
  el.textContent=msg;el.style.display='block';
}
function hideAuthError(){document.getElementById('auth-err').style.display='none';}

function showApp(data){
  document.getElementById('auth-layer').style.display='none';
  document.getElementById('app-layer').style.display='block';
  var badge=document.getElementById('remaining-badge');
  if(badge&&data.remainingDays!=null){
    if(data.freepass){
      badge.textContent='Admin Freepass';
      badge.className='remaining-badge';
      badge.style.background='#1a1a1a';badge.style.color='#fff';
    } else {
      badge.textContent=data.remainingDays+'d remaining';
      badge.className='remaining-badge'+(data.remainingDays<=3?' danger':data.remainingDays<=7?' warn':'');
    }
    badge.style.display='inline-block';
  }
}

function showAuthForm(){
  document.getElementById('auth-layer').style.display='flex';
  document.getElementById('app-layer').style.display='none';
  document.getElementById('serial-full').focus();
}

async function doVerify(){
  hideAuthError();
  var serial=getSerial();
  var upper=serial.toUpperCase();
  var isSerialFormat=/^([A-Z]{2,4}-)?[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}(-[A-Z0-9]{4})?$/.test(upper);
  if(!isSerialFormat && serial.length < 8){
    showAuthError('Please enter a serial number or admin key');
    return;
  }
  var btn=document.getElementById('auth-btn');
  var spin=document.getElementById('auth-spin');
  btn.disabled=true;spin.style.display='block';
  try{
    var res=await fetch('/api/serial/verify',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({serial:serial,app:'keiri'})
    });
    var data=await res.json();
    if(data.valid){
      localStorage.setItem('serial_auth',JSON.stringify({
        serial:serial,expiresAt:data.expiresAt,freepass:data.freepass||false,verifiedAt:new Date().toISOString(),remainingDays:data.remainingDays
      }));
      showApp(data);
    } else {
      showAuthError(data.error||'Invalid serial number');
      if(data.attemptsRemaining!=null&&data.attemptsRemaining<=2){
        showAuthError((data.error||'Invalid serial number')+' ('+data.attemptsRemaining+' attempts remaining)');
      }
    }
  }catch(e){
    showAuthError('Connection error. Please try again.');
  }finally{
    btn.disabled=false;spin.style.display='none';
  }
}

async function revalidate(serial){
  try{
    var res=await fetch('/api/serial/verify',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({serial:serial,app:'keiri'})
    });
    var data=await res.json();
    if(!data.valid){
      localStorage.removeItem('serial_auth');
      showAuthForm();
      return;
    }
    localStorage.setItem('serial_auth',JSON.stringify({
      serial:serial,expiresAt:data.expiresAt,freepass:data.freepass||false,verifiedAt:new Date().toISOString(),remainingDays:data.remainingDays
    }));
    var badge=document.getElementById('remaining-badge');
    if(badge){
      if(data.freepass){
        badge.textContent='Admin Freepass';
        badge.className='remaining-badge';
        badge.style.background='#1a1a1a';badge.style.color='#fff';
      } else {
        badge.textContent=data.remainingDays+'d remaining';
        badge.className='remaining-badge'+(data.remainingDays<=3?' danger':data.remainingDays<=7?' warn':'');
      }
    }
  }catch(e){}
}

(function checkAuth(){
  var raw=localStorage.getItem('serial_auth');
  if(raw){
    try{
      var auth=JSON.parse(raw);
      if(auth&&auth.freepass){
        showApp(auth);
        revalidate(auth.serial);
        return;
      }
      if(auth&&auth.expiresAt&&new Date(auth.expiresAt)>new Date()){
        showApp(auth);
        revalidate(auth.serial);
        return;
      }
    }catch(e){}
    localStorage.removeItem('serial_auth');
  }
  showAuthForm();
})();
</script>

<script>
// =============================================
// 状態変数
// =============================================
var SW = 'tkc';
var fixedRows = [], bankRows = [], ccCards = [], ccImgs = [];
var ccPayDate = '', ccTotal = 0;
var loaded = {}, rowId = 0, ccRid = 0, nid = 0;

// =============================================
// マスタ
// =============================================
var KM = [
  ['1111','現金'],['1112','郵便貯金'],['1113','普通預金'],['1122','売掛金'],['1125','未収金'],
  ['1222','建物'],['1223','車両運搬具'],['1224','什器備品'],
  ['2112','買掛金'],['2114','未払金'],['2115','未払費用'],['2117','預り金'],['2211','長期借入金'],
  ['4211','事業収入'],['4331','受取補助金'],['4361','受取寄附金'],['4379','雑収入'],
  ['5412','給料手当'],['5416','通勤費'],['5419','法定福利費'],
  ['5421','通信費'],['5424','接待交際費'],['5425','消耗品費'],
  ['5426','修繕費'],['5427','水道光熱費'],['5429','支払手数料'],
  ['5431','研修費'],['5432','地代家賃'],['5434','車両費'],
  ['5437','業務原価費用'],['5438','会議費'],['5441','広告宣伝費'],
  ['5442','支払報酬'],['5443','減価償却費'],['5459','雑費'],['5461','旅費交通費'],['5471','リース料'],
  ['6211','役員報酬'],['6212','給料手当（管理）'],['6218','法定福利費（管理）'],
  ['6222','通信費（管理）'],['6225','消耗品費（管理）'],
  ['6227','リース料（管理）'],['6229','支払手数料（管理）'],
  ['6233','広告宣伝費（管理）'],['6234','旅費（管理）'],
  ['6236','支払報酬（管理）'],['6244','会議費（管理）'],
  ['9991','資金諸口'],['9992','資金外諸口'],
];
var KM_MAP = Object.fromEntries(KM);
function kmN(c){ return KM_MAP[c] || c; }
function rCd(c){ return {'1113a':'1113','1113s':'1113','2117d':'2117'}[c] || c; }

var HOJO_MAP = {
  '1113':{10:'総務',20:'よしの',21:'あつた',22:'さくら',23:'大垣共立',24:'碧海信用金庫',25:'物流',26:'百五八田支店',90:'東海労金',91:'名古屋',99:'その他'},
  '1112':{},
  '1111':{10:'総務',21:'あつた',22:'物流',23:'さくら',24:'よしの',30:'循環フェス'},
  '2117':{1:'所得税(給与)',2:'所得税(報酬)',3:'住民税',99:'その他'}
};
function hojoName(cd,sub){
  if(!sub) return '';
  var m=HOJO_MAP[cd];
  return m&&m[sub]?m[sub]:'';
}
function hojoOptF(cd,sel,rid,field){
  var m=HOJO_MAP[cd];
  if(!m||Object.keys(m).length===0) return '<select style="font-size:10px" disabled><option>-</option></select>';
  var h='<select style="font-size:10px" onchange="updF(\\''+rid+'\\',\\''+field+'\\',this.value)">';
  h+='<option value="">--</option>';
  Object.keys(m).forEach(function(k){ h+='<option value="'+k+'"'+(String(sel)===String(k)?' selected':'')+'>'+k+':'+m[k]+'</option>'; });
  return h+'</select>';
}

function tkcTax(t){ return t===0.1 ? 5 : 0; }
function tkcRate(t){ return t===0.1 ? '10.0%' : ''; }

var JI = [
  [0,'調整事業'],[10,'総務'],[20,'ステーション'],
  [80,'リユース共通・物流センター'],
  [205,'あつた'],[210,'ＮＣＦ循環フェス'],[213,'さくら'],
  [214,'よしの'],[215,'なかた'],[216,'とよあけ'],
  [217,'あいおいやま'],[218,'さくらやま'],[219,'こうじょう'],
  [313,'ＪＩＣＡ研修'],[601,'中電森きっずプロジェクト']
];
var JI_MAP = Object.fromEntries(JI);

var CC_KM = [
  ['5434','ガソリン・燃料費'],['5461','旅費交通費'],['5421','通信費'],
  ['5425','消耗品費'],['5438','会議費'],['5441','広告宣伝費'],
  ['5424','接待交際費'],['5431','研修費'],['5437','業務原価費用'],
  ['5423','保険料'],['5459','雑費'],['6222','通信費（管理）'],
  ['6225','消耗品費（管理）'],['6234','旅費（管理）'],
  ['6233','広告宣伝費（管理）'],['6244','会議費（管理）'],['9992','資金外諸口'],
];
var CC_KM_MAP = Object.fromEntries(CC_KM);

var CC_RULES = [
  {kw:['イデミツ','出光','アポロ','IDEMITSU'],cd:'5434',memo:'ガソリン代',tax:0.1,group:'gas'},
  {kw:['AMAZON','アマゾン'],cd:'5425',memo:'消耗品費（Amazon）',tax:0.1},
  {kw:['ADOBE'],cd:'5425',memo:'ソフトウェア（Adobe）',tax:0.1},
  {kw:['OPENAI','CHATGPT'],cd:'5421',memo:'AI利用料',tax:0.1},
  {kw:['SOFTBANK','ソフトバンク','DOCOMO','NTT'],cd:'5421',memo:'通信費',tax:0.1},
  {kw:['FACEBOOK','FACEBK'],cd:'5441',memo:'広告費',tax:0.1},
  {kw:['駐車場','パーキング'],cd:'5461',memo:'交通費（駐車場）',tax:0.1},
];

var BANK_RULES = [
  {kw:['社会保険'],cd:'6218',ji:10,memo:'社会保険料',io:'ex',st:'auto',tax:0},
  {kw:['税務署','ゼイムショ'],cd:'2117',ji:0,memo:'源泉所得税',io:'up',st:'auto',tax:0},
  {kw:['地方税'],cd:'2117',ji:0,memo:'住民税',io:'up',st:'auto',tax:0},
  {kw:['カード','CARD'],cd:'9992',ji:10,memo:'カード引落',io:'ex',st:'check',tax:0},
  {kw:['リース'],cd:'6227',ji:10,memo:'リース料',io:'ex',st:'auto',tax:0.1},
  {kw:['振込料','手数料'],cd:'5429',ji:10,memo:'振込手数料',io:'ex',st:'auto',tax:0.1},
];

var DEFAULT_MASTER = [
  {cat:'給与',id:'J001',name:'役員報酬',ji:10,drCd:'6211',drN:'役員報酬',crCd:'2115',crN:'未払費用',amt:200000,memo:'役員報酬',tax:0,en:true},
  {cat:'給与',id:'J002',name:'給与手当（管理）',ji:10,drCd:'6212',drN:'給料手当（管理）',crCd:'2115',crN:'未払費用',amt:0,memo:'今月分給与',tax:0,en:true},
  {cat:'給与',id:'J003',name:'給与手当（事業）',ji:20,drCd:'5412',drN:'給料手当',crCd:'2115',crN:'未払費用',amt:0,memo:'今月分給与',tax:0,en:true},
  {cat:'減価償却',id:'J010',name:'減価償却費（建物）',ji:10,drCd:'5443',drN:'減価償却費',crCd:'1222',crN:'建物',amt:0,memo:'当月減価償却',tax:0,en:false},
  {cat:'減価償却',id:'J011',name:'減価償却費（車両）',ji:10,drCd:'5443',drN:'減価償却費',crCd:'1223',crN:'車両運搬具',amt:0,memo:'当月減価償却',tax:0,en:false},
  {cat:'地代家賃',id:'J020',name:'地代家賃',ji:10,drCd:'5432',drN:'地代家賃',crCd:'1112',crN:'郵便貯金',amt:0,memo:'家賃',tax:0.1,en:false},
  {cat:'法定福利',id:'J030',name:'法定福利費',ji:10,drCd:'6218',drN:'法定福利費（管理）',crCd:'2115',crN:'未払費用',amt:0,memo:'社会保険料',tax:0,en:false},
  {cat:'固定費',id:'J070',name:'通信費（固定）',ji:10,drCd:'5421',drN:'通信費',crCd:'1113',crN:'普通預金',amt:0,memo:'電話・インターネット',tax:0.1,en:false},
  {cat:'固定費',id:'J071',name:'リース料',ji:10,drCd:'6227',drN:'リース料（管理）',crCd:'1113',crN:'普通預金',amt:0,memo:'リース料',tax:0.1,en:false},
];
var CAT_C = {給与:'var(--gn)',減価償却:'var(--bl)',地代家賃:'var(--am)',法定福利:'#5b21b6',固定費:'var(--ink3)'};
var CAT_B = {給与:'var(--gnbg)',減価償却:'var(--blbg)',地代家賃:'var(--ambg)',法定福利:'#ede9fe',固定費:'#f0f0f0'};

// =============================================
// 初期化
// =============================================
(function init(){
  fixedRows = DEFAULT_MASTER.map(function(d){ return Object.assign({},d); });
  renderFixed();
  updateTop();
  var k = localStorage.getItem('tkc_api_key');
  if(k){
    var e1 = document.getElementById('cc-key'); if(e1) e1.value = k;
    var e2 = document.getElementById('g-key');  if(e2) e2.value = k;
    var ks = document.getElementById('cc-kst'); if(ks) ks.textContent = '✓ 保存済み';
    var gs = document.getElementById('g-st');
    if(gs){ gs.style.display='block'; gs.style.background='#d8f3dc'; gs.style.color='#1a6040'; gs.textContent='✅ 保存済みのAPIキーがあります'; }
  }
})();

// =============================================
// ナビゲーション
// =============================================
function goSec(id, btn){
  document.querySelectorAll('.sec').forEach(function(s){ s.classList.remove('on'); });
  document.querySelectorAll('.sbi').forEach(function(b){ b.classList.remove('on'); });
  document.getElementById('sec-' + id).classList.add('on');
  if(btn) btn.classList.add('on');
  if(id === 'out') renderOutput();
}

// =============================================
// ソフト切替
// =============================================
function switchSW(sw){
  if(sw==='yayoi'||sw==='mf'){notif('⏳ '+({yayoi:'弥生会計',mf:'マネーフォワード'}[sw])+' は近日公開予定です','orange');return;}
  SW = sw;
  ['tkc','yayoi','freee','mf'].forEach(function(s){
    var b = document.getElementById('swb-' + s);
    var c = document.getElementById('swc-' + s);
    if(b) b.className = 'swb' + (s===sw ? ' on' : '');
    if(c) c.className = 'swcard' + (s===sw ? ' act' : '');
  });
  var fmt = {tkc:'TKC 29カラム形式',yayoi:'弥生インポート形式',freee:'freee 取引インポート形式',mf:'MF 仕訳インポート形式'};
  var lbl = document.getElementById('out-lbl');
  if(lbl) lbl.textContent = '出力形式: ' + (fmt[sw] || sw);
  var nm  = {tkc:'TKC',yayoi:'弥生会計',freee:'freee',mf:'マネーフォワード'};
  notif('✓ ' + (nm[sw]||sw) + ' に切り替えました');
}

// =============================================
// ユーティリティ
// =============================================
function getYM(){ var n=new Date(); return {y:n.getFullYear(), m:n.getMonth()+1}; }
function lastDay(y,m){ return new Date(y,m,0).getDate(); }
function pD(d){ if(!d) return 0; var s=String(d).replace(/[\\/.\\-]/g,''); if(s.length===8){ return (parseInt(s.slice(0,4))-2018)*10000+parseInt(s.slice(4,6))*100+parseInt(s.slice(6,8)); } return 0; }
function r2AD(n){ if(!n) return ''; var y=Math.floor(n/10000)+2018,m=Math.floor((n%10000)/100),d=n%100; return y+'/'+(String(m).padStart(2,'0'))+'/'+String(d).padStart(2,'0'); }
function fmtD(d){ return String(d||'').replace(/[\\.\\-]/g,'/'); }
function toISO(n){ if(!n) return ''; if(typeof n==='number') return r2AD(n).replace(/\\//g,'-'); return String(n).replace(/\\//g,'-'); }
function cTax(a,t){ if(!t) return {ta:0,ex:a}; var e=Math.round(a/(1+t)); return {ta:a-e, ex:e}; }
function ce(v){ var s=String(v==null?'':v); return s.indexOf(',')>=0?'"'+s+'"':s; }
function cl(s,n){ s=String(s||''); return s.length>n?s.slice(0,n)+'…':s; }
function kmOpt(sel){
  var prompt=(sel==='CHECK'||!sel)?'<option value="CHECK" selected>-- 科目を選択 --</option>':'';
  return prompt+KM.map(function(r){ return \`<option value="\${r[0]}"\${r[0]===sel?' selected':''}>\${r[0]} \${r[1]}</option>\`; }).join('');
}
function jiOpt(sel){
  return JI.map(function(r){ return \`<option value="\${r[0]}"\${r[0]===sel?' selected':''}>\${r[0]}:\${r[1]}</option>\`; }).join('');
}
function ccKmOpt(sel){
  return CC_KM.map(function(r){ return \`<option value="\${r[0]}"\${r[0]===sel?' selected':''}>\${r[0]} \${r[1]}</option>\`; }).join('');
}

// =============================================
// 定型仕訳
// =============================================
function renderFixed(){
  var cats=[];
  fixedRows.forEach(function(r){ if(cats.indexOf(r.cat)<0) cats.push(r.cat); });
  var html='';
  cats.forEach(function(cat){
    var color = CAT_C[cat]||'var(--ink3)';
    var bg    = CAT_B[cat]||'#f0f0f0';
    var rows  = fixedRows.filter(function(r){ return r.cat===cat; });
    var total = rows.reduce(function(s,r){ return r.en?s+r.amt:s; },0);
    html += \`<div style="margin-bottom:18px">
      <div style="display:flex;align-items:center;gap:7px;margin-bottom:7px;padding-bottom:6px;border-bottom:1px solid var(--bd)">
        <span style="font-size:12px;font-weight:700">\${cat}</span>
        <span class="chip" style="background:\${bg};color:\${color}">\${rows.filter(function(r){return r.en;}).length}件</span>
        <span style="margin-left:auto;font-family:monospace;font-weight:700;font-size:12px;color:\${color}">¥\${total.toLocaleString()}</span>
      </div><div>\`;
    rows.forEach(function(r){
      html += \`
        <div class="jr\${r.en?'':' dis'}" id="jr-\${r.id}">
          <div style="display:grid;grid-template-columns:26px 1fr auto">
            <div style="padding:10px;color:#ccc;cursor:pointer;font-size:10px;text-align:center" id="tog-\${r.id}" onclick="togD('\${r.id}')">▶</div>
            <div style="padding:8px 10px 8px 0;display:flex;align-items:center;gap:7px;cursor:pointer;flex:1;min-width:0;overflow:hidden" onclick="togD('\${r.id}')">
              <div style="font-size:12px;font-weight:700;white-space:nowrap;max-width:160px;overflow:hidden;text-overflow:ellipsis">\${r.name}</div>
              <div style="display:flex;align-items:center;gap:3px;font-size:11px;flex:1;min-width:0">
                <span class="dr">\${r.drCd}</span>
                <span style="color:#ccc;font-size:10px;margin:0 2px">→</span>
                <span class="cr2">\${r.crCd}</span>
              </div>
              <div style="font-family:monospace;font-weight:700;font-size:12px;flex-shrink:0">¥\${r.amt.toLocaleString()}</div>
              <span class="chip \${r.tax>0?'cb':'cgr'}">\${r.tax>0?'課税10%':'非課税'}</span>
            </div>
            <div style="padding:7px 9px;border-left:.5px solid var(--bd);display:flex;align-items:center">
              <label class="tog"><input type="checkbox"\${r.en?' checked':''} onchange="chkFixed('\${r.id}',this.checked)"><span class="togsl"></span></label>
            </div>
          </div>
          <div class="jr-det" id="det-\${r.id}" style="display:none;border-top:.5px solid var(--bd);padding:10px 12px;background:#f9f8f5">
            <div class="detg">
              <div class="fld"><span class="flbl">名称</span><input type="text" value="\${r.name}" onchange="updF('\${r.id}','name',this.value)"></div>
              <div class="fld"><span class="flbl">金額（円）</span><input type="number" value="\${r.amt}" onchange="updF('\${r.id}','amt',+this.value)"></div>
              <div class="fld"><span class="flbl">摘要</span><input type="text" value="\${r.memo}" onchange="updF('\${r.id}','memo',this.value)"></div>
              <div class="fld"><span class="flbl">課税区分</span>
                <select onchange="updF('\${r.id}','tax',+this.value)">
                  <option value="0"\${r.tax===0?' selected':''}>非課税</option>
                  <option value="0.1"\${r.tax===0.1?' selected':''}>課税10%</option>
                </select>
              </div>
              <div class="fld"><span class="flbl">部門CD</span><select onchange="updF('\${r.id}','ji',+this.value)">\${jiOpt(r.ji)}</select></div>
              <div class="fld"><span class="flbl">借方科目</span><select onchange="updF('\${r.id}','drCd',this.value)">\${kmOpt(r.drCd)}</select></div>
              <div class="fld"><span class="flbl">借方補助</span>\${hojoOptF(r.drCd,r.drSub,r.id,'drSub')}</div>
              <div class="fld"><span class="flbl">貸方科目</span><select onchange="updF('\${r.id}','crCd',this.value)">\${kmOpt(r.crCd)}</select></div>
              <div class="fld"><span class="flbl">貸方補助</span>\${hojoOptF(r.crCd,r.crSub,r.id,'crSub')}</div>
            </div>
            <div style="display:flex;gap:5px;justify-content:flex-end;margin-top:8px">
              <button class="btn btn-o btn-sm" style="border-color:#e8a5a5;color:var(--rd)" onclick="delF('\${r.id}')">削除</button>
              <button class="btn btn-o btn-sm" onclick="togD('\${r.id}')">閉じる</button>
              <button class="btn btn-g btn-sm" onclick="togD('\${r.id}')">✓ 確定</button>
            </div>
          </div>
        </div>\`;
    });
    html += '</div></div>';
  });
  document.getElementById('fixed-body').innerHTML = html;
  var el = document.getElementById('sb-f');
  if(el) el.textContent = fixedRows.filter(function(r){return r.en;}).length || '';
  updateTop();
}
function togD(id){
  var d=document.getElementById('det-'+id);
  var t=document.getElementById('tog-'+id);
  if(!d) return;
  var open = d.style.display==='none';
  d.style.display = open ? 'block' : 'none';
  if(t) t.textContent = open ? '▼' : '▶';
}
function chkFixed(id,val){ updF(id,'en',val); }
function chkAllFixed(val){ fixedRows.forEach(function(r){ r.en=val; }); renderFixed(); }
function chkAllBank(val){ bankRows.forEach(function(r){ r.inc=val; }); renderBank(); updateTop(); }
function updF(id,field,val){
  var r=fixedRows.find(function(x){return x.id===id;});
  if(!r) return;
  r[field]=val;
  if(field==='drCd') r.drSub='';
  if(field==='crCd') r.crSub='';
  if(['en','amt','tax','ji','drCd','crCd','drSub','crSub'].indexOf(field)>=0) renderFixed();
  updateTop();
}
function delF(id){
  if(!confirm('削除しますか？')) return;
  fixedRows=fixedRows.filter(function(r){return r.id!==id;});
  renderFixed();
}
function addFixed(){
  var r={cat:'固定費',id:'N'+(++nid),name:'新しい仕訳',ji:10,drCd:'5437',drN:'業務原価費用',crCd:'2112',crN:'買掛金',drSub:'',crSub:'',amt:0,memo:'',tax:0.1,en:true};
  fixedRows.push(r);
  renderFixed();
  setTimeout(function(){ togD(r.id); },50);
}

// =============================================
// 銀行明細
// =============================================
var BACCT = {
  'UFJ':{cd:'1113',sub:'10',label:'UFJ普通預金',tag:'at-s',ji:10},
  'UFJ事業':{cd:'1113',sub:'20',label:'UFJ普通預金(事業)',tag:'at-b',ji:20},
  'ゆうちょ':{cd:'1112',sub:'',label:'ゆうちょ(郵便貯金)',tag:'at-p',ji:10}
};
function hojoOpt(cd,sel,rid,field){
  var m=HOJO_MAP[cd];
  if(!m||Object.keys(m).length===0) return '<span style="font-size:9px;color:#ccc">-</span>';
  var h='<select style="font-size:10px;max-width:100px" onchange="updB('+rid+',\\''+field+'\\',this.value)">';
  h+='<option value="">--</option>';
  Object.keys(m).forEach(function(k){ h+='<option value="'+k+'"'+(String(sel)===String(k)?' selected':'')+'>'+k+':'+m[k]+'</option>'; });
  return h+'</select>';
}
function onDrop(e){ e.preventDefault(); document.getElementById('drop').classList.remove('dg'); onFiles(e.dataTransfer.files); }
function onFiles(files){
  Array.from(files).forEach(function(f){
    var fr=new FileReader();
    fr.onload=function(ev){
      var bytes=new Uint8Array(ev.target.result);
      var enc=(bytes[0]===0xEF&&bytes[1]===0xBB)?'utf-8':'shift-jis';
      var text=new TextDecoder(enc).decode(bytes);
      var fn=f.name.toLowerCase();
      var acct=(fn.indexOf('yucho')>=0||fn.indexOf('ゆうちょ')>=0||fn.indexOf('郵便')>=0)?'ゆうちょ':(fn.indexOf('jigyou')>=0||fn.indexOf('事業')>=0)?'UFJ事業':'UFJ';
      loaded[f.name]={text:text,acct:acct};
      processBank();
    };
    fr.readAsArrayBuffer(f);
  });
}
function parseUFJ(t){
  var lines=t.split('\\n');
  // Try BizSTATION format: "1","header"... / "2","data"...
  var biz=lines.reduce(function(acc,line){
    var p=line.trim().split('","').map(function(s){return s.replace(/^"|"$/g,'').trim();});
    if(p[0]!=='2') return acc;
    var d=parseInt(p[4])||0,c=parseInt(p[5])||0;
    if(d>0) acc.push({date:p[1],io:'出金',name:p[3]||'',amt:d});
    if(c>0) acc.push({date:p[1],io:'入金',name:p[3]||'',amt:c});
    return acc;
  },[]);
  if(biz.length>0) return biz;
  // Try generic CSV: 日付,摘要,出金,入金,残高 (header auto-detect)
  var hIdx=-1,dCol=-1,nCol=-1,outCol=-1,inCol=-1;
  for(var i=0;i<Math.min(lines.length,5);i++){
    var h=lines[i].replace(/"/g,'');
    if(h.indexOf('日付')>=0||(h.indexOf('取引')>=0&&h.indexOf('日')>=0)){
      var cols=h.split(',');
      for(var j=0;j<cols.length;j++){
        var c=cols[j].trim();
        if(c.indexOf('日付')>=0||c.indexOf('取引日')>=0) dCol=j;
        if(c.indexOf('摘要')>=0||c.indexOf('内容')>=0||c.indexOf('適用')>=0||c.indexOf('取引先')>=0) nCol=j;
        if(c.indexOf('出金')>=0||c.indexOf('お支払')>=0||c.indexOf('引落')>=0||c.indexOf('支出')>=0) outCol=j;
        if(c.indexOf('入金')>=0||c.indexOf('お預')>=0||c.indexOf('受入')>=0||c.indexOf('収入')>=0) inCol=j;
      }
      hIdx=i; break;
    }
  }
  if(hIdx<0||dCol<0) return [];
  return lines.slice(hIdx+1).reduce(function(acc,line){
    if(!line.trim()) return acc;
    var p=line.split(',').map(function(s){return s.trim().replace(/"/g,'');});
    if(!p[dCol]||p[dCol].length<4) return acc;
    var oA=outCol>=0?parseInt((p[outCol]||'').replace(/,/g,''))||0:0;
    var iA=inCol>=0?parseInt((p[inCol]||'').replace(/,/g,''))||0:0;
    var nm=nCol>=0?(p[nCol]||''):'';
    if(oA>0) acc.push({date:p[dCol],io:'出金',name:nm,amt:oA});
    if(iA>0) acc.push({date:p[dCol],io:'入金',name:nm,amt:iA});
    return acc;
  },[]);
}
function parseYucho(t){
  var inD=false;
  return t.split('\\n').reduce(function(acc,line){
    if(line.indexOf('取引日')>=0&&line.indexOf('受入金額')>=0){inD=true;return acc;}
    if(!inD) return acc;
    var p=line.split(',').map(function(s){return s.trim().replace(/"/g,'');});
    if(!p[0]||p[0].length<8) return acc;
    var ny=parseInt((p[3]||'').replace(/,/g,''))||0;
    var hr=parseInt((p[5]||'').replace(/,/g,''))||0;
    if(ny>0) acc.push({date:p[0],io:'入金',name:p[7]||'',amt:ny});
    if(hr>0) acc.push({date:p[0],io:'出金',name:p[7]||'',amt:hr});
    return acc;
  },[]);
}
function matchBank(name){
  var t=(name||'').toUpperCase();
  for(var i=0;i<BANK_RULES.length;i++){
    var rule=BANK_RULES[i];
    for(var j=0;j<rule.kw.length;j++){
      if(t.indexOf(rule.kw[j].toUpperCase())>=0) return rule;
    }
  }
  return null;
}
function processBank(){
  try{
  bankRows=[];
  var parseErrors=[];
  Object.keys(loaded).forEach(function(fname){
    var entry=loaded[fname],acct=entry.acct,text=entry.text;
    var ai=BACCT[acct]||BACCT['総務'];
    var txs=(acct==='ゆうちょ')?parseYucho(text):parseUFJ(text);
    if(txs.length===0) parseErrors.push(fname);
    txs.forEach(function(tx){
      var rule=matchBank(tx.name);
      var drCd,crCd,st='check',ji=ai.ji,memo=tx.name||'',tax=0.1;
      if(rule){
        drCd=tx.io==='入金'?ai.cd:rule.cd;
        crCd=tx.io==='入金'?rule.cd:ai.cd;
        st=rule.st; ji=rule.ji!=null?rule.ji:ai.ji;
        memo=rule.memo; tax=rule.tax;
      } else {
        // 未マッチ：通帳側は確定、相手科目はユーザー選択（CHECK）
        drCd=tx.io==='入金'?ai.cd:'CHECK';
        crCd=tx.io==='入金'?'CHECK':ai.cd;
      }
      var drSub=tx.io==='入金'?ai.sub:'',crSub=tx.io==='入金'?'':ai.sub;
      bankRows.push({id:rowId++,date:tx.date,acct:acct,ai:ai,io:tx.io,name:tx.name||'',drCd:drCd,crCd:crCd,drSub:drSub,crSub:crSub,amt:tx.amt,memo:memo,ji:ji,st:st,tax:tax,inc:(st!=='skip')});
    });
  });
  bankRows.sort(function(a,b){return a.date.localeCompare(b.date);});
  if(parseErrors.length>0) notif('⚠ 読み取れないファイル: '+parseErrors.join(', ')+'\\n対応形式: UFJ BizSTATION / 汎用CSV(日付,摘要,出金,入金) / ゆうちょ');
  renderBank(); updateTop(); renderPills();
  }catch(err){notif('⚠ 銀行CSV処理エラー: '+err.message);}
}
function renderBank(){
  try{
  var has=Object.keys(loaded).length>0;
  document.getElementById('bank-empty').style.display=has?'none':'block';
  document.getElementById('bank-wrap').style.display=has?'block':'none';
  if(!has) return;
  var out=bankRows.filter(function(r){return r.inc&&r.st!=='skip'&&r.drCd!=='CHECK'&&r.crCd!=='CHECK';});
  var el=document.getElementById('sb-b'); if(el) el.textContent=out.length||'';
  document.getElementById('bank-tbody').innerHTML=bankRows.map(function(r){
    var dOk=r.drCd&&r.drCd!=='CHECK', cOk=r.crCd&&r.crCd!=='CHECK';
    return \`<tr style="\${r.st==='check'?'background:#fffcf4':''}">
      <td style="font-family:monospace;font-size:10px;color:#aaa;white-space:nowrap">\${fmtD(r.date)}</td>
      <td><span class="at \${r.ai.tag||'at-s'}">\${r.acct}</span></td>
      <td style="font-family:monospace;font-size:10px;color:var(--bl)">\${r.ai.cd}</td>
      <td style="font-size:10px;color:#888;max-width:100px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">\${cl(r.name,15)}</td>
      <td>\${dOk?\`<span class="dr">\${rCd(r.drCd)}</span>\`:\`<select style="font-size:10px;max-width:150px" onchange="updB(\${r.id},'drCd',this.value)">\${kmOpt(r.drCd)}</select>\`}</td>
      <td>\${hojoOpt(r.drCd,r.drSub,r.id,'drSub')}</td>
      <td style="color:#ddd;font-size:10px;text-align:center">→</td>
      <td>\${cOk?\`<span class="cr2">\${rCd(r.crCd)}</span>\`:\`<select style="font-size:10px;max-width:150px" onchange="updB(\${r.id},'crCd',this.value)">\${kmOpt(r.crCd)}</select>\`}</td>
      <td>\${hojoOpt(r.crCd,r.crSub,r.id,'crSub')}</td>
      <td class="ar"><span style="font-size:9px;color:\${r.io==='入金'?'var(--gn)':'var(--rd)'}">\${r.io}</span> ¥\${r.amt.toLocaleString()}</td>
      <td><input style="font-size:10px;padding:3px 5px;width:120px" value="\${r.memo}" onchange="updB(\${r.id},'memo',this.value)"></td>
      <td><label style="display:flex;align-items:center;gap:3px;cursor:pointer"><input type="checkbox"\${r.inc&&r.st!=='skip'?' checked':''} onchange="updB(\${r.id},'inc',this.checked)"><span style="font-size:9px;color:#aaa">出力</span></label></td>
    </tr>\`;
  }).join('') || '<tr><td colspan="12" style="text-align:center;padding:16px;color:#bbb">データなし</td></tr>';
  }catch(err){notif('⚠ 銀行明細表示エラー: '+err.message);}
}
function updB(id,field,val){
  var r=bankRows.find(function(x){return x.id===id;});
  if(r) r[field]=val;
  updateTop();
}
function renderPills(){
  document.getElementById('pills').innerHTML=Object.keys(loaded).map(function(n){
    return \`<div class="pill"><span style="font-size:10px;font-weight:700;color:var(--ink2)">\${loaded[n].acct}</span><span>\${n}</span><button style="background:none;border:none;cursor:pointer;color:#bbb;font-size:12px;padding:0 1px" onclick="rmFile('\${n.replace(/'/g,"\\\\'")}')">✕</button></div>\`;
  }).join('');
}
function rmFile(n){ delete loaded[n]; processBank(); renderPills(); }

// =============================================
// クレジットカード
// =============================================
function ccAuto(v){
  var u=(v||'').toUpperCase();
  for(var i=0;i<CC_RULES.length;i++){
    var r=CC_RULES[i];
    for(var j=0;j<r.kw.length;j++){
      if(u.indexOf(r.kw[j].toUpperCase())>=0) return {cd:r.cd,memo:r.memo,tax:r.tax,group:r.group||null};
    }
  }
  return {cd:'5425',memo:v,tax:0.1,group:null};
}
function ccAcctChg(){
  var cd=(document.getElementById('cc-acct')||{}).value||'1113';
  var sel=document.getElementById('cc-acct-sub');
  if(!sel) return;
  var m=HOJO_MAP[cd];
  sel.innerHTML='<option value="">--</option>';
  if(m){Object.keys(m).forEach(function(k){sel.innerHTML+='<option value="'+k+'">'+k+':'+m[k]+'</option>';});}
  ccJnl();
}
function ccDrop(e){ e.preventDefault(); ccFiles(e.dataTransfer.files); }
function ccFiles(files){
  var arr=Array.from(files).filter(function(f){return f.type.indexOf('image/')===0||f.type==='application/pdf';});
  if(!arr.length){notif('画像またはPDFを選択してください');return;}
  ccImgs=[]; document.getElementById('cc-prev').innerHTML='';
  var done=0;
  arr.forEach(function(f){
    var fr=new FileReader();
    fr.onload=function(ev){
      ccImgs.push({b64:ev.target.result.split(',')[1],mime:f.type,name:f.name});
      var prev=document.getElementById('cc-prev');
      if(f.type==='application/pdf'){
        var div=document.createElement('div');
        div.style='display:flex;align-items:center;gap:5px;background:#f9f8f5;border:.5px solid var(--bd);border-radius:4px;padding:5px 9px;font-size:11px';
        div.innerHTML='<span style="font-size:18px">📄</span><span>'+f.name+'</span>';
        prev.appendChild(div);
      } else {
        var img=document.createElement('img');
        img.src=ev.target.result;
        img.style='width:80px;height:62px;object-fit:cover;border-radius:4px;border:.5px solid var(--bd)';
        prev.appendChild(img);
      }
      done++;
      if(done===arr.length){
        var k=(document.getElementById('cc-key')||{}).value||localStorage.getItem('tkc_api_key')||'';
        if(k) ccAPI(k); else notif('APIキーを設定してください');
      }
    };
    fr.readAsDataURL(f);
  });
}
async function ccAPI(apiKey){
  var lb=document.getElementById('cc-ld'); if(lb) lb.style.display='flex';
  var imgs=ccImgs.map(function(img){
    if(img.mime==='application/pdf') return {type:'document',source:{type:'base64',media_type:'application/pdf',data:img.b64}};
    return {type:'image',source:{type:'base64',media_type:img.mime,data:img.b64}};
  });
  var prompt='このクレジットカード明細からJSONで返してください。形式: {"pay_date":"YYYY/MM/DD","total":数値,"cards":[{"card_no":"下4桁","user_name":"氏名","items":[{"date":"YYYY/MM/DD","vendor":"店名","amount":数値}]}]} JSON以外返さない。';
  try{
    var res=await fetch('https://api.anthropic.com/v1/messages',{
      method:'POST',
      headers:{'Content-Type':'application/json','x-api-key':apiKey,'anthropic-version':'2023-06-01','anthropic-dangerous-direct-browser-access':'true'},
      body:JSON.stringify({model:'claude-sonnet-4-6',max_tokens:4000,messages:[{role:'user',content:[...imgs,{type:'text',text:prompt}]}]})
    });
    if(!res.ok){var e=await res.json();throw new Error((e.error&&e.error.message)||res.status);}
    var data=await res.json();
    var text=((data.content.find(function(c){return c.type==='text';})||{}).text)||'';
    var m=text.match(/\\{[\\s\\S]+\\}/);
    if(!m) throw new Error('JSON解析エラー');
    if(lb) lb.style.display='none';
    ccLoad(JSON.parse(m[0]));
    notif('✓ 明細を読み取りました','green');
  }catch(err){
    if(lb) lb.style.display='none';
    var msg=String(err.message||err);
    notif(msg.indexOf('401')>=0?'認証エラー: APIキーを確認してください':'APIエラー: '+msg);
  }
}
function ccLoad(data){
  ccPayDate=data.pay_date||''; ccTotal=data.total||0;
  ccCards=(data.cards||[]).map(function(card){
    var items=(card.items||[]).map(function(it){
      var a=ccAuto(it.vendor);
      return {id:++ccRid,date:it.date,vendor:it.vendor,amt:it.amount,cd:a.cd,memo:a.memo,tax:a.tax,group:a.group,ji:10};
    });
    return {no:card.card_no,user:card.user_name||('カード -'+card.card_no),ji:10,items:items};
  });
  var pe=document.getElementById('cc-pay'); if(pe) pe.value=ccPayDate;
  ccRender();
  var cc=document.getElementById('cc-cont'); if(cc) cc.style.display='block';
  updateTop();
}
function ccRender(){
  var total=0;
  ccCards.forEach(function(c){ c.items.forEach(function(it){ total+=it.amt; }); });
  ccTotal=total;
  document.getElementById('cc-cards').innerHTML=ccCards.map(function(card){
    var gas=card.items.filter(function(it){return it.group==='gas';});
    var other=card.items.filter(function(it){return it.group!=='gas';});
    var gasAmt=gas.reduce(function(s,it){return s+it.amt;},0);
    var cTotal=card.items.reduce(function(s,it){return s+it.amt;},0);
    var gasRow='';
    if(gas.length){
      var g0=gas[0]||{};
      gasRow=\`<tr style="background:#f0fdf4">
        <td><span class="chip cg" style="font-size:9px">まとめ\${gas.length}回</span></td>
        <td><strong>ガソリン代 合計</strong></td>
        <td><select style="font-size:10px;max-width:160px" data-no="\${card.no}" data-field="cd" onchange="ccGas(this)">\${ccKmOpt(g0.cd)}</select></td>
        <td><input style="font-size:10px;width:110px" value="\${g0.memo||'ガソリン代'}" data-no="\${card.no}" data-field="memo" onchange="ccGas(this)"></td>
        <td class="ar">¥\${gasAmt.toLocaleString()}</td>
        <td><span class="chip cb">課税10%</span></td>
      </tr>\`;
    }
    var otherRows=other.map(function(it){
      return \`<tr>
        <td><input style="font-size:10px;width:88px" value="\${it.date||''}" data-id="\${it.id}" data-field="date" onchange="ccIt(this)" placeholder="YYYY/MM/DD"></td>
        <td><input style="font-size:10px;width:110px" value="\${it.vendor||''}" data-id="\${it.id}" data-field="vendor" onchange="ccIt(this)"></td>
        <td><select style="font-size:10px;max-width:160px" data-id="\${it.id}" data-field="cd" onchange="ccIt(this)">\${ccKmOpt(it.cd)}</select></td>
        <td><input style="font-size:10px;width:110px" value="\${it.memo||''}" data-id="\${it.id}" data-field="memo" onchange="ccIt(this)"></td>
        <td class="ar"><input type="number" style="font-size:10px;width:80px;text-align:right;font-family:monospace" value="\${it.amt}" data-id="\${it.id}" data-field="amt" onchange="ccIt(this)"></td>
        <td><select style="font-size:10px;width:76px" data-id="\${it.id}" data-field="tax" onchange="ccIt(this)">
          <option value="0.1"\${it.tax===0.1?' selected':''}>課税10%</option>
          <option value="0"\${it.tax===0?' selected':''}>非課税</option>
        </select></td>
      </tr>\`;
    }).join('');
    return \`<div class="card" style="margin-bottom:8px">
      <div class="cardh"><span class="cardt">\${card.user}</span><span class="chip cgr">-\${card.no}</span><span style="margin-left:auto;font-family:monospace;font-weight:700">¥\${cTotal.toLocaleString()}</span></div>
      <table><thead><tr><th>利用日</th><th>店名</th><th>勘定科目</th><th>摘要</th><th class="ar">金額</th><th>課税</th></tr></thead>
      <tbody>\${gasRow}\${otherRows}</tbody></table>
    </div>\`;
  }).join('');
  ccJnl(); updateTop();
  var el=document.getElementById('sb-c'); if(el) el.textContent=ccTotal>0?String(ccCards.reduce(function(s,c){return s+c.items.length;},0)):'';
}
function ccIt(el){
  var id=+el.dataset.id, field=el.dataset.field;
  ccCards.forEach(function(c){ c.items.forEach(function(it){ if(it.id===id){ it[field]=(field==='amt'||field==='tax')?+el.value:el.value; } }); });
  if(['amt','tax','cd'].indexOf(field)>=0) ccRender(); else ccJnl();
  updateTop();
}
function ccGas(el){
  var no=el.dataset.no, field=el.dataset.field;
  ccCards.forEach(function(c){ if(c.no===no) c.items.filter(function(it){return it.group==='gas';}).forEach(function(it){ it[field]=el.value; }); });
  ccJnl();
}
function ccStep2(){
  var rows=[];
  var allGas=[];
  ccCards.forEach(function(c){ c.items.filter(function(it){return it.group==='gas';}).forEach(function(it){allGas.push(it);}); });
  if(allGas.length){
    var f=allGas[0];
    rows.push({cd:f.cd,nm:CC_KM_MAP[f.cd]||f.cd,memo:f.memo||'ガソリン代',amt:allGas.reduce(function(s,it){return s+it.amt;},0),tax:0.1,ji:f.ji,date:f.date||''});
  }
  ccCards.forEach(function(c){
    c.items.filter(function(it){return it.group!=='gas';}).forEach(function(it){
      rows.push({cd:it.cd,nm:CC_KM_MAP[it.cd]||it.cd,memo:it.memo,amt:it.amt,tax:it.tax,ji:it.ji,date:it.date||''});
    });
  });
  return rows;
}
function ccJnl(){
  var s2=ccStep2();
  var s2t=s2.reduce(function(s,r){return s+r.amt;},0);
  var ba=(document.getElementById('cc-acct')||{}).value||'1113';
  var bn=ba==='1112'?'郵便貯金':'普通預金';
  var ok=(s2t===ccTotal);
  var b=document.getElementById('cc-bal');
  if(b){ b.className='chip '+(ok?'cg':'chip'); b.style.background=ok?'':'#fce4ec'; b.style.color=ok?'':'#880e4f'; b.textContent=ok?'✓ 金額一致':'⚠ 差異あり'; }
  var s2html=s2.map(function(r){
    return \`<div style="display:grid;grid-template-columns:1fr 14px 1fr 80px;gap:3px;align-items:center;margin-bottom:2px;font-size:11px">
      <span><span class="dr">\${r.cd}</span> \${cl(r.nm,12)}</span>
      <span style="color:#ddd;text-align:center">→</span>
      <span><span class="cr2">9992</span> 資金外諸口</span>
      <span class="ar">¥\${r.amt.toLocaleString()}</span>
    </div><div style="font-size:10px;color:#aaa;margin:-1px 0 5px 14px">\${r.memo} / \${r.tax>0?'課税10%':'非課税'}</div>\`;
  }).join('');
  var el=document.getElementById('cc-jnl'); if(!el) return;
  el.innerHTML=\`
    <div style="background:#f0fdf4;border:.5px solid #86efac;border-radius:6px;padding:10px 12px;margin-bottom:8px">
      <div style="font-size:10px;font-weight:700;color:#aaa;margin-bottom:5px">STEP 1 — 引落時</div>
      <div style="display:grid;grid-template-columns:1fr 14px 1fr 80px;gap:3px;font-size:11px">
        <span><span class="dr">9992</span> 資金外諸口</span><span style="color:#ddd;text-align:center">→</span>
        <span><span class="cr2">\${ba}</span> \${bn}</span><span class="ar">¥\${ccTotal.toLocaleString()}</span>
      </div>
    </div>
    <div style="background:#f9f8f5;border:.5px solid var(--bd);border-radius:6px;padding:10px 12px">
      <div style="font-size:10px;font-weight:700;color:#aaa;margin-bottom:5px">STEP 2 — 明細展開（\${s2.length}件）</div>
      \${s2html}
      <div style="display:flex;justify-content:flex-end;font-family:monospace;font-weight:700;font-size:12px;color:var(--gn);margin-top:6px;padding-top:6px;border-top:.5px solid var(--bd)">
        合計 ¥\${s2t.toLocaleString()}
        \${!ok?\`<span style="color:var(--rd);margin-left:8px;font-size:11px">差異: ¥\${Math.abs(s2t-ccTotal).toLocaleString()}</span>\`:''}
      </div>
    </div>\`;
}
function ccBuild(){
  if(!ccCards||!ccCards.length) return [];
  var ba=(document.getElementById('cc-acct')||{}).value||'1113';
  var bSub=(document.getElementById('cc-acct-sub')||{}).value||'';
  var bji=+((document.getElementById('cc-ji')||{}).value||0);
  var bn=ba==='1112'?'郵便貯金':'普通預金';
  var pd=pD((document.getElementById('cc-pay')||{}).value||ccPayDate);
  var co=(document.getElementById('cc-co')||{}).value||'カード会社';
  var rows=[];
  rows.push({sect:'CC-S1',ji:bji,jiN:JI_MAP[bji]||'',drCd:'9992',drN:'資金外諸口',drSub:'',crCd:ba,crN:bn,crSub:bSub,amt:ccTotal,tax:0,ta:0,ex:ccTotal,memo:co+' カード引落',date:pd,jissai:0,den:'CC001A',vendor:co});
  ccStep2().forEach(function(r,i){
    var t=cTax(r.amt,r.tax);
    rows.push({sect:'CC-S2',ji:r.ji,jiN:JI_MAP[r.ji]||'',drCd:r.cd,drN:CC_KM_MAP[r.cd]||r.cd,drSub:'',crCd:'9992',crN:'資金外諸口',crSub:'',amt:r.amt,tax:r.tax,ta:t.ta,ex:t.ex,memo:r.memo,date:pd,jissai:r.date?pD(r.date):0,den:'CC'+String(i+2).padStart(3,'0')+'A',vendor:''});
  });
  return rows;
}

// =============================================
// CSV 出力
// =============================================
var TKC_C=["事業CD","事業名","年月日","伝番","証番","課","事","小切手NO","借方CD","借方補助","借方科目名","借方口座名","貸方CD","貸方補助","貸方科目名","貸方口座名","取引金額","税率","内、消費税等","税抜き金額","取引先CD","取引先名（仕入先の氏名又は名称）","実際の仕入れ年月日（期間）","元帳摘要（仕入れ資産等の総称）","ﾌﾟﾛｼﾞｪｸﾄCD","ﾌﾟﾛｼﾞｪｸﾄ名","軽減対象取引区分","控除割合","事業者登録番号"];
var YY_C=["伝票No","年月日","借方勘定科目","借方補助科目","借方税区分","借方金額","借方消費税額","貸方勘定科目","貸方補助科目","貸方税区分","貸方金額","貸方消費税額","摘要","番号","期日","タイプ","生成元"];
var FR_C=["発生日","借方勘定科目","借方補助科目名","借方部門","借方税区分","借方金額","借方税額","貸方勘定科目","貸方補助科目名","貸方部門","貸方税区分","貸方金額","貸方税額","摘要","管理番号"];
var MF_C=["取引日","借方勘定科目","借方補助科目","借方税区分","借方金額","貸方勘定科目","貸方補助科目","貸方税区分","貸方金額","摘要","仕訳メモ","タグ","MF仕訳ID"];

function buildTKC(){
  var ym=getYM(),reiwa=ym.y-2018,ld=lastDay(ym.y,ym.m),date=reiwa*10000+ym.m*100+ld,rows=[],fn=fixedRows.filter(function(r){return r.en&&r.amt>0;});
  fn.forEach(function(r,i){
    var t=cTax(r.amt,r.tax);
    rows.push({"事業CD":String(r.ji).padStart(3,'0'),"事業名":JI_MAP[r.ji]||'',"年月日":date,"伝番":String(i+1).padStart(5,' ')+'A',"証番":'',"課":tkcTax(r.tax),"事":'',"小切手NO":'',"借方CD":r.drCd,"借方補助":r.drSub||'',"借方科目名":r.drN||kmN(r.drCd),"借方口座名":hojoName(r.drCd,r.drSub),"貸方CD":r.crCd,"貸方補助":r.crSub||'',"貸方科目名":r.crN||kmN(r.crCd),"貸方口座名":hojoName(r.crCd,r.crSub),"取引金額":r.amt,"税率":tkcRate(r.tax),"内、消費税等":r.tax?t.ta:0,"税抜き金額":r.tax?t.ex:r.amt,"取引先CD":0,"取引先名（仕入先の氏名又は名称）":'',"実際の仕入れ年月日（期間）":'',"元帳摘要（仕入れ資産等の総称）":r.memo,"ﾌﾟﾛｼﾞｪｸﾄCD":'',"ﾌﾟﾛｼﾞｪｸﾄ名":'',"軽減対象取引区分":'',"控除割合":'',"事業者登録番号":''});
  });
  bankRows.filter(function(r){return r.inc&&r.st!=='skip'&&r.drCd!=='CHECK'&&r.crCd!=='CHECK';}).forEach(function(r,i){
    var dr=rCd(r.drCd),cr=rCd(r.crCd),tax=r.tax||0,t=cTax(r.amt,tax);
    rows.push({"事業CD":String(r.ji).padStart(3,'0'),"事業名":JI_MAP[r.ji]||'',"年月日":pD(r.date),"伝番":String(fn.length+i+1).padStart(5,' ')+'B',"証番":'',"課":tkcTax(tax),"事":'',"小切手NO":'',"借方CD":dr,"借方補助":r.drSub||'',"借方科目名":kmN(r.drCd),"借方口座名":hojoName(r.drCd,r.drSub),"貸方CD":cr,"貸方補助":r.crSub||'',"貸方科目名":kmN(r.crCd),"貸方口座名":hojoName(r.crCd,r.crSub),"取引金額":r.amt,"税率":tkcRate(tax),"内、消費税等":tax?t.ta:0,"税抜き金額":tax?t.ex:r.amt,"取引先CD":0,"取引先名（仕入先の氏名又は名称）":r.name||'',"実際の仕入れ年月日（期間）":'',"元帳摘要（仕入れ資産等の総称）":r.memo,"ﾌﾟﾛｼﾞｪｸﾄCD":'',"ﾌﾟﾛｼﾞｪｸﾄ名":'',"軽減対象取引区分":'',"控除割合":'',"事業者登録番号":''});
  });
  ccBuild().forEach(function(r){
    rows.push({"事業CD":String(r.ji).padStart(3,'0'),"事業名":r.jiN||JI_MAP[r.ji]||'',"年月日":r.date,"伝番":r.den,"証番":'',"課":tkcTax(r.tax),"事":'',"小切手NO":'',"借方CD":r.drCd,"借方補助":r.drSub||'',"借方科目名":r.drN||kmN(r.drCd),"借方口座名":hojoName(r.drCd,r.drSub),"貸方CD":r.crCd,"貸方補助":r.crSub||'',"貸方科目名":r.crN||kmN(r.crCd),"貸方口座名":hojoName(r.crCd,r.crSub),"取引金額":r.amt,"税率":tkcRate(r.tax),"内、消費税等":r.ta||0,"税抜き金額":r.ex||r.amt,"取引先CD":0,"取引先名（仕入先の氏名又は名称）":r.vendor||'',"実際の仕入れ年月日（期間）":r.jissai||'',"元帳摘要（仕入れ資産等の総称）":r.memo,"ﾌﾟﾛｼﾞｪｸﾄCD":'',"ﾌﾟﾛｼﾞｪｸﾄ名":'',"軽減対象取引区分":'',"控除割合":'',"事業者登録番号":''});
  });
  return rows;
}
function buildYayoi(){
  var ym=getYM(),ld=lastDay(ym.y,ym.m);
  var date=ym.y+'/'+(String(ym.m).padStart(2,'0'))+'/'+String(ld).padStart(2,'0');
  var rows=[],no=1;
  function yT(t){return t===0.1?'課税売上10%':'対象外';}
  function yTA(a,t){return t?Math.round(a-Math.round(a/(1+t))):0;}
  fixedRows.filter(function(r){return r.en&&r.amt>0;}).forEach(function(r){
    rows.push({"伝票No":String(no++).padStart(5,'0'),"年月日":date,"借方勘定科目":r.drN||kmN(r.drCd),"借方補助科目":hojoName(r.drCd,r.drSub),"借方税区分":yT(r.tax),"借方金額":r.amt,"借方消費税額":yTA(r.amt,r.tax),"貸方勘定科目":r.crN||kmN(r.crCd),"貸方補助科目":hojoName(r.crCd,r.crSub),"貸方税区分":'対象外',"貸方金額":r.amt,"貸方消費税額":0,"摘要":r.memo,"番号":'',"期日":'',"タイプ":0,"生成元":''});
  });
  bankRows.filter(function(r){return r.inc&&r.st!=='skip'&&r.drCd!=='CHECK'&&r.crCd!=='CHECK';}).forEach(function(r){
    var d=fmtD(r.date),t=r.tax||0;
    rows.push({"伝票No":String(no++).padStart(5,'0'),"年月日":d,"借方勘定科目":kmN(r.drCd),"借方補助科目":hojoName(r.drCd,r.drSub),"借方税区分":yT(t),"借方金額":r.amt,"借方消費税額":yTA(r.amt,t),"貸方勘定科目":kmN(r.crCd),"貸方補助科目":hojoName(r.crCd,r.crSub),"貸方税区分":'対象外',"貸方金額":r.amt,"貸方消費税額":0,"摘要":r.memo,"番号":'',"期日":'',"タイプ":0,"生成元":''});
  });
  ccBuild().forEach(function(r){
    var d=r2AD(r.date)||date;
    rows.push({"伝票No":String(no++).padStart(5,'0'),"年月日":d,"借方勘定科目":r.drN||kmN(r.drCd),"借方補助科目":hojoName(r.drCd,r.drSub),"借方税区分":yT(r.tax),"借方金額":r.amt,"借方消費税額":r.ta||0,"貸方勘定科目":r.crN||kmN(r.crCd),"貸方補助科目":hojoName(r.crCd,r.crSub),"貸方税区分":'対象外',"貸方金額":r.amt,"貸方消費税額":0,"摘要":r.memo,"番号":'',"期日":'',"タイプ":0,"生成元":''});
  });
  return rows;
}
function buildFreee(){
  var ym=getYM(),ld=lastDay(ym.y,ym.m);
  var date=ym.y+'-'+(String(ym.m).padStart(2,'0'))+'-'+String(ld).padStart(2,'0');
  var rows=[],no=1;
  function fT(t){return t===0.1?'課税売上10%（軽）':'対象外';}
  function fTA(a,t){return t?Math.round(a-Math.round(a/(1+t))):0;}
  fixedRows.filter(function(r){return r.en&&r.amt>0;}).forEach(function(r){
    var ji=JI_MAP[r.ji]||'';
    rows.push({"発生日":date,"借方勘定科目":r.drN||kmN(r.drCd),"借方補助科目名":hojoName(r.drCd,r.drSub),"借方部門":ji,"借方税区分":fT(r.tax),"借方金額":r.amt,"借方税額":fTA(r.amt,r.tax),"貸方勘定科目":r.crN||kmN(r.crCd),"貸方補助科目名":hojoName(r.crCd,r.crSub),"貸方部門":ji,"貸方税区分":'対象外',"貸方金額":r.amt,"貸方税額":0,"摘要":r.memo,"管理番号":'F'+String(no++).padStart(4,'0')});
  });
  bankRows.filter(function(r){return r.inc&&r.st!=='skip'&&r.drCd!=='CHECK'&&r.crCd!=='CHECK';}).forEach(function(r){
    var d=fmtD(r.date).replace(/\\//g,'-'),t=r.tax||0,ji=JI_MAP[r.ji]||'';
    rows.push({"発生日":d,"借方勘定科目":kmN(r.drCd),"借方補助科目名":hojoName(r.drCd,r.drSub),"借方部門":ji,"借方税区分":fT(t),"借方金額":r.amt,"借方税額":fTA(r.amt,t),"貸方勘定科目":kmN(r.crCd),"貸方補助科目名":hojoName(r.crCd,r.crSub),"貸方部門":ji,"貸方税区分":'対象外',"貸方金額":r.amt,"貸方税額":0,"摘要":r.memo,"管理番号":'F'+String(no++).padStart(4,'0')});
  });
  ccBuild().forEach(function(r){
    var d=toISO(r.date)||date,ji=JI_MAP[r.ji]||'';
    rows.push({"発生日":d,"借方勘定科目":r.drN||kmN(r.drCd),"借方補助科目名":hojoName(r.drCd,r.drSub),"借方部門":ji,"借方税区分":fT(r.tax),"借方金額":r.amt,"借方税額":r.ta||0,"貸方勘定科目":r.crN||kmN(r.crCd),"貸方補助科目名":hojoName(r.crCd,r.crSub),"貸方部門":ji,"貸方税区分":'対象外',"貸方金額":r.amt,"貸方税額":0,"摘要":r.memo,"管理番号":'F'+String(no++).padStart(4,'0')});
  });
  return rows;
}
function buildMF(){
  var ym=getYM(),ld=lastDay(ym.y,ym.m);
  var date=ym.y+'/'+(String(ym.m).padStart(2,'0'))+'/'+String(ld).padStart(2,'0');
  var rows=[],no=1;
  function mT(t){return t===0.1?'課税 10%':'不課税';}
  fixedRows.filter(function(r){return r.en&&r.amt>0;}).forEach(function(r){
    rows.push({"取引日":date,"借方勘定科目":r.drN||kmN(r.drCd),"借方補助科目":hojoName(r.drCd,r.drSub),"借方税区分":mT(r.tax),"借方金額":r.amt,"貸方勘定科目":r.crN||kmN(r.crCd),"貸方補助科目":hojoName(r.crCd,r.crSub),"貸方税区分":'不課税',"貸方金額":r.amt,"摘要":r.memo,"仕訳メモ":'',"タグ":'',"MF仕訳ID":'MF'+String(no++).padStart(5,'0')});
  });
  bankRows.filter(function(r){return r.inc&&r.st!=='skip'&&r.drCd!=='CHECK'&&r.crCd!=='CHECK';}).forEach(function(r){
    var d=fmtD(r.date),t=r.tax||0;
    rows.push({"取引日":d,"借方勘定科目":kmN(r.drCd),"借方補助科目":hojoName(r.drCd,r.drSub),"借方税区分":mT(t),"借方金額":r.amt,"貸方勘定科目":kmN(r.crCd),"貸方補助科目":hojoName(r.crCd,r.crSub),"貸方税区分":'不課税',"貸方金額":r.amt,"摘要":r.memo,"仕訳メモ":'',"タグ":'',"MF仕訳ID":'MF'+String(no++).padStart(5,'0')});
  });
  ccBuild().forEach(function(r){
    var d=r2AD(r.date)||date;
    rows.push({"取引日":d,"借方勘定科目":r.drN||kmN(r.drCd),"借方補助科目":hojoName(r.drCd,r.drSub),"借方税区分":mT(r.tax),"借方金額":r.amt,"貸方勘定科目":r.crN||kmN(r.crCd),"貸方補助科目":hojoName(r.crCd,r.crSub),"貸方税区分":'不課税',"貸方金額":r.amt,"摘要":r.memo,"仕訳メモ":'',"タグ":'',"MF仕訳ID":'MF'+String(no++).padStart(5,'0')});
  });
  return rows;
}
function downloadAll(){
  try{
  if(SW==='yayoi'||SW==='mf'){notif('⏳ '+({yayoi:'弥生会計',mf:'マネーフォワード'}[SW])+' は近日公開予定です','orange');return;}
  var ym=getYM(),ymS=String(ym.y)+String(ym.m).padStart(2,'0');
  var rows,cols,fname,akey;
  if(SW==='yayoi')      {rows=buildYayoi();cols=YY_C;fname='仕訳_弥生_'+ymS+'.csv';akey='借方金額';}
  else if(SW==='freee') {rows=buildFreee();cols=FR_C;fname='仕訳_freee_'+ymS+'.csv';akey='借方金額';}
  else if(SW==='mf')    {rows=buildMF();  cols=MF_C;fname='仕訳_MF_'+ymS+'.csv';  akey='借方金額';}
  else                  {rows=buildTKC(); cols=TKC_C;fname='仕訳_TKC_'+ymS+'.csv'; akey='取引金額';}
  if(!rows.length){notif('出力する仕訳がありません');return;}
  var lines=[cols.join(',')].concat(rows.map(function(r){return cols.map(function(c){return ce(r[c]==null?'':r[c]);}).join(',');}));
  var a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob(['\\uFEFF'+lines.join('\\n')],{type:'text/csv;charset=utf-8'}));
  a.download=fname; a.click();
  var t=rows.reduce(function(s,r){return s+(Number(r[akey])||0);},0);
  notif('✓ '+rows.length+'件 / ¥'+t.toLocaleString()+' を出力','green');
  }catch(err){notif('⚠ CSV出力エラー: '+err.message);}
}
function dlSection(type){
  var rows=buildTKC().filter(function(r){
    var d=String(r['伝番']||'');
    if(type==='fixed') return d.indexOf('A')>=0&&d.indexOf('CC')<0;
    if(type==='bank')  return d.indexOf('B')>=0;
    if(type==='cc')    return d.indexOf('CC')>=0;
    return false;
  });
  if(!rows.length){notif('データがありません');return;}
  var ym=getYM(),ymS=String(ym.y)+String(ym.m).padStart(2,'0');
  var lb={fixed:'定型仕訳',bank:'銀行仕訳',cc:'CC仕訳'};
  var lines=[TKC_C.join(',')].concat(rows.map(function(r){return TKC_C.map(function(c){return ce(r[c]==null?'':r[c]);}).join(',');}));
  var a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob(['\\uFEFF'+lines.join('\\n')],{type:'text/csv;charset=utf-8'}));
  a.download=(lb[type]||type)+'_TKC_'+ymS+'.csv'; a.click();
  notif('✓ '+rows.length+'件を出力','green');
}

// =============================================
// 出力確認
// =============================================
function renderOutput(){
  try{
  var fn=fixedRows.filter(function(r){return r.en&&r.amt>0;});
  var bn=bankRows.filter(function(r){return r.inc&&r.st!=='skip'&&r.drCd!=='CHECK'&&r.crCd!=='CHECK';});
  var cn=ccBuild();
  var fA=fn.reduce(function(s,r){return s+r.amt;},0);
  var bA=bn.reduce(function(s,r){return s+r.amt;},0);
  var cA=cn.reduce(function(s,r){return s+r.amt;},0);
  var swN={tkc:'TKC 29列',yayoi:'弥生インポート形式',freee:'freee 取引インポート形式',mf:'MF 仕訳インポート形式'};
  var lbl=document.getElementById('out-lbl'); if(lbl) lbl.textContent='出力形式: '+(swN[SW]||SW);
  document.getElementById('out-sums').innerHTML=\`
    <div style="background:var(--sf);border:.5px solid var(--bd);border-radius:var(--r);padding:10px;text-align:center"><div style="font-size:10px;color:#aaa;margin-bottom:3px">定型仕訳</div><div style="font-size:17px;font-weight:700">¥\${fA.toLocaleString()}</div><div style="font-size:10px;color:#aaa">\${fn.length}件</div></div>
    <div style="background:var(--sf);border:.5px solid var(--bd);border-radius:var(--r);padding:10px;text-align:center"><div style="font-size:10px;color:#aaa;margin-bottom:3px">銀行仕訳</div><div style="font-size:17px;font-weight:700">¥\${bA.toLocaleString()}</div><div style="font-size:10px;color:#aaa">\${bn.length}件</div></div>
    <div style="background:var(--sf);border:.5px solid var(--bd);border-radius:var(--r);padding:10px;text-align:center"><div style="font-size:10px;color:#aaa;margin-bottom:3px">CC仕訳</div><div style="font-size:17px;font-weight:700">¥\${cA.toLocaleString()}</div><div style="font-size:10px;color:#aaa">\${cn.length}件</div></div>\`;
  var all=[].concat(
    fn.map(function(r){return {s:'定型',dr:r.drCd,drN:r.drN||kmN(r.drCd),drS:hojoName(r.drCd,r.drSub),cr:r.crCd,crN:r.crN||kmN(r.crCd),crS:hojoName(r.crCd,r.crSub),memo:r.memo,amt:r.amt,tax:r.tax};}),
    bn.map(function(r){return {s:'銀行',dr:rCd(r.drCd),drN:kmN(r.drCd),drS:hojoName(r.drCd,r.drSub),cr:rCd(r.crCd),crN:kmN(r.crCd),crS:hojoName(r.crCd,r.crSub),memo:r.memo,amt:r.amt,tax:r.tax||0};}),
    cn.map(function(r){return {s:'CC',dr:r.drCd,drN:r.drN||kmN(r.drCd),drS:hojoName(r.drCd,r.drSub),cr:r.crCd,crN:r.crN||kmN(r.crCd),crS:hojoName(r.crCd,r.crSub),memo:r.memo,amt:r.amt,tax:r.tax};})
  );
  document.getElementById('out-tbody').innerHTML=all.map(function(r){
    return \`<tr><td><span class="chip \${r.s==='定型'?'cg':r.s==='銀行'?'cb':'ca'}">\${r.s}</span></td>
      <td><span class="dr">\${r.dr}</span> <span style="font-size:10px">\${cl(r.drN,12)}</span></td>
      <td style="font-size:10px;color:#666">\${r.drS||''}</td>
      <td><span class="cr2">\${r.cr}</span> <span style="font-size:10px">\${cl(r.crN,12)}</span></td>
      <td style="font-size:10px;color:#666">\${r.crS||''}</td>
      <td style="color:#888">\${cl(r.memo,20)}</td>
      <td class="ar">¥\${r.amt.toLocaleString()}</td>
      <td><span class="chip \${r.tax>0?'cb':'cgr'}">\${r.tax>0?'課税10%':'非課税'}</span></td></tr>\`;
  }).join('') || '<tr><td colspan="8" style="text-align:center;padding:20px;color:#bbb">仕訳がありません</td></tr>';
  }catch(err){notif('⚠ 出力プレビューエラー: '+err.message);}
}

// =============================================
// APIキー
// =============================================
function saveKey(val){
  if(val&&val.indexOf('sk-ant')===0){localStorage.setItem('tkc_api_key',val);var e=document.getElementById('cc-kst');if(e)e.textContent='✓ 保存済み';}
  else if(!val){localStorage.removeItem('tkc_api_key');var e2=document.getElementById('cc-kst');if(e2)e2.textContent='';}
}
function gSave(){
  var val=((document.getElementById('g-key')||{}).value||'').trim();
  var st=document.getElementById('g-st');
  if(!val){if(st){st.style.display='block';st.style.background='#fef3c7';st.style.color='#92400e';st.textContent='⚠ APIキーを入力してください';}return;}
  if(val.indexOf('sk-ant')<0){if(st){st.style.display='block';st.style.background='#fce4ec';st.style.color='#880e4f';st.textContent='⚠ sk-ant- から始まるキーを入力してください';}return;}
  localStorage.setItem('tkc_api_key',val);
  var ck=document.getElementById('cc-key');if(ck)ck.value=val;
  var kst=document.getElementById('cc-kst');if(kst)kst.textContent='✓ 保存済み';
  if(st){st.style.display='block';st.style.background='#d8f3dc';st.style.color='#1a6040';st.textContent='✅ 保存しました！';}
  notif('✓ APIキーを保存しました','green');
}
function gClear(){
  localStorage.removeItem('tkc_api_key');
  var gel=document.getElementById('g-key');if(gel)gel.value='';
  var ck=document.getElementById('cc-key');if(ck)ck.value='';
  var kst=document.getElementById('cc-kst');if(kst)kst.textContent='';
  var st=document.getElementById('g-st');if(st){st.style.display='block';st.style.background='#f4f3ef';st.style.color='#888';st.textContent='削除しました';}
  notif('APIキーを削除しました');
}

// =============================================
// topbar 更新
// =============================================
function updateTop(){
  var fa=fixedRows.filter(function(r){return r.en;}).reduce(function(s,r){return s+r.amt;},0);
  var ba=bankRows.filter(function(r){return r.inc&&r.st!=='skip'&&r.drCd!=='CHECK'&&r.crCd!=='CHECK';}).reduce(function(s,r){return s+r.amt;},0);
  var ca=0; try{ca=ccBuild().reduce(function(s,r){return s+r.amt;},0);}catch(e){}
  var t=fa+ba+ca;
  var cnt=fixedRows.filter(function(r){return r.en;}).length+bankRows.filter(function(r){return r.inc&&r.st!=='skip';}).length+ccCards.reduce(function(s,c){return s+c.items.length;},0);
  var ts=document.getElementById('tb-stat');if(ts)ts.textContent=cnt+'件 / ¥'+t.toLocaleString();
  var tv=document.getElementById('sb-total');if(tv)tv.textContent='¥'+t.toLocaleString();
  var tc=document.getElementById('sb-cnt');if(tc)tc.textContent=cnt+'件';
}

// =============================================
// 通知
// =============================================
function notif(msg,cls){
  var el=document.getElementById('notif');
  el.textContent=msg; el.className='notif on'+(cls?' '+cls:'');
  clearTimeout(notif._t);
  notif._t=setTimeout(function(){el.classList.remove('on');},3500);
}
</script>
</body>
</html>`;
      return new Response(toolHtml, {
        headers: { 'Content-Type': 'text/html;charset=UTF-8' },
      });
    }
    
    const html = `<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TKC仕訳インポートツール | 一般社団法人サーコミュニケーション</title>
<meta name="description" content="銀行明細・クレジットカード・月末定型仕訳を自動変換。TKCへのインポートCSVをワンクリックで生成する経理自動化ツール。">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans+JP:wght@300;400;500;700;900&family=Noto+Serif+JP:wght@400;700;900&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#ffffff;
  --bg2:#f5f3ee;
  --bg3:#eceae4;
  --surface:rgba(0,0,0,.03);
  --surface2:rgba(0,0,0,.05);
  --border:rgba(0,0,0,.09);
  --border2:rgba(0,120,200,.22);
  --ink:#0f1923;
  --ink2:#3a4a5a;
  --ink3:#6a7a8a;
  --cyan:#0078c8;
  --cyan2:#005fa0;
  --cyan3:rgba(0,120,200,.12);
  --cyan4:rgba(0,120,200,.06);
  --gold:#d4a96a;
  --green:#1a7a4a;
  --red:#c0392b;
}

*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{
  font-family:'Noto Sans JP',sans-serif;
  background:var(--bg);
  color:var(--ink);
  font-size:15px;
  line-height:1.75;
  overflow-x:hidden;
}

/* ── NOISE TEXTURE ── */
body::before{
  content:'';
  position:fixed;inset:0;z-index:0;pointer-events:none;
  background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.65' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.03'/%3E%3C/svg%3E");
  opacity:.1;
}

/* ── NAV ── */
nav{
  position:fixed;top:0;left:0;right:0;z-index:200;
  display:flex;align-items:center;justify-content:space-between;
  padding:0 48px;height:68px;
  background:rgba(255,255,255,.95);
  backdrop-filter:blur(20px);
  border-bottom:1px solid var(--border);
}
.nav-logo{display:flex;align-items:center;gap:12px;text-decoration:none}
.nav-logo img{height:36px;}
.nav-logo-text{font-size:11px;color:var(--ink3);font-weight:400;letter-spacing:.06em;white-space:nowrap}
.nav-links{display:flex;align-items:center;gap:36px}
.nav-links a{color:#444;text-decoration:none;font-size:13px;letter-spacing:.04em;transition:color .2s}
.nav-links a:hover{color:var(--cyan)}
.nav-cta{
  background:var(--cyan);color:var(--bg);
  padding:8px 22px;border-radius:4px;
  font-size:13px;font-weight:700;text-decoration:none;
  letter-spacing:.04em;transition:all .2s;white-space:nowrap;
}
.nav-cta:hover{background:#fff;transform:translateY(-1px)}

/* ── HERO ── */
.hero{
  min-height:100vh;
  display:flex;flex-direction:column;
  align-items:center;justify-content:center;
  text-align:center;
  padding:120px 40px 80px;
  position:relative;
  overflow:hidden;
}
.hero-bg-ring{
  position:absolute;
  border-radius:50%;
  border:1px solid rgba(0,210,255,.12);
  animation:ringPulse 8s ease-in-out infinite;
}
.hero-bg-ring:nth-child(1){width:600px;height:600px;top:50%;left:50%;transform:translate(-50%,-50%);animation-delay:0s}
.hero-bg-ring:nth-child(2){width:900px;height:900px;top:50%;left:50%;transform:translate(-50%,-50%);animation-delay:1.5s}
.hero-bg-ring:nth-child(3){width:1200px;height:1200px;top:50%;left:50%;transform:translate(-50%,-50%);animation-delay:3s;border-color:rgba(0,210,255,.06)}
@keyframes ringPulse{
  0%,100%{opacity:.5;transform:translate(-50%,-50%) scale(1)}
  50%{opacity:1;transform:translate(-50%,-50%) scale(1.02)}
}
.hero-glow{
  position:absolute;top:40%;left:50%;transform:translate(-50%,-50%);
  width:600px;height:300px;
  background:radial-gradient(ellipse, rgba(0,120,200,.07) 0%, transparent 70%);
  pointer-events:none;
}

.hero-badge{
  display:inline-flex;align-items:center;gap:8px;
  background:var(--cyan4);border:1px solid rgba(0,120,200,.2);
  color:var(--cyan);
  padding:6px 16px;border-radius:100px;
  font-size:12px;font-weight:500;letter-spacing:.06em;
  margin-bottom:32px;position:relative;
  animation:fadeUp .8s ease both;
}
.hero-badge::before{
  content:'';width:6px;height:6px;border-radius:50%;
  background:var(--cyan);
  box-shadow:0 0 8px var(--cyan);
  animation:blink 2s ease-in-out infinite;
}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}

.hero-title{
  font-family:'Noto Serif JP',serif;
  font-size:clamp(36px,6vw,72px);
  font-weight:900;
  line-height:1.2;
  letter-spacing:-.02em;
  margin-bottom:12px;
  position:relative;
  animation:fadeUp .8s .1s ease both;
}
.hero-title span{
  background:linear-gradient(120deg,#0056a8,#0096e0 45%,#0056a8);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;
}
.hero-sub-title{
  font-size:clamp(18px,3vw,28px);
  color:var(--ink2);
  font-weight:300;
  margin-bottom:28px;
  letter-spacing:.02em;
  animation:fadeUp .8s .2s ease both;
}
.hero-desc{
  font-size:15px;color:var(--ink3);
  max-width:560px;margin:0 auto 48px;
  line-height:1.9;
  animation:fadeUp .8s .3s ease both;
}
.hero-btns{
  display:flex;gap:16px;justify-content:center;flex-wrap:wrap;
  animation:fadeUp .8s .4s ease both;
  position:relative;
}
.btn-primary{
  background:var(--cyan);color:var(--bg);
  padding:16px 40px;border-radius:6px;
  font-size:15px;font-weight:700;text-decoration:none;
  letter-spacing:.04em;transition:all .25s;
  display:inline-flex;align-items:center;gap:8px;
  box-shadow:0 4px 20px rgba(0,120,200,.2);
}
.btn-primary:hover{background:#005fa0;transform:translateY(-2px);box-shadow:0 4px 30px rgba(0,120,200,.35)}
.btn-secondary{
  border:1px solid var(--border2);color:var(--cyan);
  padding:16px 32px;border-radius:6px;
  font-size:15px;font-weight:500;text-decoration:none;
  letter-spacing:.04em;transition:all .25s;
  backdrop-filter:blur(10px);
}
.btn-secondary:hover{background:var(--cyan3);transform:translateY(-2px)}

.hero-stats{
  display:flex;gap:48px;justify-content:center;
  margin-top:72px;
  position:relative;
  animation:fadeUp .8s .5s ease both;
  flex-wrap:wrap;
}
.hero-stat{text-align:center}
.hero-stat-v{
  font-family:'DM Mono',monospace;
  font-size:clamp(28px,4vw,48px);
  font-weight:500;
  color:var(--cyan);
  line-height:1;
}
.hero-stat-l{font-size:12px;color:var(--ink3);margin-top:6px;letter-spacing:.06em}

@keyframes fadeUp{from{opacity:0;transform:translateY(24px)}to{opacity:1;transform:translateY(0)}}

/* ── SECTION BASE ── */
.section{padding:100px 40px;max-width:1100px;margin:0 auto;position:relative;z-index:1}
.section-full{padding:100px 40px;position:relative;z-index:1}
.s-label{
  font-size:11px;font-weight:700;letter-spacing:.14em;
  color:var(--cyan);text-transform:uppercase;
  margin-bottom:16px;
}
.s-title{
  font-family:'Noto Serif JP',serif;
  font-size:clamp(24px,3.5vw,42px);
  font-weight:700;line-height:1.3;
  margin-bottom:16px;
}
.s-desc{
  font-size:15px;color:var(--ink2);
  max-width:600px;line-height:1.9;
}

/* ── PROBLEM ── */
.problem-bg{
  background:linear-gradient(180deg,var(--bg) 0%,var(--bg2) 50%,var(--bg) 100%);
}
.problem-grid{
  display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));
  gap:20px;margin-top:56px;
}
.problem-card{
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:12px;padding:28px;
  position:relative;overflow:hidden;
  transition:all .3s;
}
.problem-card:hover{border-color:rgba(0,210,255,.2);background:var(--surface2);transform:translateY(-2px)}
.problem-card::before{
  content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,transparent,var(--red),transparent);
  opacity:.6;
}
.problem-icon{font-size:28px;margin-bottom:14px}
.problem-title{font-size:15px;font-weight:700;margin-bottom:8px;color:var(--ink)}
.problem-text{font-size:13px;color:var(--ink3);line-height:1.8}

/* ── FEATURES ── */
.features-grid{
  display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));
  gap:24px;margin-top:56px;
}
.feature-card{
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:12px;padding:32px;
  transition:all .3s;position:relative;overflow:hidden;
}
.feature-card::after{
  content:'';position:absolute;
  inset:0;border-radius:12px;
  background:radial-gradient(circle at top left,var(--cyan4),transparent 60%);
  opacity:0;transition:opacity .3s;
}
.feature-card:hover{border-color:var(--border2);transform:translateY(-3px);box-shadow:0 8px 40px rgba(0,210,255,.08)}
.feature-card:hover::after{opacity:1}
.feature-num{
  font-family:'DM Mono',monospace;
  font-size:11px;color:var(--cyan);
  letter-spacing:.1em;margin-bottom:14px;
}
.feature-icon{
  width:48px;height:48px;border-radius:10px;
  background:var(--cyan3);border:1px solid var(--border2);
  display:flex;align-items:center;justify-content:center;
  font-size:22px;margin-bottom:18px;position:relative;z-index:1;
}
.feature-title{font-size:17px;font-weight:700;margin-bottom:10px;position:relative;z-index:1}
.feature-text{font-size:13px;color:var(--ink3);line-height:1.85;position:relative;z-index:1}
.feature-tag{
  display:inline-block;margin-top:14px;
  background:var(--cyan4);border:1px solid var(--border2);
  color:var(--cyan);padding:3px 10px;border-radius:100px;
  font-size:11px;font-weight:600;letter-spacing:.04em;
  position:relative;z-index:1;
}
.feature-tag.api{background:rgba(0,229,170,.08);border-color:rgba(0,229,170,.25);color:var(--green)}
.feature-tag.free{background:rgba(212,169,106,.08);border-color:rgba(212,169,106,.25);color:var(--gold)}

/* ── HOW IT WORKS ── */
.howto-bg{
  background:var(--bg2);
  border-top:1px solid var(--border);
  border-bottom:1px solid var(--border);
}
.steps{
  display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
  gap:0;margin-top:56px;
  position:relative;
}
.steps::before{
  content:'';position:absolute;top:28px;left:15%;right:15%;height:1px;
  background:linear-gradient(90deg,transparent,var(--border2),var(--border2),transparent);
}
.step{
  text-align:center;padding:0 24px;
  position:relative;
}
.step-num{
  width:56px;height:56px;border-radius:50%;
  background:var(--bg3);border:2px solid var(--cyan);
  display:flex;align-items:center;justify-content:center;
  font-family:'DM Mono',monospace;font-size:16px;font-weight:500;color:var(--cyan);
  margin:0 auto 20px;
  box-shadow:0 2px 10px rgba(0,120,200,.15);
  position:relative;z-index:1;
}
.step-title{font-size:16px;font-weight:700;margin-bottom:8px}
.step-text{font-size:13px;color:var(--ink3);line-height:1.8}
.step-sub{
  font-size:11px;color:var(--cyan);margin-top:8px;
  font-weight:600;letter-spacing:.04em;
}

/* ── SPEC TABLE ── */
.spec-bg{background:var(--bg)}
.spec-grid{
  display:grid;grid-template-columns:1fr 1fr;
  gap:16px;margin-top:48px;
}
@media(max-width:640px){.spec-grid{grid-template-columns:1fr}}
.spec-card{
  background:var(--surface);border:1px solid var(--border);
  border-radius:10px;padding:24px;
}
.spec-card-title{
  font-size:12px;font-weight:700;letter-spacing:.08em;
  color:var(--cyan);text-transform:uppercase;margin-bottom:16px;
  padding-bottom:10px;border-bottom:1px solid var(--border);
}
.spec-row{
  display:flex;justify-content:space-between;align-items:baseline;
  padding:7px 0;border-bottom:1px solid rgba(255,255,255,.04);
  font-size:13px;
}
.spec-row:last-child{border:none}
.spec-key{color:var(--ink3)}
.spec-val{color:var(--ink);font-weight:500;text-align:right;font-family:'DM Mono',monospace;font-size:12px}
.spec-val.ok{color:var(--green)}
.spec-val.api{color:var(--cyan)}

/* ── COST ── */
.cost-wrap{
  background:var(--surface);border:1px solid var(--border2);
  border-radius:16px;padding:40px;margin-top:48px;
  display:grid;grid-template-columns:1fr 1fr;gap:32px;
  position:relative;overflow:hidden;
}
.cost-wrap::before{
  content:'';position:absolute;top:-40px;right:-40px;
  width:200px;height:200px;border-radius:50%;
  background:radial-gradient(circle,rgba(0,120,200,.07),transparent 70%);
}
@media(max-width:640px){.cost-wrap{grid-template-columns:1fr}}
.cost-item-title{
  font-size:12px;letter-spacing:.08em;color:var(--ink3);
  text-transform:uppercase;margin-bottom:16px;
}
.cost-amount{
  font-family:'DM Mono',monospace;
  font-size:36px;font-weight:500;
  line-height:1;margin-bottom:6px;
}
.cost-amount.free{color:var(--green)}
.cost-amount.paid{color:var(--cyan)}
.cost-note{font-size:12px;color:var(--ink3)}
.cost-list{margin-top:16px;display:flex;flex-direction:column;gap:8px}
.cost-list-item{
  display:flex;align-items:center;gap:8px;
  font-size:13px;color:var(--ink2);
}
.cost-list-item::before{
  content:'✓';color:var(--green);font-weight:700;font-size:12px;flex-shrink:0;
}

/* ── SECURITY ── */
.security-bg{
  background:var(--bg2);
  border-top:1px solid var(--border);
  border-bottom:1px solid var(--border);
}
.security-grid{
  display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));
  gap:20px;margin-top:48px;
}
.security-card{
  background:var(--surface);border:1px solid var(--border);
  border-radius:10px;padding:24px;text-align:center;
}
.security-icon{font-size:30px;margin-bottom:12px}
.security-title{font-size:14px;font-weight:700;margin-bottom:6px}
.security-text{font-size:12px;color:var(--ink3);line-height:1.7}

/* ── CTA ── */
.cta-bg{
  text-align:center;
  background:linear-gradient(180deg,var(--bg) 0%,var(--bg2) 100%);
}
.cta-box{
  background:var(--surface);
  border:1px solid var(--border2);
  border-radius:20px;padding:64px 40px;
  max-width:760px;margin:0 auto;
  position:relative;overflow:hidden;
}
.cta-box::before{
  content:'';position:absolute;top:-60px;left:50%;transform:translateX(-50%);
  width:400px;height:200px;
  background:radial-gradient(ellipse,rgba(0,120,200,.09),transparent 70%);
  pointer-events:none;
}
.cta-title{
  font-family:'Noto Serif JP',serif;
  font-size:clamp(22px,3.5vw,38px);
  font-weight:700;margin-bottom:16px;position:relative;
}
.cta-desc{font-size:14px;color:var(--ink3);max-width:500px;margin:0 auto 36px;line-height:1.9}

/* ── FOOTER ── */
footer{
  border-top:1px solid var(--border);
  padding:48px 48px;
  display:flex;align-items:center;justify-content:space-between;
  flex-wrap:wrap;gap:24px;
  position:relative;z-index:1;
}
.footer-logo{display:flex;align-items:center;gap:12px}
.footer-logo img{height:40px;}
.footer-info{font-size:12px;color:var(--ink3);line-height:1.7}
.footer-info strong{color:var(--ink2);display:block;margin-bottom:2px}
.footer-right{font-size:11px;color:var(--ink3);text-align:right}

/* ── DIVIDER ── */
.divider{
  height:1px;
  background:linear-gradient(90deg,transparent,var(--border2),transparent);
  margin:0 auto;max-width:800px;opacity:.6;
}

/* ── SCROLL ANIMATION ── */
.reveal{opacity:0;transform:translateY(28px);transition:opacity .7s ease,transform .7s ease}
.reveal.visible{opacity:1;transform:translateY(0)}

/* ── RESPONSIVE ── */
@media(max-width:768px){
  nav{padding:0 20px}
  .nav-links{display:none}
  .hero{padding:100px 20px 60px}
  .hero-stats{gap:28px}
  .steps::before{display:none}
  footer{padding:32px 20px;flex-direction:column}
  .footer-right{text-align:left}
}
</style>
</head>
<body>

<!-- NAV -->
<nav>
  <a class="nav-logo" href="https://surc.online/" target="_blank" rel="noopener">
    <img src="data:image/png;base64,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" alt="サーコミュニケーション">
    <span class="nav-logo-text">一般社団法人 サーコミュニケーション</span>
  </a>
  <div class="nav-links">
    <a href="#features">機能</a>
    <a href="#howto">使い方</a>
    <a href="#spec">仕様</a>
    <a href="#cost">料金</a>
    <a href="#contact">お問い合わせ</a>
  </div>
  <a class="nav-cta" href="https://surc.online/" target="_blank" rel="noopener">導入を相談する</a>
</nav>

<!-- HERO -->
<section class="hero">
  <div class="hero-bg-ring"></div>
  <div class="hero-bg-ring"></div>
  <div class="hero-bg-ring"></div>
  <div class="hero-glow"></div>

  <div class="hero-badge">Claude AI × TKC経理自動化</div>

  <h1 class="hero-title">
    月次経理を、<br><span>自動化する。</span>
  </h1>
  <p class="hero-sub-title">AI 仕訳インポートツール</p>
  <p class="hero-desc">
    銀行明細・クレジットカード・月末定型仕訳を自動変換。<br>
    TKC・freee会計に対応したインポートCSVをワンクリックで生成します。弥生会計・マネーフォワード対応版も開発中。
  </p>
  <div class="hero-btns">
    <a class="btn-primary" href="tool.html" target="_blank">&#9654;&#xFE0E; 今すぐ無料で試す</a>
    <a class="btn-secondary" href="#features">機能を見る</a>
    <a class="btn-secondary" href="https://surc.online/" target="_blank" rel="noopener" style="border-color:rgba(0,120,200,.2)">導入を相談する</a>
  </div>

  <div class="hero-stats">
    <div class="hero-stat">
      <div class="hero-stat-v">90<span style="font-size:.5em;color:var(--ink3)">分</span></div>
      <div class="hero-stat-l">→ 約 15 分に短縮</div>
    </div>
    <div class="hero-stat" style="border-left:1px solid var(--border);border-right:1px solid var(--border);padding:0 48px">
      <div class="hero-stat-v">52<span style="font-size:.5em;color:var(--ink3)">件</span></div>
      <div class="hero-stat-l">定型仕訳 自動生成</div>
    </div>
    <div class="hero-stat">
      <div class="hero-stat-v">6<span style="font-size:.5em;color:var(--ink3)">口座</span></div>
      <div class="hero-stat-l">銀行CSV 同時対応</div>
    </div>
  </div>
</section>

<!-- PROBLEM -->

<!-- SUPPORTED SOFTWARE -->
<div style="background:#fff;border-top:1px solid rgba(0,0,0,.07);border-bottom:1px solid rgba(0,0,0,.07)">
  <div class="section reveal" style="padding-top:72px;padding-bottom:72px">
    <p class="s-label">Supported Software</p>
    <h2 class="s-title">TKCとfreee会計に対応。<br>弥生・マネーフォワードも開発中。</h2>
    <p class="s-desc" style="max-width:700px">本ツールはTKCの仕訳インポート形式に加え、freee会計の取引インポート形式（18列CSV）にも対応しています。弥生会計・マネーフォワードクラウドについても順次対応予定です。</p>

    <div style="display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;margin-top:40px">

      <!-- TKC: 対応済み -->
      <div style="background:#f0f6ff;border:2px solid rgba(0,120,200,.3);border-radius:12px;padding:24px;position:relative;overflow:hidden">
        <div style="position:absolute;top:0;left:0;right:0;height:3px;background:#0078c8"></div>
        <div style="position:absolute;top:12px;right:12px;background:#0078c8;color:#fff;font-size:10px;font-weight:700;padding:2px 8px;border-radius:20px;letter-spacing:.04em">対応済み</div>
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">
          <div style="width:40px;height:40px;border-radius:8px;background:#fff;border:1px solid rgba(0,120,200,.2);display:flex;align-items:center;justify-content:center;font-weight:700;font-size:13px;color:#0078c8">TKC</div>
          <div>
            <div style="font-size:13px;font-weight:700;color:#1a1a1a">TKC</div>
            <div style="font-size:11px;color:#999">税理士向け会計システム</div>
          </div>
        </div>
        <div style="font-size:12px;color:#555;line-height:1.8;margin-bottom:14px">税理士事務所・法人で広く使われる高機能会計システム。独自の29カラムCSV形式でのインポートに完全対応。銀行明細・カード・定型仕訳をワンクリックで生成します。</div>
        <div style="background:#0078c8;border-radius:6px;padding:8px 10px;font-size:11px;color:#fff;font-weight:600;text-align:center">✓ 29カラム形式CSV 完全対応</div>
      </div>

      <!-- 弥生: 開発対応 -->
      <div style="background:#f8f7f4;border:1px solid #e2dfd8;border-radius:12px;padding:24px;position:relative;overflow:hidden">
        <div style="position:absolute;top:0;left:0;right:0;height:3px;background:#e0ddd5"></div>
        <div style="position:absolute;top:12px;right:12px;background:#f0ede8;color:#888;font-size:10px;font-weight:700;padding:2px 8px;border-radius:20px;letter-spacing:.04em">開発対応</div>
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">
          <div style="width:40px;height:40px;border-radius:8px;background:#fff3ee;border:1px solid #fdd;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:13px;color:#e85a10">弥生</div>
          <div>
            <div style="font-size:13px;font-weight:700;color:#1a1a1a">弥生会計</div>
            <div style="font-size:11px;color:#999">シェア 55.4%（国内1位）</div>
          </div>
        </div>
        <div style="font-size:12px;color:#777;line-height:1.8;margin-bottom:14px">国内26年連続売上1位の定番ソフト。独自の弥生インポート形式CSVが必要。外部AIとの直接連携は非搭載のため、専用ツールを開発します。</div>
        <div style="background:#f0ede8;border-radius:6px;padding:8px 10px;font-size:11px;color:#888;font-weight:600;text-align:center">ご依頼に応じてAI開発</div>
      </div>

      <!-- freee: 対応済み -->
      <div style="background:#f0f6ff;border:2px solid rgba(0,120,200,.3);border-radius:12px;padding:24px;position:relative;overflow:hidden">
        <div style="position:absolute;top:0;left:0;right:0;height:3px;background:#0078c8"></div>
        <div style="position:absolute;top:12px;right:12px;background:#0078c8;color:#fff;font-size:10px;font-weight:700;padding:2px 8px;border-radius:20px;letter-spacing:.04em">対応済み</div>
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">
          <div style="width:40px;height:40px;border-radius:8px;background:#e8fdf6;border:1px solid #b2f0df;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:13px;color:#00b894">f</div>
          <div>
            <div style="font-size:13px;font-weight:700;color:#1a1a1a">freee会計</div>
            <div style="font-size:11px;color:#999">シェア 24.0%（国内2位）</div>
          </div>
        </div>
        <div style="font-size:12px;color:#555;line-height:1.8;margin-bottom:14px">個人事業主・中小企業に人気のクラウド会計。取引インポート形式（18列CSV）に対応済み。実機テスト完了。</div>
        <div style="background:#0078c8;border-radius:6px;padding:8px 10px;font-size:11px;color:#fff;font-weight:600;text-align:center">✓ 18列CSV形式 対応済み</div>
      </div>

      <!-- マネーフォワード: 開発対応 -->
      <div style="background:#f8f7f4;border:1px solid #e2dfd8;border-radius:12px;padding:24px;position:relative;overflow:hidden">
        <div style="position:absolute;top:0;left:0;right:0;height:3px;background:#e0ddd5"></div>
        <div style="position:absolute;top:12px;right:12px;background:#f0ede8;color:#888;font-size:10px;font-weight:700;padding:2px 8px;border-radius:20px;letter-spacing:.04em">開発対応</div>
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">
          <div style="width:40px;height:40px;border-radius:8px;background:#e8f0ff;border:1px solid #b8d0ff;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:11px;color:#0066cc">MF</div>
          <div>
            <div style="font-size:13px;font-weight:700;color:#1a1a1a">マネーフォワード</div>
            <div style="font-size:11px;color:#999">シェア 14.3%（国内3位）</div>
          </div>
        </div>
        <div style="font-size:12px;color:#777;line-height:1.8;margin-bottom:14px">2,300以上の金融機関連携が強みのクラウド会計。仕訳インポートは独自CSV形式が必要で、外部AIからの直接書込みは不可。専用ツールを開発します。</div>
        <div style="background:#f0ede8;border-radius:6px;padding:8px 10px;font-size:11px;color:#888;font-weight:600;text-align:center">ご依頼に応じてAI開発</div>
      </div>

    </div>

    <div style="margin-top:20px;background:#fff;border:1px solid rgba(0,120,200,.18);border-radius:10px;padding:20px 24px;display:flex;align-items:flex-start;gap:14px">
      <span style="font-size:22px;flex-shrink:0;margin-top:2px">🤖</span>
      <div>
        <div style="font-size:13px;font-weight:700;color:#1a1a1a;margin-bottom:4px">主要な会計ソフトに順次対応中</div>
        <p style="font-size:13px;color:#666;line-height:1.8;margin:0">これらの会計ソフトはセキュリティ上の理由から外部AIとの直接連携が制限されています。本ツールはAIが生成した仕訳を各ソフト専用のCSVに変換してインポートする方式で、この制約を解決します。TKC・freee会計は対応済みです。弥生・マネーフォワードをお使いの場合は、貴社のソフト仕様・勘定科目・インポート形式をヒアリングしたうえで、担当コンサルタントとAIが専用ツールを開発・納品します。<a href="https://surc.online/" target="_blank" rel="noopener" style="color:#0078c8;font-weight:600;margin-left:4px">まずはご相談ください →</a></p>
      </div>
    </div>
  </div>
</div>

<div class="problem-bg section-full"id="problem">
  <div class="section" style="padding-top:0;padding-bottom:0">
    <p class="s-label">Problem</p>
    <h2 class="s-title">こんな悩み、ありませんか？</h2>
    <p class="s-desc">会計ソフトへの月次入力では、多くの手作業が発生しています。</p>
    <div class="problem-grid reveal">
      <div class="problem-card">
        <div class="problem-icon">📋</div>
        <div class="problem-title">銀行明細の仕訳が大変</div>
        <div class="problem-text">複数口座のCSVをダウンロードし、1件ずつ勘定科目を確認しながら入力。毎月同じ作業の繰り返しです。</div>
      </div>
      <div class="problem-card">
        <div class="problem-icon">💳</div>
        <div class="problem-title">カード明細の処理が複雑</div>
        <div class="problem-text">法人カードの明細をPDFで受け取り、手入力で会計ソフトへ。引落仕訳と明細展開の2ステップ処理はミスが起きやすい。</div>
      </div>
      <div class="problem-card">
        <div class="problem-icon">🔁</div>
        <div class="problem-title">毎月同じ定型仕訳を繰り返す</div>
        <div class="problem-text">給与・減価償却・家賃・社会保険料など、毎月ほぼ同じ仕訳を手作業で入力。単純作業に時間を取られています。</div>
      </div>
    </div>
  </div>
</div>

<div class="divider"></div>


<!-- CONCEPT: 1次情報をまとめてアップ -->
<div style="background:#fff;border-top:1px solid rgba(0,0,0,.07);border-bottom:1px solid rgba(0,0,0,.07)">
  <div class="section" style="padding-top:80px;padding-bottom:80px;max-width:1000px">
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:48px;align-items:center">
      <div>
        <p class="s-label">Concept</p>
        <h2 class="s-title">１次情報を<br>まとめてアップロードする</h2>
        <p style="font-size:15px;color:var(--ink2);line-height:1.9;margin-top:16px">
          銀行やカード会社から届く取引の生データ（１次情報）を、そのままAIが会計の言葉に翻訳し、お使いの会計ソフトへ送り込みます。<br><br>
          人間がこれまで担っていた「読み取り・分類・入力」という翻訳作業を自動化することで、<strong>データが会計ソフトに正確に入力された状態</strong>を、ほぼ手間なく実現します。
        </p>
        <div style="margin-top:24px;display:flex;flex-direction:column;gap:10px">
          <div style="display:flex;align-items:center;gap:10px;font-size:13px;color:var(--ink2)">
            <span style="width:28px;height:28px;background:var(--cyan-bg);border:1px solid rgba(0,120,200,.2);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:var(--cyan);flex-shrink:0">✓</span>
            銀行・カード明細はこれまで通り届く
          </div>
          <div style="display:flex;align-items:center;gap:10px;font-size:13px;color:var(--ink2)">
            <span style="width:28px;height:28px;background:var(--cyan-bg);border:1px solid rgba(0,120,200,.2);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:var(--cyan);flex-shrink:0">✓</span>
            AIが自動で仕訳・勘定科目に変換
          </div>
          <div style="display:flex;align-items:center;gap:10px;font-size:13px;color:var(--ink2)">
            <span style="width:28px;height:28px;background:var(--green-bg);border:1px solid rgba(26,96,64,.2);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:var(--green);flex-shrink:0">→</span>
            会計ソフトにCSVをアップロード、<strong>完了</strong>
          </div>
        </div>
      </div>
      <div>
        <div style="background:#f8f7f4;border:1px solid #e2dfd8;border-radius:16px;padding:28px">
          <div style="font-size:11px;font-weight:700;color:#aaa;letter-spacing:.08em;margin-bottom:16px">WORKFLOW</div>
          <div style="display:flex;flex-direction:column;gap:0">
            <div style="background:#fff;border:1px solid #e2dfd8;border-radius:8px;padding:12px 16px;display:flex;align-items:center;gap:12px">
              <span style="font-size:20px">📄</span>
              <div><div style="font-size:12px;font-weight:700">銀行明細CSV</div><div style="font-size:11px;color:#aaa">各銀行からダウンロード</div></div>
            </div>
            <div style="display:flex;align-items:center;gap:8px;padding:6px 16px">
              <div style="width:1px;height:20px;background:#e2dfd8;margin-left:10px"></div>
            </div>
            <div style="background:#fff;border:1px solid #e2dfd8;border-radius:8px;padding:12px 16px;display:flex;align-items:center;gap:12px">
              <span style="font-size:20px">💳</span>
              <div><div style="font-size:12px;font-weight:700">クレジットカード明細</div><div style="font-size:11px;color:#aaa">画像・PDFをドロップ → AI読取</div></div>
            </div>
            <div style="display:flex;align-items:center;gap:8px;padding:6px 16px">
              <div style="width:1px;height:20px;background:#e2dfd8;margin-left:10px"></div>
            </div>
            <div style="background:#fff;border:1px solid #e2dfd8;border-radius:8px;padding:12px 16px;display:flex;align-items:center;gap:12px">
              <span style="font-size:20px">📅</span>
              <div><div style="font-size:12px;font-weight:700">月末定型仕訳</div><div style="font-size:11px;color:#aaa">給与・減価償却など自動生成</div></div>
            </div>
            <div style="display:flex;align-items:center;gap:8px;padding:6px 16px">
              <div style="width:1px;height:20px;background:rgba(0,120,200,.3);margin-left:10px"></div>
              <span style="font-size:10px;color:var(--cyan);font-weight:700">AI が変換</span>
            </div>
            <div style="background:var(--cyan);border-radius:8px;padding:12px 16px;display:flex;align-items:center;gap:12px">
              <span style="font-size:20px">⬇</span>
              <div><div style="font-size:12px;font-weight:700;color:#fff">会計ソフトへCSVアップロード</div><div style="font-size:11px;color:rgba(255,255,255,.7)">TKC・freee に対応（弥生・MF 開発中）</div></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<div id="features">
  <div class="section reveal">
    <p class="s-label">Features</p>
    <h2 class="s-title">3つの自動化機能</h2>
    <p class="s-desc">月次経理の主要な作業を自動化。ブラウザだけで動作し、インストール不要です。</p>
    <div class="features-grid">
      <div class="feature-card">
        <div class="feature-num">01</div>
        <div class="feature-icon">🏦</div>
        <h3 class="feature-title">銀行明細 → 仕訳自動変換</h3>
        <p class="feature-text">銀行CSVをドラッグ＆ドロップするだけ。取引先名からルールベースで自動判定し、売掛金・未払費用・給与振込などを即座に仕訳します。API不要・完全無料で動作します。</p>
        <span class="feature-tag free">無料・API不要</span>
      </div>
      <div class="feature-card">
        <div class="feature-num">02</div>
        <div class="feature-icon">💳</div>
        <h3 class="feature-title">クレジットカード明細 AI読取</h3>
        <p class="feature-text">法人カードの明細画像やPDFをドロップするとClaude AIが自動読取。引落仕訳（STEP1）と明細展開（STEP2）の2ステップ仕訳を自動生成。ガソリン代は複数カードを合算して1行に。</p>
        <span class="feature-tag api">Claude AI 使用</span>
      </div>
      <div class="feature-card">
        <div class="feature-num">03</div>
        <div class="feature-icon">📅</div>
        <h3 class="feature-title">月末定型仕訳 自動生成</h3>
        <p class="feature-text">給与手当・減価償却費・地代家賃・通勤費・法定福利費など52件の定型仕訳を毎月自動生成。金額・課税区分・事業CDも個別に変更・保存できます。</p>
        <span class="feature-tag free">無料・API不要</span>
      </div>
    </div>
  </div>
</div>

<div class="howto-bg section-full" id="howto">
  <div class="section reveal" style="padding-top:0;padding-bottom:0">
    <p class="s-label">How it works</p>
    <h2 class="s-title">3ステップで完了</h2>
    <p class="s-desc">複雑な設定は不要。ブラウザを開いてデータをドロップするだけです。</p>
    <div class="steps">
      <div class="step">
        <div class="step-num">01</div>
        <h3 class="step-title">データを読み込む</h3>
        <p class="step-text">銀行CSVをドラッグ＆ドロップ、またはカード明細画像をアップロード</p>
        <p class="step-sub">自動識別 / 複数同時OK</p>
      </div>
      <div class="step">
        <div class="step-num">02</div>
        <h3 class="step-title">仕訳を確認・修正</h3>
        <p class="step-text">自動判定された仕訳を一覧で確認。勘定科目・事業CD・摘要を1クリックで変更</p>
        <p class="step-sub">AIが90%以上を自動判定</p>
      </div>
      <div class="step">
        <div class="step-num">03</div>
        <h3 class="step-title">CSVを出力 → 会計ソフトへ</h3>
        <p class="step-text">「全仕訳CSV出力」ボタンで各会計ソフト形式のCSVを生成。そのままインポート可能</p>
        <p class="step-sub">TKC 29カラム完全対応</p>
      </div>
    </div>
  </div>
</div>

<div id="spec">
  <div class="section reveal">
    <p class="s-label">Specification</p>
    <h2 class="s-title">対応仕様</h2>
    <div class="spec-grid">
      <div class="spec-card">
        <div class="spec-card-title">対応銀行・口座</div>
        <div class="spec-row"><span class="spec-key">三菱UFJ（総務）</span><span class="spec-val ok">✓</span></div>
        <div class="spec-row"><span class="spec-key">三菱UFJ（拠点口座）</span><span class="spec-val ok">✓ 4拠点</span></div>
        <div class="spec-row"><span class="spec-key">三菱UFJ（物流）</span><span class="spec-val ok">✓</span></div>
        <div class="spec-row"><span class="spec-key">ゆうちょ銀行</span><span class="spec-val ok">✓</span></div>
        <div class="spec-row"><span class="spec-key">最大同時読込</span><span class="spec-val">6口座</span></div>
      </div>
      <div class="spec-card">
        <div class="spec-card-title">クレジットカード</div>
        <div class="spec-row"><span class="spec-key">対応形式</span><span class="spec-val">画像 / PDF</span></div>
        <div class="spec-row"><span class="spec-key">AI読取エンジン</span><span class="spec-val api">Claude API</span></div>
        <div class="spec-row"><span class="spec-key">複数カード</span><span class="spec-val ok">✓ 同時対応</span></div>
        <div class="spec-row"><span class="spec-key">ガソリン代合算</span><span class="spec-val ok">✓ 自動</span></div>
        <div class="spec-row"><span class="spec-key">仕訳方式</span><span class="spec-val">2ステップ</span></div>
      </div>
      <div class="spec-card">
        <div class="spec-card-title">CSV出力仕様（TKC）</div>
        <div class="spec-row"><span class="spec-key">カラム数</span><span class="spec-val">29列</span></div>
        <div class="spec-row"><span class="spec-key">日付形式</span><span class="spec-val">令和 (YMMDD)</span></div>
        <div class="spec-row"><span class="spec-key">実際の仕入年月日</span><span class="spec-val ok">✓ 対応</span></div>
        <div class="spec-row"><span class="spec-key">文字コード</span><span class="spec-val">UTF-8 (BOM)</span></div>
        <div class="spec-row"><span class="spec-key">TKCインポート</span><span class="spec-val ok">✓ 直接可能</span></div>
      </div>
      <div class="spec-card">
        <div class="spec-card-title">動作環境</div>
        <div class="spec-row"><span class="spec-key">インストール</span><span class="spec-val ok">不要</span></div>
        <div class="spec-row"><span class="spec-key">対応ブラウザ</span><span class="spec-val">Chrome / Edge</span></div>
        <div class="spec-row"><span class="spec-key">データ保存先</span><span class="spec-val">ブラウザのみ</span></div>
        <div class="spec-row"><span class="spec-key">外部サーバー送信</span><span class="spec-val ok">なし *</span></div>
        <div class="spec-row"><span class="spec-key">オフライン</span><span class="spec-val">一部可能</span></div>
      </div>
    </div>
    <p style="font-size:11px;color:var(--ink3);margin-top:12px">* カード明細のAI読取時のみ、Anthropic APIへ画像データが送信されます。</p>
  </div>
</div>

<div class="section-full security-bg" id="cost">
  <div class="section reveal" style="padding-top:0;padding-bottom:0">
    <p class="s-label">Cost</p>
    <h2 class="s-title">利用コスト</h2>
    <p class="s-desc">ほとんどの機能は無料で利用可能。AI読取機能のみ従量課金です。</p>
    <div class="cost-wrap">
      <div>
        <div class="cost-item-title">銀行明細 / 定型仕訳</div>
        <div class="cost-amount free">¥0</div>
        <div class="cost-note">完全無料 / APIキー不要</div>
        <div class="cost-list">
          <div class="cost-list-item">月末定型仕訳 52件 自動生成</div>
          <div class="cost-list-item">銀行CSV → 仕訳変換（6口座）</div>
          <div class="cost-list-item">TKC 29カラムCSV出力</div>
          <div class="cost-list-item">ブラウザのみで動作</div>
        </div>
      </div>
      <div>
        <div class="cost-item-title">カード明細 AI読取</div>
        <div class="cost-amount paid">約 ¥5</div>
        <div class="cost-note">1回あたりの目安（月1回利用で年間約60円）</div>
        <div class="cost-list">
          <div class="cost-list-item">Anthropic APIキーが必要</div>
          <div class="cost-list-item">画像・PDF → 自動仕訳</div>
          <div class="cost-list-item">初回登録で$5クレジット付与</div>
          <div class="cost-list-item">APIキーは自社管理（安全）</div>
        </div>
      </div>
    </div>
  </div>
</div>

<div class="security-bg section-full" style="border-top:1px solid var(--border)">
  <div class="section reveal" style="padding-top:0;padding-bottom:0">
    <p class="s-label">Security & Privacy</p>
    <h2 class="s-title">セキュリティ</h2>
    <div class="security-grid">
      <div class="security-card">
        <div class="security-icon">🔒</div>
        <div class="security-title">データはブラウザ内のみ</div>
        <div class="security-text">銀行CSVや仕訳データは外部サーバーに送信されません。すべてブラウザ内で処理されます。</div>
      </div>
      <div class="security-card">
        <div class="security-icon">🔑</div>
        <div class="security-title">APIキーは自社管理</div>
        <div class="security-text">Anthropic APIキーはブラウザのlocalStorageに保存。第三者が参照することはできません。</div>
      </div>
      <div class="security-card">
        <div class="security-icon">📡</div>
        <div class="security-title">AI通信は暗号化済み</div>
        <div class="security-text">カード明細のAI読取時はHTTPS通信。Cloudflare Workers経由でAnthropicと安全に通信します。</div>
      </div>
      <div class="security-card">
        <div class="security-icon">🖥</div>
        <div class="security-title">インストール不要</div>
        <div class="security-text">Webブラウザで動作するため、PCへのソフトウェアインストールは一切不要です。</div>
      </div>
    </div>
  </div>
</div>


<!-- TRIAL CTA -->
<div style="background:var(--cyan);padding:48px 40px;text-align:center">
  <p style="font-size:12px;font-weight:700;letter-spacing:.1em;color:rgba(255,255,255,.7);text-transform:uppercase;margin-bottom:12px">Free Trial</p>
  <h2 style="font-family:'Noto Serif JP',serif;font-size:clamp(22px,3vw,36px);font-weight:700;color:#fff;margin-bottom:12px;letter-spacing:-.01em">今すぐ無料で試してみる</h2>
  <p style="font-size:14px;color:rgba(255,255,255,.8);margin-bottom:28px;line-height:1.8;max-width:560px;margin-left:auto;margin-right:auto">
    TKC・freee会計対応版を無料公開中。インストール不要・ブラウザだけで動作します。<br>
    弥生会計・マネーフォワード対応版は順次リリース予定です。
  </p>
  <div style="display:flex;gap:12px;justify-content:center;flex-wrap:wrap;margin-bottom:20px">
    <a href="tool.html" target="_blank" style="background:#fff;color:var(--cyan);padding:14px 36px;border-radius:8px;font-size:15px;font-weight:700;text-decoration:none;display:inline-flex;align-items:center;gap:8px;transition:all .2s" onmouseover="this.style.background='#f0f8ff'" onmouseout="this.style.background='#fff'">
      ▶ 今すぐ試す（無料）
    </a>
  </div>
  <div style="display:flex;gap:20px;justify-content:center;flex-wrap:wrap">
    <div style="display:flex;align-items:center;gap:6px;font-size:12px;color:rgba(255,255,255,.75)">
      <span style="font-size:16px">弥生</span>
      <span style="font-size:10px;background:rgba(255,255,255,.2);padding:2px 8px;border-radius:20px">実装予定</span>
    </div>
    <div style="display:flex;align-items:center;gap:6px;font-size:12px;color:rgba(255,255,255,.75)">
      <span style="font-size:16px">freee</span>
      <span style="font-size:10px;background:#fff;color:#0078c8;padding:2px 8px;border-radius:20px;font-weight:700">✓ 対応済み</span>
    </div>
    <div style="display:flex;align-items:center;gap:6px;font-size:12px;color:rgba(255,255,255,.75)">
      <span style="font-size:16px">MF</span>
      <span style="font-size:10px;background:rgba(255,255,255,.2);padding:2px 8px;border-radius:20px">実装予定</span>
    </div>
  </div>
</div>

<!-- CONSULTING -->
<div style="background:#f8f7f4;border-top:1px solid rgba(0,0,0,.08)">
  <div class="section reveal" style="padding-top:80px;padding-bottom:80px">
    <p class="s-label">Consulting & Customization</p>
    <h2 class="s-title">コンサルタントと協働しながら<br>貴社に合わせた改善を</h2>
    <p class="s-desc" style="max-width:700px">どんなに優れたツールも、使う組織に合わせて設定・調整することで初めて真価を発揮します。私たちは導入後も担当コンサルタントが伴走し、貴社の勘定科目・事業コード・業務フローに最適化された経理自動化を実現します。</p>
    <div style="display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:20px;margin-top:48px">
      <div style="background:#fff;border:1px solid #e2dfd8;border-radius:12px;padding:28px">
        <div style="width:44px;height:44px;border-radius:10px;background:#e8f2ff;border:1px solid rgba(0,120,200,.15);display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:16px">🔍</div>
        <h3 style="font-size:15px;font-weight:700;margin-bottom:10px;color:#1a1a1a">現状分析・ヒアリング</h3>
        <p style="font-size:13px;color:#777;line-height:1.8">現在の月次経理フロー・会計ソフト設定・勘定科目体系を詳しくヒアリング。どこに工数がかかっているかを数値で把握します。</p>
      </div>
      <div style="background:#fff;border:1px solid #e2dfd8;border-radius:12px;padding:28px">
        <div style="width:44px;height:44px;border-radius:10px;background:#e8f2ff;border:1px solid rgba(0,120,200,.15);display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:16px">⚙️</div>
        <h3 style="font-size:15px;font-weight:700;margin-bottom:10px;color:#1a1a1a">貴社専用にカスタマイズ</h3>
        <p style="font-size:13px;color:#777;line-height:1.8">勘定科目・事業コード・部門コード・定型仕訳パターンをすべて貴社の設定に合わせて構築。弥生・freee・MF・TKCいずれにも対応します。</p>
      </div>
      <div style="background:#fff;border:1px solid #e2dfd8;border-radius:12px;padding:28px">
        <div style="width:44px;height:44px;border-radius:10px;background:#e8f2ff;border:1px solid rgba(0,120,200,.15);display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:16px">🤝</div>
        <h3 style="font-size:15px;font-weight:700;margin-bottom:10px;color:#1a1a1a">導入後も継続サポート</h3>
        <p style="font-size:13px;color:#777;line-height:1.8">担当コンサルタントが毎月の処理に同行。取引先の追加・法改正対応・新口座の追加など、変化に合わせて継続的に改善します。</p>
      </div>
      <div style="background:#fff;border:1px solid #e2dfd8;border-radius:12px;padding:28px">
        <div style="width:44px;height:44px;border-radius:10px;background:#e8f2ff;border:1px solid rgba(0,120,200,.15);display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:16px">📊</div>
        <h3 style="font-size:15px;font-weight:700;margin-bottom:10px;color:#1a1a1a">効果測定・改善提案</h3>
        <p style="font-size:13px;color:#777;line-height:1.8">導入前後の工数を数値で比較。「どこでまだ時間がかかっているか」を定期的に分析し、さらなる自動化ポイントを提案します。</p>
      </div>
      <div style="background:#fff;border:1px solid #e2dfd8;border-radius:12px;padding:28px">
        <div style="width:44px;height:44px;border-radius:10px;background:#e8f2ff;border:1px solid rgba(0,120,200,.15);display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:16px">👩‍💼</div>
        <h3 style="font-size:15px;font-weight:700;margin-bottom:10px;color:#1a1a1a">経理担当者への研修</h3>
        <p style="font-size:13px;color:#777;line-height:1.8">ツールの操作方法だけでなく、AIを活用した経理業務の考え方まで丁寧に研修。担当者が変わっても安心して引き継げる体制を構築します。</p>
      </div>
      <div style="background:#fff;border:1px solid #e2dfd8;border-radius:12px;padding:28px">
        <div style="width:44px;height:44px;border-radius:10px;background:#e8f2ff;border:1px solid rgba(0,120,200,.15);display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:16px">🔒</div>
        <h3 style="font-size:15px;font-weight:700;margin-bottom:10px;color:#1a1a1a">NPO・社会福祉法人に精通</h3>
        <p style="font-size:13px;color:#777;line-height:1.8">複数事業・部門振替・助成金管理など、NPO・社会福祉法人特有の会計処理に対応。一般法人とは異なる複雑な要件も丁寧に対応します。</p>
      </div>
    </div>
    <div style="margin-top:32px;background:#fff;border:1px solid rgba(0,120,200,.2);border-radius:12px;padding:28px;display:flex;align-items:center;gap:24px;flex-wrap:wrap">
      <div style="flex:1;min-width:280px">
        <div style="font-size:15px;font-weight:700;color:#1a1a1a;margin-bottom:6px">まずは無料相談から</div>
        <div style="font-size:13px;color:#777;line-height:1.8">現在の経理フローをお聞かせください。貴社に合った改善プランをご提案します。オンライン・対面どちらにも対応しています。</div>
      </div>
      <a href="https://surc.online/" target="_blank" rel="noopener" style="background:#0078c8;color:#fff;padding:14px 32px;border-radius:8px;font-size:14px;font-weight:700;text-decoration:none;white-space:nowrap;flex-shrink:0">無料相談を申し込む →</a>
    </div>
  </div>
</div>

<div class="cta-bg section-full" id="contact">
  <div class="section reveal" style="padding-top:0;padding-bottom:0">
    <div class="cta-box">
      <h2 class="cta-title">月次経理の自動化を<br>はじめてみませんか？</h2>
      <p class="cta-desc">TKCをご利用中の法人・NPO・社会福祉法人に対応。<br>お客様の勘定科目・事業CDに合わせてカスタマイズします。</p>
      <div style="display:flex;gap:16px;justify-content:center;flex-wrap:wrap">
        <a class="btn-primary" href="https://surc.online/" target="_blank" rel="noopener">&#9993; 導入を相談する</a>
      </div>
      <p style="margin-top:24px;font-size:12px;color:var(--ink3)">※ 導入後のサポート・カスタマイズも承ります</p>
    </div>
  </div>
</div>

<footer>
  <div class="footer-logo">
    <img src="data:image/png;base64,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" alt="サーコミュニケーション">
    <div class="footer-info">
      <strong>一般社団法人 サーコミュニケーション</strong>
      Sur Communication
    </div>
  </div>
  <div class="footer-right">
    <div>© 2026 Sur Communication. All rights reserved.</div>
    <div style="margin-top:4px">TKC仕訳インポートツール</div>
  </div>
</footer>

<script>
const observer = new IntersectionObserver(entries => {
  entries.forEach(e => { if(e.isIntersecting) e.target.classList.add('visible'); });
}, {threshold:0.1});
document.querySelectorAll('.reveal').forEach(el => observer.observe(el));
</script>
</body>
</html>`;
    return new Response(html, {
      headers: { 'Content-Type': 'text/html;charset=UTF-8' },
    });
  },
};
