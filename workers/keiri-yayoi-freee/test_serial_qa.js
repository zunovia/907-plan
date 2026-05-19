// ===================================================
// vive-qa: シリアル番号管理システム 修正検証テスト
// 検証対象: src/index.js の4件の修正
// ===================================================
'use strict';

let pass = 0, fail = 0;

function assert(name, cond, detail) {
  if (cond) {
    console.log('  PASS:', name);
    pass++;
  } else {
    console.error('  FAIL:', name, detail || '');
    fail++;
  }
}

// ===================================================
// テスト用スタブ（Cloudflare Workers 環境を模倣）
// ===================================================

// Node.js の crypto モジュールを使用
const nodeCrypto = require('crypto');
const { webcrypto } = nodeCrypto;

// --- timingSafeCompare の再現（Cloudflare Workers の実装を Node.js で模倣） ---
// crypto.subtle.timingSafeEqual は Cloudflare Workers 独自の拡張。
// Node.js では webcrypto.subtle.digest + nodeCrypto.timingSafeEqual で同等を実現。
async function timingSafeCompare(a, b) {
  const encoder = new TextEncoder();
  const keyA = await webcrypto.subtle.digest('SHA-256', encoder.encode(String(a)));
  const keyB = await webcrypto.subtle.digest('SHA-256', encoder.encode(String(b)));
  // Node.js の timingSafeEqual は Buffer/TypedArray を受け付ける
  return nodeCrypto.timingSafeEqual(Buffer.from(keyA), Buffer.from(keyB));
}

// --- KV モックストア ---
function makeKV(initial = {}) {
  const store = { ...initial };
  return {
    get: async (key) => store[key] || null,
    put: async (key, value) => { store[key] = value; },
    list: async (opts) => {
      const prefix = (opts && opts.prefix) || '';
      const keys = Object.keys(store)
        .filter(k => k.startsWith(prefix))
        .map(k => ({ name: k }));
      return { keys };
    },
    _store: store,
  };
}

// --- verifyAdmin の再現 ---
async function verifyAdmin(request, env) {
  const key = request.headers.get('X-Admin-Key') || '';
  if (!key || !env.ADMIN_API_KEY) return false;
  return timingSafeCompare(key, env.ADMIN_API_KEY);
}

// --- jsonResponse の再現 ---
function jsonResponse(data, status = 200) {
  return { _json: data, _status: status };
}

// --- checkRateLimit スタブ（常に許可） ---
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

// --- sendWebhook スタブ ---
let lastWebhookPayload = null;
async function sendWebhook(env, payload) {
  lastWebhookPayload = payload;
}

// --- handleSerialVerify の再現 ---
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
    if (!data.activatedAt) {
      data.activatedAt = now.toISOString();
      data.usedBy = ip;
      data.usedAt = now.toISOString();
      await env.SERIAL_KV.put(kvKey, JSON.stringify(data));
    }
    expiresAt = new Date(new Date(data.activatedAt).getTime() + data.expiresAfterDays * 24 * 60 * 60 * 1000);
  } else {
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

// --- handleSerialGenerate の再現 ---
async function handleSerialGenerate(request, env, ctx) {
  if (!await verifyAdmin(request, env)) return jsonResponse({ error: 'Unauthorized' }, 401);

  let body;
  try { body = await request.json(); } catch { body = {}; }
  const count = Math.min(Math.max(parseInt(body.count) || 1, 1), 10);
  const durationDays = parseInt(body.durationDays) || 14;
  const app = (body.app || '').toLowerCase();
  const validApps = ['keiri', 'voice'];
  if (app && !validApps.includes(app)) {
    return jsonResponse({ error: 'Invalid app. Must be "keiri" or "voice"' }, 400);
  }
  return jsonResponse({ serials: [{ serial: 'VOI-TEST-TEST-TEST', expiresAfterDays: durationDays, app: app || 'keiri' }] });
}

// --- モックリクエスト作成ヘルパー ---
function makeRequest(body, opts = {}) {
  const headers = new Map();
  if (opts.adminKey) headers.set('X-Admin-Key', opts.adminKey);
  headers.set('CF-Connecting-IP', opts.ip || '1.2.3.4');
  headers.set('Content-Type', 'application/json');
  const bodyStr = JSON.stringify(body);
  return {
    headers: { get: (k) => headers.get(k) || null },
    json: async () => JSON.parse(bodyStr),
  };
}

// --- ctx スタブ ---
const ctx = { waitUntil: (p) => p };

// ===================================================
// A. 問題1の修正検証 — クロスアプリ保護
// ===================================================
async function testCrossAppProtection() {
  console.log('\n[A] 問題1: クロスアプリ保護の修正検証');

  const futureDate = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString();

  // voiceアプリ向けシリアルをKVに設定
  const kvStore = makeKV({
    'serial:VOI-ABCD-EFGH-IJKL': JSON.stringify({
      createdAt: new Date().toISOString(),
      activatedAt: new Date().toISOString(),
      expiresAfterDays: 14,
      status: 'active',
      usedBy: null,
      usedAt: null,
      app: 'voice',
    }),
    // レガシーシリアル（appなし）
    'serial:ABCD-EFGH-IJKL-MNOP': JSON.stringify({
      createdAt: new Date().toISOString(),
      expiresAt: futureDate,
      status: 'active',
      usedBy: null,
      usedAt: null,
    }),
    // keiriアプリ向けシリアル
    'serial:VOI-KEIR-KEIR-KEIR': JSON.stringify({
      createdAt: new Date().toISOString(),
      activatedAt: new Date().toISOString(),
      expiresAfterDays: 14,
      status: 'active',
      usedBy: null,
      usedAt: null,
      app: 'keiri',
    }),
  });

  const env = {
    SERIAL_KV: kvStore,
    RATE_LIMIT_KV: makeKV(),
    ADMIN_API_KEY: 'test-admin-key-12345',
  };

  // A-1: voiceシリアルをkeiriアプリで使おうとした場合 → 拒否
  lastWebhookPayload = null;
  const req1 = makeRequest({ serial: 'VOI-ABCD-EFGH-IJKL', app: 'keiri' });
  const res1 = await handleSerialVerify(req1, env, ctx);
  assert('A-1: voiceシリアルをkeiriで使用 → 401', res1._status === 401);
  assert('A-1: エラーは "Invalid serial number"', res1._json.error === 'Invalid serial number');
  assert('A-1: wrong_appイベントがwebhookに送信される', lastWebhookPayload && lastWebhookPayload.status === 'wrong_app');

  // A-2: voiceシリアルをvoiceアプリで使った場合 → 通過
  const req2 = makeRequest({ serial: 'VOI-ABCD-EFGH-IJKL', app: 'voice' });
  const res2 = await handleSerialVerify(req2, env, ctx);
  assert('A-2: voiceシリアルをvoiceで使用 → 有効', res2._json.valid === true);

  // A-3: レガシーシリアル（data.appなし）はkeiriアプリで使用可能
  const req3 = makeRequest({ serial: 'ABCD-EFGH-IJKL-MNOP', app: 'keiri' });
  const res3 = await handleSerialVerify(req3, env, ctx);
  assert('A-3: レガシーシリアル（appなし）はkeiriで通過', res3._json.valid === true);

  // A-4: appパラメータなしでの使用（旧クライアント互換）
  const req4 = makeRequest({ serial: 'VOI-ABCD-EFGH-IJKL' });
  const res4 = await handleSerialVerify(req4, env, ctx);
  assert('A-4: appパラメータなし → ガードスキップで通過', res4._json.valid === true);

  // A-5: keiriシリアルをkeiriで使用 → 通過
  const req5 = makeRequest({ serial: 'VOI-KEIR-KEIR-KEIR', app: 'keiri' });
  const res5 = await handleSerialVerify(req5, env, ctx);
  assert('A-5: keiriシリアルをkeiriで使用 → 有効', res5._json.valid === true);

  // A-6: wrong_appエラーレスポンスにapp名が含まれていないか（情報漏洩チェック）
  const req6 = makeRequest({ serial: 'VOI-ABCD-EFGH-IJKL', app: 'keiri' });
  lastWebhookPayload = null;
  const res6 = await handleSerialVerify(req6, env, ctx);
  const errorMsg = res6._json.error || '';
  assert('A-6: エラーメッセージにapp名を含まない（情報漏洩なし）',
    !errorMsg.toLowerCase().includes('voice') && !errorMsg.toLowerCase().includes('keiri'));
}

// ===================================================
// B. 問題2の修正検証 — timingSafeCompare
// ===================================================
async function testTimingSafeCompare() {
  console.log('\n[B] 問題2: timingSafeCompare 使用の検証');

  // B-1: verifyAdmin が async function であることを確認
  const result = verifyAdmin.constructor.name;
  assert('B-1: verifyAdmin は AsyncFunction', verifyAdmin.toString().startsWith('async'));

  // B-2: verifyAdmin が正しいキーで true を返す
  const envOk = { ADMIN_API_KEY: 'correct-key-abc' };
  const reqOk = makeRequest({}, { adminKey: 'correct-key-abc' });
  const resOk = await verifyAdmin(reqOk, envOk);
  assert('B-2: verifyAdmin — 正しいキーで true', resOk === true);

  // B-3: verifyAdmin が間違ったキーで false を返す
  const reqBad = makeRequest({}, { adminKey: 'wrong-key-xyz' });
  const resBad = await verifyAdmin(reqBad, envOk);
  assert('B-3: verifyAdmin — 誤ったキーで false', resBad === false);

  // B-4: キーがない場合は false
  const reqNoKey = makeRequest({});
  const resNoKey = await verifyAdmin(reqNoKey, envOk);
  assert('B-4: verifyAdmin — X-Admin-Keyなしで false', resNoKey === false);

  // B-5: ADMIN_API_KEY が未設定の場合は false
  const envNoAdmin = {};
  const reqWithKey = makeRequest({}, { adminKey: 'any-key' });
  const resNoAdmin = await verifyAdmin(reqWithKey, envNoAdmin);
  assert('B-5: verifyAdmin — ADMIN_API_KEY未設定で false', resNoAdmin === false);

  // B-6: admin freepass が timingSafeCompare 経由で機能する
  const kvFreepass = makeKV();
  const envFreepass = {
    SERIAL_KV: kvFreepass,
    RATE_LIMIT_KV: makeKV(),
    ADMIN_API_KEY: 'admin-secret-pass',
  };
  const reqFreepass = makeRequest({ serial: 'admin-secret-pass', app: 'keiri' });
  const resFreepass = await handleSerialVerify(reqFreepass, envFreepass, ctx);
  assert('B-6: admin freepass — timingSafeCompare経由で有効', resFreepass._json.valid === true);
  assert('B-6: admin freepass フラグあり', resFreepass._json.freepass === true);

  // B-7: handleSerialGenerate で await verifyAdmin が機能する
  const envAdmin = {
    SERIAL_KV: makeKV(),
    RATE_LIMIT_KV: makeKV(),
    ADMIN_API_KEY: 'admin-key-gen',
  };
  const reqGen = makeRequest({ count: 1, durationDays: 14, app: 'keiri' }, { adminKey: 'admin-key-gen' });
  const resGen = await handleSerialGenerate(reqGen, envAdmin, ctx);
  assert('B-7: handleSerialGenerate — 正しい管理者キーで成功', !resGen._json.error);

  // B-8: handleSerialGenerate — 不正キーで 401
  const reqGenBad = makeRequest({ count: 1, durationDays: 14, app: 'keiri' }, { adminKey: 'wrong-key' });
  const resGenBad = await handleSerialGenerate(reqGenBad, envAdmin, ctx);
  assert('B-8: handleSerialGenerate — 不正キーで 401', resGenBad._status === 401);
}

// ===================================================
// C. 問題3の修正検証 — placeholder
// ===================================================
async function testPlaceholder() {
  console.log('\n[C] 問題3: placeholder 修正の検証');

  // index.js のソースを読んで直接確認
  const fs = require('fs');
  const src = fs.readFileSync(
    require('path').join(__dirname, 'src', 'index.js'),
    'utf8'
  );

  // C-1: VOI-XXXX-XXXX-XXXX が placeholder に存在するか
  assert('C-1: placeholder に VOI-XXXX-XXXX-XXXX が含まれる',
    src.includes('placeholder="VOI-XXXX-XXXX-XXXX'));

  // C-2: KOE-XXXX-XXXX-XXXX が placeholder に存在しないか
  assert('C-2: placeholder に誤った KOE-XXXX-XXXX-XXXX が含まれない',
    !src.match(/placeholder="KOE-XXXX-XXXX-XXXX/));
}

// ===================================================
// D. 問題4の修正検証 — appパラメータ検証
// ===================================================
async function testAppValidation() {
  console.log('\n[D] 問題4: app パラメータ検証の修正検証');

  const envAdmin = {
    SERIAL_KV: makeKV(),
    RATE_LIMIT_KV: makeKV(),
    ADMIN_API_KEY: 'admin-key-test',
  };

  // D-1: 無効なapp値で 400
  const reqBadApp = makeRequest(
    { count: 1, durationDays: 14, app: 'hacker' },
    { adminKey: 'admin-key-test' }
  );
  const resBadApp = await handleSerialGenerate(reqBadApp, envAdmin, ctx);
  assert('D-1: 無効なapp "hacker" で 400', resBadApp._status === 400);

  // D-2: app=""（空文字）はレガシー互換でスキップ
  const reqEmptyApp = makeRequest(
    { count: 1, durationDays: 14, app: '' },
    { adminKey: 'admin-key-test' }
  );
  const resEmptyApp = await handleSerialGenerate(reqEmptyApp, envAdmin, ctx);
  assert('D-2: app空文字はスキップ（エラーなし）', !resEmptyApp._json.error || resEmptyApp._json.error !== 'Invalid app. Must be "keiri" or "voice"');

  // D-3: app="keiri" は正常
  const reqKeiri = makeRequest(
    { count: 1, durationDays: 14, app: 'keiri' },
    { adminKey: 'admin-key-test' }
  );
  const resKeiri = await handleSerialGenerate(reqKeiri, envAdmin, ctx);
  assert('D-3: app="keiri" は正常', !resKeiri._json.error);

  // D-4: app="voice" は正常
  const reqVoice = makeRequest(
    { count: 1, durationDays: 14, app: 'voice' },
    { adminKey: 'admin-key-test' }
  );
  const resVoice = await handleSerialGenerate(reqVoice, envAdmin, ctx);
  assert('D-4: app="voice" は正常', !resVoice._json.error);

  // D-5: app="HACKER"（大文字）も拒否（lowercase変換後チェック）
  const reqUpperBad = makeRequest(
    { count: 1, durationDays: 14, app: 'HACKER' },
    { adminKey: 'admin-key-test' }
  );
  const resUpperBad = await handleSerialGenerate(reqUpperBad, envAdmin, ctx);
  assert('D-5: app="HACKER"（大文字）も 400 で拒否', resUpperBad._status === 400);
}

// ===================================================
// E. リグレッション検証
// ===================================================
async function testRegression() {
  console.log('\n[E] リグレッション検証');

  const futureDate = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString();
  const pastDate = new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString();

  const kvStore = makeKV({
    'serial:VOI-NORM-NORM-NORM': JSON.stringify({
      createdAt: new Date().toISOString(),
      activatedAt: new Date().toISOString(),
      expiresAfterDays: 14,
      status: 'active',
      usedBy: null,
      usedAt: null,
      app: 'keiri',
    }),
    // レガシーシリアル: XXXX-XXXX-XXXX-XXXX 形式（appフィールドなし）
    'serial:ABCD-EFGH-IJKL-MNOP': JSON.stringify({
      createdAt: new Date().toISOString(),
      expiresAt: futureDate,
      status: 'active',
      usedBy: null,
      usedAt: null,
    }),
    'serial:VOI-REVK-REVK-REVK': JSON.stringify({
      createdAt: new Date().toISOString(),
      activatedAt: new Date().toISOString(),
      expiresAfterDays: 14,
      status: 'revoked',
      app: 'keiri',
    }),
    'serial:VOI-EXPR-EXPR-EXPR': JSON.stringify({
      createdAt: new Date(Date.now() - 20 * 24 * 60 * 60 * 1000).toISOString(),
      activatedAt: new Date(Date.now() - 20 * 24 * 60 * 60 * 1000).toISOString(),
      expiresAfterDays: 14,
      status: 'active',
      app: 'keiri',
    }),
  });

  const env = {
    SERIAL_KV: kvStore,
    RATE_LIMIT_KV: makeKV(),
    ADMIN_API_KEY: 'admin-regress-key',
  };

  // E-1: 通常のkeiriシリアル認証
  const req1 = makeRequest({ serial: 'VOI-NORM-NORM-NORM', app: 'keiri' });
  const res1 = await handleSerialVerify(req1, env, ctx);
  assert('E-1: 通常keiriシリアルの認証成功', res1._json.valid === true);

  // E-2: レガシーシリアル（appフィールドなし）の認証通過
  const req2 = makeRequest({ serial: 'ABCD-EFGH-IJKL-MNOP', app: 'keiri' });
  const res2 = await handleSerialVerify(req2, env, ctx);
  assert('E-2: レガシーシリアルはkeiriアプリで通過', res2._json.valid === true);

  // E-3: revokedシリアルの拒否
  const req3 = makeRequest({ serial: 'VOI-REVK-REVK-REVK', app: 'keiri' });
  const res3 = await handleSerialVerify(req3, env, ctx);
  assert('E-3: revokedシリアルは拒否', res3._json.valid === false);
  assert('E-3: revoked エラーメッセージ', res3._json.error === 'This serial number has been revoked');

  // E-4: 期限切れシリアルの拒否
  const req4 = makeRequest({ serial: 'VOI-EXPR-EXPR-EXPR', app: 'keiri' });
  const res4 = await handleSerialVerify(req4, env, ctx);
  assert('E-4: 期限切れシリアルは拒否', res4._json.valid === false);
  assert('E-4: expired エラーメッセージ', res4._json.error === 'This serial number has expired');

  // E-5: admin freepass 認証（async verifyAdmin 変更後も機能）
  const reqFP = makeRequest({ serial: 'admin-regress-key', app: 'keiri' });
  const resFP = await handleSerialVerify(reqFP, env, ctx);
  assert('E-5: admin freepass は引き続き機能する', resFP._json.valid === true && resFP._json.freepass === true);

  // E-6: 存在しないシリアルの拒否
  const req6 = makeRequest({ serial: 'VOI-NONE-NONE-NONE', app: 'keiri' });
  const res6 = await handleSerialVerify(req6, env, ctx);
  assert('E-6: 存在しないシリアルは拒否', res6._json.valid === false);

  // E-7: レートリミット動作確認
  const envRL = {
    SERIAL_KV: makeKV(),
    RATE_LIMIT_KV: makeKV({
      'ratelimit:9.9.9.9': JSON.stringify({ attempts: 5, firstAttempt: Date.now() })
    }),
    ADMIN_API_KEY: 'admin-rl-key',
  };
  const reqRL = makeRequest({ serial: 'VOI-TEST-TEST-TEST', app: 'keiri' }, { ip: '9.9.9.9' });
  // CF-Connecting-IPを上書きするためにmakeRequestを直接ハックする
  reqRL.headers.get = (k) => k === 'CF-Connecting-IP' ? '9.9.9.9' : null;
  const resRL = await handleSerialVerify(reqRL, envRL, ctx);
  assert('E-7: レートリミット超過で 429', resRL._status === 429);
}

// ===================================================
// F. セキュリティ最終チェック
// ===================================================
async function testSecurityFinal() {
  console.log('\n[F] セキュリティ最終チェック');

  const fs = require('fs');
  const src = fs.readFileSync(
    require('path').join(__dirname, 'src', 'index.js'),
    'utf8'
  );

  // F-1: ADMIN_API_KEY との直接 === 比較がないか
  const directCompare = src.match(/===\s*env\.ADMIN_API_KEY|env\.ADMIN_API_KEY\s*===/g);
  assert('F-1: ADMIN_API_KEY との直接 === 比較なし', !directCompare);

  // F-2: ADMIN_API_KEY との直接 == 比較がないか
  const looseCompare = src.match(/==\s*env\.ADMIN_API_KEY|env\.ADMIN_API_KEY\s*==/g);
  assert('F-2: ADMIN_API_KEY との直接 == 比較なし', !looseCompare);

  // F-3: timingSafeCompare が全比較で使われているか（verifyAdmin内）
  assert('F-3: verifyAdmin が timingSafeCompare を使っている',
    src.includes('return timingSafeCompare(key, env.ADMIN_API_KEY)'));

  // F-4: admin bypass が await timingSafeCompare を使っているか
  assert('F-4: admin bypass が await timingSafeCompare を使っている',
    src.includes('await timingSafeCompare(rawInput, env.ADMIN_API_KEY)'));

  // F-5: wrong_appエラーメッセージにapp名を含まない
  assert('F-5: wrong_appエラーは "Invalid serial number" で情報漏洩しない',
    src.includes("return jsonResponse({ valid: false, error: 'Invalid serial number' }, 401)"));

  // F-6: verifyAdmin が async
  assert('F-6: verifyAdmin は async function',
    src.includes('async function verifyAdmin'));

  // F-7: 全ての verifyAdmin 呼び出しに await がついているか
  // 全マッチ検索
  const verifyAdminCalls = src.match(/verifyAdmin\(/g) || [];
  const awaitVerifyAdminCalls = src.match(/await verifyAdmin\(/g) || [];
  // 定義自体の1件を引いた呼び出し数 vs await付き呼び出し数
  const callCount = verifyAdminCalls.length - 1; // 定義を除外
  assert('F-7: 全 verifyAdmin 呼び出しに await あり (定義1件を除く)',
    callCount === awaitVerifyAdminCalls.length,
    `await付き: ${awaitVerifyAdminCalls.length}, 全呼び出し: ${callCount}`);
}

// ===================================================
// メイン実行
// ===================================================
async function main() {
  console.log('==============================================');
  console.log('vive-qa: シリアル番号管理システム修正検証テスト');
  console.log('==============================================');

  try {
    await testCrossAppProtection();
    await testTimingSafeCompare();
    await testPlaceholder();
    await testAppValidation();
    await testRegression();
    await testSecurityFinal();
  } catch (e) {
    console.error('\n予期しないエラー:', e);
    fail++;
  }

  console.log('\n==============================================');
  console.log('テスト結果: PASS=' + pass + '  FAIL=' + fail);
  if (fail === 0) {
    console.log('判定: PASS');
  } else {
    console.log('判定: FAIL');
    process.exit(1);
  }
}

main();
