// keiri-receipt-ocr Worker
// Serves receipt-ocr.html at GET / and handles Claude API calls at POST /api/analyze

const CLAUDE_MODEL = 'claude-sonnet-4-20250514';
const CLAUDE_API_URL = 'https://api.anthropic.com/v1/messages';

function getSystemPrompt(sw) {
  const softName = {tkc:'TKC会計',yayoi:'弥生会計',freee:'freee会計',mf:'マネーフォワードクラウド'}[sw] || 'TKC会計';

  if (!sw || sw === 'tkc') {
    return `あなたは日本の経理処理の専門家です。レシートや領収書の画像を読み取り、${softName}の勘定科目体系に沿って仕訳データを作成してください。

## 勘定科目マスタ（主要費用科目）
| コード | 科目名 | 該当例 |
|--------|--------|--------|
| 5425 | 消耗品費 | 電池, 文具, 日用品, 工具 |
| 5434 | 車両費 | ガソリン, 車検, 駐車場(業務用車両), オイル交換 |
| 5461 | 旅費 | 交通費, ICカードチャージ, 駐車場(出張・移動), 高速代 |
| 5427 | 水道光熱費 | 電気, ガス, 水道 |
| 5421 | 通信費 | 電話, 郵送, 切手 |
| 5423 | 保険料 | 各種保険 |
| 5432 | 地代家賃 | 家賃, 駐車場賃料(月極) |
| 5426 | 修繕費 | 修繕, 修理 |
| 5438 | 会議費 | 打ち合わせ飲食 |
| 5424 | 接待交際費 | 接待, 贈答 |
| 5429 | 支払手数料 | 振込手数料, 各種手数料 |
| 5428 | リース料 | リース |
| 5459 | 雑費 | その他 |
| 5212 | 資源回収処理費 | 廃棄物処理, ゴミ処理, 産廃 |
| 6225 | 消耗品費(管理) | 管理部門の消耗品 |
| 6234 | 旅費(管理) | 管理部門の交通費 |

## 補助科目（部署）
| コード | 部署名 |
|--------|--------|
| 10 | 総務 |
| 21 | あつた |
| 22 | 物流 |
| 23 | さくら |
| 24 | よしの |
| 30 | 循環フェス |

## 仕分けルール
- 駐車場の領収書で時間貸し（コインパーキング等）→ 旅費(5461)
- 駐車場の領収書で月極 → 地代家賃(5432)
- manacaやICカードチャージ → 旅費(5461)
- ガソリン・灯油 → 車両費(5434)
- ゴミ処理・廃棄物処理場 → 資源回収処理費(5212)
- 税率は10%が基本、食品は軽減税率8%を考慮
- インボイス番号（T始まり13桁）があれば記録
- 1ページに複数レシートが貼り付けられている場合あり、すべて個別に読み取ること
- 手書きメモで部署名が書かれている場合はそれに従う

## 出力形式
以下のJSON形式で返してください。必ずJSONのみを返し、説明文は不要です。
\`\`\`json
{
  "receipts": [
    {
      "date": "2026-04-26",
      "vendor": "店名",
      "items": "品名の概要",
      "total": 550,
      "tax_amount": 50,
      "tax_rate": "10%",
      "payment_method": "現金",
      "account_code": "5425",
      "account_name": "消耗品費",
      "sub_account": "",
      "tax_category": "課税仕入10%",
      "invoice_number": "T3120101003135",
      "department": "物流",
      "memo": ""
    }
  ]
}
\`\`\``;
  }

  // TKC以外: コードなし、科目名のみ
  return `あなたは日本の経理処理の専門家です。レシートや領収書の画像を読み取り、仕訳データを作成してください。出力先は${softName}です。

## 勘定科目マスタ（主要費用科目）
| 科目名 | 該当例 |
|--------|--------|
| 消耗品費 | 電池, 文具, 日用品, 工具 |
| 車両費 | ガソリン, 車検, 駐車場(業務用車両), オイル交換 |
| 旅費交通費 | 交通費, ICカードチャージ, 駐車場(出張・移動), 高速代 |
| 水道光熱費 | 電気, ガス, 水道 |
| 通信費 | 電話, 郵送, 切手 |
| 保険料 | 各種保険 |
| 地代家賃 | 家賃, 駐車場賃料(月極) |
| 修繕費 | 修繕, 修理 |
| 会議費 | 打ち合わせ飲食 |
| 交際費 | 接待, 贈答 |
| 支払手数料 | 振込手数料, 各種手数料 |
| リース料 | リース |
| 雑費 | その他 |
| 廃棄物処理費 | 廃棄物処理, ゴミ処理, 産廃 |

## 補助科目（部署）
| 部署名 |
|--------|
| 総務 |
| あつた |
| 物流 |
| さくら |
| よしの |
| 循環フェス |

## 仕分けルール
- 駐車場の領収書で時間貸し（コインパーキング等）→ 旅費交通費
- 駐車場の領収書で月極 → 地代家賃
- manacaやICカードチャージ → 旅費交通費
- ガソリン・灯油 → 車両費
- ゴミ処理・廃棄物処理場 → 廃棄物処理費
- 税率は10%が基本、食品は軽減税率8%を考慮
- インボイス番号（T始まり13桁）があれば記録
- 1ページに複数レシートが貼り付けられている場合あり、すべて個別に読み取ること
- 手書きメモで部署名が書かれている場合はそれに従う
- account_codeフィールドは空文字にしてください

## 出力形式
以下のJSON形式で返してください。必ずJSONのみを返し、説明文は不要です。
\`\`\`json
{
  "receipts": [
    {
      "date": "2026-04-26",
      "vendor": "店名",
      "items": "品名の概要",
      "total": 550,
      "tax_amount": 50,
      "tax_rate": "10%",
      "payment_method": "現金",
      "account_code": "",
      "account_name": "消耗品費",
      "sub_account": "",
      "tax_category": "課税仕入10%",
      "invoice_number": "T3120101003135",
      "department": "物流",
      "memo": ""
    }
  ]
}
\`\`\``;
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

async function handleAnalyze(request, env) {
  if (!env.ANTHROPIC_API_KEY) {
    return jsonResponse({ error: 'ANTHROPIC_API_KEY が設定されていません' }, 500);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: 'リクエストの形式が不正です' }, 400);
  }

  const { images, department: rawDept, sw: rawSw } = body;
  const department = typeof rawDept === 'string' ? rawDept.slice(0, 100) : '';
  const sw = ['tkc','yayoi','freee','mf'].includes(rawSw) ? rawSw : 'tkc';
  if (!images || !Array.isArray(images) || images.length === 0) {
    return jsonResponse({ error: '画像データがありません' }, 400);
  }
  if (images.length > 30) {
    return jsonResponse({ error: '画像は30ページ以内にしてください' }, 400);
  }

  // Build content blocks: images + text prompt
  const content = [];
  for (const base64Data of images) {
    // Detect media type from base64 magic bytes
    let media_type = 'image/png';
    if (base64Data.startsWith('/9j/')) media_type = 'image/jpeg';
    else if (base64Data.startsWith('UklGR')) media_type = 'image/webp';
    content.push({
      type: 'image',
      source: {
        type: 'base64',
        media_type,
        data: base64Data,
      },
    });
  }

  let userPrompt = 'これらのレシート・領収書画像を読み取り、仕訳データをJSON形式で返してください。';
  if (department) {
    userPrompt += '\nデフォルト部署: ' + department + '（手書きメモで別の部署が指定されていればそちらを優先）';
  }
  userPrompt += '\n画像にレシートが複数枚写っている場合は、すべて個別に読み取ってください。';
  content.push({ type: 'text', text: userPrompt });

  // Call Claude API
  const claudeBody = {
    model: CLAUDE_MODEL,
    max_tokens: 8192,
    system: getSystemPrompt(sw),
    messages: [{ role: 'user', content }],
  };

  let claudeResp;
  try {
    claudeResp = await fetch(CLAUDE_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(claudeBody),
    });
  } catch (err) {
    return jsonResponse({ error: 'Claude API接続エラー: ' + err.message }, 502);
  }

  if (!claudeResp.ok) {
    const errBody = await claudeResp.text().catch(() => '');
    return jsonResponse({
      error: 'Claude API エラー (' + claudeResp.status + ')',
      detail: errBody.slice(0, 500),
    }, 502);
  }

  const claudeData = await claudeResp.json();
  const textBlock = claudeData.content?.find(b => b.type === 'text');
  if (!textBlock) {
    return jsonResponse({ error: 'Claude APIから応答テキストがありません' }, 502);
  }

  // Extract JSON from response (handle markdown code blocks)
  let jsonStr = textBlock.text.trim();
  const jsonMatch = jsonStr.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (jsonMatch) {
    jsonStr = jsonMatch[1].trim();
  }

  let result;
  try {
    result = JSON.parse(jsonStr);
  } catch {
    return jsonResponse({
      error: 'Claude APIの応答をJSONとしてパースできません',
      raw: textBlock.text.slice(0, 1000),
    }, 502);
  }

  return jsonResponse(result);
}

// HTML will be embedded by build script
const HTML_CONTENT = `<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>レシートOCR仕分け | 中部リサイクル運動市民の会</title>
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans+JP:wght@400;500;700&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.mini.min.js"></script>
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
.tb-stat{font-size:11px;color:rgba(255,255,255,.45);font-family:monospace;margin:0 8px;white-space:nowrap}
.tb-dl{background:var(--cy);color:#fff;border:none;padding:6px 14px;border-radius:4px;font-size:12px;font-weight:700;cursor:pointer;font-family:inherit}
.tb-dl:hover{background:#005fa0}
.tb-dl:disabled{opacity:.4;cursor:not-allowed}
.sw-wrap{display:flex;gap:2px;background:rgba(0,0,0,.25);border-radius:5px;padding:2px}
.swb{background:none;border:none;color:rgba(255,255,255,.5);font-size:11px;font-weight:700;padding:4px 10px;border-radius:4px;cursor:pointer;font-family:inherit}
.swb.on{background:rgba(255,255,255,.18);color:#fff}
.wrap{max-width:1100px;margin:0 auto;padding:20px 18px 60px}
.card{background:var(--sf);border:.5px solid var(--bd);border-radius:var(--r);overflow:hidden;margin-bottom:12px}
.cardh{padding:9px 12px;display:flex;align-items:center;gap:7px;border-bottom:.5px solid var(--bd);background:#f9f8f5}
.cardt{font-size:12px;font-weight:700;flex:1}
.btn{display:inline-flex;align-items:center;gap:4px;padding:6px 13px;border:none;border-radius:4px;font-size:12px;font-family:inherit;font-weight:700;cursor:pointer;transition:all .12s;white-space:nowrap}
.btn-g{background:var(--gn);color:#fff}.btn-g:hover{background:#237a4e}
.btn-o{background:var(--sf);border:.5px solid var(--bd2);color:var(--ink)}.btn-o:hover{background:#f5f4f0}
.btn-r{background:var(--rd);color:#fff}.btn-r:hover{background:#6d0b3f}
.btn-sm{padding:4px 10px;font-size:11px}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:5px 8px;background:#f9f8f5;border-bottom:.5px solid var(--bd);font-size:10px;font-weight:700;color:var(--ink3);white-space:nowrap}
td{padding:6px 8px;border-bottom:.5px solid var(--bd);vertical-align:middle}
tr:last-child td{border:none}
tr:hover td{background:#fafaf8}
.ar{text-align:right;font-family:'DM Mono',monospace;font-weight:500}
input,select{font-family:'Noto Sans JP',sans-serif;font-size:11px;padding:3px 6px;border:.5px solid var(--bd2);border-radius:3px;background:var(--sf);color:var(--ink);outline:none}
input:focus,select:focus{border-color:#999}
.chip{font-size:9px;font-weight:700;padding:2px 6px;border-radius:3px}
.cg{background:var(--gnbg);color:var(--gn)}
.cb{background:var(--blbg);color:var(--bl)}
.ca{background:var(--ambg);color:var(--am)}

.drop{border:2px dashed var(--bd2);border-radius:var(--r);padding:30px;text-align:center;cursor:pointer;background:var(--sf);margin-bottom:12px;transition:all .2s}
.drop:hover,.drop.dg{border-color:var(--cy);background:var(--cybg)}
.drop.processing{border-color:var(--gn);background:var(--gnbg);pointer-events:none}

.pills{display:flex;gap:5px;flex-wrap:wrap;margin-bottom:10px}
.pill{display:flex;align-items:center;gap:4px;background:var(--sf);border:.5px solid var(--bd);border-radius:4px;padding:3px 7px;font-size:11px}
.pill .x{cursor:pointer;color:#ccc;font-size:14px;line-height:1}.pill .x:hover{color:var(--rd)}

.ld{display:none;background:var(--gnbg);border:.5px solid var(--gn);border-radius:var(--r);padding:12px 14px;align-items:center;gap:10px;margin-bottom:12px}
.ld.on{display:flex}
.spin{width:16px;height:16px;border:2px solid var(--gnbg);border-top-color:var(--gn);border-radius:50%;animation:sp .6s linear infinite;flex-shrink:0}
@keyframes sp{to{transform:rotate(360deg)}}
.ld-text{font-size:12px;font-weight:600;color:var(--gn)}
.ld-sub{font-size:10px;color:var(--gn);opacity:.7;margin-left:auto}

.notif{position:fixed;bottom:14px;right:14px;background:#1a1a1a;color:#fff;padding:9px 14px;border-radius:var(--r);font-size:12px;box-shadow:0 4px 20px rgba(0,0,0,.2);z-index:999;transform:translateY(60px);opacity:0;transition:all .3s cubic-bezier(.34,1.56,.64,1)}
.notif.on{transform:translateY(0);opacity:1}
.notif.err{background:var(--rd)}

.concept{background:linear-gradient(135deg,#1a1a2e,#16213e);border-radius:var(--r);padding:18px 20px;margin-bottom:16px;color:#fff}

.sum-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px;margin-bottom:12px}
.sum-card{background:var(--sf);border:.5px solid var(--bd);border-radius:var(--r);padding:10px 12px}
.sum-lbl{font-size:10px;font-weight:700;color:var(--ink3)}
.sum-val{font-size:16px;font-weight:700;font-family:'DM Mono',monospace;margin-top:2px}

td input[type="text"],td input[type="number"]{width:100%;border:none;background:transparent;padding:2px 0;font-size:12px}
td input[type="text"]:focus,td input[type="number"]:focus{background:var(--cybg);border-radius:2px;padding:2px 4px}
td select{border:none;background:transparent;font-size:11px;padding:1px 0;cursor:pointer;max-width:130px}
td select:focus{background:var(--cybg)}
td .del-row{cursor:pointer;color:#ccc;font-size:14px}.del-row:hover{color:var(--rd)}

.empty{text-align:center;padding:40px;color:#bbb}

/* ===== レスポンシブ ===== */
@media(max-width:768px){
  .tb{height:auto;min-height:44px;flex-wrap:wrap;padding:8px 10px;gap:6px}
  .tb-logo{font-size:12px}
  .tb-org{display:none}
  .tb-sp{flex-basis:100%;height:0}
  .tb-sw-label{display:none}
  .sw-wrap{order:1}
  .swb{font-size:10px;padding:3px 7px}
  .tb-stat{order:2;font-size:10px;margin:0 4px}
  .tb-dl{order:3;font-size:11px;padding:5px 10px}
  .wrap{padding:10px 8px 40px}
  .concept{padding:14px 14px}
  .concept>div:first-child{font-size:13px}
  .drop{padding:20px 14px}
  .sum-grid{grid-template-columns:1fr 1fr}
  .card{border-radius:6px}
  .cardh{flex-wrap:wrap;gap:5px;padding:8px 10px}
  .cardh>div:last-child{width:100%;justify-content:flex-end}
  table{font-size:11px}
  th,td{padding:5px 5px}
  td input[type="text"],td input[type="number"]{font-size:11px}
  td select{font-size:10px}
  .notif{left:10px;right:10px;bottom:10px;text-align:center}
}
@media(max-width:480px){
  .tb-logo{font-size:11px}
  .sw-wrap{gap:1px}
  .swb{font-size:9px;padding:3px 5px}
  .tb-stat{font-size:9px}
  .tb-dl{font-size:10px;padding:4px 8px}
  .concept>div:last-child{gap:4px}
  .concept>div:last-child>span{font-size:9px;padding:4px 6px}
  .sum-grid{grid-template-columns:1fr}
  .drop>div:nth-child(2){font-size:12px}
  .drop>div:nth-child(3){font-size:10px}
}
</style>
</head>
<body>

<div class="tb">
  <span class="tb-logo">レシートOCR仕分け</span>
  <span class="tb-badge">AI</span>
  <span class="tb-org" style="font-size:10px;color:rgba(255,255,255,.4);margin-left:4px">中部リサイクル運動市民の会 専用</span>
  <div class="tb-sp"></div>
  <div class="tb-sw-label" style="font-size:10px;color:rgba(255,255,255,.65);margin-right:4px">出力ソフト:</div>
  <div class="sw-wrap">
    <button class="swb on" id="swb-tkc" onclick="switchSW('tkc')">TKC</button>
    <button class="swb" id="swb-yayoi" onclick="switchSW('yayoi')">弥生</button>
    <button class="swb" id="swb-freee" onclick="switchSW('freee')">freee</button>
    <button class="swb" id="swb-mf" onclick="switchSW('mf')">MF</button>
  </div>
  <span class="tb-stat" id="tb-stat">0件 / ¥0</span>
  <button class="tb-dl" id="btn-excel" onclick="downloadExcel()" disabled>Excel出力</button>
</div>

<div class="wrap">

<!-- HERO -->
<div class="concept">
  <div style="font-size:14px;font-weight:700;margin-bottom:6px">レシート・領収書を自動仕分け</div>
  <div style="font-size:12px;color:rgba(255,255,255,.65);line-height:1.8">PDF・JPEG・PNGをアップロードするだけ。Claude AIがOCR読取→勘定科目で自動仕分け。</div>
  <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:10px">
    <span style="background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.18);border-radius:5px;padding:5px 10px;font-size:11px;color:rgba(255,255,255,.85)">ファイル選択</span>
    <span style="color:rgba(255,255,255,.3)">&rarr;</span>
    <span style="background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.18);border-radius:5px;padding:5px 10px;font-size:11px;color:rgba(255,255,255,.85)">AI OCR+仕分け</span>
    <span style="color:rgba(255,255,255,.3)">&rarr;</span>
    <span style="background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.18);border-radius:5px;padding:5px 10px;font-size:11px;color:rgba(255,255,255,.85)">確認・修正</span>
    <span style="color:rgba(255,255,255,.3)">&rarr;</span>
    <span style="background:rgba(0,120,200,.3);border:1px solid rgba(0,120,200,.5);border-radius:5px;padding:5px 10px;font-size:11px;color:rgba(255,255,255,.85)">Excel出力</span>
  </div>
</div>

<!-- DROP ZONE -->
<div class="drop" id="drop-zone"
  ondragover="event.preventDefault();this.classList.add('dg')"
  ondragleave="this.classList.remove('dg')"
  ondrop="onDrop(event)">
  <input type="file" id="file-input" accept="application/pdf,image/jpeg,image/png,image/webp" multiple onchange="onFileSelect(this.files)" style="display:none">
  <div style="font-size:28px;margin-bottom:4px">&#128196;</div>
  <div style="font-size:13px;font-weight:700;margin-bottom:2px">レシート・領収書をドラッグ＆ドロップ</div>
  <div style="font-size:11px;color:#aaa">PDF / JPEG / PNG対応 / 複数ファイルOK / ファイル名から部署を自動判定</div>
</div>
<div class="pills" id="file-pills"></div>

<!-- LOADING -->
<div class="ld" id="loading">
  <div class="spin"></div>
  <span class="ld-text" id="ld-text">Claude AIで読み取り中...</span>
  <span class="ld-sub" id="ld-sub"></span>
</div>

<!-- RESULTS -->
<div id="results" style="display:none">

  <!-- SUMMARY -->
  <div class="sum-grid" id="summary-grid"></div>

  <!-- TABLE -->
  <div class="card">
    <div class="cardh">
      <span class="cardt">仕訳一覧</span>
      <span class="chip cb" id="result-count">0件</span>
      <div style="margin-left:auto;display:flex;gap:6px">
        <button class="btn btn-o btn-sm" onclick="addRow()">+ 行追加</button>
        <button class="btn btn-g btn-sm" onclick="downloadExcel()">Excel出力</button>
      </div>
    </div>
    <div style="overflow-x:auto">
    <table>
      <thead><tr>
        <th style="width:30px"></th>
        <th>日付</th>
        <th>店名/取引先</th>
        <th>勘定科目</th>
        <th class="ar">金額</th>
        <th>税区分</th>
        <th>補助科目(部署)</th>
        <th>部門CD</th>
        <th>摘要</th>
        <th style="width:28px"></th>
      </tr></thead>
      <tbody id="result-tbody"></tbody>
    </table>
    </div>
  </div>

  <!-- ACCOUNT SUMMARY -->
  <div class="card">
    <div class="cardh"><span class="cardt">勘定科目別集計</span></div>
    <table>
      <thead><tr><th>コード</th><th>勘定科目</th><th>件数</th><th class="ar">合計金額</th></tr></thead>
      <tbody id="acct-summary"></tbody>
    </table>
  </div>

  <!-- DEPT SUMMARY -->
  <div class="card">
    <div class="cardh"><span class="cardt">部署別集計</span></div>
    <table>
      <thead><tr><th>部署</th><th>件数</th><th class="ar">合計金額</th></tr></thead>
      <tbody id="dept-summary"></tbody>
    </table>
  </div>
</div>

<!-- EMPTY -->
<div class="empty" id="empty-state">
  <div style="font-size:28px;margin-bottom:6px">&#128203;</div>
  <div style="font-weight:600">PDFをアップロードすると仕分け結果が表示されます</div>
</div>

</div><!-- /wrap -->

<div class="notif" id="notif"></div>

<script>
// ===== CONFIG =====
var SW = 'tkc';

var ACCOUNTS_MAP = {
  tkc: [
    {code:'5425',name:'消耗品費'},{code:'5434',name:'車両費'},{code:'5461',name:'旅費'},
    {code:'5427',name:'水道光熱費'},{code:'5421',name:'通信費'},{code:'5423',name:'保険料'},
    {code:'5432',name:'地代家賃'},{code:'5426',name:'修繕費'},{code:'5438',name:'会議費'},
    {code:'5424',name:'接待交際費'},{code:'5429',name:'支払手数料'},{code:'5428',name:'リース料'},
    {code:'5459',name:'雑費'},{code:'5212',name:'資源回収処理費'},
    {code:'6225',name:'消耗品費(管理)'},{code:'6234',name:'旅費(管理)'}
  ],
  yayoi: [
    {code:'',name:'消耗品費'},{code:'',name:'車両費'},{code:'',name:'旅費交通費'},
    {code:'',name:'水道光熱費'},{code:'',name:'通信費'},{code:'',name:'保険料'},
    {code:'',name:'地代家賃'},{code:'',name:'修繕費'},{code:'',name:'会議費'},
    {code:'',name:'交際費'},{code:'',name:'支払手数料'},{code:'',name:'リース料'},
    {code:'',name:'雑費'},{code:'',name:'廃棄物処理費'},
    {code:'',name:'消耗品費'},{code:'',name:'旅費交通費'}
  ],
  freee: [
    {code:'',name:'消耗品費'},{code:'',name:'車両費'},{code:'',name:'旅費交通費'},
    {code:'',name:'水道光熱費'},{code:'',name:'通信費'},{code:'',name:'保険料'},
    {code:'',name:'地代家賃'},{code:'',name:'修繕費'},{code:'',name:'会議費'},
    {code:'',name:'交際費'},{code:'',name:'支払手数料'},{code:'',name:'リース料'},
    {code:'',name:'雑費'},{code:'',name:'廃棄物処理費'},
    {code:'',name:'消耗品費'},{code:'',name:'旅費交通費'}
  ],
  mf: [
    {code:'',name:'消耗品費'},{code:'',name:'車両費'},{code:'',name:'旅費交通費'},
    {code:'',name:'水道光熱費'},{code:'',name:'通信費'},{code:'',name:'保険料'},
    {code:'',name:'地代家賃'},{code:'',name:'修繕費'},{code:'',name:'会議費'},
    {code:'',name:'交際費'},{code:'',name:'支払手数料'},{code:'',name:'リース料'},
    {code:'',name:'雑費'},{code:'',name:'廃棄物処理費'},
    {code:'',name:'消耗品費'},{code:'',name:'旅費交通費'}
  ]
};

var ACCOUNTS = ACCOUNTS_MAP.tkc;

const DEPARTMENTS = [
  {code:'10',name:'総務'},
  {code:'21',name:'あつた'},
  {code:'22',name:'物流'},
  {code:'23',name:'さくら'},
  {code:'24',name:'よしの'},
  {code:'30',name:'循環フェス'}
];

const TAX_CATEGORIES = [
  '課税仕入10%','課税仕入8%（軽減）','非課税仕入','不課税仕入','対象外'
];

function switchSW(sw) {
  SW = sw;
  ACCOUNTS = ACCOUNTS_MAP[sw];
  ['tkc','yayoi','freee','mf'].forEach(function(s) {
    var b = document.getElementById('swb-' + s);
    if (b) b.classList.toggle('on', s === sw);
  });
  // 既存データがあれば科目を再マッピング
  if (allReceipts.length) {
    allReceipts.forEach(function(r) {
      var match = ACCOUNTS.find(function(a) { return a.name === r.account_name; });
      if (match) r.account_code = match.code;
      else r.account_code = '';
    });
    renderResults();
  }
  var swNames = {tkc:'TKC',yayoi:'弥生会計',freee:'freee',mf:'マネーフォワード'};
  notify('出力形式: ' + swNames[sw]);
}

function deptCode(name) {
  const d = DEPARTMENTS.find(d => d.name === name);
  return d ? d.code : '';
}
function deptName(code) {
  const d = DEPARTMENTS.find(d => d.code === code);
  return d ? d.name : '';
}

let allReceipts = [];
let fileQueue = [];

// ===== PDF to Images =====
pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
// Disable worker if it fails to load (falls back to main thread)
pdfjsLib.GlobalWorkerOptions.isEvalSupported = false;

function extractDeptFromFilename(filename) {
  const deptNames = DEPARTMENTS.map(d => d.name);
  for (const name of deptNames) {
    if (filename.includes(name)) return name;
  }
  if (filename.includes('butsuryu') || filename.includes('物流')) return '物流';
  if (filename.includes('soumu') || filename.includes('総務')) return '総務';
  return '';
}

async function pdfToImages(file) {
  const arrayBuf = await file.arrayBuffer();
  const pdf = await pdfjsLib.getDocument({data: new Uint8Array(arrayBuf)}).promise;
  const images = [];
  const scale = 2.0;
  if (pdf.numPages > 30) {
    throw new Error('PDFが' + pdf.numPages + 'ページあります。30ページ以内のPDFを選択してください');
  }
  for (let i = 1; i <= pdf.numPages; i++) {
    const page = await pdf.getPage(i);
    const vp = page.getViewport({scale});
    const canvas = document.createElement('canvas');
    canvas.width = vp.width;
    canvas.height = vp.height;
    const ctx = canvas.getContext('2d');
    await page.render({canvasContext: ctx, viewport: vp}).promise;
    const dataUrl = canvas.toDataURL('image/png');
    images.push(dataUrl.split(',')[1]);
  }
  return images;
}

// ===== IMAGE FILE TO BASE64 =====
async function imageFileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const dataUrl = reader.result;
      const base64 = dataUrl.split(',')[1];
      resolve([base64]);
    };
    reader.onerror = () => reject(new Error('ファイルの読み込みに失敗しました'));
    reader.readAsDataURL(file);
  });
}

// ===== DRAG & DROP =====
function onDrop(e) {
  e.preventDefault();
  e.currentTarget.classList.remove('dg');
  const ACCEPT = ['application/pdf','image/jpeg','image/png','image/webp'];
  const files = Array.from(e.dataTransfer.files).filter(f => ACCEPT.includes(f.type));
  if (files.length) processFiles(files);
}

function onFileSelect(fileList) {
  const ACCEPT = ['application/pdf','image/jpeg','image/png','image/webp'];
  const files = Array.from(fileList).filter(f => ACCEPT.includes(f.type));
  if (files.length) processFiles(files);
  document.getElementById('file-input').value = '';
}

document.getElementById('drop-zone').addEventListener('click', function(e) {
  if (e.target === this || e.target.parentElement === this) {
    document.getElementById('file-input').click();
  }
});

function showPills() {
  const el = document.getElementById('file-pills');
  el.innerHTML = fileQueue.map((f,i) =>
    '<div class="pill"><span>' + escH(f.name) + '</span> <span class="chip ' +
    (f.status==='done'?'cg':f.status==='processing'?'ca':'') + '">' +
    (f.status==='done'?'完了':f.status==='processing'?'処理中':'待機') +
    '</span></div>'
  ).join('');
}

// ===== PROCESS =====
async function processFiles(files) {
  try {
    for (const f of files) {
      if (!fileQueue.find(q => q.name === f.name)) {
        fileQueue.push({name: f.name, file: f, status: 'pending'});
      }
    }
    showPills();
    document.getElementById('drop-zone').classList.add('processing');
    document.getElementById('loading').classList.add('on');
    document.getElementById('empty-state').style.display = 'none';

    for (const item of fileQueue) {
      if (item.status !== 'pending') continue;
      item.status = 'processing';
      showPills();
      const dept = extractDeptFromFilename(item.name);
      document.getElementById('ld-text').textContent = item.name + ' を処理中...';
      document.getElementById('ld-sub').textContent = dept ? '部署: ' + dept : '';

      try {
        let images;
        if (item.file.type === 'application/pdf') {
          images = await pdfToImages(item.file);
        } else {
          images = await imageFileToBase64(item.file);
        }
        document.getElementById('ld-text').textContent = 'Claude AIで読み取り中... (' + images.length + (item.file.type === 'application/pdf' ? 'ページ' : '枚') + ')';
        const result = await callAPI(images, dept);
        if (result.receipts && result.receipts.length > 0) {
          allReceipts = allReceipts.concat(result.receipts);
        }
        item.status = 'done';
        notify(item.name + ': ' + (result.receipts?.length || 0) + '件検出');
      } catch (err) {
        item.status = 'error';
        notify(item.name + ': エラー - ' + err.message, true);
      }
      showPills();
    }
  } catch (outerErr) {
    notify('処理エラー: ' + outerErr.message, true);
  } finally {
    document.getElementById('loading').classList.remove('on');
    document.getElementById('drop-zone').classList.remove('processing');
  }
  renderResults();
}

async function callAPI(images, department) {
  const resp = await fetch('/api/analyze', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({images, department, sw: SW})
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({error:'サーバーエラー'}));
    throw new Error(err.error || 'HTTP ' + resp.status);
  }
  return resp.json();
}

// ===== RENDER =====
function escH(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function fmtYen(n) { return '¥' + Number(n||0).toLocaleString(); }

function accountOptions(selected) {
  return ACCOUNTS.map(function(a) {
    var val = a.code || a.name;
    var label = a.code ? a.code + ' ' + escH(a.name) : escH(a.name);
    return '<option value="' + escH(val) + '"' + (val === selected ? ' selected' : '') + '>' + label + '</option>';
  }).join('');
}

function deptOptions(selected) {
  return '<option value="">--</option>' + DEPARTMENTS.map(d =>
    '<option value="' + escH(d.name) + '"' + (d.name===selected?' selected':'') + '>' + escH(d.name) + '</option>'
  ).join('');
}

function taxOptions(selected) {
  return TAX_CATEGORIES.map(t =>
    '<option value="' + escH(t) + '"' + (t===selected?' selected':'') + '>' + escH(t) + '</option>'
  ).join('');
}

function renderResults() {
  document.getElementById('results').style.display = allReceipts.length ? '' : 'none';
  document.getElementById('empty-state').style.display = allReceipts.length ? 'none' : '';

  // Table
  const tbody = document.getElementById('result-tbody');
  tbody.innerHTML = allReceipts.map((r, i) => {
    // 補助科目を部署から自動設定（未設定の場合）
    if (!r.sub_account && r.department) r.sub_account = r.department;
    if (!r.dept_code) r.dept_code = deptCode(r.department || r.sub_account || '');
    // TKC以外では部門CDを空にする
    var deptCdDisplay = (SW === 'tkc') ? escH(r.dept_code || '') : '';
    // account_codeとaccount_nameからselectの選択値を決定
    var acctSelected = r.account_code || r.account_name || '';
    return '<tr data-idx="' + i + '">' +
    '<td style="color:#ccc;font-size:10px;font-family:monospace">' + (i+1) + '</td>' +
    '<td><input type="text" value="' + escH(r.date||'') + '" onchange="upd('+i+',\\'date\\',this.value)"></td>' +
    '<td><input type="text" value="' + escH(r.vendor||'') + '" onchange="upd('+i+',\\'vendor\\',this.value)" style="min-width:100px"></td>' +
    '<td><select onchange="upd('+i+',\\'account_code\\',this.value);updAcctName('+i+')">' + accountOptions(acctSelected) + '</select></td>' +
    '<td class="ar"><input type="number" value="' + Number(r.total||0) + '" onchange="upd('+i+',\\'total\\',Number(this.value));renderSummaries()" style="width:80px;text-align:right"></td>' +
    '<td><select onchange="upd('+i+',\\'tax_category\\',this.value)">' + taxOptions(r.tax_category) + '</select></td>' +
    '<td><select onchange="updDept('+i+',this.value)">' + deptOptions(r.sub_account || r.department) + '</select></td>' +
    '<td class="ar" style="font-family:monospace;font-size:11px">' + deptCdDisplay + '</td>' +
    '<td><input type="text" value="' + escH(r.memo || r.items || '') + '" onchange="upd('+i+',\\'memo\\',this.value)" style="min-width:120px"></td>' +
    '<td><span class="del-row" onclick="delRow('+i+')">&times;</span></td>' +
    '</tr>';
  }).join('');

  renderSummaries();
}

function renderSummaries() {
  const total = allReceipts.reduce((s,r) => s + Number(r.total||0), 0);
  document.getElementById('tb-stat').textContent = allReceipts.length + '件 / ' + fmtYen(total);
  document.getElementById('result-count').textContent = allReceipts.length + '件';
  document.getElementById('btn-excel').disabled = !allReceipts.length;

  // Summary cards
  const grid = document.getElementById('summary-grid');
  grid.innerHTML =
    '<div class="sum-card"><div class="sum-lbl">総件数</div><div class="sum-val">' + allReceipts.length + '件</div></div>' +
    '<div class="sum-card"><div class="sum-lbl">合計金額</div><div class="sum-val">' + fmtYen(total) + '</div></div>';

  // Account summary
  const acctMap = {};
  allReceipts.forEach(r => {
    const key = r.account_code || r.account_name || '????';
    if (!acctMap[key]) acctMap[key] = {code: r.account_code || '', name: r.account_name||'', count:0, total:0};
    acctMap[key].count++;
    acctMap[key].total += Number(r.total||0);
  });
  const acctRows = Object.values(acctMap).sort((a,b) => (a.code||a.name).localeCompare(b.code||b.name));
  document.getElementById('acct-summary').innerHTML = acctRows.map(a =>
    '<tr><td>' + escH(a.code) + '</td><td>' + escH(a.name) + '</td><td>' + a.count + '</td><td class="ar">' + fmtYen(a.total) + '</td></tr>'
  ).join('') + '<tr style="font-weight:700;background:#f9f8f5"><td></td><td>合計</td><td>' + allReceipts.length + '</td><td class="ar">' + fmtYen(total) + '</td></tr>';

  // Dept summary
  const deptMap = {};
  allReceipts.forEach(r => {
    const key = r.department || '未設定';
    if (!deptMap[key]) deptMap[key] = {name: key, count:0, total:0};
    deptMap[key].count++;
    deptMap[key].total += Number(r.total||0);
  });
  const deptRows = Object.values(deptMap).sort((a,b) => a.name.localeCompare(b.name));
  document.getElementById('dept-summary').innerHTML = deptRows.map(d =>
    '<tr><td>' + escH(d.name) + '</td><td>' + d.count + '</td><td class="ar">' + fmtYen(d.total) + '</td></tr>'
  ).join('') + '<tr style="font-weight:700;background:#f9f8f5"><td>合計</td><td>' + allReceipts.length + '</td><td class="ar">' + fmtYen(total) + '</td></tr>';
}

// ===== EDIT =====
function upd(i, key, val) { allReceipts[i][key] = val; }
function updAcctName(i) {
  var val = allReceipts[i].account_code;
  var acct = ACCOUNTS.find(function(a) { return (a.code || a.name) === val; });
  if (acct) {
    allReceipts[i].account_code = acct.code;
    allReceipts[i].account_name = acct.name;
  }
  renderSummaries();
}
function updDept(i, val) {
  allReceipts[i].sub_account = val;
  allReceipts[i].department = val;
  allReceipts[i].dept_code = deptCode(val);
  renderResults();
}

function delRow(i) {
  allReceipts.splice(i, 1);
  renderResults();
}

function addRow() {
  var defaultAcct = ACCOUNTS[0] || {code:'',name:'雑費'};
  allReceipts.push({
    date: new Date().toISOString().slice(0,10),
    vendor: '',
    items: '',
    total: 0,
    tax_amount: 0,
    tax_rate: '10%',
    payment_method: '',
    account_code: defaultAcct.code,
    account_name: defaultAcct.name,
    sub_account: '',
    tax_category: '課税仕入10%',
    invoice_number: '',
    department: '',
    memo: ''
  });
  renderResults();
  const tbody = document.getElementById('result-tbody');
  tbody.lastElementChild?.scrollIntoView({behavior:'smooth'});
}

// ===== EXCEL =====
function downloadExcel() {
  if (!allReceipts.length) return;
  const headers = ['日付','店名/取引先','品目','勘定科目コード','勘定科目名','補助科目(部署)','部門CD','金額','税額','税率','支払方法','税区分','インボイス番号','摘要'];
  const data = allReceipts.map(r => [
    r.date, r.vendor, r.items||r.memo||'',
    r.account_code, r.account_name, r.sub_account||r.department||'',
    SW === 'tkc' ? (r.dept_code || deptCode(r.sub_account||r.department||'')) : '',
    Number(r.total||0), Number(r.tax_amount||0), r.tax_rate||'',
    r.payment_method||'', r.tax_category||'',
    r.invoice_number||'', r.memo||''
  ]);

  const wb = XLSX.utils.book_new();
  const ws = XLSX.utils.aoa_to_sheet([headers, ...data]);

  // Column widths
  ws['!cols'] = [
    {wch:12},{wch:20},{wch:30},{wch:8},{wch:14},{wch:10},{wch:8},
    {wch:10},{wch:8},{wch:6},{wch:8},{wch:14},{wch:16},{wch:20}
  ];

  XLSX.utils.book_append_sheet(wb, ws, '仕訳一覧');

  // Account summary sheet
  const acctMap = {};
  allReceipts.forEach(r => {
    const key = r.account_code || r.account_name || '????';
    if (!acctMap[key]) acctMap[key] = {code:r.account_code||'', name:r.account_name||'', count:0, total:0};
    acctMap[key].count++;
    acctMap[key].total += Number(r.total||0);
  });
  const acctData = Object.values(acctMap).sort((a,b) => (a.code||a.name).localeCompare(b.code||b.name));
  const ws2 = XLSX.utils.aoa_to_sheet([
    ['科目コード','科目名','件数','合計金額'],
    ...acctData.map(a => [a.code, a.name, a.count, a.total])
  ]);
  XLSX.utils.book_append_sheet(wb, ws2, '科目別集計');

  const now = new Date();
  const fname = 'レシート仕分け_' + now.getFullYear() + ('0'+(now.getMonth()+1)).slice(-2) + ('0'+now.getDate()).slice(-2) + '.xlsx';
  XLSX.writeFile(wb, fname);
  notify('Excel出力: ' + fname);
}

// ===== NOTIFY =====
function notify(msg, isErr) {
  const el = document.getElementById('notif');
  el.textContent = msg;
  el.className = 'notif on' + (isErr ? ' err' : '');
  clearTimeout(el._t);
  el._t = setTimeout(() => el.className = 'notif', 3000);
}
</script>
</body>
</html>
`;

// =============================================
// パスワード保護
// =============================================
const SITE_PASSWORD = '######';

const LOGIN_HTML = `<!DOCTYPE html>
<html lang="ja"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ログイン - レシートOCR</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f4f3ef;display:flex;align-items:center;justify-content:center;min-height:100vh}
.login-card{background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08);padding:40px;width:100%;max-width:380px;text-align:center}
.login-card h1{font-size:18px;margin-bottom:6px;color:#1a1a1a}
.login-card p{font-size:12px;color:#888;margin-bottom:24px}
.login-card input{width:100%;padding:10px 14px;border:1px solid #ddd;border-radius:6px;font-size:14px;margin-bottom:12px}
.login-card input:focus{outline:none;border-color:#0078c8}
.login-card button{width:100%;padding:10px;background:#0078c8;color:#fff;border:none;border-radius:6px;font-size:14px;font-weight:700;cursor:pointer}
.login-card button:hover{background:#005fa0}
.err{color:#e74c3c;font-size:12px;margin-bottom:8px;display:none}
</style></head><body>
<div class="login-card">
<h1>レシートOCR 自動仕分け</h1>
<p>中部リサイクル運動市民の会 専用サイト</p>
<div class="err" id="err">パスワードが正しくありません</div>
<form method="POST" action="/login">
<input type="password" name="password" placeholder="パスワードを入力" required autofocus>
<button type="submit">ログイン</button>
</form>
</div>
<script>
if(location.search.includes('err=1'))document.getElementById('err').style.display='block';
</script>
</body></html>`;

function checkAuth(request) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(/churi_auth=([^;]+)/);
  return match && match[1] === 'authenticated';
}

function authResponse(response) {
  return response;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
        },
      });
    }

    // Login handler
    if (url.pathname === '/login' && request.method === 'POST') {
      const formData = await request.formData();
      const password = formData.get('password');
      if (password === SITE_PASSWORD) {
        return new Response(null, {
          status: 302,
          headers: {
            'Location': '/',
            'Set-Cookie': 'churi_auth=authenticated; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000',
          },
        });
      }
      return new Response(null, { status: 302, headers: { 'Location': '/?err=1' } });
    }

    // API endpoint (requires auth)
    if (url.pathname === '/api/analyze' && request.method === 'POST') {
      if (!checkAuth(request)) {
        return jsonResponse({ error: '認証が必要です' }, 401);
      }
      const resp = await handleAnalyze(request, env);
      resp.headers.set('Access-Control-Allow-Origin', '*');
      return resp;
    }

    // Serve HTML (requires auth)
    if (request.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      if (!checkAuth(request)) {
        return new Response(LOGIN_HTML, {
          headers: { 'Content-Type': 'text/html;charset=UTF-8' },
        });
      }
      return new Response(HTML_CONTENT, {
        headers: { 'Content-Type': 'text/html;charset=UTF-8' },
      });
    }

    return new Response('Not Found', { status: 404 });
  },
};
