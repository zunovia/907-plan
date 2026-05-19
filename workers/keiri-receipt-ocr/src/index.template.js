// keiri-receipt-ocr Worker
// Serves receipt-ocr.html at GET / and handles Claude API calls at POST /api/analyze

const CLAUDE_MODEL = 'claude-sonnet-4-20250514';
const CLAUDE_API_URL = 'https://api.anthropic.com/v1/messages';

const SYSTEM_PROMPT = `あなたは日本の経理処理の専門家です。レシートや領収書の画像を読み取り、TKC会計の勘定科目体系に沿って仕訳データを作成してください。

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

  const { images, department: rawDept } = body;
  const department = typeof rawDept === 'string' ? rawDept.slice(0, 100) : '';
  if (!images || !Array.isArray(images) || images.length === 0) {
    return jsonResponse({ error: '画像データがありません' }, 400);
  }
  if (images.length > 30) {
    return jsonResponse({ error: '画像は30ページ以内にしてください' }, 400);
  }

  // Build content blocks: images + text prompt
  const content = [];
  for (const base64Data of images) {
    content.push({
      type: 'image',
      source: {
        type: 'base64',
        media_type: 'image/png',
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
    system: SYSTEM_PROMPT,
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
const HTML_CONTENT = `__HTML_PLACEHOLDER__`;

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

    // API endpoint
    if (url.pathname === '/api/analyze' && request.method === 'POST') {
      const resp = await handleAnalyze(request, env);
      resp.headers.set('Access-Control-Allow-Origin', '*');
      return resp;
    }

    // Serve HTML
    if (request.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      return new Response(HTML_CONTENT, {
        headers: { 'Content-Type': 'text/html;charset=UTF-8' },
      });
    }

    return new Response('Not Found', { status: 404 });
  },
};
