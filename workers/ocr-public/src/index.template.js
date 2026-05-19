// ocr-public Worker
// Serves HTML + transparent AI API proxy (no data storage)

const HTML_CONTENT = `__HTML_PLACEHOLDER__`;

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

// Proxy AI API requests - forwards request as-is, stores nothing
async function handleProxy(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResp({ error: 'Invalid JSON' }, 400);
  }

  const { provider, apiKey, model, content, systemPrompt, maxTokens } = body;
  if (!provider || !apiKey) {
    return jsonResp({ error: 'provider and apiKey are required' }, 400);
  }

  try {
    let resp;

    if (provider === 'claude') {
      const reqBody = {
        model: model || 'claude-sonnet-4-20250514',
        max_tokens: maxTokens || 8192,
        messages: [{ role: 'user', content }],
      };
      if (systemPrompt) reqBody.system = systemPrompt;

      resp = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify(reqBody),
      });

    } else if (provider === 'openai') {
      const messages = [];
      if (systemPrompt) messages.push({ role: 'system', content: systemPrompt });
      // Convert image content for OpenAI format
      const userContent = content.map(c => {
        if (c.type === 'image') {
          return { type: 'image_url', image_url: { url: 'data:' + (c.source.media_type || 'image/png') + ';base64,' + c.source.data } };
        }
        return c;
      });
      messages.push({ role: 'user', content: userContent });

      resp = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + apiKey,
        },
        body: JSON.stringify({ model: model || 'gpt-4o', messages, max_tokens: maxTokens || 8192 }),
      });

    } else {
      return jsonResp({ error: 'Unsupported provider: ' + provider }, 400);
    }

    // Forward the API response as-is
    const data = await resp.json();
    return jsonResp(data, resp.status);

  } catch (err) {
    return jsonResp({ error: 'Proxy error: ' + err.message }, 502);
  }
}

function jsonResp(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
  });
}

export default {
  async fetch(request) {
    const url = new URL(request.url);

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    // AI API proxy
    if (url.pathname === '/api/proxy' && request.method === 'POST') {
      return handleProxy(request);
    }

    // Favicon
    if (url.pathname === '/favicon.ico') {
      return new Response(null, { status: 204 });
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
