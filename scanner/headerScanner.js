/**
 * headerScanner.js
 * 掃描 HTTP Response Headers 的安全問題
 * 安全原則：只讀取 headers，不修改任何資料，不向第三方傳送任何資訊
 */

const HEADER_CHECKS = [
  // ── P0 高危 ──────────────────────────────────────────────
  {
    id: 'https-not-enforced',
    severity: 'P0',
    category: 'headers',
    title_en: 'HTTPS Not Enforced',
    title_zh: 'HTTPS 未強制',
    desc_en: 'Your site does not redirect HTTP to HTTPS. Data sent by users can be intercepted.',
    desc_zh: '網站沒有將 HTTP 強制導向 HTTPS，用戶資料可能被攔截。',
    ref: 'OWASP A02',
    check: (headers, url) => !url.startsWith('https://'),
    fixPrompt: (url, stack) =>
      `My website (${url}) does not enforce HTTPS. Tech stack: ${stack}. Please provide the exact configuration to redirect all HTTP traffic to HTTPS and where to add it.`
  },
  {
    id: 'hsts-missing',
    severity: 'P0',
    category: 'headers',
    isLegal: true,
    title_en: 'HSTS Header Missing',
    title_zh: 'HSTS Header 缺失',
    desc_en: 'Strict-Transport-Security is missing. Browsers may allow downgrade attacks.',
    desc_zh: '缺少 Strict-Transport-Security，瀏覽器可能允許 HTTPS 降級攻擊。',
    ref: 'OWASP A02 / Mozilla Observatory',
    check: (headers) => !headers['strict-transport-security'],
    fixPrompt: (url, stack) =>
      `My website (${url}) is missing the Strict-Transport-Security (HSTS) header. Tech stack: ${stack}. Please provide the exact header value and where to configure it.`
  },

  // ── P1 中危 ──────────────────────────────────────────────
  {
    id: 'csp-missing',
    severity: 'P1',
    category: 'headers',
    title_en: 'Content-Security-Policy Missing',
    title_zh: 'CSP Header 缺失',
    desc_en: 'No Content-Security-Policy header. XSS attacks can load malicious scripts.',
    desc_zh: '缺少 Content-Security-Policy，攻擊者可在你的頁面執行惡意腳本。',
    ref: 'OWASP A03 / Mozilla Observatory',
    check: (headers) => !headers['content-security-policy'],
    fixPrompt: (url, stack) =>
      `My website (${url}) is missing a Content-Security-Policy header. Tech stack: ${stack}. Please generate an appropriate CSP policy and show me exactly where to add it in my config.`
  },
  {
    id: 'x-frame-options-missing',
    severity: 'P1',
    category: 'headers',
    title_en: 'X-Frame-Options Missing',
    title_zh: 'X-Frame-Options 缺失',
    desc_en: 'Your site can be embedded in an iframe on another site. Risk of clickjacking attacks.',
    desc_zh: '網站可被嵌入其他網站的 iframe，有點擊劫持風險。',
    ref: 'OWASP A04 / Mozilla Observatory',
    check: (headers) => {
      if (headers['x-frame-options']) return false;
      const csp = headers['content-security-policy'] || '';
      return !csp.includes('frame-ancestors');
    },
    fixPrompt: (url, stack) =>
      `My website (${url}) is missing the X-Frame-Options header, making it vulnerable to clickjacking. Tech stack: ${stack}. Please provide the fix.`
  },
  {
    id: 'x-content-type-missing',
    severity: 'P1',
    category: 'headers',
    title_en: 'X-Content-Type-Options Missing',
    title_zh: 'X-Content-Type-Options 缺失',
    desc_en: 'Browsers may MIME-sniff responses, enabling attacks via uploaded files.',
    desc_zh: '瀏覽器可能猜測檔案類型，讓上傳的惡意檔案被執行。',
    ref: 'OWASP A05 / Mozilla Observatory',
    check: (headers) => !headers['x-content-type-options'],
    fixPrompt: (url, stack) =>
      `My website (${url}) is missing X-Content-Type-Options: nosniff. Tech stack: ${stack}. Please show me where to add this header.`
  },
  {
    id: 'referrer-policy-missing',
    severity: 'P2',
    category: 'headers',
    isLegal: true,
    title_en: 'Referrer-Policy Missing',
    title_zh: 'Referrer-Policy 缺失',
    desc_en: 'When users click links leaving your site, the full URL (including tokens) may be sent to third parties.',
    desc_zh: '用戶點擊離開時，完整 URL（包含 token）可能洩漏給第三方網站。',
    ref: 'Mozilla Observatory',
    check: (headers) => !headers['referrer-policy'],
    fixPrompt: (url, stack) =>
      `My website (${url}) is missing a Referrer-Policy header. Tech stack: ${stack}. Please recommend the appropriate policy and show me how to add it.`
  },
  {
    id: 'permissions-policy-missing',
    severity: 'P2',
    category: 'headers',
    title_en: 'Permissions-Policy Missing',
    title_zh: 'Permissions-Policy 缺失',
    desc_en: 'Browser features like camera, microphone, and geolocation are not restricted.',
    desc_zh: '未限制瀏覽器功能（攝影機、麥克風、定位），第三方腳本可能濫用。',
    ref: 'Mozilla Observatory',
    check: (headers) => !headers['permissions-policy'] && !headers['feature-policy'],
    fixPrompt: (url, stack) =>
      `My website (${url}) is missing a Permissions-Policy header. Tech stack: ${stack}. Please provide an appropriate policy to restrict browser features.`
  },
  {
    id: 'cors-wildcard',
    severity: 'P1',
    category: 'headers',
    isLegal: true,
    title_en: 'CORS Wildcard Detected',
    title_zh: 'CORS 開放 * 萬用字元',
    desc_en: 'Access-Control-Allow-Origin: * allows any website to read your API responses.',
    desc_zh: 'CORS 設為 * 代表任何網站都能讀取你的 API 回應，包含惡意網站。',
    ref: 'OWASP A01',
    check: (headers) => headers['access-control-allow-origin'] === '*',
    fixPrompt: (url, stack) =>
      `My website (${url}) has CORS set to Access-Control-Allow-Origin: *, which is too permissive. Tech stack: ${stack}. Please show me how to restrict CORS to specific allowed origins only.`
  },
  {
    id: 'server-version-exposed',
    severity: 'P2',
    category: 'headers',
    title_en: 'Server Version Exposed',
    title_zh: '伺服器版本號洩漏',
    desc_en: `Server header reveals software version. Attackers can target known vulnerabilities.`,
    desc_zh: 'Server header 洩漏了軟體版本，讓攻擊者能針對已知漏洞攻擊。',
    ref: 'OWASP A05',
    check: (headers) => {
      const server = headers['server'] || '';
      return /[\d.]+/.test(server) && server.length > 0;
    },
    detail: (headers) => `Server: ${headers['server']}`,
    fixPrompt: (url, stack) =>
      `My website (${url}) exposes the server version in the Server header (value: ${'{server_value}'}). Tech stack: ${stack}. Please show me how to hide or remove this header.`
  },
  {
    id: 'x-powered-by-exposed',
    severity: 'P2',
    category: 'headers',
    title_en: 'X-Powered-By Header Exposed',
    title_zh: 'X-Powered-By 洩漏技術棧',
    desc_en: 'X-Powered-By reveals your tech stack, helping attackers choose exploits.',
    desc_zh: 'X-Powered-By 暴露你使用的技術（如 Express），方便攻擊者選擇攻擊方式。',
    ref: 'OWASP A05',
    check: (headers) => !!headers['x-powered-by'],
    detail: (headers) => `X-Powered-By: ${headers['x-powered-by']}`,
    fixPrompt: (url, stack) =>
      `My website (${url}) exposes the X-Powered-By header. Tech stack: ${stack}. Please show me how to remove this header completely.`
  },

  // ── P2 建議 ──────────────────────────────────────────────
  {
    id: 'cache-control-missing',
    severity: 'P2',
    category: 'headers',
    isLegal: true,
    title_en: 'Cache-Control Not Set',
    title_zh: 'Cache-Control 未設定',
    desc_en: 'Sensitive pages may be cached by browsers or proxies, leaking data to shared device users.',
    desc_zh: '敏感頁面可能被瀏覽器快取，在公用電腦上洩漏資料。',
    ref: 'OWASP A02',
    check: (headers) => !headers['cache-control'],
    fixPrompt: (url, stack) =>
      `My website (${url}) is missing Cache-Control headers on sensitive pages. Tech stack: ${stack}. Please show me how to set appropriate cache control for authenticated pages.`
  },
  {
    id: 'corp-missing',
    severity: 'P2',
    category: 'headers',
    title_en: 'Cross-Origin-Resource-Policy Not Set',
    title_zh: 'Cross-Origin-Resource-Policy 未設定',
    desc_en: 'Resources can be loaded by other sites, enabling side-channel attacks.',
    desc_zh: '未設定跨來源資源政策，資源可被其他網站載入。',
    ref: 'Mozilla Observatory',
    check: (headers) => !headers['cross-origin-resource-policy'],
    fixPrompt: (url, stack) =>
      `My website (${url}) is missing Cross-Origin-Resource-Policy header. Tech stack: ${stack}. Please advise on the appropriate setting.`
  }
];

/**
 * 當技術棧未知時，在修復指令裡加上引導句
 * 讓 AI 先詢問技術棧再給出精準答案
 */
function wrapPromptWithUnknownStack(prompt, stack) {
  if (stack && !stack.includes('Unknown')) return prompt;
  return prompt + '\n\nNote: I am not sure what tech stack I use. Please first ask me 2-3 targeted yes/no questions to identify my stack (e.g. "Are you using Next.js?", "Is your server on Vercel/Netlify/a VPS?"), then provide the exact fix based on my answers.';
}

/**
 * 執行 header 掃描
 * @param {string} url - 目標網站 URL
 * @returns {Promise<{issues: Array, headers: Object, techStack: string}>}
 */
async function runHeaderScan(url) {
  const issues = [];
  let headers = {};
  let techStack = 'Unknown';

  try {
    // 使用 HEAD 請求先取得 headers（減少流量）
    // 若 HEAD 不支援，改用 GET
    let response;
    try {
      response = await fetch(url, {
        method: 'HEAD',
        cache: 'no-store',
        credentials: 'omit', // 安全原則：不帶任何 cookie
        signal: AbortSignal.timeout(5000)
      });
    } catch {
      response = await fetch(url, {
        method: 'GET',
        cache: 'no-store',
        credentials: 'omit',
        signal: AbortSignal.timeout(5000)
      });
    }

    // 將所有 headers 轉為小寫 key 存入 headers 物件
    response.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });

    // 偵測技術棧
    techStack = detectTechStack(headers, url);

  } catch (err) {
    // fetch 失敗（例如 CORS 完全阻擋），回傳空結果
    return { issues: [], headers: {}, techStack: 'Unknown', error: err.message };
  }

  // 執行每一項 header 檢查
  for (const check of HEADER_CHECKS) {
    try {
      if (check.check(headers, url)) {
        const rawPrompt = check.fixPrompt(url, techStack);
        const issue = {
          id: check.id,
          severity: check.severity,
          category: check.category,
          title_en: check.title_en,
          title_zh: check.title_zh,
          desc_en: check.desc_en,
          desc_zh: check.desc_zh,
          ref: check.ref,
          fixPrompt: wrapPromptWithUnknownStack(rawPrompt, techStack)
        };
        if (check.isLegal) issue.isLegal = true;
        if (check.detail) {
          issue.detail = check.detail(headers);
          // 將實際 server header 值填入修復指令
          issue.fixPrompt = issue.fixPrompt.replace('{server_value}', headers['server'] || '');
        }
        issues.push(issue);
      }
    } catch {
      // 單項檢查失敗不中斷整體掃描
    }
  }

  return { issues, headers, techStack };
}

/**
 * 從 headers 推測技術棧
 * 不依賴 AI，純規則判斷
 */
function detectTechStack(headers, url) {
  const powered = (headers['x-powered-by'] || '').toLowerCase();
  const server = (headers['server'] || '').toLowerCase();
  const via = (headers['via'] || '').toLowerCase();
  const cf = headers['cf-ray'];

  const clues = [];

  if (powered.includes('next.js') || headers['x-nextjs-cache']) clues.push('Next.js');
  if (powered.includes('express')) clues.push('Node.js / Express');
  if (powered.includes('php')) clues.push('PHP');
  if (server.includes('nginx')) clues.push('Nginx');
  if (server.includes('apache')) clues.push('Apache');
  if (server.includes('cloudflare') || cf) clues.push('Cloudflare');
  if (headers['x-vercel-id'] || headers['x-vercel-cache']) clues.push('Vercel');
  if (server.includes('netlify') || headers['x-nf-request-id']) clues.push('Netlify');
  if (headers['x-render-origin-server']) clues.push('Render');
  if (via.includes('1.1 google')) clues.push('Google Cloud / Firebase');

  return clues.length > 0 ? clues.join(', ') : 'Unknown (could not auto-detect)';
}

function getHeaderCheckCount() {
  return HEADER_CHECKS.length;
}
