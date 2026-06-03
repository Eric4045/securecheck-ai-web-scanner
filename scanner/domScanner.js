/**
 * domScanner.js
 * 在頁面 context 中執行，掃描 DOM 和原始碼的安全問題
 * 安全原則：只讀取不寫入，結果只傳回 background script，不傳到外部
 * 此函式會被序列化後注入頁面執行，不可參照外部變數
 */

async function runDomScan() {
  const issues = [];
  const pageUrl = window.location.href;
  const isHttps = pageUrl.startsWith('https://');

  // ── API Key 外洩偵測 ──────────────────────────────────────
  const API_KEY_PATTERNS = [
    { name: 'OpenAI',        regex: /sk-[a-zA-Z0-9]{20,}/g,                   severity: 'P0' },
    { name: 'OpenAI Project',regex: /sk-proj-[a-zA-Z0-9\-_]{20,}/g,           severity: 'P0' },
    { name: 'Anthropic',     regex: /sk-ant-[a-zA-Z0-9\-_]{40,}/g,            severity: 'P0' },
    { name: 'Google API',    regex: /AIza[0-9A-Za-z\-_]{35}/g,                severity: 'P0' },
    { name: 'AWS Key ID',    regex: /AKIA[0-9A-Z]{16}/g,                       severity: 'P0' },
    { name: 'AWS Secret',    regex: /aws_secret_access_key\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}/gi, severity: 'P0' },
    { name: 'Stripe Live',   regex: /sk_live_[a-zA-Z0-9]{20,}/g,              severity: 'P0' },
    { name: 'GitHub Token',  regex: /ghp_[a-zA-Z0-9]{36}/g,                   severity: 'P0' },
    { name: 'GitHub Token',  regex: /github_pat_[a-zA-Z0-9_]{82}/g,           severity: 'P0' },
    { name: 'Firebase',      regex: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/g, severity: 'P0' },
    { name: 'SendGrid',      regex: /SG\.[a-zA-Z0-9\-_.]{22}\.[a-zA-Z0-9\-_.]{43}/g, severity: 'P0' },
    { name: 'Twilio',        regex: /SK[0-9a-fA-F]{32}/g,                     severity: 'P0' },
    { name: 'Stripe Test',        regex: /sk_test_[a-zA-Z0-9]{20,}/g,                        severity: 'P1' },
    { name: 'JWT Token',          regex: /eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+/g, severity: 'P1' },
    { name: 'Private Key',        regex: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/g,           severity: 'P0' },
    { name: 'Hardcoded Password', regex: /(password|passwd|pwd)\s*[:=]\s*["'][^"']{6,}["']/gi, severity: 'P1' },
    { name: 'Hardcoded Secret',   regex: /(secret|api_key|apikey|auth_token)\s*[:=]\s*["'][^"']{8,}["']/gi, severity: 'P1' },
    // ── Common AI-built site 常見問題 ───────────────────────────────────
    { name: 'Supabase Service Key', regex: /(supabase[_\-]?service[_\-]?(?:role[_\-]?)?key|service_role)\s*[:=]\s*["']?eyJ[a-zA-Z0-9\-_]{20,}/gi, severity: 'P0' },
    { name: 'NEXT_PUBLIC Secret',   regex: /NEXT_PUBLIC_(SECRET|PRIVATE_KEY|PASSWORD|JWT_SECRET|AUTH_SECRET|SERVICE_KEY)\s*[:=]\s*["'][^"']{6,}["']/gi, severity: 'P0' }
  ];

  // 收集所有要掃描的文字來源
  const textSources = [];

  // 1. 行內 script 標籤內容
  document.querySelectorAll('script:not([src])').forEach(el => {
    textSources.push({ type: 'inline-script', label: 'inline script', content: el.textContent });
  });

  // 2. 同源外部 JS bundle。多數 AI-built React/Vite/Next 網站的風險都在 bundle 裡。
  const externalScriptSources = await collectSameOriginScriptSources();
  externalScriptSources.forEach(source => {
    textSources.push({ type: 'external-script', label: source.url, content: source.content });
  });

  // 3. 頁面 HTML 原始碼（掃描 data- 屬性中的 key，限制 1MB 防止惡意頁面塞爆記憶體）
  const MAX_HTML_CHARS = 1_000_000;
  textSources.push({ type: 'html', label: 'page html', content: document.documentElement.innerHTML.slice(0, MAX_HTML_CHARS) });

  const foundKeys = new Set();

  for (const source of textSources) {
    for (const pattern of API_KEY_PATTERNS) {
      const matches = source.content.match(pattern.regex);
      if (matches) {
        for (const match of matches) {
          // 避免重複回報同一個 key
          const key = `${pattern.name}:${match.slice(0, 12)}`;
          if (!foundKeys.has(key)) {
            foundKeys.add(key);
            // 遮蔽 key 的中段，不在報告中顯示完整 key
            const masked = match.slice(0, 8) + '****' + match.slice(-4);
            const foundIn = source.type === 'external-script' ? ` in ${source.label}` : '';
            issues.push({
              id: `api-key-${pattern.name.toLowerCase().replace(/\s+/g, '-')}`,
              severity: pattern.severity,
              category: 'dom',
              isLegal: true,
              title_en: `${pattern.name} API Key Exposed in Frontend`,
              title_zh: `${pattern.name} API Key 外洩在前端原始碼`,
              desc_en: `A ${pattern.name} API key was found in your frontend code${foundIn}. Anyone visiting your site can steal this key.`,
              desc_zh: `在前端原始碼${foundIn ? '（外部 JS bundle）' : ''}中發現 ${pattern.name} API Key。任何訪客都可以直接竊取這個 key 並冒用你的帳戶。`,
              ref: 'OWASP A02 / CWE-312',
              detail: `Found: ${masked}`,
              fixPrompt: `URGENT: My website has a ${pattern.name} API key exposed in the frontend JavaScript source code (found: ${masked}...). Tech stack: Unknown. Please: 1) Tell me how to immediately revoke and regenerate this key, 2) Show me how to move API calls to a backend service so keys are never exposed in frontend code.`
            });
          }
        }
      }
    }
  }

  // ── 混合內容偵測（HTTPS 頁面載入 HTTP 資源）──────────────
  if (isHttps) {
    const mixedResources = [];

    // 圖片
    document.querySelectorAll('img[src^="http:"]').forEach(el => {
      mixedResources.push({ tag: 'img', src: el.getAttribute('src') });
    });
    // Script
    document.querySelectorAll('script[src^="http:"]').forEach(el => {
      mixedResources.push({ tag: 'script', src: el.getAttribute('src') });
    });
    // CSS
    document.querySelectorAll('link[href^="http:"][rel="stylesheet"]').forEach(el => {
      mixedResources.push({ tag: 'link', src: el.getAttribute('href') });
    });
    // iframe
    document.querySelectorAll('iframe[src^="http:"]').forEach(el => {
      mixedResources.push({ tag: 'iframe', src: el.getAttribute('src') });
    });

    if (mixedResources.length > 0) {
      issues.push({
        id: 'mixed-content',
        severity: 'P0',
        category: 'dom',
        title_en: 'Mixed Content Detected',
        title_zh: '混合內容（HTTPS 頁面載入 HTTP 資源）',
        desc_en: 'Your HTTPS page loads resources over HTTP. These can be intercepted and replaced by attackers.',
        desc_zh: 'HTTPS 頁面中有用 HTTP 載入的資源，這些資源可被中間人攔截並替換成惡意內容。',
        ref: 'OWASP A02 / W3C Mixed Content',
        detail: `${mixedResources.length} mixed resource(s): ${mixedResources.slice(0, 3).map(r => r.src).join(', ')}`,
        fixPrompt: `My HTTPS website (${pageUrl}) has mixed content — it loads ${mixedResources.length} resource(s) over HTTP instead of HTTPS. Resources: ${mixedResources.slice(0, 5).map(r => r.src).join(', ')}. Please show me how to fix all mixed content issues.`
      });
    }
  }

  // ── innerHTML 直接插入偵測（XSS 風險）──────────────────
  const scriptSourceText = textSources
    .filter(source => source.type === 'inline-script' || source.type === 'external-script')
    .map(source => source.content)
    .join('\n');

  const innerHtmlPatterns = [
    /\.innerHTML\s*=/g,
    /\.outerHTML\s*=/g,
    /document\.write\s*\(/g,
    /document\.writeln\s*\(/g,
    /insertAdjacentHTML\s*\(/g
  ];

  const foundXssPatterns = [];
  for (const pattern of innerHtmlPatterns) {
    const matches = scriptSourceText.match(pattern);
    if (matches) {
      foundXssPatterns.push(...matches.map(m => m.trim()));
    }
  }

  // 白名單：如果程式碼裡有常見的跳脫函式，降低誤報可能
  const hasEscapeFunction = /\besc\s*\(|\bescHtml\s*\(|\bDOMPurify\b|\bsanitize\s*\(|\btextContent\s*=/.test(scriptSourceText);
  const adjustedXssCount = hasEscapeFunction
    ? foundXssPatterns.length - Math.floor(foundXssPatterns.length * 0.5)
    : foundXssPatterns.length;

  if (adjustedXssCount > 0) {
    issues.push({
      id: 'xss-innerhtml',
      severity: 'P1',
      category: 'dom',
      title_en: 'Potential XSS — Direct DOM Insertion Detected',
      title_zh: '潛在 XSS — 偵測到直接 DOM 插入',
      desc_en: 'Code uses innerHTML or document.write(). If user data is inserted without escaping, it allows XSS attacks.',
      desc_zh: '程式碼使用了 innerHTML 或 document.write()，若插入未跳脫的用戶資料，攻擊者可執行任意 JavaScript。',
      ref: 'OWASP A03 / CWE-79',
      detail: `Patterns found: ${[...new Set(foundXssPatterns)].slice(0, 5).join(', ')}`,
      fixPrompt: `My website (${pageUrl}) uses innerHTML or document.write() in frontend JavaScript code. Patterns found: ${foundXssPatterns.slice(0, 5).join(', ')}. Please show me how to safely insert dynamic content using textContent, createElement, or a sanitization library, and explain why innerHTML is dangerous.`
    });
  }

  // ── console.log 殘留偵測 ──────────────────────────────────
  const consoleLogs = scriptSourceText.match(/console\.(log|error|warn|debug|info)\s*\(/g);
  if (consoleLogs && consoleLogs.length > 0) {
    // 進一步確認是否有敏感資料
    const sensitiveLogs = scriptSourceText.match(/console\.(log|error|warn)\s*\([^)]*?(password|token|key|secret|auth|user|email)[^)]*\)/gi);

    issues.push({
      id: 'console-log-found',
      severity: sensitiveLogs ? 'P1' : 'P2',
      category: 'dom',
      title_en: sensitiveLogs ? 'console.log Leaking Sensitive Data' : 'console.log Statements Found',
      title_zh: sensitiveLogs ? 'console.log 洩漏敏感資料' : 'console.log 殘留未清除',
      desc_en: sensitiveLogs
        ? 'console.log statements appear to output sensitive data (tokens, passwords, user info). Anyone can see this in DevTools.'
        : 'console.log statements were not removed before deployment. They may expose internal logic or data.',
      desc_zh: sensitiveLogs
        ? 'console.log 疑似輸出敏感資料（token、密碼、用戶資訊），任何人開啟開發者工具都能看到。'
        : '部署前未清除 console.log，可能洩漏內部邏輯或資料給開啟開發者工具的訪客。',
      ref: 'OWASP A09',
      detail: `${consoleLogs.length} console statement(s) found`,
      fixPrompt: `My website (${pageUrl}) has ${consoleLogs.length} console.log/warn/error statements in the frontend code that were not removed before deployment. Please show me: 1) How to find and remove all console statements, 2) How to configure my build tool to automatically strip console logs in production.`
    });
  }

  // ── CDN Script 缺少 SRI 驗證 ──────────────────────────────
  const externalScriptElements = Array.from(document.querySelectorAll('script[src]')).filter(el => {
    const src = el.getAttribute('src') || '';
    return (src.startsWith('http') || src.startsWith('//')) &&
           !src.includes(window.location.hostname);
  });

  const noSriScripts = externalScriptElements.filter(el => !el.getAttribute('integrity'));

  if (noSriScripts.length > 0) {
    issues.push({
      id: 'sri-missing',
      severity: 'P2',
      category: 'dom',
      title_en: 'External Scripts Without SRI',
      title_zh: '外部 CDN Script 缺少 SRI 驗證',
      desc_en: 'External scripts from CDNs have no Subresource Integrity check. If the CDN is compromised, malicious code runs on your site.',
      desc_zh: '外部 CDN 的 script 沒有 SRI 完整性驗證，若 CDN 遭入侵，惡意程式碼會直接在你的網站上執行。',
      ref: 'OWASP A08 / W3C SRI',
      detail: `${noSriScripts.length} external script(s) without integrity: ${noSriScripts.slice(0, 3).map(el => el.getAttribute('src')).join(', ')}`,
      fixPrompt: `My website (${pageUrl}) loads ${noSriScripts.length} external scripts without Subresource Integrity (SRI) checks. Scripts: ${noSriScripts.slice(0, 5).map(el => el.getAttribute('src')).join(', ')}. Please show me how to generate and add integrity hashes to these script tags.`
    });
  }

  // ── localStorage 存放 Token 偵測 ──────────────────────────
  try {
    const lsKeys = Object.keys(localStorage);
    const tokenKeys = lsKeys.filter(k =>
      /token|jwt|auth|session|credential/i.test(k)
    );

    if (tokenKeys.length > 0) {
      issues.push({
        id: 'localstorage-token',
        severity: 'P1',
        category: 'dom',
        isLegal: true,
        title_en: 'Auth Tokens Stored in localStorage',
        title_zh: 'Token 存放在 localStorage（XSS 高風險）',
        desc_en: 'Authentication tokens in localStorage can be stolen by any JavaScript on the page, including from XSS attacks.',
        desc_zh: 'localStorage 裡的 token 可被頁面上任何 JavaScript 讀取，一旦有 XSS 漏洞，攻擊者可直接竊取所有 session。',
        ref: 'OWASP A02 / CWE-922',
        detail: `Keys found: ${tokenKeys.join(', ')}`,
        fixPrompt: `My website (${pageUrl}) stores authentication tokens in localStorage (keys: ${tokenKeys.join(', ')}). This is vulnerable to XSS theft. Tech stack: Unknown. Please show me how to migrate to httpOnly cookies for token storage, and explain the security difference.`
      });
    }
  } catch {
    // localStorage 存取被阻擋，跳過
  }

  // ── 偵測是否使用 eval() ──────────────────────────────────
  const evalMatches = scriptSourceText.match(/\beval\s*\(/g);
  if (evalMatches && evalMatches.length > 0) {
    issues.push({
      id: 'eval-usage',
      severity: 'P1',
      category: 'dom',
      title_en: 'eval() Usage Detected',
      title_zh: '偵測到 eval() 使用',
      desc_en: 'eval() executes arbitrary strings as code. If user input reaches eval(), it enables code injection attacks.',
      desc_zh: 'eval() 可執行任意字串為程式碼，若用戶輸入進入 eval()，攻擊者可完全控制你的前端邏輯。',
      ref: 'OWASP A03 / CWE-95',
      detail: `${evalMatches.length} eval() call(s) found`,
      fixPrompt: `My website (${pageUrl}) uses eval() in frontend JavaScript (${evalMatches.length} occurrence(s)). Please explain why eval() is dangerous and show me safe alternatives for common use cases.`
    });
  }

  return issues;
}

async function collectSameOriginScriptSources() {
  const MAX_EXTERNAL_SCRIPTS = 12;
  const MAX_SCRIPT_CHARS = 350_000;
  const scripts = Array.from(document.querySelectorAll('script[src]'));
  const seen = new Set();
  const urls = [];

  for (const script of scripts) {
    const rawSrc = script.getAttribute('src') || '';
    if (!rawSrc || rawSrc.startsWith('data:') || rawSrc.startsWith('blob:')) continue;

    try {
      const url = new URL(rawSrc, window.location.href);
      if (url.protocol !== 'http:' && url.protocol !== 'https:') continue;
      if (url.origin !== window.location.origin) continue;
      if (seen.has(url.href)) continue;
      seen.add(url.href);
      urls.push(url.href);
      if (urls.length >= MAX_EXTERNAL_SCRIPTS) break;
    } catch {
      // Ignore malformed script URLs.
    }
  }

  const results = await Promise.allSettled(urls.map(async (url) => {
    const response = await fetch(url, {
      method: 'GET',
      cache: 'no-store',
      credentials: 'omit',
      signal: AbortSignal.timeout(4000)
    });

    if (!response.ok) return null;
    const contentType = response.headers.get('content-type') || '';
    if (contentType && !/javascript|ecmascript|text\/plain|application\/octet-stream/i.test(contentType)) {
      return null;
    }

    const content = (await response.text()).slice(0, MAX_SCRIPT_CHARS);
    return { url, content };
  }));

  return results
    .filter(result => result.status === 'fulfilled' && result.value && result.value.content)
    .map(result => result.value);
}
