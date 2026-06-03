/**
 * endpointScanner.js
 * 掃描敏感端點、公開檔案、Rate Limit、API 文件外洩
 * 安全原則：所有請求只送到用戶自己的網站，timeout 5 秒，不傳任何用戶資料
 */

const SENSITIVE_PATHS = [
  // ── P0 高危 ──────────────────────────────────────────────
  {
    path: '/.env',
    id: 'env-exposed',
    severity: 'P0',
    title_en: '.env File Publicly Accessible',
    title_zh: '.env 檔案公開外洩',
    desc_en: 'Your .env file is accessible to anyone. All API keys, DB passwords, and secrets are exposed.',
    desc_zh: '.env 檔案可被任何人讀取，所有 API Key、資料庫密碼、Secret 都已外洩。',
    ref: 'OWASP A02 / CWE-312'
  },
  {
    path: '/.git/config',
    id: 'git-exposed',
    severity: 'P0',
    title_en: '.git Directory Exposed',
    title_zh: 'Git 原始碼倉庫外洩',
    desc_en: 'Your .git directory is public. Anyone can download your entire commit history including secrets.',
    desc_zh: 'Git 目錄公開，任何人可下載你所有的 commit 歷史，包含所有曾經的密碼和 key。',
    ref: 'OWASP A05 / CWE-540'
  },
  {
    path: '/.git/HEAD',
    id: 'git-head-exposed',
    severity: 'P0',
    title_en: '.git/HEAD Exposed',
    title_zh: '.git/HEAD 外洩',
    desc_en: '.git/HEAD is accessible, confirming git directory exposure.',
    desc_zh: '.git/HEAD 可存取，確認 Git 目錄已外洩。',
    ref: 'OWASP A05 / CWE-540'
  },
  {
    path: '/backup.sql',
    id: 'backup-sql-exposed',
    severity: 'P0',
    title_en: 'Database Backup File Exposed',
    title_zh: '資料庫備份檔案外洩',
    desc_en: 'A database backup file is publicly accessible. All user data may be exposed.',
    desc_zh: '資料庫備份檔可公開存取，所有用戶資料可能已完全外洩。',
    ref: 'OWASP A02 / CWE-312'
  },
  {
    path: '/db.sql',
    id: 'db-sql-exposed',
    severity: 'P0',
    title_en: 'Database File Exposed (db.sql)',
    title_zh: '資料庫檔案外洩 (db.sql)',
    desc_en: 'A database file is publicly accessible.',
    desc_zh: '資料庫檔案可公開存取。',
    ref: 'OWASP A02 / CWE-312'
  },
  {
    path: '/database.sql',
    id: 'database-sql-exposed',
    severity: 'P0',
    title_en: 'Database File Exposed (database.sql)',
    title_zh: '資料庫檔案外洩 (database.sql)',
    desc_en: 'A database file is publicly accessible.',
    desc_zh: '資料庫檔案可公開存取。',
    ref: 'OWASP A02 / CWE-312'
  },
  {
    path: '/.env.local',
    id: 'env-local-exposed',
    severity: 'P0',
    title_en: '.env.local File Exposed',
    title_zh: '.env.local 外洩',
    desc_en: 'Local environment config is publicly accessible.',
    desc_zh: '本地環境設定檔可公開存取。',
    ref: 'OWASP A02'
  },
  {
    path: '/.env.production',
    id: 'env-production-exposed',
    severity: 'P0',
    title_en: '.env.production File Exposed',
    title_zh: '.env.production 外洩',
    desc_en: 'Production environment config is publicly accessible.',
    desc_zh: '正式環境設定檔可公開存取，極度危險。',
    ref: 'OWASP A02'
  },

  // ── Vibe Coder 常見問題 ──────────────────────────────────
  {
    path: '/admin',
    id: 'admin-exposed',
    severity: 'P2',
    title_en: 'Admin Panel May Be Publicly Accessible',
    title_zh: '後台管理頁面可能無需登入',
    desc_en: 'The /admin path returned a public response. Confirm that it requires authentication before showing any sensitive data or actions.',
    desc_zh: '/admin 路徑有公開回應。請確認它在顯示敏感資料或操作前一定需要登入驗證。',
    ref: 'OWASP A01',
    allowHtml: true
  },
  {
    path: '/dashboard',
    id: 'dashboard-exposed',
    severity: 'P2',
    title_en: 'Dashboard May Be Publicly Accessible',
    title_zh: 'Dashboard 頁面可能無需登入',
    desc_en: 'The /dashboard path returned a public response. Confirm this page requires authentication before exposing private data.',
    desc_zh: '/dashboard 路徑有公開回應。請確認它在暴露私人資料前一定需要登入驗證。',
    ref: 'OWASP A01',
    allowHtml: true
  },

  // ── P1 中危 ──────────────────────────────────────────────
  {
    path: '/api-docs',
    id: 'api-docs-exposed',
    severity: 'P1',
    title_en: 'API Documentation Exposed',
    title_zh: 'API 文件公開外洩',
    desc_en: 'Your API documentation is publicly accessible, listing all endpoints and their parameters.',
    desc_zh: 'API 文件公開，攻擊者可看到所有端點和參數，方便針對性攻擊。',
    ref: 'OWASP A01'
  },
  {
    path: '/swagger',
    id: 'swagger-exposed',
    severity: 'P1',
    title_en: 'Swagger UI Exposed',
    title_zh: 'Swagger UI 公開外洩',
    desc_en: 'Swagger API documentation is publicly accessible.',
    desc_zh: 'Swagger API 文件公開，攻擊者可直接從瀏覽器測試你的所有 API。',
    ref: 'OWASP A01'
  },
  {
    path: '/swagger-ui.html',
    id: 'swagger-ui-exposed',
    severity: 'P1',
    title_en: 'Swagger UI (swagger-ui.html) Exposed',
    title_zh: 'Swagger UI 頁面外洩',
    desc_en: 'Swagger UI HTML page is publicly accessible.',
    desc_zh: 'Swagger UI 頁面可公開存取。',
    ref: 'OWASP A01'
  },
  {
    path: '/graphql',
    id: 'graphql-introspection',
    severity: 'P1',
    title_en: 'GraphQL Endpoint Exposed',
    title_zh: 'GraphQL 端點公開',
    desc_en: 'GraphQL endpoint is accessible. Introspection may reveal your entire schema.',
    desc_zh: 'GraphQL 端點可存取，Introspection 可能洩露你的完整 schema。',
    ref: 'OWASP A01'
  },
  {
    path: '/.DS_Store',
    id: 'ds-store-exposed',
    severity: 'P1',
    title_en: '.DS_Store File Exposed',
    title_zh: '.DS_Store 外洩（Mac 開發者常見）',
    desc_en: '.DS_Store reveals your directory structure. Common for Mac developers who forgot to add it to .gitignore.',
    desc_zh: '.DS_Store 洩漏你的資料夾結構，是 Mac 開發者最常忘記加入 .gitignore 的檔案。',
    ref: 'CWE-538'
  },
  {
    path: '/phpinfo.php',
    id: 'phpinfo-exposed',
    severity: 'P1',
    title_en: 'phpinfo() Page Exposed',
    title_zh: 'phpinfo() 頁面外洩',
    desc_en: 'phpinfo() reveals complete server configuration, PHP version, and environment variables.',
    desc_zh: 'phpinfo() 洩漏完整伺服器設定、PHP 版本、環境變數，是嚴重的資訊洩漏。',
    ref: 'CWE-200'
  },
  {
    path: '/robots.txt',
    id: 'robots-check',
    severity: 'P2',
    title_en: 'robots.txt May Expose Sensitive Paths',
    title_zh: 'robots.txt 可能洩漏敏感路徑',
    desc_en: 'robots.txt is accessible. Check if it lists admin or private paths (attackers read it too).',
    desc_zh: 'robots.txt 可存取。確認裡面是否有列出 /admin 等私有路徑（攻擊者也會看這個）。',
    ref: 'CWE-200',
    checkContent: true,
    sensitivePatterns: [/\/admin/i, /\/backup/i, /\/private/i, /\/internal/i, /\/api\//i, /\/dashboard/i]
  }
];

/**
 * 測試單一路徑是否可存取
 */
async function probeEndpoint(baseUrl, path, options = {}) {
  const { checkContent = false, sensitivePatterns = [], allowHtml = false } = options;

  try {
    const url = new URL(path, baseUrl).href;
    const response = await fetch(url, {
      method: 'GET',
      cache: 'no-store',
      credentials: 'omit',
      signal: AbortSignal.timeout(5000) // 5 秒 timeout
    });

    // 只有 200 才算真正暴露（排除 redirect 到首頁的假陽性）
    if (response.status !== 200) return { exposed: false };

    // 檢查 Content-Type，避免首頁重定向的假陽性
    const contentType = response.headers.get('content-type') || '';

    // HTML 回應通常代表被導向首頁（假陽性），對所有路徑都過濾
    // 但 allowHtml 的路徑（如 /admin）本來就是 HTML，要保留
    const isHtmlPage = contentType.includes('text/html');
    if (isHtmlPage && !allowHtml) return { exposed: false };

    if (checkContent && sensitivePatterns.length > 0) {
      const text = await response.text();
      const hasSensitivePath = sensitivePatterns.some(p => p.test(text));
      return { exposed: hasSensitivePath, content: text.slice(0, 500) };
    }

    return { exposed: true };
  } catch {
    return { exposed: false };
  }
}

/**
 * 透過 Response Headers 判斷有無 Rate Limit 設定
 * 比主動送大量請求更穩定、更不會有誤報
 */
async function testRateLimit(baseUrl) {
  try {
    const response = await fetch(baseUrl, {
      method: 'HEAD',
      cache: 'no-store',
      credentials: 'omit',
      signal: AbortSignal.timeout(5000)
    });

    // 檢查常見的 Rate Limit headers
    const rateLimitHeaders = [
      'x-ratelimit-limit',
      'x-ratelimit-remaining',
      'ratelimit-limit',
      'retry-after',
      'x-rate-limit-limit',
      'cf-ray' // Cloudflare 通常有自己的保護
    ];

    const hasRateLimitHeader = rateLimitHeaders.some(h => response.headers.get(h));

    // Cloudflare 用戶視為有 Rate Limit（Cloudflare 預設有保護）
    const hasCloudflare = !!response.headers.get('cf-ray') ||
                          (response.headers.get('server') || '').toLowerCase().includes('cloudflare');

    return {
      hasRateLimit: hasRateLimitHeader || hasCloudflare,
      allSuccess: true
    };
  } catch {
    return { hasRateLimit: false, allSuccess: false };
  }
}

/**
 * 執行所有端點掃描
 */
async function runEndpointScan(url, techStack) {
  const issues = [];
  const baseUrl = new URL(url).origin;

  // 並行掃描所有敏感路徑（效率最高）
  const results = await Promise.all(
    SENSITIVE_PATHS.map(async (check) => {
      const result = await probeEndpoint(baseUrl, check.path, {
        checkContent: check.checkContent,
        sensitivePatterns: check.sensitivePatterns,
        allowHtml: check.allowHtml
      });
      return { check, result };
    })
  );

  for (const { check, result } of results) {
    if (result.exposed) {
      issues.push({
        id: check.id,
        severity: check.severity,
        category: 'endpoints',
        title_en: check.title_en,
        title_zh: check.title_zh,
        desc_en: check.desc_en,
        desc_zh: check.desc_zh,
        ref: check.ref,
        detail: `${baseUrl}${check.path}`,
        fixPrompt: generateEndpointFixPrompt(check, baseUrl, techStack)
      });
    }
  }

  // 測試 Rate Limit
  const { hasRateLimit, allSuccess } = await testRateLimit(baseUrl);
  if (!hasRateLimit && allSuccess) {
    issues.push({
      id: 'rate-limit-missing',
      severity: 'P2',
      category: 'endpoints',
      title_en: 'Rate-Limit Headers Not Detected',
      title_zh: '未偵測到 Rate-Limit Headers',
      desc_en: 'No rate-limit headers were detected on the homepage response. This does not prove rate limiting is missing, but login, API, and form endpoints should be reviewed.',
      desc_zh: '首頁回應未偵測到 rate-limit headers。這不代表一定沒有 rate limit，但登入、API、表單端點仍應檢查。',
      ref: 'OWASP A04 / CWE-770',
      fixPrompt: `My website (${baseUrl}) did not expose rate-limit headers on the homepage response. Tech stack: ${techStack}. Please help me review whether login, API, and form submission endpoints have proper rate limiting, and show a safe implementation if missing.`
    });
  }

  return { issues };
}

function generateEndpointFixPrompt(check, baseUrl, techStack) {
  if (check.allowHtml) {
    return `My website (${baseUrl}) returned HTTP 200 for ${baseUrl}${check.path}. Tech stack: ${techStack}. Please help me verify whether this route exposes any private admin/dashboard data or actions without authentication. If it should be protected, show me exactly how to require authentication before rendering it.`;
  }

  if (check.checkContent) {
    return `My website (${baseUrl}) has a potentially sensitive robots.txt entry related to ${check.path}. Tech stack: ${techStack}. Please help me review whether robots.txt reveals private paths and how to avoid exposing sensitive routes through public metadata.`;
  }

  const issueLevel = check.severity === 'P0' ? 'critical security issue' : 'security issue';
  const base = `My website (${baseUrl}) has a ${issueLevel}: ${check.title_en}. The file/endpoint at ${baseUrl}${check.path} is publicly accessible. Tech stack: ${techStack}. Please provide the exact steps to block public access to this path, including any server configuration or deployment platform settings needed.`;
  if (!techStack || techStack.includes('Unknown')) {
    return base + '\n\nNote: I am not sure what tech stack or hosting platform I use. Please ask me 2-3 quick yes/no questions to identify it (e.g. "Are you on Vercel, Netlify, or a VPS?"), then give the exact fix.';
  }
  return base;
}

function getEndpointCheckCount() {
  return SENSITIVE_PATHS.length + 1;
}
