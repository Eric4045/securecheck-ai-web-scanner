/**
 * cookieScanner.js
 * 掃描 Cookie 的安全屬性
 * 安全原則：只讀取 cookie 屬性，不讀取 cookie 值，不傳送任何資料到外部
 */

/**
 * 執行 Cookie 安全掃描
 * @param {string} url - 目標網站 URL
 * @param {string} techStack - 偵測到的技術棧
 * @returns {Promise<{issues: Array}>}
 */
function maskCookieName(name) {
  if (name.length <= 3) return name[0] + '…';
  return name.slice(0, 3) + '…' + name.slice(-2);
}

function maskNames(names) {
  return names.map(maskCookieName).join(', ');
}

async function runCookieScan(url, techStack) {
  const issues = [];

  let cookies = [];
  try {
    cookies = await chrome.cookies.getAll({ url });
  } catch {
    return { issues: [] };
  }

  if (cookies.length === 0) {
    return { issues: [] };
  }

  // 判斷是否為 session/auth 相關的敏感 cookie
  const SESSION_PATTERN = /session|token|auth|login|jwt|sid|user.*id|id.*user|credential|access/i;

  const insecureCookies = {
    noHttpOnly_session: [],
    noHttpOnly_tracking: [],
    noSecure: [],
    noSameSite_session: [],
    noSameSite_tracking: [],
    sameSiteNoneWithoutSecure: []
  };

  for (const cookie of cookies) {
    // 只記錄 cookie 名稱，不記錄任何值（保護用戶隱私）
    const name = cookie.name;
    const isSession = SESSION_PATTERN.test(name);

    if (!cookie.httpOnly) {
      if (isSession) insecureCookies.noHttpOnly_session.push(name);
      else insecureCookies.noHttpOnly_tracking.push(name);
    }
    if (!cookie.secure) {
      insecureCookies.noSecure.push(name);
    }
    if (!cookie.sameSite || cookie.sameSite === 'unspecified') {
      if (isSession) insecureCookies.noSameSite_session.push(name);
      else insecureCookies.noSameSite_tracking.push(name);
    }
    if (cookie.sameSite === 'no_restriction' && !cookie.secure) {
      insecureCookies.sameSiteNoneWithoutSecure.push(name);
    }
  }

  // HttpOnly 缺失（session cookie）→ P1
  if (insecureCookies.noHttpOnly_session.length > 0) {
    issues.push({
      id: 'cookie-no-httponly',
      severity: 'P1',
      category: 'cookies',
      isLegal: true,
      title_en: 'Session Cookies Missing HttpOnly Flag',
      title_zh: 'Session Cookie 缺少 HttpOnly 旗標',
      desc_en: 'Authentication or session cookies without HttpOnly can be stolen by JavaScript if your site has an XSS vulnerability.',
      desc_zh: '登入或 session 相關的 Cookie 沒有 HttpOnly，一旦有 XSS 漏洞，所有 session 都會被竊取。',
      ref: 'OWASP A02 / CWE-1004',
      detail: `Affected session cookies: ${maskNames(insecureCookies.noHttpOnly_session.slice(0, 5))}${insecureCookies.noHttpOnly_session.length > 5 ? '...' : ''}`,
      fixPrompt: `My website (${url}) has ${insecureCookies.noHttpOnly_session.length} session/auth cookie(s) without the HttpOnly flag. Tech stack: ${techStack}. Please show me exactly how to set HttpOnly on all session and authentication cookies.`
    });
  }

  // HttpOnly 缺失（追蹤 cookie）→ P2
  if (insecureCookies.noHttpOnly_tracking.length > 0) {
    issues.push({
      id: 'cookie-no-httponly-tracking',
      severity: 'P2',
      category: 'cookies',
      title_en: 'Tracking Cookies Missing HttpOnly Flag',
      title_zh: '追蹤 Cookie 缺少 HttpOnly 旗標',
      desc_en: 'Non-session cookies without HttpOnly are accessible to JavaScript. These appear to be analytics or tracking cookies, which may intentionally need JS access.',
      desc_zh: '非 session 類的 Cookie 缺少 HttpOnly，這些可能是分析或追蹤用途的 Cookie，有時本來就需要 JavaScript 存取。',
      ref: 'OWASP A02 / CWE-1004',
      detail: `Affected tracking cookies: ${maskNames(insecureCookies.noHttpOnly_tracking.slice(0, 5))}${insecureCookies.noHttpOnly_tracking.length > 5 ? '...' : ''}`,
      fixPrompt: `My website (${url}) has ${insecureCookies.noHttpOnly_tracking.length} non-session cookie(s) without the HttpOnly flag. Tech stack: ${techStack}. Please confirm whether these cookies need JavaScript access, and if not, show me how to add HttpOnly.`
    });
  }

  // Secure 缺失 → Cookie 可在 HTTP 連線中被攔截
  if (insecureCookies.noSecure.length > 0) {
    issues.push({
      id: 'cookie-no-secure',
      severity: 'P1',
      category: 'cookies',
      isLegal: true,
      title_en: 'Cookies Missing Secure Flag',
      title_zh: 'Cookie 缺少 Secure 旗標',
      desc_en: 'Cookies without Secure flag can be transmitted over HTTP connections and intercepted.',
      desc_zh: '沒有 Secure 旗標的 Cookie 可能在 HTTP 連線中傳送，被中間人攔截。',
      ref: 'OWASP A02 / CWE-614',
      detail: `Affected cookies: ${maskNames(insecureCookies.noSecure.slice(0, 5))}${insecureCookies.noSecure.length > 5 ? '...' : ''}`,
      fixPrompt: `My website (${url}) has ${insecureCookies.noSecure.length} cookie(s) without the Secure flag. Tech stack: ${techStack}. Please show me how to add the Secure flag to all cookies.`
    });
  }

  // SameSite 缺失（session cookie）→ P1
  if (insecureCookies.noSameSite_session.length > 0) {
    issues.push({
      id: 'cookie-no-samesite',
      severity: 'P1',
      category: 'cookies',
      isLegal: true,
      title_en: 'Session Cookies Missing SameSite Attribute',
      title_zh: 'Session Cookie 缺少 SameSite 屬性',
      desc_en: 'Session cookies without SameSite=Strict or Lax are vulnerable to Cross-Site Request Forgery (CSRF) attacks.',
      desc_zh: '登入相關 Cookie 缺少 SameSite 屬性，容易受到 CSRF 攻擊，攻擊者可利用用戶已登入的狀態執行惡意操作。',
      ref: 'OWASP A01 / CWE-352',
      detail: `Affected session cookies: ${maskNames(insecureCookies.noSameSite_session.slice(0, 5))}${insecureCookies.noSameSite_session.length > 5 ? '...' : ''}`,
      fixPrompt: `My website (${url}) has ${insecureCookies.noSameSite_session.length} session/auth cookie(s) without the SameSite attribute, making them vulnerable to CSRF attacks. Tech stack: ${techStack}. Please explain the difference between SameSite=Strict and Lax, and show me how to set the appropriate value.`
    });
  }

  // SameSite 缺失（追蹤 cookie）→ P2
  if (insecureCookies.noSameSite_tracking.length > 0) {
    issues.push({
      id: 'cookie-no-samesite-tracking',
      severity: 'P2',
      category: 'cookies',
      title_en: 'Tracking Cookies Missing SameSite Attribute',
      title_zh: '追蹤 Cookie 缺少 SameSite 屬性',
      desc_en: 'Non-session cookies without SameSite. These appear to be analytics or tracking cookies — please confirm whether SameSite is needed.',
      desc_zh: '非 session 類的 Cookie 缺少 SameSite，可能是分析追蹤用途，請確認是否需要設定。',
      ref: 'OWASP A01 / CWE-352',
      detail: `Affected tracking cookies: ${maskNames(insecureCookies.noSameSite_tracking.slice(0, 5))}${insecureCookies.noSameSite_tracking.length > 5 ? '...' : ''}`,
      fixPrompt: `My website (${url}) has ${insecureCookies.noSameSite_tracking.length} tracking/analytics cookie(s) without the SameSite attribute. Tech stack: ${techStack}. Please advise whether these cookies need SameSite and what value to use.`
    });
  }

  // SameSite=None 但沒有 Secure → 瀏覽器會直接拒絕
  if (insecureCookies.sameSiteNoneWithoutSecure.length > 0) {
    issues.push({
      id: 'cookie-samesite-none-no-secure',
      severity: 'P0',
      category: 'cookies',
      isLegal: true,
      title_en: 'SameSite=None Without Secure Flag',
      title_zh: 'SameSite=None 但缺少 Secure 旗標',
      desc_en: 'SameSite=None requires the Secure flag. Modern browsers will reject these cookies entirely.',
      desc_zh: 'SameSite=None 必須搭配 Secure 旗標，否則現代瀏覽器會完全拒絕這個 Cookie，功能會壞掉。',
      ref: 'OWASP A02',
      detail: `Affected cookies: ${maskNames(insecureCookies.sameSiteNoneWithoutSecure)}`,
      fixPrompt: `My website (${url}) has ${insecureCookies.sameSiteNoneWithoutSecure.length} cookie(s) with SameSite=None but without the Secure flag. This will cause cookies to be rejected by modern browsers. Tech stack: ${techStack}. Please show me the fix.`
    });
  }

  return { issues };
}
