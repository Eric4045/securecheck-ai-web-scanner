/**
 * background.js — Service Worker
 * 協調所有掃描模組，管理掃描狀態
 * 安全原則：
 *   - 驗證所有 message sender
 *   - 不儲存任何掃描結果到 storage（隱私保護）
 *   - 所有 fetch 都設 credentials: 'omit'
 *   - 不向任何第三方傳送資料
 */

importScripts(
  'scanner/headerScanner.js',
  'scanner/endpointScanner.js',
  'scanner/cookieScanner.js'
);

// 掃描狀態暫存（只存在記憶體，不持久化）
const scanState = new Map();
const COOKIE_CHECK_COUNT = 6;
const DOM_CHECK_COUNT = 7;

chrome.tabs.onRemoved.addListener((tabId) => {
  scanState.delete(tabId);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // 安全驗證：只接受來自本 extension 的 popup 訊息
  if (sender.id !== chrome.runtime.id) return;
  if (!message || typeof message.action !== 'string') return;

  if (message.action === 'startScan') {
    const { url, tabId, nonce } = message;

    // 基本輸入驗證
    if (!url || typeof url !== 'string' || !tabId || typeof tabId !== 'number') {
      sendResponse({ error: 'Invalid parameters' });
      return;
    }
    if (!nonce || typeof nonce !== 'string') {
      sendResponse({ error: 'Invalid parameters' });
      return;
    }

    // 只允許 http/https
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      sendResponse({ error: 'Cannot scan this page type' });
      return;
    }

    // 驗證 tabId 確實對應傳入的 URL，防止 URL 偽造
    sendResponse({ started: true });
    chrome.tabs.get(tabId, (tab) => {
      if (chrome.runtime.lastError || !tab) return;
      if (tab.url !== url) return;
      if (!tab.url.startsWith('http://') && !tab.url.startsWith('https://')) return;
      performScan(url, tabId, nonce);
    });
    return true;
  }

  if (message.action === 'getScanResult') {
    const { tabId, nonce } = message;
    const result = scanState.get(tabId);
    // 驗證 nonce，確保只有發起掃描的 popup 能讀取結果
    if (!result || result.nonce !== nonce) {
      sendResponse({ status: 'pending' });
      return;
    }
    sendResponse(result);
    return;
  }
});

/**
 * 執行完整掃描流程
 */
async function performScan(url, tabId, nonce) {
  // 設定掃描中狀態
  scanState.set(tabId, { status: 'scanning', nonce });

  try {
    // Header scan provides the best passive tech-stack signal. Run it first so
    // generated AI fix prompts can be framework/host aware.
    const [headerResult, domResult] = await Promise.allSettled([
      runHeaderScan(url),
      runDomScanInTab(tabId, url)
    ]);

    // 取得技術棧資訊（從 header 掃描結果）
    const techStack = headerResult.status === 'fulfilled'
      ? (headerResult.value.techStack || 'Unknown')
      : 'Unknown';

    const headerIssues = headerResult.status === 'fulfilled'
      ? (headerResult.value.issues || [])
      : [];

    const domIssues = domResult.status === 'fulfilled'
      ? applyDetectedTechStack(domResult.value || [], techStack)
      : [];

    const [endpointResult, cookieResult] = await Promise.allSettled([
      runEndpointScan(url, techStack),
      runCookieScan(url, techStack)
    ]);

    const endpointIssues = endpointResult.status === 'fulfilled'
      ? endpointResult.value.issues
      : [];

    const cookieIssues = cookieResult.status === 'fulfilled'
      ? cookieResult.value.issues
      : [];

    // 合併所有問題
    const allIssues = [
      ...headerIssues,
      ...endpointIssues,
      ...cookieIssues,
      ...domIssues
    ];

    // 計算安全分數與合規分數
    const score = calculateScore(allIssues);
    const complianceScore = calculateComplianceScore(allIssues);

    // 儲存結果（只存在記憶體）
    scanState.set(tabId, {
      status: 'done',
      nonce,
      url,
      techStack,
      score,
      complianceScore,
      issues: allIssues,
      scannedAt: Date.now(),
      totalChecks: getTotalCheckCount()
    });
    scheduleScanCleanup(tabId, nonce);

    // 通知 popup 掃描完成
    try {
      await chrome.runtime.sendMessage({
        action: 'scanComplete',
        tabId
      });
    } catch {
      // Popup 可能已關閉，忽略錯誤
    }

  } catch (err) {
    scanState.set(tabId, {
      status: 'error',
      nonce,
      error: 'Scan failed. Please try again.'
    });
    scheduleScanCleanup(tabId, nonce);
  }
}

/**
 * 在目標 tab 中執行 DOM 掃描
 */
async function runDomScanInTab(tabId, url) {
  try {
    // 先注入 domScanner.js，再執行 runDomScan 函式
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ['scanner/domScanner.js']
    });

    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        if (typeof runDomScan === 'function') {
          return runDomScan();
        }
        return [];
      }
    });

    return results?.[0]?.result || [];
  } catch {
    return [];
  }
}

/**
 * 將偵測到的技術棧資訊填入其他掃描器產生的修復指令
 */
function applyDetectedTechStack(issues, techStack) {
  if (!techStack || techStack.includes('Unknown')) return issues;
  return issues.map(issue => ({
    ...issue,
    fixPrompt: issue.fixPrompt
      ? issue.fixPrompt
          .replaceAll('Tech stack: Unknown (could not auto-detect)', `Tech stack: ${techStack}`)
          .replaceAll('Tech stack: Unknown', `Tech stack: ${techStack}`)
      : issue.fixPrompt
  }));
}

function getTotalCheckCount() {
  const headerCount = typeof getHeaderCheckCount === 'function' ? getHeaderCheckCount() : 0;
  const endpointCount = typeof getEndpointCheckCount === 'function' ? getEndpointCheckCount() : 0;
  return headerCount + endpointCount + COOKIE_CHECK_COUNT + DOM_CHECK_COUNT;
}

function scheduleScanCleanup(tabId, nonce) {
  setTimeout(() => {
    const result = scanState.get(tabId);
    if (result && result.nonce === nonce) scanState.delete(tabId);
  }, 10 * 60 * 1000);
}

/**
 * 計算技術安全分數
 * 每個類別有扣分上限，避免大型網站因問題數量多而嚴重失真
 */
function calculateScore(issues) {
  const caps = { headers: 30, cookies: 20, endpoints: 25, dom: 25 };
  const deductions = { headers: 0, cookies: 0, endpoints: 0, dom: 0 };

  for (const issue of issues) {
    const d = issue.severity === 'P0' ? 20 : issue.severity === 'P1' ? 10 : 3;
    const cat = issue.category;
    if (cat in deductions) deductions[cat] += d;
  }

  let total = 0;
  for (const cat of Object.keys(caps)) {
    total += Math.min(deductions[cat], caps[cat]);
  }

  return Math.max(0, 100 - total);
}

/**
 * 計算合規風險分數（只看標記 isLegal 的問題）
 * 分數越高代表合規風險越低
 */
function calculateComplianceScore(issues) {
  const caps = { headers: 25, cookies: 25, endpoints: 30, dom: 20 };
  const deductions = { headers: 0, cookies: 0, endpoints: 0, dom: 0 };

  for (const issue of issues.filter(i => i.isLegal)) {
    const d = issue.severity === 'P0' ? 25 : issue.severity === 'P1' ? 12 : 4;
    const cat = issue.category;
    if (cat in deductions) deductions[cat] += d;
  }

  let total = 0;
  for (const cat of Object.keys(caps)) {
    total += Math.min(deductions[cat], caps[cat]);
  }

  return Math.max(0, 100 - total);
}
