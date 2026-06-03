// ── Splash animation (runs immediately on script load) ────
(function () {
  var bar    = document.getElementById('sp-bar');
  var splash = document.getElementById('splash-screen');
  if (!bar || !splash) return;

  // 0.52s: start bar fill (GPU-accelerated scaleX)
  setTimeout(function () { bar.style.transform = 'scaleX(1)'; }, 520);

  // 1.38s: fade out entire splash
  setTimeout(function () {
    splash.classList.add('out');
    setTimeout(function () { splash.style.display = 'none'; }, 280);
  }, 1380);
})();

/**
 * popup.js
 * 安全原則：
 *   - 所有 DOM 插入使用 textContent / createElement，絕不使用 innerHTML
 *   - 驗證所有來自 background 的資料
 *   - 不向任何外部傳送資料
 */

'use strict';

// ── 語言設定 ──────────────────────────────────────────────
const i18n = {
  en: {
    scanBtn: 'Scan This Site',
    scanning: 'Scanning...',
    rescan: 'Scan Again',
    scoreLabel: 'Security Score',
    good: 'Good', warning: 'Needs Improvement', danger: 'Dangerous', critical: 'Critical Risk',
    p0: 'Critical', p1: 'Warning', p2: 'Advisory',
    complianceLabel: 'Compliance Risk',
    complianceLow: 'Low Risk', complianceMed: 'Medium Risk', complianceHigh: 'High Risk', complianceCritical: 'Critical',
    legalTag: '⚖️ Legal',
    noIssues: '✓ No issues found',
    copyPrompt: 'Copy AI Fix Prompt',
    copied: '✓ Copied!',
    copyAll: '✦  Copy All Issues for AI',
    copyAllDone: '✓  Copied! Paste to your AI',
    coverageNote: 'Runs {n} passive browser-visible checks mapped to OWASP/CWE. Backend logic vulnerabilities still require code review.',
    cannotScan: 'Cannot scan this page. Please open a website and try again.',
    catHeaders: 'HTTP Security Headers',
    catEndpoints: 'Exposed Files & Endpoints',
    catCookies: 'Cookie Security',
    catDom: 'Source Code & DOM',
    initialDesc: 'Scan your AI-built, vibe-coded site for security vulnerabilities.',
    progHeaders: 'Checking security headers',
    progEndpoints: 'Checking exposed files',
    progCookies: 'Checking cookies',
    progDom: 'Scanning source code',
    techStack: 'Detected:',
    issuesFound: 'issues found'
  },
  zh: {
    scanBtn: '掃描這個網站',
    scanning: '掃描中...',
    rescan: '重新掃描',
    scoreLabel: '安全評分',
    good: '良好', warning: '需改善', danger: '危險', critical: '嚴重風險',
    p0: '高危', p1: '中危', p2: '建議',
    complianceLabel: '合規風險',
    complianceLow: '低風險', complianceMed: '中等風險', complianceHigh: '高風險', complianceCritical: '嚴重',
    legalTag: '⚖️ 合規',
    noIssues: '✓ 未發現問題',
    copyPrompt: '複製 AI 修復指令',
    copied: '✓ 已複製！',
    copyAll: '✦  複製所有漏洞給 AI',
    copyAllDone: '✓  已複製！貼給 AI 即可',
    coverageNote: '執行 {n} 項可從瀏覽器被動偵測、對應 OWASP/CWE 的安全檢查。後端邏輯漏洞仍需要原始碼審查。',
    cannotScan: '無法掃描此頁面，請開啟一個網站後再試。',
    catHeaders: 'HTTP 安全標頭',
    catEndpoints: '敏感檔案與端點',
    catCookies: 'Cookie 安全性',
    catDom: '原始碼與 DOM',
    initialDesc: '掃描你用 AI Vibe Coding 做出的網站有沒有安全漏洞。',
    progHeaders: '檢查安全 Headers',
    progEndpoints: '檢查敏感檔案',
    progCookies: '檢查 Cookie',
    progDom: '掃描原始碼',
    techStack: '偵測到：',
    issuesFound: '個問題'
  }
};

let lang = 'en';
let currentTabId = null;
let pollInterval = null;
let lastScanResult = null; // 儲存最後一次掃描結果，供語言切換重新渲染用
let scanNonce = null;      // 一次性 nonce，防止跨 popup 讀取掃描結果

// ── 初始化 ────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  // 讀取語言偏好
  const stored = await safeStorageGet('lang');
  if (stored === 'zh') lang = 'zh';

  applyLang();
  setupEventListeners();

  // 取得當前 tab
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tab = tabs?.[0];
  if (!tab) { showError(); return; }

  currentTabId = tab.id;
  const url = tab.url || '';

  // 檢查是否可掃描的頁面
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    showError();
    return;
  }

  // 顯示目前 URL
  setText('current-url-display', truncateUrl(url));
  showView('view-initial');
});

// ── 事件監聽 ──────────────────────────────────────────────
function setupEventListeners() {
  // 掃描按鈕
  safeAddClick('scan-btn', startScan);

  // 重新掃描
  safeAddClick('rescan-btn', startScan);

  // 語言切換
  const langToggle = document.getElementById('lang-toggle');
  if (langToggle) {
    langToggle.addEventListener('click', toggleLang);
    langToggle.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleLang(); }
    });
  }

  // 一鍵複製全部
  safeAddClick('copy-all-btn', handleCopyAll);

  // 監聽 background 掃描完成通知
  chrome.runtime.onMessage.addListener((message) => {
    if (!message || typeof message.action !== 'string') return;
    if (message.action === 'scanComplete' && message.tabId === currentTabId) {
      fetchAndShowResult();
    }
  });
}

// ── 開始掃描 ──────────────────────────────────────────────
async function startScan() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tab = tabs?.[0];
  if (!tab?.url || !tab?.id) { showError(); return; }

  currentTabId = tab.id;
  showView('view-scanning');
  animateProgress();

  // 產生一次性 nonce，綁定此次掃描的結果查詢
  scanNonce = crypto.randomUUID();

  // 只請求當前網站的 origin，不請求 <all_urls>
  // Must be called from a user gesture — this function is triggered by button click
  try {
    const currentOrigin = new URL(tab.url).origin + '/*';
    await chrome.permissions.request({
      permissions: ['cookies'],
      origins: [currentOrigin]
    });
  } catch {
    // Denied or unavailable — scan continues, cookie checks will be skipped automatically
  }

  try {
    await chrome.runtime.sendMessage({
      action: 'startScan',
      url: tab.url,
      tabId: tab.id,
      nonce: scanNonce
    });
  } catch {
    showError();
    return;
  }

  // 設定 timeout：30 秒後如果還沒完成，主動 poll
  let waited = 0;
  pollInterval = setInterval(async () => {
    waited += 2000;
    if (waited > 30000) {
      clearInterval(pollInterval);
      await fetchAndShowResult();
    }
  }, 2000);
}

// ── 取得掃描結果 ──────────────────────────────────────────
async function fetchAndShowResult() {
  clearInterval(pollInterval);

  try {
    const result = await chrome.runtime.sendMessage({
      action: 'getScanResult',
      tabId: currentTabId,
      nonce: scanNonce
    });

    if (!result || result.status === 'pending') {
      showError();
      return;
    }
    if (result.status === 'error') {
      showError(result.error);
      return;
    }

    lastScanResult = result; // 儲存結果以供語言切換重新渲染
    renderResult(result);

    // 掃描完成後移除站點權限（不長期保留）
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const tab = tabs?.[0];
      if (tab?.url) {
        const origin = new URL(tab.url).origin + '/*';
        await chrome.permissions.remove({ permissions: ['cookies'], origins: [origin] });
      }
    } catch { /* 靜默失敗 */ }

  } catch {
    showError();
  }
}

// ── 渲染結果 ──────────────────────────────────────────────
function renderResult(data) {
  const t = i18n[lang];
  const { score, complianceScore = 100, issues = [], techStack = '', totalChecks = 0 } = data;

  // 顏色依分數決定
  const scoreColor = score >= 80 ? '#22c55e' : score >= 60 ? '#eab308' : score >= 40 ? '#f97316' : '#ef4444';

  // 評分圓環動畫（延遲 100ms 讓畫面先出現）
  const ringFill = document.getElementById('score-ring-fill');
  const circumference = 238.8; // 2π × 38
  setTimeout(() => {
    if (ringFill) {
      const offset = circumference - (score / 100) * circumference;
      ringFill.style.strokeDasharray = circumference;
      ringFill.style.strokeDashoffset = offset;
      ringFill.style.stroke = scoreColor;
    }
    // 圓環外圈光暈
    const glow = document.getElementById('score-glow');
    if (glow) {
      glow.style.boxShadow = `0 0 20px ${scoreColor}40, 0 0 40px ${scoreColor}20`;
      glow.classList.add('active');
    }
  }, 100);

  // 數字跳動計數動畫
  setText('score-number', '0');
  animateCount('score-number', 0, score, 1000, scoreColor);

  setText('score-label', t.scoreLabel);

  const statusText = score >= 80 ? t.good : score >= 60 ? t.warning : score >= 40 ? t.danger : t.critical;
  const statusEl = document.getElementById('score-status');
  if (statusEl) {
    // 數字跑完後才顯示狀態文字
    setTimeout(() => {
      statusEl.textContent = statusText;
      statusEl.style.color = scoreColor;
      statusEl.style.animation = 'slide-up 0.4s ease';
    }, 900);
  }

  // 合規風險圓環
  const complianceColor = complianceScore >= 80 ? '#22c55e' : complianceScore >= 60 ? '#eab308' : complianceScore >= 40 ? '#f97316' : '#ef4444';
  const complianceRingFill = document.getElementById('compliance-ring-fill');
  setTimeout(() => {
    if (complianceRingFill) {
      const offset = circumference - (complianceScore / 100) * circumference;
      complianceRingFill.style.strokeDasharray = circumference;
      complianceRingFill.style.strokeDashoffset = offset;
      complianceRingFill.style.stroke = complianceColor;
    }
    const complianceGlow = document.getElementById('compliance-glow');
    if (complianceGlow) {
      complianceGlow.style.boxShadow = `0 0 20px ${complianceColor}40, 0 0 40px ${complianceColor}20`;
      complianceGlow.classList.add('active');
    }
  }, 100);

  setText('compliance-label', t.complianceLabel);
  setText('compliance-number', '0');
  animateCount('compliance-number', 0, complianceScore, 1000, complianceColor);

  const complianceStatusEl = document.getElementById('compliance-status');
  if (complianceStatusEl) {
    setTimeout(() => {
      const complianceStatusText = complianceScore >= 80 ? t.complianceLow : complianceScore >= 60 ? t.complianceMed : complianceScore >= 40 ? t.complianceHigh : t.complianceCritical;
      complianceStatusEl.textContent = complianceStatusText;
      complianceStatusEl.style.color = complianceColor;
    }, 900);
  }

  if (techStack && techStack !== 'Unknown') {
    setText('score-tech', `${t.techStack} ${techStack}`);
  }

  // 問題摘要列
  renderSummaryBar(issues, t);

  // 問題清單
  renderIssuesList(issues, t);

  // Copy All 按鈕（有問題才顯示）
  const copyAllWrap = document.getElementById('copy-all-wrap');
  if (copyAllWrap) copyAllWrap.style.display = issues.length > 0 ? 'block' : 'none';
  setText('copy-all-text', t.copyAll);

  // 底部說明
  setText('coverage-note', formatCoverageNote(t.coverageNote, totalChecks));

  // 重新掃描按鈕文字
  setText('rescan-btn', t.rescan);

  showView('view-result');
}

function renderSummaryBar(issues, t) {
  const bar = document.getElementById('summary-bar');
  if (!bar) return;

  const p0 = issues.filter(i => i.severity === 'P0').length;
  const p1 = issues.filter(i => i.severity === 'P1').length;
  const p2 = issues.filter(i => i.severity === 'P2').length;

  // 安全清空（不用 innerHTML）
  while (bar.firstChild) bar.removeChild(bar.firstChild);

  if (issues.length === 0) {
    const chip = createEl('div', 'summary-chip chip-good');
    chip.textContent = t.noIssues;
    chip.style.animationDelay = '0.3s';
    bar.appendChild(chip);
    return;
  }

  // 依序彈入，各間隔 80ms
  let delay = 0.3;
  if (p0 > 0) { const c = createChip(`🔴 ${p0} ${t.p0}`, 'chip-p0'); c.style.animationDelay = `${delay}s`; bar.appendChild(c); delay += 0.08; }
  if (p1 > 0) { const c = createChip(`🟠 ${p1} ${t.p1}`, 'chip-p1'); c.style.animationDelay = `${delay}s`; bar.appendChild(c); delay += 0.08; }
  if (p2 > 0) { const c = createChip(`🟡 ${p2} ${t.p2}`, 'chip-p2'); c.style.animationDelay = `${delay}s`; bar.appendChild(c); }
}

function renderIssuesList(issues, t) {
  const list = document.getElementById('issues-list');
  if (!list) return;
  while (list.firstChild) list.removeChild(list.firstChild);

  if (issues.length === 0) {
    const empty = createEl('div', 'no-issues');
    const icon = createEl('div', 'no-issues-icon');
    icon.textContent = '✅';
    const msg = createEl('p');
    msg.textContent = t.noIssues;
    empty.appendChild(icon);
    empty.appendChild(msg);
    list.appendChild(empty);
    return;
  }

  const categories = [
    { key: 'headers',   label: t.catHeaders },
    { key: 'endpoints', label: t.catEndpoints },
    { key: 'cookies',   label: t.catCookies },
    { key: 'dom',       label: t.catDom }
  ];

  // 依嚴重度排序
  const sorted = [...issues].sort((a, b) => {
    const order = { P0: 0, P1: 1, P2: 2 };
    return (order[a.severity] ?? 3) - (order[b.severity] ?? 3);
  });

  let cardIndex = 0;
  for (const cat of categories) {
    const catIssues = sorted.filter(i => i.category === cat.key);
    if (catIssues.length === 0) continue;

    const label = createEl('div', 'issue-group-label');
    label.textContent = cat.label;
    list.appendChild(label);

    for (const issue of catIssues) {
      const card = createIssueCard(issue, t);
      list.appendChild(card);
      // 依序延遲滑入
      const delay = 50 + cardIndex * 60;
      setTimeout(() => card.classList.add('visible'), delay);
      cardIndex++;
    }
  }
}

function createIssueCard(issue, t) {
  const card = createEl('div', 'issue-card');

  // Header
  const header = createEl('div', 'issue-card-header');
  header.setAttribute('role', 'button');
  header.setAttribute('tabindex', '0');

  const dot = createEl('div', `issue-severity-dot dot-${issue.severity.toLowerCase()}`);

  const titleWrap = createEl('div', 'issue-title-wrap');
  const title = createEl('div', 'issue-title');
  // 依語言顯示標題
  title.textContent = lang === 'zh' ? (issue.title_zh || issue.title_en) : issue.title_en;

  const ref = createEl('div', 'issue-ref');
  ref.textContent = issue.ref || '';
  if (issue.isLegal) {
    const legalTag = createEl('span', 'issue-legal-tag');
    legalTag.textContent = i18n[lang].legalTag;
    ref.appendChild(legalTag);
  }

  titleWrap.appendChild(title);
  titleWrap.appendChild(ref);

  const chevron = createEl('span', 'issue-chevron');
  chevron.textContent = '›';

  header.appendChild(dot);
  header.appendChild(titleWrap);
  header.appendChild(chevron);

  // Body（max-height 展開動畫）
  const body = createEl('div', 'issue-card-body');
  const inner = createEl('div', 'issue-body-inner');

  const desc = createEl('p', 'issue-desc');
  desc.textContent = lang === 'zh' ? (issue.desc_zh || issue.desc_en) : issue.desc_en;
  inner.appendChild(desc);

  if (issue.detail) {
    const detail = createEl('div', 'issue-detail');
    detail.textContent = issue.detail;
    inner.appendChild(detail);
  }

  if (issue.fixPrompt) {
    const copyBtn = createEl('button', 'copy-prompt-btn');
    copyBtn.textContent = t.copyPrompt;
    copyBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      copyToClipboard(issue.fixPrompt, copyBtn, t);
    });
    inner.appendChild(copyBtn);
  }

  body.appendChild(inner);

  card.appendChild(header);
  card.appendChild(body);

  // Toggle 展開/收合
  const toggleCard = () => card.classList.toggle('open');
  header.addEventListener('click', toggleCard);
  header.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleCard(); }
  });

  return card;
}

// ── 一鍵複製全部給 AI ─────────────────────────────────────
function handleCopyAll() {
  if (!lastScanResult) return;
  const t = i18n[lang];
  const btn = document.getElementById('copy-all-btn');
  const textEl = document.getElementById('copy-all-text');
  const text = formatAllIssues(lastScanResult, lang);
  navigator.clipboard.writeText(text).then(() => {
    if (textEl) textEl.textContent = t.copyAllDone;
    if (btn) btn.classList.add('copied');
    setTimeout(() => {
      if (textEl) textEl.textContent = t.copyAll;
      if (btn) btn.classList.remove('copied');
    }, 3000);
  }).catch(() => {});
}

function formatAllIssues(data, currentLang) {
  const { score = 0, complianceScore = 100, issues = [], techStack = '' } = data;
  const isZh = currentLang === 'zh';
  const severityOrder = { P0: 0, P1: 1, P2: 2 };
  const sorted = [...issues].sort((a, b) => (severityOrder[a.severity] ?? 3) - (severityOrder[b.severity] ?? 3));

  const p0 = sorted.filter(i => i.severity === 'P0');
  const p1 = sorted.filter(i => i.severity === 'P1');
  const p2 = sorted.filter(i => i.severity === 'P2');

  const line = '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━';
  const thin = '──────────────────────────────────────';

  let out = '';
  out += isZh ? '🔒 SecureCheck 安全掃描報告\n' : '🔒 SecureCheck Security Report\n';
  out += `${line}\n`;
  out += isZh
    ? `發現 ${issues.length} 個問題 | 技術安全分數: ${score}/100 | 合規風險分數: ${complianceScore}/100\n`
    : `Found ${issues.length} issue(s) | Security Score: ${score}/100 | Compliance Score: ${complianceScore}/100\n`;
  if (techStack && techStack !== 'Unknown') out += `Tech Stack: ${techStack}\n`;
  out += `${line}\n\n`;

  function formatGroup(items, emoji, label) {
    if (items.length === 0) return '';
    let s = `${emoji} ${label}\n${thin}\n`;
    items.forEach((issue, idx) => {
      const title = isZh ? (issue.title_zh || issue.title_en) : issue.title_en;
      const desc  = isZh ? (issue.desc_zh  || issue.desc_en)  : issue.desc_en;
      s += `[${idx + 1}] ${title}\n`;
      if (issue.ref) s += `    ${issue.ref}\n`;
      s += `    ${desc}\n`;
      if (issue.detail) s += `    → ${issue.detail}\n`;
      if (issue.fixPrompt) {
        s += isZh ? `\n    ▶ AI 修復指令:\n    ${issue.fixPrompt}\n` : `\n    ▶ Fix prompt for AI:\n    ${issue.fixPrompt}\n`;
      }
      s += '\n';
    });
    return s;
  }

  out += formatGroup(p0, '🔴', isZh ? '高危 (P0)' : 'Critical (P0)');
  out += formatGroup(p1, '🟠', isZh ? '中危 (P1)' : 'Warning (P1)');
  out += formatGroup(p2, '🟡', isZh ? '建議 (P2)' : 'Advisory (P2)');

  out += `${line}\n`;
  out += isZh
    ? '請幫我修復以上所有安全問題，從最嚴重的開始。'
    : 'Please help me fix all the security issues above, starting with the most critical ones.';

  return out;
}

// ── 掃描進度動畫 ──────────────────────────────────────────
function animateProgress() {
  const t = i18n[lang];
  const steps = [
    { id: 'prog-headers',   text: t.progHeaders,   delay: 0 },
    { id: 'prog-endpoints', text: t.progEndpoints,  delay: 2500 },
    { id: 'prog-cookies',   text: t.progCookies,    delay: 5000 },
    { id: 'prog-dom',       text: t.progDom,        delay: 7000 }
  ];

  setText('scanning-text', t.scanning);

  steps.forEach(({ id, text, delay }) => {
    const el = document.getElementById(id);
    if (el) el.textContent = text;

    setTimeout(() => {
      // 把前一個標為完成
      steps.forEach(s => {
        const prev = document.getElementById(s.id);
        if (prev) prev.classList.remove('active');
      });

      if (el) {
        el.classList.add('active');
        // 把之前的都標為 done
        steps.forEach(s => {
          if (s.delay < delay) {
            const prevEl = document.getElementById(s.id);
            if (prevEl) { prevEl.classList.remove('active'); prevEl.classList.add('done'); }
          }
        });
      }
    }, delay);
  });
}

// ── 工具函式 ──────────────────────────────────────────────
function showView(viewId) {
  ['view-initial', 'view-scanning', 'view-result', 'view-error'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.classList.remove('active');
  });
  const target = document.getElementById(viewId);
  if (target) target.classList.add('active');
}

function showError(msg) {
  const t = i18n[lang];
  setText('error-msg', msg || t.cannotScan);
  showView('view-error');
}

function toggleLang() {
  lang = lang === 'en' ? 'zh' : 'en';
  safeStorageSet('lang', lang);
  applyLang();

  const resultView = document.getElementById('view-result');
  if (resultView && resultView.classList.contains('active') && lastScanResult) {
    renderResult(lastScanResult);
  }
}

function applyLang() {
  const t = i18n[lang];
  setText('scan-btn-text', t.scanBtn);
  setText('initial-desc', t.initialDesc);
}

function formatCoverageNote(template, totalChecks) {
  const count = Number.isFinite(totalChecks) && totalChecks > 0 ? totalChecks : '?';
  return template.replace('{n}', String(count));
}

// 安全的文字設定（不用 innerHTML）
function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = String(text);
}

// 安全的元素建立
function createEl(tag, className) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  return el;
}

function createChip(text, className) {
  const chip = createEl('div', `summary-chip ${className}`);
  chip.textContent = text;
  return chip;
}

function safeAddClick(id, handler) {
  const el = document.getElementById(id);
  if (el) el.addEventListener('click', handler);
}

function truncateUrl(url) {
  try {
    const u = new URL(url);
    return u.hostname + (u.pathname !== '/' ? u.pathname.slice(0, 20) : '');
  } catch {
    return url.slice(0, 40);
  }
}

async function copyToClipboard(text, btn, t) {
  try {
    await navigator.clipboard.writeText(text);
    btn.textContent = t.copied;
    btn.classList.add('copied');
    setTimeout(() => {
      btn.textContent = t.copyPrompt;
      btn.classList.remove('copied');
    }, 2000);
  } catch {
    // clipboard 存取失敗，靜默處理
  }
}

// 安全的 storage 存取（wrap try/catch）
/**
 * 數字跳動計數動畫
 * 使用 easeOutCubic 緩動，讓數字先快後慢地跑到目標值
 */
function animateCount(id, from, to, duration, finalColor) {
  const el = document.getElementById(id);
  if (!el) return;

  const startTime = performance.now();

  function easeOutCubic(t) {
    return 1 - Math.pow(1 - t, 3);
  }

  function tick(now) {
    const elapsed = now - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const eased = easeOutCubic(progress);
    const current = Math.round(from + (to - from) * eased);

    el.textContent = String(current);

    // 數字跑到一半時開始變色
    if (progress > 0.5 && finalColor) {
      el.style.color = finalColor;
    }

    if (progress < 1) {
      requestAnimationFrame(tick);
    }
  }

  requestAnimationFrame(tick);
}

async function safeStorageGet(key) {
  try {
    const result = await chrome.storage.local.get(key);
    return result?.[key] ?? null;
  } catch { return null; }
}

async function safeStorageSet(key, value) {
  try {
    await chrome.storage.local.set({ [key]: value });
  } catch { /* 靜默失敗 */ }
}
