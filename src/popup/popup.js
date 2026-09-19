// ScamShield Pro - Popup Controller

document.addEventListener('DOMContentLoaded', async () => {
  // DOM Elements
  const tabActiveSite = document.getElementById('tab-active-site');
  const tabUrlInspector = document.getElementById('tab-url-inspector');
  const viewActiveRadar = document.getElementById('view-active-radar');
  const viewUrlInspector = document.getElementById('view-url-inspector');
  const btnOpenOptions = document.getElementById('btn-open-options');

  const gaugeMeter = document.getElementById('gauge-meter');
  const gaugeScore = document.getElementById('gauge-score');
  const gaugeVerdict = document.getElementById('gauge-verdict');
  const siteProtocol = document.getElementById('site-protocol');
  const siteHostname = document.getElementById('site-hostname');
  const siteBrandTarget = document.getElementById('site-brand-target');
  const brandTargetName = document.getElementById('brand-target-name');

  const threatIndicatorPill = document.getElementById('threat-indicator-pill');
  const threatSummaryText = document.getElementById('threat-summary-text');
  const metricTypo = document.getElementById('metric-typo');
  const metricHomo = document.getElementById('metric-homo');
  const metricDomain = document.getElementById('metric-domain');
  const metricDom = document.getElementById('metric-dom');

  const flagsContainer = document.getElementById('flags-container');
  const flagsCount = document.getElementById('flags-count');
  const flagsList = document.getElementById('flags-list');

  const btnRescan = document.getElementById('btn-rescan');
  const btnWhitelistCurrent = document.getElementById('btn-whitelist-current');

  const inputCustomUrl = document.getElementById('input-custom-url');
  const btnRunInspect = document.getElementById('btn-run-inspect');
  const inspectorResults = document.getElementById('inspector-results');
  const inspectScoreBadge = document.getElementById('inspect-score-badge');
  const inspectVerdict = document.getElementById('inspect-verdict');
  const inspectSummary = document.getElementById('inspect-summary');
  const inspectFlags = document.getElementById('inspect-flags');

  let currentTabReport = null;
  let currentTab = null;

  // Tab Switching
  tabActiveSite.addEventListener('click', () => {
    tabActiveSite.classList.add('active');
    tabUrlInspector.classList.remove('active');
    viewActiveRadar.classList.add('active');
    viewUrlInspector.classList.remove('active');
  });

  tabUrlInspector.addEventListener('click', () => {
    tabUrlInspector.classList.add('active');
    tabActiveSite.classList.remove('active');
    viewUrlInspector.classList.add('active');
    viewActiveRadar.classList.remove('active');
    inputCustomUrl.focus();
  });

  // Open Options Page
  btnOpenOptions.addEventListener('click', () => {
    if (chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    } else {
      window.open(chrome.runtime.getURL('src/options/options.html'));
    }
  });

  /**
   * Updates the UI with threat evaluation report
   */
  function renderReport(report) {
    currentTabReport = report;
    const score = report.riskScore || 0;
    const circumference = 264;
    const offset = circumference - (score / 100) * circumference;

    gaugeMeter.style.strokeDashoffset = offset;
    gaugeScore.textContent = score;

    let themeColor = '#10b981';
    let pillClass = 'pill-safe';

    if (report.verdict === 'DANGER') {
      themeColor = '#ef4444';
      pillClass = 'pill-danger';
      gaugeVerdict.textContent = 'HIGH RISK';
    } else if (report.verdict === 'SUSPICIOUS') {
      themeColor = '#f59e0b';
      pillClass = 'pill-warn';
      gaugeVerdict.textContent = 'CAUTION';
    } else {
      themeColor = '#10b981';
      pillClass = 'pill-safe';
      gaugeVerdict.textContent = 'SAFE';
    }

    gaugeMeter.style.stroke = themeColor;
    gaugeVerdict.style.color = themeColor;
    gaugeScore.style.color = themeColor;

    threatIndicatorPill.className = `pill ${pillClass}`;
    threatIndicatorPill.textContent = report.verdict;

    // Host & Protocol
    let proto = 'HTTPS';
    try {
      const u = new URL(report.url);
      proto = u.protocol.replace(':', '').toUpperCase();
    } catch (e) {}
    siteProtocol.textContent = proto;
    siteHostname.textContent = report.hostname || 'Unknown Host';

    // Brand Target Tag
    if (report.brandTarget) {
      siteBrandTarget.classList.remove('hidden');
      brandTargetName.textContent = report.brandTarget;
    } else {
      siteBrandTarget.classList.add('hidden');
    }

    // Threat Summary
    threatSummaryText.textContent = report.summary || 'Domain verified clean with zero detected risk vectors.';

    // Heuristics Grid
    const bd = report.breakdown || { typosquatScore: 0, homoglyphScore: 0, domainRiskScore: 0, domRiskScore: 0 };
    setMetric(metricTypo, bd.typosquatScore);
    setMetric(metricHomo, bd.homoglyphScore);
    setMetric(metricDomain, bd.domainRiskScore);
    setMetric(metricDom, bd.domRiskScore);

    // Flags Evidence
    if (report.flags && report.flags.length > 0) {
      flagsContainer.classList.remove('hidden');
      flagsCount.textContent = report.flags.length;
      flagsList.innerHTML = report.flags.map(f => `
        <div class="flag-badge-row sev-${f.severity.toLowerCase()}">
          <div class="flag-row-title">
            <span>${f.type.replace(/_/g, ' ')}</span>
            <span>${f.severity}</span>
          </div>
          <div class="flag-row-desc">${f.description}</div>
        </div>
      `).join('');
    } else {
      flagsContainer.classList.add('hidden');
    }
  }

  function setMetric(el, val) {
    el.textContent = `${val}%`;
    if (val >= 60) el.className = 'cell-val val-red';
    else if (val >= 25) el.className = 'cell-val val-amber';
    else el.className = 'cell-val val-green';
  }

  // Load current active tab report
  async function loadActiveTabReport() {
    if (typeof chrome === 'undefined' || !chrome.tabs) {
      renderReport({
        url: 'https://github.com',
        hostname: 'github.com',
        riskScore: 0,
        verdict: 'SAFE',
        summary: 'Verified Legitimate Domain.',
        flags: [],
        breakdown: { typosquatScore: 0, homoglyphScore: 0, domainRiskScore: 0, domRiskScore: 0 }
      });
      return;
    }

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentTab = tab;

    if (!tab || !tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('edge://')) {
      renderReport({
        url: 'System / Internal Page',
        hostname: 'Browser Internal',
        riskScore: 0,
        verdict: 'SAFE',
        summary: 'Browser internal page. Protection active.',
        flags: [],
        breakdown: { typosquatScore: 0, homoglyphScore: 0, domainRiskScore: 0, domRiskScore: 0 }
      });
      return;
    }

    chrome.runtime.sendMessage({
      type: 'GET_CURRENT_TAB_STATUS',
      tabId: tab.id
    }, (response) => {
      if (response && response.report) {
        renderReport(response.report);
      }
    });
  }

  // Re-scan button action
  btnRescan.addEventListener('click', async () => {
    gaugeScore.textContent = '...';
    gaugeVerdict.textContent = 'SCANNING';
    if (currentTab && currentTab.id) {
      chrome.tabs.sendMessage(currentTab.id, { type: 'TRIGGER_PAGE_SCAN' }, (resp) => {
        loadActiveTabReport();
      });
    } else {
      loadActiveTabReport();
    }
  });

  // Whitelist domain button action
  btnWhitelistCurrent.addEventListener('click', () => {
    if (!currentTabReport || !currentTabReport.hostname) return;
    const host = currentTabReport.hostname;
    chrome.storage.local.get(['whitelist'], (res) => {
      const list = res.whitelist || [];
      if (!list.includes(host)) {
        list.push(host);
        chrome.storage.local.set({ whitelist: list }, () => {
          btnWhitelistCurrent.textContent = '✓ Trusted';
          btnWhitelistCurrent.style.background = '#059669';
          setTimeout(() => {
            loadActiveTabReport();
          }, 400);
        });
      }
    });
  });

  // Instant URL Inspector Audit
  btnRunInspect.addEventListener('click', () => {
    const rawInput = inputCustomUrl.value.trim();
    if (!rawInput) return;

    btnRunInspect.textContent = 'Auditing...';
    btnRunInspect.disabled = true;

    chrome.runtime.sendMessage({
      type: 'ANALYZE_CUSTOM_URL',
      url: rawInput
    }, (response) => {
      const report = response && response.report ? response.report : {
        url: rawInput,
        riskScore: 0,
        verdict: 'SAFE',
        summary: 'Analysis completed.',
        flags: []
      };

      inspectorResults.classList.remove('hidden');

      inspectScoreBadge.textContent = `${report.riskScore} / 100`;
      inspectVerdict.textContent = report.verdict;

      let pillColor = '#10b981';
      let bgPill = 'rgba(16, 185, 129, 0.15)';
      if (report.verdict === 'DANGER') {
        pillColor = '#ef4444';
        bgPill = 'rgba(239, 68, 68, 0.15)';
      } else if (report.verdict === 'SUSPICIOUS') {
        pillColor = '#f59e0b';
        bgPill = 'rgba(245, 158, 11, 0.15)';
      }

      inspectScoreBadge.style.color = pillColor;
      inspectVerdict.style.color = pillColor;
      inspectVerdict.style.background = bgPill;
      inspectSummary.textContent = report.summary;

      if (report.flags && report.flags.length > 0) {
        inspectFlags.innerHTML = report.flags.map(f => `
          <div class="flag-badge-row sev-${f.severity.toLowerCase()}">
            <div class="flag-row-title">
              <span>${f.type.replace(/_/g, ' ')}</span>
              <span>${f.severity}</span>
            </div>
            <div class="flag-row-desc">${f.description}</div>
          </div>
        `).join('');
      } else {
        inspectFlags.innerHTML = '<div class="summary-desc" style="color: #10b981;">✓ 0 Threat flags detected on target domain.</div>';
      }

      btnRunInspect.textContent = 'Audit';
      btnRunInspect.disabled = false;
    });
  });

  // Enter key on inspector input
  inputCustomUrl.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      btnRunInspect.click();
    }
  });

  // Initialize
  await loadActiveTabReport();
});
