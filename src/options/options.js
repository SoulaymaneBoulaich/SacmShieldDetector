// ScamShield Pro - Options & Threat Intelligence Hub Controller

document.addEventListener('DOMContentLoaded', async () => {
  // Navigation Tabs
  const navItems = document.querySelectorAll('.nav-item');
  const panels = document.querySelectorAll('.content-panel');

  navItems.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');
      navItems.forEach(n => n.classList.remove('active'));
      panels.forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const targetPanel = document.getElementById(targetTab);
      if (targetPanel) targetPanel.classList.add('active');
    });
  });

  // State
  let scanLogs = [];
  let whitelist = [];
  let blacklist = [];
  let customBrands = [];
  let currentLogFilter = 'all';

  // DOM Elements
  const logsTbody = document.getElementById('logs-tbody');
  const logsEmptyState = document.getElementById('logs-empty-state');
  const filterLogsInput = document.getElementById('filter-logs-input');
  const filterPills = document.querySelectorAll('.filter-pill');
  const btnExportLogs = document.getElementById('btn-export-logs');
  const btnClearLogs = document.getElementById('btn-clear-logs');

  const inputWhitelistDomain = document.getElementById('input-whitelist-domain');
  const btnAddWhitelist = document.getElementById('btn-add-whitelist');
  const listWhitelist = document.getElementById('list-whitelist');

  const inputBlacklistDomain = document.getElementById('input-blacklist-domain');
  const btnAddBlacklist = document.getElementById('btn-add-blacklist');
  const listBlacklist = document.getElementById('list-blacklist');

  const inputBrandName = document.getElementById('input-brand-name');
  const inputBrandDomains = document.getElementById('input-brand-domains');
  const inputBrandKeywords = document.getElementById('input-brand-keywords');
  const btnAddCustomBrand = document.getElementById('btn-add-custom-brand');
  const customBrandsList = document.getElementById('custom-brands-list');

  const selectSensitivity = document.getElementById('select-sensitivity');
  const checkInterstitial = document.getElementById('check-interstitial');
  const checkPunycodeStrict = document.getElementById('check-punycode-strict');
  const checkDomProtection = document.getElementById('check-dom-protection');
  const btnSaveSettings = document.getElementById('btn-save-settings');

  // Load from Storage
  async function loadData() {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
      // Demo mock data for offline/test preview
      scanLogs = [
        {
          id: '1',
          timestamp: Date.now() - 3600000,
          hostname: 'pаypal-verify-account.tk',
          url: 'https://pаypal-verify-account.tk/login',
          riskScore: 94,
          verdict: 'DANGER',
          brandTarget: 'PayPal',
          summary: 'High-confidence phishing scam impersonating PayPal with Cyrillic homoglyph.'
        },
        {
          id: '2',
          timestamp: Date.now() - 7200000,
          hostname: 'apple-login-security.xyz',
          url: 'https://apple-login-security.xyz',
          riskScore: 85,
          verdict: 'DANGER',
          brandTarget: 'Apple',
          summary: 'Combo-squatting with high-risk TLD.'
        },
        {
          id: '3',
          timestamp: Date.now() - 14400000,
          hostname: 'github.com',
          url: 'https://github.com/trending',
          riskScore: 0,
          verdict: 'SAFE',
          brandTarget: null,
          summary: 'Verified Legitimate Domain (Whitelisted).'
        }
      ];
      whitelist = ['mycompany.internal', 'dev.local'];
      blacklist = ['malicious-stealer.xyz'];
      customBrands = [{ name: 'MyBrand', domains: ['mybrand.com'], keywords: ['mybrand'] }];
      renderAll();
      return;
    }

    chrome.storage.local.get([
      'scanHistory', 'whitelist', 'blacklist', 'customBrands',
      'sensitivity', 'enableInterstitial', 'strictPunycode', 'enableDomProtection'
    ], (res) => {
      scanLogs = res.scanHistory || [];
      whitelist = res.whitelist || [];
      blacklist = res.blacklist || [];
      customBrands = res.customBrands || [];

      if (res.sensitivity) selectSensitivity.value = res.sensitivity;
      if (res.enableInterstitial !== undefined) checkInterstitial.checked = res.enableInterstitial;
      if (res.strictPunycode !== undefined) checkPunycodeStrict.checked = res.strictPunycode;
      if (res.enableDomProtection !== undefined) checkDomProtection.checked = res.enableDomProtection;

      renderAll();
    });
  }

  function renderAll() {
    renderLogs();
    renderWhitelist();
    renderBlacklist();
    renderCustomBrands();
  }

  // Render Logs Table
  function renderLogs() {
    const query = filterLogsInput.value.trim().toLowerCase();
    const filtered = scanLogs.filter(log => {
      if (currentLogFilter !== 'all' && log.verdict !== currentLogFilter) return false;
      if (query) {
        return (log.hostname && log.hostname.toLowerCase().includes(query)) ||
               (log.brandTarget && log.brandTarget.toLowerCase().includes(query)) ||
               (log.summary && log.summary.toLowerCase().includes(query));
      }
      return true;
    });

    if (filtered.length === 0) {
      logsTbody.innerHTML = '';
      logsEmptyState.classList.remove('hidden');
      return;
    }

    logsEmptyState.classList.add('hidden');
    logsTbody.innerHTML = filtered.map(log => {
      const date = new Date(log.timestamp).toLocaleString();
      let pillStyle = 'color: #10b981; background: rgba(16,185,129,0.15);';
      if (log.verdict === 'DANGER') pillStyle = 'color: #f87171; background: rgba(239,68,68,0.15);';
      else if (log.verdict === 'SUSPICIOUS') pillStyle = 'color: #f59e0b; background: rgba(245,158,11,0.15);';

      return `
        <tr>
          <td style="color: #64748b; font-size: 11px;">${date}</td>
          <td>
            <div style="font-weight: 700; color: #ffffff;">${log.hostname || 'Unknown'}</div>
            <div style="font-size: 11px; color: #64748b; max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${log.url || ''}</div>
          </td>
          <td><span style="font-size: 10px; font-weight: 800; padding: 2px 8px; border-radius: 6px; ${pillStyle}">${log.verdict}</span></td>
          <td style="font-weight: 800;">${log.riskScore}/100</td>
          <td>${log.brandTarget ? `<span style="color: #38bdf8; font-weight: 600;">${log.brandTarget}</span>` : '<span style="color:#64748b">—</span>'}</td>
          <td style="font-size: 12px; color: #94a3b8; max-width: 320px;">${log.summary || ''}</td>
        </tr>
      `;
    }).join('');
  }

  // Filter logs listeners
  filterLogsInput.addEventListener('input', renderLogs);
  filterPills.forEach(btn => {
    btn.addEventListener('click', () => {
      filterPills.forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      currentLogFilter = btn.getAttribute('data-filter');
      renderLogs();
    });
  });

  // Export JSON Logs
  btnExportLogs.addEventListener('click', () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(scanLogs, null, 2));
    const dlAnchor = document.createElement('a');
    dlAnchor.setAttribute('href', dataStr);
    dlAnchor.setAttribute('download', `scamshield-threat-audit-${Date.now()}.json`);
    dlAnchor.click();
  });

  // Clear Logs
  btnClearLogs.addEventListener('click', () => {
    if (confirm('Are you sure you want to clear all recorded threat logs?')) {
      scanLogs = [];
      if (chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({ scanHistory: [] }, renderLogs);
      } else {
        renderLogs();
      }
    }
  });

  // Whitelist Logic
  function renderWhitelist() {
    listWhitelist.innerHTML = whitelist.map((domain, i) => `
      <li class="rule-tag">
        <span>${domain}</span>
        <span class="rule-tag-del" data-type="white" data-index="${i}">×</span>
      </li>
    `).join('') || '<div style="color: #64748b; font-size: 12px;">No custom whitelist domains added yet.</div>';
  }

  btnAddWhitelist.addEventListener('click', () => {
    const domain = inputWhitelistDomain.value.trim().toLowerCase();
    if (!domain) return;
    if (!whitelist.includes(domain)) {
      whitelist.push(domain);
      inputWhitelistDomain.value = '';
      if (chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({ whitelist }, renderWhitelist);
      } else {
        renderWhitelist();
      }
    }
  });

  // Blacklist Logic
  function renderBlacklist() {
    listBlacklist.innerHTML = blacklist.map((domain, i) => `
      <li class="rule-tag" style="border-color: rgba(239, 68, 68, 0.4);">
        <span style="color: #f87171;">${domain}</span>
        <span class="rule-tag-del" data-type="black" data-index="${i}">×</span>
      </li>
    `).join('') || '<div style="color: #64748b; font-size: 12px;">No custom blacklisted domains.</div>';
  }

  btnAddBlacklist.addEventListener('click', () => {
    const domain = inputBlacklistDomain.value.trim().toLowerCase();
    if (!domain) return;
    if (!blacklist.includes(domain)) {
      blacklist.push(domain);
      inputBlacklistDomain.value = '';
      if (chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({ blacklist }, renderBlacklist);
      } else {
        renderBlacklist();
      }
    }
  });

  // Remove tag handler
  document.addEventListener('click', (e) => {
    if (e.target.classList.contains('rule-tag-del')) {
      const type = e.target.getAttribute('data-type');
      const idx = parseInt(e.target.getAttribute('data-index'), 10);
      if (type === 'white') {
        whitelist.splice(idx, 1);
        if (chrome.storage && chrome.storage.local) {
          chrome.storage.local.set({ whitelist }, renderWhitelist);
        } else {
          renderWhitelist();
        }
      } else if (type === 'black') {
        blacklist.splice(idx, 1);
        if (chrome.storage && chrome.storage.local) {
          chrome.storage.local.set({ blacklist }, renderBlacklist);
        } else {
          renderBlacklist();
        }
      } else if (type === 'brand') {
        customBrands.splice(idx, 1);
        if (chrome.storage && chrome.storage.local) {
          chrome.storage.local.set({ customBrands }, renderCustomBrands);
        } else {
          renderCustomBrands();
        }
      }
    }
  });

  // Custom Brands Protection Logic
  function renderCustomBrands() {
    customBrandsList.innerHTML = customBrands.map((b, i) => `
      <div class="custom-brand-card">
        <div>
          <div class="brand-card-title">${b.name}</div>
          <div class="brand-card-sub">Domains: ${b.domains.join(', ')}</div>
          <div class="brand-card-sub">Keywords: ${(b.keywords || []).join(', ')}</div>
        </div>
        <button class="rule-tag-del" data-type="brand" data-index="${i}" title="Remove Brand" style="background:none; border:none; font-size:16px;">×</button>
      </div>
    `).join('') || '<div style="color: #64748b; font-size: 12px; grid-column: 1/-1;">No custom brand monitors added yet. Top 50 global brands are monitored by default.</div>';
  }

  btnAddCustomBrand.addEventListener('click', () => {
    const name = inputBrandName.value.trim();
    const domainsStr = inputBrandDomains.value.trim();
    const keywordsStr = inputBrandKeywords.value.trim();

    if (!name || !domainsStr) {
      alert('Please provide a brand name and at least one official domain.');
      return;
    }

    const domains = domainsStr.split(',').map(d => d.trim().toLowerCase()).filter(Boolean);
    const keywords = keywordsStr ? keywordsStr.split(',').map(k => k.trim().toLowerCase()).filter(Boolean) : [name.toLowerCase()];

    customBrands.push({ name, domains, keywords });
    inputBrandName.value = '';
    inputBrandDomains.value = '';
    inputBrandKeywords.value = '';

    if (chrome.storage && chrome.storage.local) {
      chrome.storage.local.set({ customBrands }, renderCustomBrands);
    } else {
      renderCustomBrands();
    }
  });

  // Save Settings
  btnSaveSettings.addEventListener('click', () => {
    const settings = {
      sensitivity: selectSensitivity.value,
      enableInterstitial: checkInterstitial.checked,
      strictPunycode: checkPunycodeStrict.checked,
      enableDomProtection: checkDomProtection.checked
    };

    if (chrome.storage && chrome.storage.local) {
      chrome.storage.local.set(settings, () => {
        btnSaveSettings.textContent = '✓ Saved Successfully';
        btnSaveSettings.style.background = '#059669';
        setTimeout(() => {
          btnSaveSettings.textContent = 'Save Changes';
          btnSaveSettings.style.background = '#0284c7';
        }, 1500);
      });
    } else {
      btnSaveSettings.textContent = '✓ Saved (Local)';
      setTimeout(() => {
        btnSaveSettings.textContent = 'Save Changes';
      }, 1500);
    }
  });

  await loadData();
});
