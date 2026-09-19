// ScamShield Pro - In-Page DOM Threat Scanner & Interstitial Shield
// Inspects loaded DOM for credential harvesting, deceptive links, fake security popups, and high-pressure scam vectors

(function () {
  'use strict';

  // Prevent multiple injections
  if (window.__SCAM_SHIELD_INITIALIZED__) return;
  window.__SCAM_SHIELD_INITIALIZED__ = true;

  const currentOrigin = window.location.origin;
  const currentHostname = window.location.hostname.toLowerCase();

  /**
   * Scans DOM for phishing indicators
   */
  function scanDom() {
    const flags = [];

    // 1. Cross-Origin Password Harvesting Form
    const forms = document.querySelectorAll('form');
    forms.forEach((form, idx) => {
      const passwordInputs = form.querySelectorAll('input[type="password"]');
      if (passwordInputs.length > 0) {
        let action = form.getAttribute('action') || '';
        if (action) {
          try {
            const parsedAction = new URL(action, window.location.href);
            if (parsedAction.origin !== currentOrigin && !parsedAction.protocol.startsWith('chrome')) {
              flags.push({
                type: 'CROSS_ORIGIN_PASSWORD_ACTION',
                severity: 'CRITICAL',
                description: `Password form #${idx + 1} submits credentials to external origin '${parsedAction.origin}' instead of current site.`
              });
            }
            if (parsedAction.protocol === 'http:' && currentHostname !== 'localhost') {
              flags.push({
                type: 'INSECURE_PASSWORD_ACTION_HTTP',
                severity: 'CRITICAL',
                description: `Password form #${idx + 1} transmits sensitive credentials over insecure unencrypted HTTP.`
              });
            }
          } catch (e) {}
        }
      }
    });

    // 2. Deceptive Links (Visual text claims brand A, but href points to brand B)
    const links = document.querySelectorAll('a[href]');
    let deceptiveLinkCount = 0;
    const trustedBrandDomains = ['paypal.com', 'google.com', 'apple.com', 'microsoft.com', 'chase.com', 'bankofamerica.com', 'binance.com', 'coinbase.com', 'amazon.com', 'netflix.com'];

    links.forEach(a => {
      const text = (a.innerText || a.textContent || '').trim().toLowerCase();
      const href = a.getAttribute('href') || '';
      try {
        const parsedHref = new URL(href, window.location.href);
        for (const brandDomain of trustedBrandDomains) {
          if (text.includes(brandDomain) && !parsedHref.hostname.endsWith(brandDomain) && !currentHostname.endsWith(brandDomain)) {
            deceptiveLinkCount++;
            if (deceptiveLinkCount <= 3) {
              flags.push({
                type: 'DECEPTIVE_ANCHOR_MISMATCH',
                severity: 'HIGH',
                description: `Link text displays '${brandDomain}', but destination URL actually leads to '${parsedHref.hostname}'.`
              });
            }
          }
        }
      } catch (e) {}
    });

    // 3. Fake Tech Support / Security Alert Scareware Keywords
    const bodyText = (document.body ? document.body.innerText || '' : '').toLowerCase();
    const scarewareKeywords = [
      'windows defender security center',
      'apple support alert',
      'your computer has been blocked',
      'critical error 0x',
      'call microsoft support',
      'call toll-free',
      'system warning: infected with virus',
      'enter 12-word seed phrase',
      'enter secret recovery phrase',
      'private key export'
    ];

    let foundScareware = [];
    scarewareKeywords.forEach(kw => {
      if (bodyText.includes(kw)) {
        foundScareware.push(kw);
      }
    });

    if (foundScareware.length >= 2) {
      flags.push({
        type: 'SCAREWARE_URGENCY_PATTERNS',
        severity: 'CRITICAL',
        description: `Tech support / fake security alert phrases detected: "${foundScareware.slice(0, 2).join('", "')}".`
      });
    }

    // 4. Fake In-DOM Browser / Window Spoofing Elements
    const fakeWindowBars = document.querySelectorAll('[class*="window-header"], [class*="browser-bar"], [class*="address-bar"]');
    if (fakeWindowBars.length > 0 && (bodyText.includes('http://') || bodyText.includes('https://'))) {
      flags.push({
        type: 'IN_DOM_FAKE_BROWSER_OVERLAY',
        severity: 'HIGH',
        description: 'Possible fake browser window or simulated OS prompt overlay detected in page elements.'
      });
    }

    return {
      url: window.location.href,
      hostname: currentHostname,
      flags,
      timestamp: Date.now()
    };
  }

  /**
   * Renders the ScamShield In-Page Warning Shield overlay
   */
  function showWarningShield(threatReport) {
    if (document.getElementById('scamshield-warning-overlay')) return;

    const overlay = document.createElement('div');
    overlay.id = 'scamshield-warning-overlay';

    const flagsHtml = threatReport.flags.slice(0, 4).map(f => `
      <div class="scamshield-flag-item scamshield-severity-${f.severity.toLowerCase()}">
        <span class="scamshield-flag-badge">${f.severity}</span>
        <span class="scamshield-flag-desc">${f.description}</span>
      </div>
    `).join('');

    overlay.innerHTML = `
      <div class="scamshield-modal-card">
        <div class="scamshield-header">
          <div class="scamshield-shield-icon">
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <path d="M12 8v4M12 16h.01" stroke="#ef4444" stroke-width="2.5" stroke-linecap="round"/>
            </svg>
          </div>
          <div>
            <div class="scamshield-title">Scam & Phishing Hazard Detected</div>
            <div class="scamshield-subtitle">ScamShield Pro intercepted this suspicious page</div>
          </div>
        </div>

        <div class="scamshield-risk-meter">
          <div class="scamshield-risk-label">
            <span>Threat Score: <strong>${threatReport.riskScore}/100</strong> (${threatReport.verdict})</span>
            ${threatReport.brandTarget ? `<span class="scamshield-brand-target">Target: ${threatReport.brandTarget}</span>` : ''}
          </div>
          <div class="scamshield-bar-bg">
            <div class="scamshield-bar-fill" style="width: ${threatReport.riskScore}%"></div>
          </div>
        </div>

        <p class="scamshield-summary">${threatReport.summary}</p>

        <div class="scamshield-flags-list">
          <div class="scamshield-flags-header">Detected Risk Vectors:</div>
          ${flagsHtml || '<div class="scamshield-flag-desc">High risk heuristic score triggered.</div>'}
        </div>

        <div class="scamshield-actions">
          <button id="scamshield-btn-safety" class="scamshield-btn scamshield-btn-primary">
            ← Return to Safety (Recommended)
          </button>
          <button id="scamshield-btn-dismiss" class="scamshield-btn scamshield-btn-secondary">
            Dismiss & View Page Anyway
          </button>
        </div>
      </div>
    `;

    document.documentElement.appendChild(overlay);

    document.getElementById('scamshield-btn-safety').addEventListener('click', () => {
      window.history.back();
      setTimeout(() => {
        window.location.href = 'https://www.google.com';
      }, 300);
    });

    document.getElementById('scamshield-btn-dismiss').addEventListener('click', () => {
      overlay.remove();
    });
  }

  // Execute scan when DOM is ready
  function initScanner() {
    const domSignals = scanDom();
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage({
        type: 'DOM_SCAN_RESULTS',
        payload: domSignals
      }, (response) => {
        if (response && response.threatReport && response.threatReport.verdict === 'DANGER' && !response.threatReport.isDismissed) {
          showWarningShield(response.threatReport);
        }
      });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initScanner);
  } else {
    initScanner();
  }

  // Listen for messages from background/popup
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.type === 'TRIGGER_PAGE_SCAN') {
        const signals = scanDom();
        sendResponse({ success: true, signals });
      } else if (message.type === 'SHOW_WARNING_BANNER') {
        showWarningShield(message.threatReport);
        sendResponse({ success: true });
      }
      return true;
    });
  }
})();
