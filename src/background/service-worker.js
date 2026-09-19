// ScamShield Pro - Background Service Worker (Manifest V3)
// Coordinates real-time threat monitoring, badge updates, threat logging, and popup communication

try {
  importScripts(
    '/src/engine/brands.js',
    '/src/engine/homoglyphs.js',
    '/src/engine/typosquatting.js',
    '/src/engine/domain-risk.js',
    '/src/engine/risk-aggregator.js'
  );
} catch (e) {
  console.error('ScamShield: Failed to import engine scripts', e);
}

// Cache for active tab scan results
const tabReports = new Map();
const tabDomSignals = new Map();

/**
 * Loads user configuration from storage
 */
async function getUserSettings() {
  return new Promise((resolve) => {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
      resolve({ whitelist: [], blacklist: [], customBrands: [], sensitivity: 'standard' });
      return;
    }
    chrome.storage.local.get(['whitelist', 'blacklist', 'customBrands', 'sensitivity'], (res) => {
      resolve({
        whitelist: res.whitelist || [],
        blacklist: res.blacklist || [],
        customBrands: res.customBrands || [],
        sensitivity: res.sensitivity || 'standard'
      });
    });
  });
}

/**
 * Updates extension action badge based on threat verdict
 */
function updateBadge(tabId, report) {
  if (typeof chrome === 'undefined' || !chrome.action) return;

  try {
    if (report.verdict === 'DANGER') {
      chrome.action.setBadgeText({ tabId, text: 'RISK' });
      chrome.action.setBadgeBackgroundColor({ tabId, color: '#ef4444' });
      chrome.action.setTitle({ tabId, title: `ScamShield: THREAT DETECTED (${report.riskScore}/100)` });
    } else if (report.verdict === 'SUSPICIOUS') {
      chrome.action.setBadgeText({ tabId, text: 'WARN' });
      chrome.action.setBadgeBackgroundColor({ tabId, color: '#f59e0b' });
      chrome.action.setTitle({ tabId, title: `ScamShield: Caution (${report.riskScore}/100)` });
    } else {
      chrome.action.setBadgeText({ tabId, text: 'SAFE' });
      chrome.action.setBadgeBackgroundColor({ tabId, color: '#10b981' });
      chrome.action.setTitle({ tabId, title: `ScamShield: Safe Verified (${report.hostname})` });
    }
  } catch (e) {}
}

/**
 * Logs threat event into storage history
 */
async function logScanEvent(report) {
  if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) return;
  chrome.storage.local.get(['scanHistory'], (res) => {
    const history = res.scanHistory || [];
    history.unshift({
      id: `${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      url: report.url,
      hostname: report.hostname,
      riskScore: report.riskScore,
      verdict: report.verdict,
      brandTarget: report.brandTarget,
      summary: report.summary,
      flagsCount: report.flags ? report.flags.length : 0,
      timestamp: Date.now()
    });
    chrome.storage.local.set({ scanHistory: history.slice(0, 150) });
  });
}

/**
 * Analyzes a tab's URL and updates badge & cache
 */
async function processTabUrl(tabId, url) {
  if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('edge://') || url.startsWith('about:')) {
    return;
  }

  const settings = await getUserSettings();
  const domSignals = tabDomSignals.get(tabId) || null;
  const report = evaluateUrlRisk(url, domSignals, settings);

  tabReports.set(tabId, report);
  updateBadge(tabId, report);

  if (report.verdict !== 'SAFE') {
    logScanEvent(report);
  }
}

// Listen for tab navigation
if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.onUpdated) {
  chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.url) {
      tabDomSignals.delete(tabId);
      processTabUrl(tabId, changeInfo.url);
    } else if (changeInfo.status === 'complete' && tab && tab.url) {
      processTabUrl(tabId, tab.url);
    }
  });

  chrome.tabs.onActivated.addListener(async (activeInfo) => {
    try {
      const tab = await chrome.tabs.get(activeInfo.tabId);
      if (tab && tab.url) {
        if (tabReports.has(activeInfo.tabId)) {
          updateBadge(activeInfo.tabId, tabReports.get(activeInfo.tabId));
        } else {
          processTabUrl(activeInfo.tabId, tab.url);
        }
      }
    } catch (e) {}
  });

  chrome.tabs.onRemoved.addListener((tabId) => {
    tabReports.delete(tabId);
    tabDomSignals.delete(tabId);
  });
}

// Message listener for popup and content script requests
if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'GET_CURRENT_TAB_STATUS') {
      const tabId = message.tabId;
      if (tabReports.has(tabId)) {
        sendResponse({ success: true, report: tabReports.get(tabId) });
      } else {
        chrome.tabs.get(tabId, async (tab) => {
          if (tab && tab.url) {
            const settings = await getUserSettings();
            const report = evaluateUrlRisk(tab.url, tabDomSignals.get(tabId), settings);
            tabReports.set(tabId, report);
            updateBadge(tabId, report);
            sendResponse({ success: true, report });
          } else {
            sendResponse({ success: false, error: 'Could not access active tab URL.' });
          }
        });
        return true;
      }
    } else if (message.type === 'DOM_SCAN_RESULTS') {
      if (sender.tab && sender.tab.id) {
        const tabId = sender.tab.id;
        tabDomSignals.set(tabId, message.payload);
        getUserSettings().then((settings) => {
          const report = evaluateUrlRisk(sender.tab.url || message.payload.url, message.payload, settings);
          tabReports.set(tabId, report);
          updateBadge(tabId, report);
          sendResponse({ success: true, threatReport: report });
        });
        return true;
      }
    } else if (message.type === 'ANALYZE_CUSTOM_URL') {
      getUserSettings().then((settings) => {
        const report = evaluateUrlRisk(message.url, null, settings);
        sendResponse({ success: true, report });
      });
      return true;
    }
  });
}
