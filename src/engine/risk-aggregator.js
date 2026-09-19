// ScamShield Pro - Unified Multi-Vector Risk Aggregator
// Consolidates Homoglyphs, Typosquatting, Domain Risk, and DOM Heuristics into an explainable verdict

function _getHomoglyphsAnalyzer() {
  if (typeof analyzeHomoglyphs === 'function') return analyzeHomoglyphs;
  if (typeof require !== 'undefined') {
    try {
      return require('./homoglyphs.js').analyzeHomoglyphs;
    } catch (e) {}
  }
  return () => ({ score: 0, flags: [] });
}

function _getTyposquattingAnalyzer() {
  if (typeof analyzeTyposquatting === 'function') return analyzeTyposquatting;
  if (typeof require !== 'undefined') {
    try {
      return require('./typosquatting.js').analyzeTyposquatting;
    } catch (e) {}
  }
  return () => ({ score: 0, flags: [], isOfficial: false });
}

function _getDomainRiskAnalyzer() {
  if (typeof analyzeDomainRisk === 'function') return analyzeDomainRisk;
  if (typeof require !== 'undefined') {
    try {
      return require('./domain-risk.js').analyzeDomainRisk;
    } catch (e) {}
  }
  return () => ({ score: 0, flags: [], entropy: 0 });
}

const DEFAULT_WHITELIST = [
  'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'wikipedia.org',
  'twitter.com', 'x.com', 'instagram.com', 'linkedin.com', 'reddit.com',
  'netflix.com', 'microsoft.com', 'apple.com', 'github.com', 'bing.com',
  'yahoo.com', 'twitch.tv', 'openai.com', 'anthropic.com', 'cloudflare.com',
  'mozilla.org', 'w3.org', 'stackoverflow.com', 'medium.com', 'spotify.com',
  'paypal.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citi.com'
];

function evaluateUrlRisk(url, domSignals = null, options = {}) {
  const userWhitelist = options.whitelist || [];
  const userBlacklist = options.blacklist || [];
  const customBrands = options.customBrands || [];

  let cleanUrl = (url || '').trim();
  if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
    cleanUrl = `https://${cleanUrl}`;
  }

  let hostname = '';
  let rawHostname = '';
  try {
    const parsed = new URL(cleanUrl);
    hostname = parsed.hostname.toLowerCase();
    const match = cleanUrl.match(/^https?:\/\/([^/?#@]+@)?([^/?#:]+)/i);
    if (match && match[2]) {
      rawHostname = match[2].toLowerCase();
    }
  } catch (e) {
    return {
      url: cleanUrl,
      hostname: '',
      riskScore: 60,
      verdict: 'SUSPICIOUS',
      color: '#f59e0b',
      summary: 'Invalid or unparseable URL structure.',
      flags: [{ type: 'INVALID_URL', severity: 'HIGH', description: 'Could not parse target URL.' }],
      breakdown: { homoglyphScore: 0, typosquatScore: 0, domainRiskScore: 60, domRiskScore: 0 }
    };
  }

  const analysisHost = rawHostname || hostname;

  // 1. Check Whitelist
  const combinedWhitelist = [...DEFAULT_WHITELIST, ...userWhitelist];
  const isWhitelisted = combinedWhitelist.some(w => analysisHost === w || analysisHost.endsWith('.' + w) || hostname === w || hostname.endsWith('.' + w));
  if (isWhitelisted) {
    return {
      url: cleanUrl,
      hostname: analysisHost,
      riskScore: 0,
      verdict: 'SAFE',
      color: '#10b981',
      summary: 'Verified Legitimate Domain (Whitelisted).',
      flags: [],
      breakdown: { homoglyphScore: 0, typosquatScore: 0, domainRiskScore: 0, domRiskScore: 0 },
      isWhitelisted: true
    };
  }

  // 2. Check Blacklist
  const isBlacklisted = userBlacklist.some(b => analysisHost === b || analysisHost.endsWith('.' + b) || hostname === b || hostname.endsWith('.' + b));
  if (isBlacklisted) {
    return {
      url: cleanUrl,
      hostname: analysisHost,
      riskScore: 100,
      verdict: 'DANGER',
      color: '#ef4444',
      summary: 'Custom Blocklist Match: This domain is explicitly blocked in your security policy.',
      flags: [{ type: 'USER_BLOCKLIST_MATCH', severity: 'CRITICAL', description: 'Domain is in your custom threat blacklist.' }],
      breakdown: { homoglyphScore: 0, typosquatScore: 0, domainRiskScore: 100, domRiskScore: 0 },
      isBlacklisted: true
    };
  }

  // 3. Run Heuristic Engines
  const runHomoglyphs = _getHomoglyphsAnalyzer();
  const runTyposquatting = _getTyposquattingAnalyzer();
  const runDomainRisk = _getDomainRiskAnalyzer();

  const homoglyphRes = runHomoglyphs(analysisHost);
  const typoRes = runTyposquatting(analysisHost, customBrands);
  const domainRiskRes = runDomainRisk(cleanUrl);

  // If typosquatting engine detected official brand domain
  if (typoRes.isOfficial) {
    return {
      url: cleanUrl,
      hostname: analysisHost,
      riskScore: 0,
      verdict: 'SAFE',
      color: '#10b981',
      brandTarget: typoRes.matchedBrand,
      summary: `Verified Official ${typoRes.matchedBrand} Domain.`,
      flags: [],
      breakdown: { homoglyphScore: 0, typosquatScore: 0, domainRiskScore: 0, domRiskScore: 0 },
      isOfficial: true
    };
  }

  // Calculate DOM heuristic score if provided
  let domRiskScore = 0;
  const domFlags = [];
  if (domSignals && Array.isArray(domSignals.flags)) {
    for (const flag of domSignals.flags) {
      domFlags.push(flag);
      if (flag.severity === 'CRITICAL') domRiskScore += 45;
      else if (flag.severity === 'HIGH') domRiskScore += 25;
      else if (flag.severity === 'MEDIUM') domRiskScore += 15;
    }
    domRiskScore = Math.min(domRiskScore, 100);
  }

  // All collected flags
  const allFlags = [
    ...homoglyphRes.flags,
    ...typoRes.flags,
    ...domainRiskRes.flags,
    ...domFlags
  ];

  let calculatedScore = 0;
  
  if (typoRes.score >= 80 || homoglyphRes.score >= 60) {
    calculatedScore = Math.max(typoRes.score, homoglyphRes.score) + (domainRiskRes.score * 0.2) + (domRiskScore * 0.2);
  } else {
    calculatedScore = (typoRes.score * 0.4) + (homoglyphRes.score * 0.3) + (domainRiskRes.score * 0.45) + (domRiskScore * 0.35);
  }

  const finalRiskScore = Math.min(Math.round(calculatedScore), 100);

  let verdict = 'SAFE';
  let color = '#10b981';
  let summary = 'No significant threat vectors or phishing patterns detected.';

  if (finalRiskScore >= 60) {
    verdict = 'DANGER';
    color = '#ef4444';
    if (typoRes.matchedBrand) {
      summary = `CRITICAL THREAT: High-confidence phishing scam impersonating ${typoRes.matchedBrand}.`;
    } else if (homoglyphRes.flags.length > 0) {
      summary = 'CRITICAL THREAT: Visual Unicode character spoofing / homoglyph attack detected.';
    } else {
      summary = 'HIGH RISK: Multiple suspicious domain and structural scam indicators detected.';
    }
  } else if (finalRiskScore >= 25) {
    verdict = 'SUSPICIOUS';
    color = '#f59e0b';
    summary = 'CAUTION: Domain exhibits unusual characteristics or risk patterns. Proceed carefully.';
  }

  return {
    url: cleanUrl,
    hostname: analysisHost,
    riskScore: finalRiskScore,
    verdict,
    color,
    brandTarget: typoRes.matchedBrand || null,
    summary,
    flags: allFlags.sort((a, b) => {
      const order = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
      return (order[b.severity] || 0) - (order[a.severity] || 0);
    }),
    breakdown: {
      homoglyphScore: homoglyphRes.score,
      typosquatScore: typoRes.score,
      domainRiskScore: domainRiskRes.score,
      domRiskScore
    },
    entropy: domainRiskRes.entropy,
    timestamp: Date.now()
  };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    DEFAULT_WHITELIST,
    evaluateUrlRisk
  };
}
