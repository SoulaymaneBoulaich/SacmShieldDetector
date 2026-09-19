// ScamShield Pro - Domain Risk & URL Structural Heuristics
// Computes Shannon Entropy, Suspicious TLD weighting, IP obfuscation, and URL-level risk flags

// High-Risk TLDs frequently utilized in automated phishing & disposable scam infrastructure
const HIGH_RISK_TLDS = {
  // Free / Abused TLDs (Critical risk)
  'tk': 45, 'ml': 45, 'ga': 45, 'cf': 45, 'gq': 45,
  // Low-cost / spam-heavy TLDs (High risk)
  'top': 35, 'xyz': 25, 'buzz': 35, 'icu': 35, 'vip': 30, 'fit': 30, 'cam': 35,
  'sbs': 35, 'click': 30, 'link': 25, 'rest': 30, 'work': 25, 'surf': 30,
  'monster': 30, 'live': 20, 'cfd': 35, 'quest': 30, 'bond': 30, 'stream': 30,
  'tokyo': 25, 'site': 20, 'website': 20, 'space': 20, 'fun': 25, 'shop': 15
};

// Recognized safe / institutional TLDs
const TRUSTED_TLDS = ['gov', 'mil', 'edu', 'gov.uk', 'edu.au'];

/**
 * Calculates Shannon Entropy of a string: H(X) = - sum(p(x) * log2(p(x)))
 * High entropy (> 3.8 for strings of 10+ chars) indicates pseudo-randomly generated strings (DGA)
 */
function calculateShannonEntropy(str) {
  if (!str || str.length === 0) return 0;

  const len = str.length;
  const frequencies = {};

  for (let i = 0; i < len; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }

  let entropy = 0;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Checks if hostname is a raw IPv4 or IPv6 address or hexadecimal/octal IP representation
 */
function isIpAddress(hostname) {
  if (!hostname) return false;
  const clean = hostname.split(':')[0].trim();

  // Standard IPv4
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Pattern.test(clean)) {
    const parts = clean.split('.').map(Number);
    return parts.every(p => p >= 0 && p <= 255);
  }

  // IPv6
  const ipv6Pattern = /^\[?[a-fA-F0-9:]+\]?$/;
  if (clean.includes(':') && ipv6Pattern.test(clean)) return true;

  // Hexadecimal IP (e.g., 0x7f000001)
  if (/^0x[0-9a-fA-F]{8}$/.test(clean)) return true;

  // Dword / Decimal IP (e.g., http://2130706433)
  if (/^\d{8,10}$/.test(clean)) return true;

  return false;
}

/**
 * Analyzes URL and domain structure for risk signals
 */
function analyzeDomainRisk(rawUrl) {
  let parsedUrl;
  try {
    // Ensure protocol exists for URL parser
    const urlString = rawUrl.startsWith('http://') || rawUrl.startsWith('https://') ? rawUrl : `http://${rawUrl}`;
    parsedUrl = new URL(urlString);
  } catch (e) {
    return {
      score: 50,
      flags: [{
        type: 'INVALID_MALFORMED_URL',
        severity: 'HIGH',
        description: 'URL syntax is malformed or invalid.'
      }]
    };
  }

  const hostname = parsedUrl.hostname.toLowerCase();
  const protocol = parsedUrl.protocol;
  const pathname = parsedUrl.pathname;
  const search = parsedUrl.search;
  const port = parsedUrl.port;

  let threatScore = 0;
  const flags = [];

  // 1. IP Address as Hostname
  if (isIpAddress(hostname)) {
    threatScore += 55;
    flags.push({
      type: 'IP_ADDRESS_HOSTNAME',
      severity: 'HIGH',
      description: `URL uses a raw IP address (${hostname}) instead of a registered domain name.`
    });
  }

  // 2. High-Risk TLD
  const parts = hostname.split('.');
  const tld = parts.length > 1 ? parts[parts.length - 1] : '';
  const compoundTld = parts.length > 2 ? parts.slice(-2).join('.') : '';

  if (HIGH_RISK_TLDS[compoundTld] || HIGH_RISK_TLDS[tld]) {
    const tldScore = HIGH_RISK_TLDS[compoundTld] || HIGH_RISK_TLDS[tld];
    threatScore += tldScore;
    flags.push({
      type: 'SUSPICIOUS_HIGH_RISK_TLD',
      severity: tldScore >= 35 ? 'HIGH' : 'MEDIUM',
      tld: compoundTld || tld,
      description: `Domain uses top-level domain '.${compoundTld || tld}', commonly associated with high scam and phishing velocity.`
    });
  }

  // 3. Shannon Entropy of SLD (DGA / Algorithmic Domain Detection)
  const sld = parts.length >= 2 ? parts[parts.length - 2] : parts[0];
  if (sld && sld.length >= 8) {
    const entropy = calculateShannonEntropy(sld);
    // Strings with high entropy and consonant clusters
    const hasVowels = /[aeiouy]/i.test(sld);
    const hasExcessiveNumbers = (sld.match(/\d/g) || []).length >= 4;

    if (entropy > 3.4 && (!hasVowels || hasExcessiveNumbers)) {
      threatScore += 45;
      flags.push({
        type: 'HIGH_ENTROPY_DGA_DOMAIN',
        severity: 'HIGH',
        entropy: Number(entropy.toFixed(2)),
        description: `Domain SLD '${sld}' exhibits high entropy (${entropy.toFixed(2)}) characteristic of algorithmically generated scam domains.`
      });
    }
  }

  // 4. Excessive Subdomains (Domain Stacking)
  if (parts.length > 4) {
    threatScore += 30;
    flags.push({
      type: 'EXCESSIVE_SUBDOMAINS',
      severity: 'MEDIUM',
      count: parts.length,
      description: `Domain has excessive subdomain depth (${parts.length} levels), commonly used to disguise actual root destination.`
    });
  }

  // 5. Excessive Hyphens / Punctuation in Domain
  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    threatScore += 35;
    flags.push({
      type: 'EXCESSIVE_HYPHENS',
      severity: 'MEDIUM',
      count: hyphenCount,
      description: `Domain contains ${hyphenCount} hyphens, typical of deceptive phishing domains.`
    });
  }

  // 6. Insecure HTTP Protocol
  if (protocol === 'http:' && !hostname.includes('localhost') && hostname !== '127.0.0.1') {
    threatScore += 20;
    flags.push({
      type: 'UNENCRYPTED_HTTP',
      severity: 'MEDIUM',
      description: 'Connection is unencrypted HTTP with no SSL/TLS certificate protection.'
    });
  }

  // 7. Dangerous Open Redirect Parameters in Query String
  const dangerousParams = ['redirect', 'redir', 'url', 'next', 'return', 'target', 'dest', 'go', 'link', 'out'];
  const searchParams = new URLSearchParams(search);
  for (const param of dangerousParams) {
    const val = searchParams.get(param);
    if (val && (val.startsWith('http://') || val.startsWith('https://') || val.startsWith('//'))) {
      threatScore += 30;
      flags.push({
        type: 'SUSPICIOUS_REDIRECT_PARAMETER',
        severity: 'MEDIUM',
        param,
        target: val,
        description: `URL contains parameter '${param}' pointing to external URL (${val.substring(0, 40)}...).`
      });
      break;
    }
  }

  // 8. Basic Auth URL Obfuscation (e.g., http://google.com@phishingsite.com)
  if (parsedUrl.username || parsedUrl.password) {
    threatScore += 75;
    flags.push({
      type: 'URL_USERINFO_OBFUSCATION',
      severity: 'CRITICAL',
      description: 'URL uses "@" authority trick to deceive users about the true destination domain.'
    });
  }

  return {
    score: Math.min(threatScore, 100),
    flags,
    entropy: sld ? Number(calculateShannonEntropy(sld).toFixed(2)) : 0,
    hostname,
    protocol
  };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    HIGH_RISK_TLDS,
    TRUSTED_TLDS,
    calculateShannonEntropy,
    isIpAddress,
    analyzeDomainRisk
  };
}
