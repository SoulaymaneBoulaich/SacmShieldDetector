// ScamShield Pro - Typosquatting & Brand Impersonation Detector
// Identifies Damerau-Levenshtein distance spoofs, subdomain masquerading, and keyword phishing patterns

function _getBrandsList() {
  if (typeof TOP_BRANDS !== 'undefined') return TOP_BRANDS;
  if (typeof require !== 'undefined') {
    try {
      return require('./brands.js').TOP_BRANDS;
    } catch (e) {}
  }
  return [];
}

function _getSubdomainKeywords() {
  if (typeof SUSPICIOUS_SUBDOMAIN_KEYWORDS !== 'undefined') return SUSPICIOUS_SUBDOMAIN_KEYWORDS;
  if (typeof require !== 'undefined') {
    try {
      return require('./brands.js').SUSPICIOUS_SUBDOMAIN_KEYWORDS;
    } catch (e) {}
  }
  return [];
}

function _normalizeHomoglyphs(str) {
  if (typeof normalizeHomoglyphs === 'function') return normalizeHomoglyphs(str);
  if (typeof require !== 'undefined') {
    try {
      return require('./homoglyphs.js').normalizeHomoglyphs(str);
    } catch (e) {}
  }
  return { normalized: str };
}

/**
 * Calculates Damerau-Levenshtein distance between two strings
 */
function damerauLevenshteinDistance(source, target) {
  if (!source || !target) return (source || target || '').length;
  if (source === target) return 0;

  const sLen = source.length;
  const tLen = target.length;
  const d = [];

  for (let i = 0; i <= sLen; i++) {
    d[i] = [i];
  }
  for (let j = 0; j <= tLen; j++) {
    d[0][j] = j;
  }

  for (let i = 1; i <= sLen; i++) {
    for (let j = 1; j <= tLen; j++) {
      const cost = source[i - 1] === target[j - 1] ? 0 : 1;
      d[i][j] = Math.min(
        d[i - 1][j] + 1,
        d[i][j - 1] + 1,
        d[i - 1][j - 1] + cost
      );

      if (i > 1 && j > 1 && source[i - 1] === target[j - 2] && source[i - 2] === target[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + cost);
      }
    }
  }

  return d[sLen][tLen];
}

/**
 * Extracts SLD, root domain, subdomains and TLD
 */
function parseDomainStructure(hostname) {
  if (!hostname) return { sld: '', rootDomain: '', subdomains: [], tld: '' };
  
  let clean = hostname.toLowerCase().split(':')[0].trim();
  const parts = clean.split('.').filter(Boolean);

  if (parts.length === 0) return { sld: '', rootDomain: '', subdomains: [], tld: '' };
  if (parts.length === 1) return { sld: parts[0], rootDomain: parts[0], subdomains: [], tld: '' };

  const compoundTLDs = ['co.uk', 'gov.uk', 'ac.uk', 'org.uk', 'com.br', 'com.au', 'co.jp', 'com.sg', 'co.nz'];
  const lastTwo = parts.slice(-2).join('.');
  let tld = '';
  let sld = '';
  let subdomains = [];

  if (compoundTLDs.includes(lastTwo) && parts.length >= 3) {
    tld = lastTwo;
    sld = parts[parts.length - 3];
    subdomains = parts.slice(0, parts.length - 3);
  } else {
    tld = parts[parts.length - 1];
    sld = parts[parts.length - 2];
    subdomains = parts.slice(0, parts.length - 2);
  }

  const rootDomain = `${sld}.${tld}`;
  return { sld, rootDomain, subdomains, tld, fullHostname: clean };
}

function isOfficialBrandDomain(hostname, brand) {
  const clean = hostname.toLowerCase().split(':')[0].trim();
  return brand.domains.some(d => clean === d || clean.endsWith('.' + d));
}

function analyzeTyposquatting(hostname, customBrands = []) {
  const brandsList = [..._getBrandsList(), ...customBrands];
  const subKwList = _getSubdomainKeywords();
  const domainInfo = parseDomainStructure(hostname);
  const normalizedInfo = parseDomainStructure(_normalizeHomoglyphs(hostname).normalized || hostname);

  let highestThreatScore = 0;
  let detectedTarget = null;
  const flags = [];

  for (const brand of brandsList) {
    if (isOfficialBrandDomain(hostname, brand)) {
      return {
        isOfficial: true,
        matchedBrand: brand.name,
        score: 0,
        flags: []
      };
    }

    const brandKeywords = brand.keywords || [brand.name.toLowerCase()];

    // 2. Subdomain Brand Masquerading
    const subdomainJoined = domainInfo.subdomains.join('.');
    const normSubdomainJoined = normalizedInfo.subdomains.join('.');
    for (const officialDomain of brand.domains) {
      if (subdomainJoined.includes(officialDomain) || normSubdomainJoined.includes(officialDomain)) {
        highestThreatScore = Math.max(highestThreatScore, 90);
        flags.push({
          type: 'SUBDOMAIN_BRAND_MASQUERADE',
          severity: 'CRITICAL',
          brand: brand.name,
          description: `Subdomain mimics legitimate brand root '${officialDomain}' on third-party domain '${domainInfo.rootDomain}'.`
        });
        detectedTarget = brand.name;
      }
    }

    // 3. Subdomain Keyword Embedding + Sensitive Actions
    for (const kw of brandKeywords) {
      if (subdomainJoined.includes(kw) || normSubdomainJoined.includes(kw)) {
        const hasActionKw = subKwList.some(act => 
          subdomainJoined.includes(act) || normSubdomainJoined.includes(act) || 
          domainInfo.sld.includes(act) || normalizedInfo.sld.includes(act)
        );
        const threat = hasActionKw ? 80 : 50;
        highestThreatScore = Math.max(highestThreatScore, threat);
        flags.push({
          type: 'SUBDOMAIN_BRAND_KEYWORD',
          severity: hasActionKw ? 'CRITICAL' : 'HIGH',
          brand: brand.name,
          description: `Brand keyword '${kw}' embedded in subdomain on unrelated domain '${domainInfo.rootDomain}'.`
        });
        detectedTarget = brand.name;
      }

      // 4. SLD Keyword Combo Squatting
      const rawMatch = domainInfo.sld.includes(kw) && domainInfo.sld !== kw;
      const normMatch = normalizedInfo.sld.includes(kw) && normalizedInfo.sld !== kw;
      if (rawMatch || normMatch) {
        const hasActionInSld = subKwList.some(act => 
          domainInfo.sld.includes(act) || normalizedInfo.sld.includes(act)
        );
        const threat = hasActionInSld ? 85 : 65;
        highestThreatScore = Math.max(highestThreatScore, threat);
        flags.push({
          type: 'COMBO_SQUATTING',
          severity: 'HIGH',
          brand: brand.name,
          description: `Domain SLD combines brand name '${kw}' with additional terms ('${domainInfo.sld}').`
        });
        detectedTarget = brand.name;
      }

      // 5. Damerau-Levenshtein Typosquatting
      const sldToCheck = normalizedInfo.sld;
      const dist = damerauLevenshteinDistance(sldToCheck, kw);
      const isCloseTypo = (dist === 1 && kw.length >= 4) || (dist === 2 && kw.length >= 7);

      if (isCloseTypo && sldToCheck !== kw) {
        highestThreatScore = Math.max(highestThreatScore, 85);
        flags.push({
          type: 'TYPOSQUATTING_DISTANCE',
          severity: 'CRITICAL',
          brand: brand.name,
          distance: dist,
          description: `Domain '${domainInfo.sld}' is a near-identical typosquat of '${kw}' (Levenshtein distance: ${dist}).`
        });
        detectedTarget = brand.name;
      }
    }
  }

  return {
    isOfficial: false,
    matchedBrand: detectedTarget,
    score: highestThreatScore,
    flags,
    domainInfo
  };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    damerauLevenshteinDistance,
    parseDomainStructure,
    isOfficialBrandDomain,
    analyzeTyposquatting
  };
}
