// ScamShield Pro - Automated Heuristic Test Suite
// Rigorous verification of Homoglyphs, Typosquatting, Domain Risk, and Risk Aggregator

const { analyzeHomoglyphs, normalizeHomoglyphs } = require('../src/engine/homoglyphs.js');
const { analyzeTyposquatting, damerauLevenshteinDistance } = require('../src/engine/typosquatting.js');
const { analyzeDomainRisk, calculateShannonEntropy, isIpAddress } = require('../src/engine/domain-risk.js');
const { evaluateUrlRisk } = require('../src/engine/risk-aggregator.js');

let passedTests = 0;
let failedTests = 0;

function assert(condition, message) {
  if (condition) {
    passedTests++;
    console.log(`  ✓ ${message}`);
  } else {
    failedTests++;
    console.error(`  ✗ FAIL: ${message}`);
  }
}

console.log('====================================================');
console.log('  ScamShield Pro - Heuristic Engine Test Suite');
console.log('====================================================\n');

// 1. Homoglyph & Unicode Confusable Tests
console.log('[1] Testing Homoglyph & Unicode Confusable Engine...');
{
  // Cyrillic 'а' (U+0430) spoofing 'paypal.com'
  const cyrillicA = '\u0430';
  const spoofedPaypal = `p${cyrillicA}ypal.com`;
  const res = analyzeHomoglyphs(spoofedPaypal);
  assert(res.score >= 60, `Flagged Cyrillic homoglyph in '${spoofedPaypal}' (Score: ${res.score})`);
  assert(res.flags.some(f => f.type.includes('HOMOGLYPH')), 'Generated homoglyph detection flag');
  assert(res.normalizedDomain === 'paypal.com', `Correctly decoded homoglyph to ASCII 'paypal.com' (Got: '${res.normalizedDomain}')`);

  // Punycode detection
  const punycodeRes = analyzeHomoglyphs('xn--google-vwa.com');
  assert(punycodeRes.isPunycode === true, 'Detected Punycode IDN encoding');

  // Normal ASCII domain (clean)
  const cleanRes = analyzeHomoglyphs('github.com');
  assert(cleanRes.score === 0, 'Clean ASCII domain gets 0 homoglyph risk score');
}

// 2. Damerau-Levenshtein & Typosquatting Tests
console.log('\n[2] Testing Typosquatting & Brand Spoofing Engine...');
{
  // Levenshtein distance checks
  assert(damerauLevenshteinDistance('google', 'goolge') === 1, 'Transposition distance is 1');
  assert(damerauLevenshteinDistance('paypal', 'paypa1') === 1, 'Substitution distance is 1');
  assert(damerauLevenshteinDistance('netflix', 'netfix') === 1, 'Deletion distance is 1');

  // Brand spoofing distance flag
  const typoGoogle = analyzeTyposquatting('goolge.com');
  assert(typoGoogle.score >= 80, `Flagged typosquat 'goolge.com' (Score: ${typoGoogle.score})`);
  assert(typoGoogle.matchedBrand === 'Google', `Identified target brand as Google (Got: ${typoGoogle.matchedBrand})`);

  // Subdomain masquerade (paypal.com.accounts-verify.xyz)
  const subMasquerade = analyzeTyposquatting('paypal.com.accounts-verify.xyz');
  assert(subMasquerade.score >= 80, `Flagged subdomain masquerade (Score: ${subMasquerade.score})`);
  assert(subMasquerade.flags.some(f => f.type === 'SUBDOMAIN_BRAND_MASQUERADE'), 'Generated SUBDOMAIN_BRAND_MASQUERADE flag');

  // Combo-squatting (apple-support-login.com)
  const comboSquat = analyzeTyposquatting('apple-login-verify.com');
  assert(comboSquat.score >= 65, `Flagged combo-squat 'apple-login-verify.com' (Score: ${comboSquat.score})`);

  // Legitimate official domain check (Zero false positive)
  const officialPaypal = analyzeTyposquatting('accounts.google.com');
  assert(officialPaypal.isOfficial === true, 'Legitimate official domain recognized as official (0 false positive)');
  assert(officialPaypal.score === 0, 'Legitimate official domain gets 0 risk score');
}

// 3. Domain Risk & Entropy Tests
console.log('\n[3] Testing Domain Risk & Shannon Entropy Heuristics...');
{
  // High-Risk TLD (.tk, .top, .xyz)
  const tldRisk = analyzeDomainRisk('https://my-crypto-wallet.tk');
  assert(tldRisk.score >= 35, `Flagged high-risk TLD .tk (Score: ${tldRisk.score})`);
  assert(tldRisk.flags.some(f => f.type === 'SUSPICIOUS_HIGH_RISK_TLD'), 'Generated high-risk TLD flag');

  // IP address as hostname
  const ipRisk = analyzeDomainRisk('http://192.168.1.100/login');
  assert(ipRisk.flags.some(f => f.type === 'IP_ADDRESS_HOSTNAME'), 'Detected IP address as hostname');
  assert(ipRisk.flags.some(f => f.type === 'UNENCRYPTED_HTTP'), 'Detected unencrypted HTTP');

  // Open redirect parameter
  const redirRisk = analyzeDomainRisk('https://example.com/login?redirect=https://scam-site.xyz/steal');
  assert(redirRisk.flags.some(f => f.type === 'SUSPICIOUS_REDIRECT_PARAMETER'), 'Detected dangerous redirect parameter');

  // Basic auth obfuscation trick (http://google.com@phish-site.cc)
  const authTrick = analyzeDomainRisk('http://google.com@phish-site.cc/login');
  assert(authTrick.flags.some(f => f.type === 'URL_USERINFO_OBFUSCATION'), 'Detected Userinfo @ authority spoofing');

  // Shannon Entropy of DGA random strings
  const lowEntropy = calculateShannonEntropy('amazon');
  const highEntropy = calculateShannonEntropy('x8f93kd9z2q1');
  assert(highEntropy > lowEntropy, `DGA entropy (${highEntropy.toFixed(2)}) > Normal entropy (${lowEntropy.toFixed(2)})`);
}

// 4. Unified Risk Aggregator Tests
console.log('\n[4] Testing Unified Risk Aggregator Pipeline...');
{
  // Test 1: Real Phishing URL with Homoglyph + High Risk TLD
  const cyrillicA = '\u0430';
  const maliciousUrl = `https://p${cyrillicA}ypal-verify-account.tk/login`;
  const malResult = evaluateUrlRisk(maliciousUrl);
  assert(malResult.verdict === 'DANGER', `Correctly verdicted '${maliciousUrl}' as DANGER (Got: ${malResult.verdict}, Score: ${malResult.riskScore})`);
  assert(malResult.riskScore >= 75, `High risk score for complex phishing vector (${malResult.riskScore})`);

  // Test 2: Legitimate Top-50 Domain (Whitelisted)
  const legitResult = evaluateUrlRisk('https://github.com/trending');
  assert(legitResult.verdict === 'SAFE', `Legitimate URL verified as SAFE (Got: ${legitResult.verdict})`);
  assert(legitResult.riskScore === 0, 'Whitelisted URL gets 0 risk score');

  // Test 3: Typosquatted Binance on .top with DOM credential harvesting signal
  const domSignals = {
    flags: [
      { type: 'CROSS_ORIGIN_PASSWORD_ACTION', severity: 'CRITICAL', description: 'Password submitted to foreign origin.' }
    ]
  };
  const binanceTypo = evaluateUrlRisk('https://binancee-login.top', domSignals);
  assert(binanceTypo.verdict === 'DANGER', `Detected combo typosquat + DOM harvesting as DANGER (Score: ${binanceTypo.riskScore})`);
  assert(binanceTypo.brandTarget === 'Binance', `Identified target brand as Binance (Got: ${binanceTypo.brandTarget})`);

  // Test 4: Custom Whitelist override
  const customWhitelist = ['internal-company-portal.xyz'];
  const whitelistResult = evaluateUrlRisk('https://internal-company-portal.xyz', null, { whitelist: customWhitelist });
  assert(whitelistResult.verdict === 'SAFE' && whitelistResult.riskScore === 0, 'Custom whitelist overrides TLD risk');
}

console.log('\n====================================================');
console.log(`  Tests Passed: ${passedTests} | Tests Failed: ${failedTests}`);
console.log('====================================================');

if (failedTests > 0) {
  process.exit(1);
} else {
  console.log('  ALL SCAM DETECTOR HEURISTIC TESTS PASSED CLEANLY!\n');
}
