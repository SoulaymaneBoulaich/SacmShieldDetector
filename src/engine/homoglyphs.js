// ScamShield Pro - Homoglyph & Unicode Confusable Detector
// Identifies IDN spoofing, mixed-script attacks, Punycode abuse, and zero-width obfuscation

const CONFUSABLE_MAP = {
  // Cyrillic Lookalikes
  '\u0430': 'a', '\u0410': 'A', '\u0441': 'c', '\u0421': 'C',
  '\u0435': 'e', '\u0415': 'E', '\u0456': 'i', '\u0406': 'I',
  '\u0458': 'j', '\u0408': 'J', '\u043e': 'o', '\u041e': 'O',
  '\u0440': 'p', '\u0420': 'P', '\u0455': 's', '\u0405': 'S',
  '\u0443': 'y', '\u0423': 'Y', '\u0445': 'x', '\u0425': 'X',
  '\u0432': 'b', '\u0412': 'B', '\u043d': 'h', '\u041d': 'H',
  '\u0442': 't', '\u0422': 'T',

  // Greek Lookalikes
  '\u03b1': 'a', '\u0391': 'A', '\u03b2': 'b', '\u0392': 'B',
  '\u03b5': 'e', '\u0395': 'E', '\u03b9': 'i', '\u0399': 'I',
  '\u03ba': 'k', '\u039a': 'K', '\u03bf': 'o', '\u039f': 'O',
  '\u03c1': 'p', '\u03a1': 'P', '\u03c4': 't', '\u03a4': 'T',
  '\u03c5': 'u', '\u03a5': 'Y', '\u03c7': 'x', '\u03a7': 'X',

  // Common symbol/number confusables
  '0': 'o', '1': 'l', '|': 'l', '!': 'i',
  '3': 'e', '4': 'a', '5': 's', '@': 'a', '$': 's'
};

const ZERO_WIDTH_CHARS = /[\u200B-\u200D\uFEFF\u00AD\u2060\u200E\u200F]/g;

function cleanZeroWidth(text) {
  if (!text) return '';
  return text.replace(ZERO_WIDTH_CHARS, '');
}

function isPunycode(str) {
  return /xn--/i.test(str);
}

function detectMixedScript(str) {
  let hasLatin = false;
  let hasCyrillic = false;
  let hasGreek = false;
  let hasOtherNonAscii = false;

  const chars = Array.from(cleanZeroWidth(str));
  for (const ch of chars) {
    const code = ch.charCodeAt(0);
    if ((code >= 0x0041 && code <= 0x005A) || (code >= 0x0061 && code <= 0x007A)) {
      hasLatin = true;
    } else if (code >= 0x0400 && code <= 0x04FF) {
      hasCyrillic = true;
    } else if (code >= 0x0370 && code <= 0x03FF) {
      hasGreek = true;
    } else if (code > 0x007F && ch !== '.' && ch !== '-' && ch !== '_') {
      hasOtherNonAscii = true;
    }
  }

  const scriptsCount = [hasLatin, hasCyrillic, hasGreek, hasOtherNonAscii].filter(Boolean).length;
  return {
    isMixed: scriptsCount > 1,
    hasLatin,
    hasCyrillic,
    hasGreek,
    hasOtherNonAscii,
    scriptsCount
  };
}

function normalizeHomoglyphs(str) {
  const cleaned = cleanZeroWidth(str);
  let normalized = '';
  let spoofedCharsCount = 0;
  const detectedConfusables = [];

  for (const ch of cleaned) {
    if (CONFUSABLE_MAP[ch]) {
      normalized += CONFUSABLE_MAP[ch];
      if (ch.charCodeAt(0) > 127) {
        spoofedCharsCount++;
        detectedConfusables.push({
          char: ch,
          unicode: 'U+' + ch.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0'),
          mapsTo: CONFUSABLE_MAP[ch]
        });
      }
    } else {
      normalized += ch;
    }
  }

  return {
    original: str,
    normalized: normalized.toLowerCase(),
    spoofedCharsCount,
    detectedConfusables,
    isPunycode: isPunycode(str),
    hasZeroWidth: ZERO_WIDTH_CHARS.test(str)
  };
}

function analyzeHomoglyphs(hostname) {
  const cleanHost = cleanZeroWidth(hostname.toLowerCase());
  const mixedCheck = detectMixedScript(cleanHost);
  const normResult = normalizeHomoglyphs(cleanHost);

  let threatScore = 0;
  const flags = [];

  if (normResult.hasZeroWidth) {
    threatScore += 50;
    flags.push({
      type: 'ZERO_WIDTH_OBSFUCATION',
      severity: 'HIGH',
      description: 'Zero-width or invisible characters detected in domain/URL structure.'
    });
  }

  if (normResult.isPunycode) {
    threatScore += 35;
    flags.push({
      type: 'PUNYCODE_IDN_SPOOFING',
      severity: 'MEDIUM',
      description: 'Domain uses Punycode (xn--) IDN encoding, frequently abused for visual brand impersonation.'
    });
  }

  if (mixedCheck.isMixed && normResult.spoofedCharsCount > 0) {
    threatScore += 65;
    flags.push({
      type: 'MIXED_SCRIPT_HOMOGLYPH',
      severity: 'CRITICAL',
      description: `Mixed-script spoofing detected (${normResult.spoofedCharsCount} non-Latin characters visually mimicking Latin letters).`,
      details: normResult.detectedConfusables
    });
  } else if (normResult.spoofedCharsCount > 0) {
    threatScore += 45;
    flags.push({
      type: 'HOMOGLYPH_CHARACTERS',
      severity: 'HIGH',
      description: `Detected ${normResult.spoofedCharsCount} unicode confusable character(s).`,
      details: normResult.detectedConfusables
    });
  }

  return {
    score: Math.min(threatScore, 100),
    flags,
    normalizedDomain: normResult.normalized,
    detectedConfusables: normResult.detectedConfusables,
    isPunycode: normResult.isPunycode
  };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    CONFUSABLE_MAP,
    cleanZeroWidth,
    isPunycode,
    detectMixedScript,
    normalizeHomoglyphs,
    analyzeHomoglyphs
  };
}
