// Red-flag engine: plain-code checks for the tricks Indian scam messages use most.
//
// These run before any model, on every message, in every mode, offline. They catch the
// patterns a model can talk itself out of (a lookalike bank link, a request for an OTP),
// give each finding in English and Hindi, and set a floor under the final verdict: the
// model may raise the risk, never lower it below what the code found.

/** Link shorteners hide where a link goes. */
export const SHORTENERS = [
  "bit.ly", "tinyurl.com", "cutt.ly", "rb.gy", "t.ly", "is.gd", "shorturl.at", "tiny.cc",
  "ow.ly", "rebrand.ly", "s.id", "shorturl.asia", "v.gd", "goo.su", "t.co", "lnkd.in",
];

/** Top-level domains that are cheap and common in phishing. */
export const RISKY_TLDS = [
  "xyz", "top", "click", "buzz", "online", "site", "live", "icu", "monster", "rest",
  "cfd", "sbs", "lol", "shop", "vip", "work", "fit", "cam", "gq", "tk", "ml", "cf", "ga",
];

/**
 * Brands scammers impersonate, with the domains that really belong to them.
 * A link that names the brand on any other domain is a lookalike.
 */
export const BRANDS = {
  sbi: ["sbi.co.in", "onlinesbi.sbi", "sbi.bank.in", "onlinesbi.com"],
  hdfc: ["hdfcbank.com", "hdfc.bank.in", "hdfc.com"],
  icici: ["icicibank.com", "icici.bank.in"],
  axis: ["axisbank.com", "axis.bank.in"],
  kotak: ["kotak.com", "kotak.bank.in"],
  paytm: ["paytm.com", "paytmbank.com"],
  phonepe: ["phonepe.com"],
  gpay: ["pay.google.com", "google.com"],
  amazon: ["amazon.in", "amazon.com"],
  flipkart: ["flipkart.com"],
  aadhaar: ["uidai.gov.in", "myaadhaar.uidai.gov.in"],
  uidai: ["uidai.gov.in"],
  incometax: ["incometax.gov.in"],
  epfo: ["epfindia.gov.in", "epfo.gov.in"],
  indiapost: ["indiapost.gov.in"],
  fastag: ["ihmcl.co.in", "npci.org.in"],
  npci: ["npci.org.in"],
  irctc: ["irctc.co.in"],
  bescom: ["bescom.karnataka.gov.in", "bescom.co.in"],
  echallan: ["echallan.parivahan.gov.in", "parivahan.gov.in"],
  parivahan: ["parivahan.gov.in"],
};

/**
 * Keyword checks. Each has an id, a weight (how much it adds to the risk score), the
 * patterns that trigger it (English, Hindi and Hinglish), and the finding in two
 * languages. Weights: 3 = alone it is a scam sign, 2 = strong sign, 1 = weak sign.
 */
export const KEYWORD_RULES = [
  {
    id: "secret_request",
    weight: 3,
    // Only a request counts. "Your OTP is 4829. Do not share it." is how real services
    // deliver an OTP, so a sentence that says not to share is skipped.
    patterns: [
      /\b(share|send|tell|give|provide|forward|read out|reply with|confirm|enter|type)\b[^.\n]{0,40}\b(otp|one[- ]time password|upi pin|atm pin|m-?pin|pin|cvv|password|passcode)\b/i,
      /\b(otp|upi pin|atm pin|cvv|password)\b[^.\n]{0,40}\b(to (verify|complete|confirm|unblock|activate|update|receive))\b/i,
      /(ओटीपी|पिन|पासवर्ड)[^।\n]{0,30}(बताएं|बताइए|बताओ|शेयर|भेजें|भेजो|दें)/,
    ],
    unless: /\b(do not|don't|dont|never|nobody|no one)\b|मत|न\s*करें|कभी\s*नहीं/i,
    en: "Asks for an OTP, PIN, CVV or password. No bank, company or officer ever asks for these.",
    hi: "OTP, PIN, CVV या पासवर्ड माँगा गया है। कोई बैंक या अधिकारी ये कभी नहीं माँगता।",
  },
  {
    id: "receive_needs_pin",
    weight: 3,
    patterns: [/(receive|get|claim|credit)[^.\n]{0,40}(enter|type|put)[^.\n]{0,20}\bpin\b/i, /\b(collect request|scan (the )?qr( code)? to (receive|get))\b/i, /पैसे\s*(पाने|लेने)\s*के\s*लिए\s*पिन/],
    en: "Says you must enter your PIN or scan a QR code to receive money. Receiving money never needs your PIN.",
    hi: "पैसे पाने के लिए PIN डालने या QR स्कैन करने को कहा है। पैसे पाने के लिए PIN कभी नहीं लगता।",
  },
  {
    id: "account_threat",
    weight: 2,
    patterns: [/\b(kyc|pan)\b[^.\n]{0,60}\b(expire|expired|pending|update|block|suspend)/i, /\b(account|a\/c|card|sim|number|connection|wallet)[^.\n]{0,40}\b(blocked|suspended|deactivated|frozen|closed|disconnected)\b/i, /केवाईसी|खाता\s*(बंद|ब्लॉक)|बिजली\s*(काट|कनेक्शन)/],
    en: "Threatens to block your account, card, SIM or power unless you act. Real notices don't work this way.",
    hi: "खाता, कार्ड, सिम या बिजली बंद करने की धमकी है। असली सूचनाएँ ऐसे नहीं आतीं।",
  },
  {
    id: "urgency",
    weight: 1,
    patterns: [/\b(urgent|urgently|immediately|right now|within \d+ ?(hours?|hrs|minutes?|mins)|today itself|last (chance|date|warning)|final notice|tonight)\b/i, /तुरंत|अभी|आज\s*ही|अंतिम\s*(मौका|चेतावनी)/],
    en: "Rushes you ('immediately', 'within 2 hours', 'tonight'). Scammers rush you so you don't stop to check.",
    hi: "जल्दबाज़ी करवाई जा रही है। ठग इसलिए जल्दी करवाते हैं ताकि आप जाँच न करें।",
  },
  {
    id: "prize",
    weight: 2,
    patterns: [/\b(you('ve| have)? won|winner|lottery|lucky draw|jackpot|prize|reward points? (expire|expiring|redeem)|cashback of|claim your)\b/i, /लॉटरी|इनाम|आपने\s*जीता|जीत\s*लिए/],
    en: "Offers a prize, lottery, reward or cashback you didn't apply for.",
    hi: "बिना माँगे इनाम, लॉटरी या कैशबैक का लालच दिया गया है।",
  },
  {
    id: "authority",
    weight: 2,
    patterns: [/\b(cbi|police|cyber cell|narcotics|ncb|customs|ed officer|enforcement directorate|rbi officer|trai|income tax officer|court notice|arrest warrant|digital arrest)\b/i, /पुलिस|गिरफ़्तार|गिरफ्तार|सीबीआई|डिजिटल\s*अरेस्ट/],
    en: "Claims to be police, CBI, customs, RBI or a court, or mentions arrest. Officials never 'arrest' anyone over a call or message.",
    hi: "पुलिस, CBI, कस्टम या कोर्ट होने का दावा, या गिरफ़्तारी की बात। कोई अधिकारी फ़ोन या मैसेज पर 'अरेस्ट' नहीं करता।",
  },
  {
    id: "parcel",
    weight: 1,
    patterns: [/\b(parcel|courier|package|shipment)\b[^.\n]{0,60}\b(held|seized|illegal|drugs|on hold|address (is )?incomplete|undeliver)/i],
    en: "Says a parcel is held, seized or undeliverable. This is a common opening for fake courier and 'digital arrest' scams.",
    hi: "पार्सल रोके जाने की बात है। यह नकली कूरियर और 'डिजिटल अरेस्ट' ठगी की आम शुरुआत है।",
  },
  {
    id: "remote_access",
    weight: 3,
    patterns: [/\b(anydesk|teamviewer|quick ?support|rustdesk|airdroid|screen ?share|screen sharing)\b/i],
    en: "Asks you to install a remote-access or screen-sharing app. That lets a stranger see and control your phone.",
    hi: "स्क्रीन शेयर या रिमोट ऐप डालने को कहा है। इससे अजनबी आपका फ़ोन देख और चला सकता है।",
  },
  {
    id: "apk",
    weight: 3,
    patterns: [/\.apk\b/i, /\b(download|install)[^.\n]{0,30}\b(apk|app from (this|the) link)\b/i],
    en: "Asks you to install an app from a link (.apk). Fake apps steal OTPs and bank details.",
    hi: "लिंक से ऐप (.apk) डालने को कहा है। नकली ऐप OTP और बैंक जानकारी चुराते हैं।",
  },
  {
    id: "task_job",
    weight: 2,
    patterns: [/\b(part[- ]?time|work from home|daily (income|earning)|earn (rs\.?|₹|inr)?\s?[\d,]+\s*(per|\/|a) ?(day|hour|task)|like (youtube )?videos|rate (hotels|products)|prepaid task)\b/i, /घर\s*बैठे\s*कमाएं|पार्ट\s*टाइम/],
    en: "Offers easy part-time money for simple tasks. These 'task' jobs end by asking you to pay first.",
    hi: "आसान काम के बदले पैसे का ऑफ़र है। ऐसे 'टास्क' जॉब अंत में पहले पैसे माँगते हैं।",
  },
  {
    id: "investment",
    weight: 2,
    patterns: [/\b(guaranteed (returns?|profit)|double your money|\d+% (daily|weekly|monthly) (returns?|profit)|stock tips?|ipo allotment|crypto (trading|investment)|vip (group|trading))\b/i, /पैसा\s*डबल|गारंटी(ड)?\s*(रिटर्न|मुनाफ़ा)/],
    en: "Promises guaranteed or very high returns. Real investments never guarantee profit.",
    hi: "पक्का या बहुत ज़्यादा मुनाफ़ा बताया गया है। असली निवेश में मुनाफ़े की गारंटी नहीं होती।",
  },
  {
    id: "move_chat",
    weight: 1,
    patterns: [/\b(whatsapp|telegram)\b[^.\n]{0,40}\b(me|us|this number|join|contact|message)\b/i, /\b(join|contact)[^.\n]{0,20}\b(telegram|whatsapp)\b/i],
    en: "Asks you to move to WhatsApp or Telegram, away from official channels.",
    hi: "WhatsApp या Telegram पर बात करने को कहा है, सरकारी/आधिकारिक रास्ते से हटकर।",
  },
  {
    id: "pay_to_get",
    weight: 2,
    patterns: [/\b(pay|deposit|transfer)\b[^.\n]{0,40}\b(processing|registration|release|clearance|customs|verification|security) (fee|charge|amount|deposit)\b/i, /\b(refundable deposit|small fee to (receive|release|claim))\b/i],
    en: "Asks you to pay a 'fee' to receive money, a job, a loan or a parcel.",
    hi: "पैसा, नौकरी, लोन या पार्सल पाने के लिए पहले 'फीस' माँगी गई है।",
  },
  {
    id: "secrecy",
    weight: 2,
    patterns: [/\b(don'?t|do not) (tell|inform|share (this )?with) (anyone|your family|bank)\b/i, /\b(keep (this|it) (secret|confidential))\b/i, /किसी\s*को\s*(मत|न)\s*बताएं/],
    en: "Tells you to keep it secret from family or the bank. That is how scammers stop you getting help.",
    hi: "परिवार या बैंक से छिपाने को कहा है। ठग ऐसा इसलिए कहते हैं ताकि आप मदद न ले सकें।",
  },
];

const LEVELS = ["safe", "suspicious", "scam"];

/**
 * Pure functions that find red flags in a message.
 */
export class RedFlags {
  /**
   * Find every link in a message, with its host in lower case.
   *
   * :param text: The message.
   * :return: A list of {url, host}. Bare hosts such as "sbi-kyc.xyz/x" count too.
   */
  static links(text) {
    const found = [];
    const pattern = /\b((?:https?:\/\/)?(?:(?:[a-z0-9-]+\.)+[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?(?:\/[^\s<>"')]*)?)/gi;
    for (const match of String(text).matchAll(pattern)) {
      const raw = match[1].replace(/[.,;:!?)]+$/u, "");
      // Skip emails, and numbers such as "Rs.500" or a version "1.2.3.4" that only look
      // like hosts. An IP address counts as a link when it has a scheme or a path.
      const before = String(text)[match.index - 1];
      const isIp = /^(?:https?:\/\/)?\d+\.\d+\.\d+\.\d+/i.test(raw);
      if (before === "@" || (/^\d/.test(raw) && !isIp) || (isIp && !/^https?:|\//i.test(raw))) {
        continue;
      }
      const hostPart = raw.replace(/^https?:\/\//i, "").split(/[/:?#]/)[0].toLowerCase();
      if (!/\.[a-z]{2,}$/.test(hostPart) && !/^\d+\.\d+\.\d+\.\d+$/.test(hostPart)) {
        continue;
      }
      found.push({ url: raw, host: hostPart });
    }
    return found;
  }

  /**
   * Tell whether a host is a given domain or one of its subdomains.
   *
   * :param host: A host, such as "www.sbi.co.in".
   * :param domain: A domain, such as "sbi.co.in".
   * :return: True when the host belongs to the domain.
   */
  static isOn(host, domain) {
    return host === domain || host.endsWith(`.${domain}`);
  }

  /**
   * Check one link against the link rules.
   *
   * :param link: {url, host} from links().
   * :param extraShorteners: More shortener hosts, from Remote Config.
   * :return: A list of findings for this link.
   */
  static checkLink(link, extraShorteners = []) {
    const findings = [];
    const host = link.host;
    if ([...SHORTENERS, ...extraShorteners].some(RedFlags.isOn.bind(null, host))) {
      findings.push({
        id: "short_link",
        weight: 2,
        detail: link.url,
        en: `The link ${link.url} is shortened, so you can't see where it really goes.`,
        hi: `लिंक ${link.url} छोटा (short) किया गया है, असली पता छिपा है।`,
      });
    }
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
      findings.push({
        id: "ip_link",
        weight: 3,
        detail: link.url,
        en: `The link ${link.url} is a bare number address. Real banks and services use names.`,
        hi: `लिंक ${link.url} सिर्फ़ नंबरों वाला पता है। असली बैंक नाम वाले पते इस्तेमाल करते हैं।`,
      });
    }
    const tld = host.split(".").pop();
    if (RISKY_TLDS.includes(tld)) {
      findings.push({
        id: "risky_tld",
        weight: 1,
        detail: link.url,
        en: `The link ends in .${tld}, an ending that is cheap and common in fake sites.`,
        hi: `लिंक .${tld} पर खत्म होता है, जो नकली साइटों में आम है।`,
      });
    }
    const squashed = host.replace(/[^a-z0-9]/g, "");
    for (const [brand, domains] of Object.entries(BRANDS)) {
      if (squashed.includes(brand) && !domains.some(RedFlags.isOn.bind(null, host))) {
        findings.push({
          id: "lookalike",
          weight: 3,
          detail: link.url,
          en: `The link ${link.url} uses the name "${brand.toUpperCase()}" but is not its real website (${domains[0]}).`,
          hi: `लिंक ${link.url} में "${brand.toUpperCase()}" का नाम है, पर यह उसकी असली वेबसाइट (${domains[0]}) नहीं है।`,
        });
        break;
      }
    }
    return findings;
  }

  /**
   * Find every red flag in a message.
   *
   * :param text: The message.
   * :param extra: Optional {shorteners, rules} from Remote Config. Each extra rule has
   *   id, weight, pattern (a string for new RegExp, case-insensitive), en and hi.
   * :return: {flags, score, level}. level is safe, suspicious or scam.
   */
  static analyse(text, extra = {}) {
    const value = String(text || "");
    const flags = [];
    const rules = [...KEYWORD_RULES, ...RedFlags.compileExtra(extra.rules || [])];
    for (const rule of rules) {
      const match = RedFlags.ruleMatch(value, rule);
      if (match) {
        flags.push({ id: rule.id, weight: rule.weight, detail: match, en: rule.en, hi: rule.hi });
      }
    }
    for (const link of RedFlags.links(value)) {
      flags.push(...RedFlags.checkLink(link, extra.shorteners || []));
    }
    const score = flags.reduce(RedFlags.addWeight, 0);
    return { flags, score, level: RedFlags.levelFor(score, flags) };
  }

  /**
   * Turn Remote Config rules into keyword rules. A rule whose pattern does not compile is
   * left out, so a bad config value cannot break the check.
   *
   * :param rules: The rules from Remote Config.
   * :return: The compiled rules.
   */
  static compileExtra(rules) {
    const compiled = [];
    for (const rule of Array.isArray(rules) ? rules : []) {
      try {
        if (!rule.id || !rule.pattern || !rule.en) {
          continue;
        }
        compiled.push({
          id: String(rule.id),
          weight: Math.max(1, Math.min(3, Number(rule.weight) || 1)),
          patterns: [new RegExp(rule.pattern, "iu")],
          en: String(rule.en),
          hi: String(rule.hi || rule.en),
        });
      } catch {
        // Ignore a rule that does not compile.
      }
    }
    return compiled;
  }

  /**
   * Find the first sentence a rule matches. A rule with "unless" skips any sentence that
   * also matches it, such as "Do not share your OTP".
   *
   * :param text: The message.
   * :param rule: A keyword rule.
   * :return: The matched text, or null.
   */
  static ruleMatch(text, rule) {
    const sentences = rule.unless ? text.split(/(?<=[.!?।\n])\s*/u) : [text];
    for (const sentence of sentences) {
      if (rule.unless && rule.unless.test(sentence)) {
        continue;
      }
      const match = rule.patterns.map(RedFlags.firstMatch.bind(null, sentence)).find(Boolean);
      if (match) {
        return match;
      }
    }
    return null;
  }

  /**
   * Return the text a pattern matches, or null.
   *
   * :param text: The message.
   * :param pattern: A RegExp.
   * :return: The matched text, trimmed to 60 characters, or null.
   */
  static firstMatch(text, pattern) {
    const match = text.match(pattern);
    return match ? match[0].slice(0, 60) : null;
  }

  /**
   * Add a flag's weight to a running total.
   *
   * :param total: The total so far.
   * :param flag: A flag.
   * :return: The new total.
   */
  static addWeight(total, flag) {
    return total + flag.weight;
  }

  /**
   * Decide the code's own level from the flags.
   *
   * :param score: The sum of weights.
   * :param flags: The flags.
   * :return: "scam" when any weight-3 flag fired or the score is 4 or more,
   *   "suspicious" from a score of 2, otherwise "safe".
   */
  static levelFor(score, flags) {
    if (flags.some(RedFlags.isSevere) || score >= 4) {
      return "scam";
    }
    if (score >= 2) {
      return "suspicious";
    }
    return "safe";
  }

  /**
   * Tell whether a flag alone means scam.
   *
   * :param flag: A flag.
   * :return: True for weight 3.
   */
  static isSevere(flag) {
    return flag.weight >= 3;
  }

  /**
   * Combine the code's level with the model's verdict. The model can raise the risk but
   * never lower it below what the code found.
   *
   * :param codeLevel: safe, suspicious or scam.
   * :param modelLevel: safe, suspicious or scam, or null when no model answered.
   * :return: The higher of the two.
   */
  static combine(codeLevel, modelLevel) {
    const code = LEVELS.indexOf(codeLevel);
    const model = LEVELS.indexOf(modelLevel);
    return LEVELS[Math.max(code, model)];
  }
}
