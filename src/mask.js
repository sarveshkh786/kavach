// Privacy mask: hides personal details before a message may leave the device.
//
// Kavach checks messages on the device first. Only when no on-device model is available,
// and only after the person agrees, does it send the message to the cloud model, and
// then it sends this masked copy. Links, amounts and sender-style wording stay, because
// they are what shows a scam; OTPs, account and card numbers, Aadhaar and PAN numbers,
// phone numbers and email addresses are replaced with labels.

const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;

const MASKS = [
  // Links are kept whole, so the digits inside them are not masked. Emails are masked
  // before links are found, so an email's domain is not mistaken for a link.
  { label: null, pattern: /\b(?:https?:\/\/)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/[^\s<>"')]*)?/gi },
  // UPI IDs: keep the bank handle, which can show a fake, and hide the person.
  { label: "upi", pattern: /\b[A-Za-z0-9._-]{2,}@(?:ok)?[a-z]{2,15}\b/g },
  { label: "[PAN]", pattern: /\b[A-Z]{5}\d{4}[A-Z]\b/g },
  { label: "[CARD]", pattern: /\b(?:\d[ -]?){15,18}\d\b/g },
  { label: "[AADHAAR]", pattern: /\b\d{4}[ -]?\d{4}[ -]?\d{4}\b/g },
  { label: "[PHONE]", pattern: /(?:\+91[ -]?|\b0)?\b[6-9]\d{4}[ -]?\d{5}\b/g },
  { label: "[ACCOUNT]", pattern: /\b(?:a\/?c|acct?|account)(?:\s*(?:no\.?|number|ending(?: with| in)?))?\s*[:#-]?\s*[Xx*]*\d{3,}\b/gi },
  { label: "[OTP]", pattern: /\b(?:otp|code|pin)\b[^\d\n]{0,20}\d{4,8}\b/gi },
  { label: "[NUMBER]", pattern: /\b\d{9,}\b/g },
];

/**
 * Pure functions that mask personal details.
 */
export class PrivacyMask {
  /**
   * Mask a message. Links and amounts stay; personal details become labels.
   *
   * :param text: The message.
   * :return: {masked, count, kinds}: the masked text, how many details were hidden and
   *   which kinds.
   */
  static mask(text) {
    const kept = [];
    let count = 0;
    const kinds = new Set();
    let working = String(text || "").replace(EMAIL, () => {
      count += 1;
      kinds.add("[EMAIL]");
      return "[EMAIL]";
    });
    // Protect links with placeholders, so later patterns cannot touch them.
    working = working.replace(MASKS[0].pattern, PrivacyMask.protect.bind(null, kept));
    for (const rule of MASKS.slice(1)) {
      working = working.replace(rule.pattern, (match) => {
        count += 1;
        if (rule.label === "upi") {
          kinds.add("[UPI-ID]");
          return `[UPI-ID]@${match.split("@")[1]}`;
        }
        kinds.add(rule.label);
        if (rule.label === "[OTP]" || rule.label === "[ACCOUNT]") {
          return match.replace(/\d{3,}$/, rule.label);
        }
        return rule.label;
      });
    }
    const masked = working.replace(/\u0000(\d+)\u0000/g, PrivacyMask.restore.bind(null, kept));
    return { masked, count, kinds: [...kinds] };
  }

  /**
   * Swap a link for a placeholder and remember it.
   *
   * :param kept: The list of kept links.
   * :param match: The link.
   * :return: The placeholder.
   */
  static protect(kept, match) {
    kept.push(match);
    return `\u0000${kept.length - 1}\u0000`;
  }

  /**
   * Put a kept link back.
   *
   * :param kept: The list of kept links.
   * :param _match: The placeholder.
   * :param index: The link's index.
   * :return: The link.
   */
  static restore(kept, _match, index) {
    return kept[Number(index)];
  }
}
