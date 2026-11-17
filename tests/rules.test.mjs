// Run: node --test "tests/*.test.mjs"
import assert from "node:assert/strict";
import test from "node:test";
import { RedFlags } from "../src/rules.js";
import { PrivacyMask } from "../src/mask.js";

const ids = (text) => RedFlags.analyse(text).flags.map((f) => f.id);

test("a fake SBI KYC message is a scam, for several independent reasons", () => {
  const msg = "Dear customer your SBI account will be blocked today. KYC pending. Update immediately at http://sbi-kyc-update.xyz/login and share the OTP.";
  const result = RedFlags.analyse(msg);
  assert.equal(result.level, "scam");
  for (const id of ["secret_request", "account_threat", "urgency", "lookalike", "risky_tld"]) {
    assert.ok(ids(msg).includes(id), id);
  }
  assert.match(result.flags.find((f) => f.id === "lookalike").en, /not its real website \(sbi\.co\.in\)/);
});

test("the real bank domain is not a lookalike", () => {
  assert.deepEqual(ids("Login at https://www.onlinesbi.sbi to see your statement."), []);
  assert.deepEqual(ids("Your Amazon order ships today: https://www.amazon.in/orders"), []);
});

test("receiving money never needs a PIN", () => {
  assert.equal(RedFlags.analyse("You will receive Rs 5000 refund. Enter your UPI PIN to receive it.").level, "scam");
  assert.ok(ids("Scan the QR code to receive your cashback of 999").includes("receive_needs_pin"));
});

test("digital arrest, parcel and secrecy patterns", () => {
  const msg = "This is CBI. A parcel in your name was seized with drugs. You are under digital arrest. Do not tell anyone.";
  assert.deepEqual(ids(msg).sort(), ["authority", "parcel", "secrecy"]);
  assert.equal(RedFlags.analyse(msg).level, "scam");
});

test("Hindi messages are checked too", () => {
  const msg = "आपका बिजली कनेक्शन आज रात काट दिया जाएगा। तुरंत इस नंबर पर कॉल करें।";
  assert.deepEqual(ids(msg).sort(), ["account_threat", "urgency"]);
  assert.equal(RedFlags.analyse(msg).level, "suspicious");
});

test("task jobs, investment promises, remote access and APKs", () => {
  assert.ok(ids("Part time job! Earn ₹3000 per day by liking YouTube videos. Join Telegram").includes("task_job"));
  assert.ok(ids("Guaranteed returns, double your money in 30 days").includes("investment"));
  assert.equal(RedFlags.analyse("Please install AnyDesk so our support team can help").level, "scam");
  assert.equal(RedFlags.analyse("Download the bill app: http://bescom-pay.top/bill.apk").level, "scam");
});

test("short links and bare IP addresses", () => {
  assert.ok(ids("Track it: bit.ly/3xYzAb").includes("short_link"));
  assert.ok(ids("Verify at http://103.21.44.9/verify").includes("ip_link"));
});

test("an ordinary message is safe and has no flags", () => {
  const result = RedFlags.analyse("Hi beta, reached Pune safely. Will call you at 8. Rs.500 sent for books.");
  assert.equal(result.level, "safe");
  assert.deepEqual(result.flags, []);
});

test("a real OTP delivery is not flagged, but asking for the OTP is", () => {
  assert.deepEqual(ids("482913 is your OTP to log in to Swiggy. It is valid for 10 minutes. Do not share it with anyone."), []);
  assert.ok(ids("Share the OTP received to complete verification.").includes("secret_request"));
  assert.ok(ids("Please send me the OTP you just got").includes("secret_request"));
  assert.ok(ids("अपना ओटीपी बताएं ताकि रिफंड मिल सके").includes("secret_request"));
  assert.deepEqual(ids("Never share your PIN with anyone."), []);
});

test("an a/c abbreviation counts as an account", () => {
  assert.ok(ids("Your HDFC a/c XX4521 is blocked").includes("account_threat"));
});

test("the model can raise the risk but never lower it", () => {
  assert.equal(RedFlags.combine("scam", "safe"), "scam");
  assert.equal(RedFlags.combine("safe", "suspicious"), "suspicious");
  assert.equal(RedFlags.combine("suspicious", null), "suspicious");
});

test("Remote Config rules add checks, and a broken pattern is ignored", () => {
  const extra = { rules: [{ id: "fastag", weight: 2, pattern: "fastag[^.]{0,30}recharge", en: "FASTag recharge lure." }, { id: "bad", pattern: "(", en: "x" }], shorteners: ["sus.link"] };
  const result = RedFlags.analyse("Your FASTag recharge failed, pay at sus.link/f", extra);
  assert.deepEqual(result.flags.map((f) => f.id).sort(), ["fastag", "short_link"]);
});

test("the mask hides personal details and keeps links and amounts", () => {
  const msg = "Dear Ravi, your OTP is 482913. A/c XX4521 debited Rs.2,500. Call 9876543210 or mail help@fakebank.in. Card 4111 1111 1111 1111. Aadhaar 1234 5678 9012. PAN ABCDE1234F. Pay to ravi.k@okaxis. Visit http://sbi-kyc.xyz/u?id=99887766";
  const { masked, count, kinds } = PrivacyMask.mask(msg);
  for (const secret of ["482913", "4521", "9876543210", "help@fakebank.in", "4111", "1234 5678 9012", "ABCDE1234F", "ravi.k@"]) {
    assert.ok(!masked.includes(secret), secret);
  }
  assert.ok(masked.includes("http://sbi-kyc.xyz/u?id=99887766"));
  assert.ok(masked.includes("Rs.2,500"));
  assert.ok(masked.includes("[UPI-ID]@okaxis"));
  assert.equal(count, 8);
  assert.deepEqual(kinds.sort(), ["[AADHAAR]", "[ACCOUNT]", "[CARD]", "[EMAIL]", "[OTP]", "[PAN]", "[PHONE]", "[UPI-ID]"]);
});
