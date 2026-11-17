# 🛡️ Kavach — private scam check for SMS and WhatsApp

**Live:** https://sarveshkh786.github.io/kavach/

Paste a suspicious SMS, WhatsApp message or email, or drop a screenshot. Kavach tells
you whether it is a scam, why, and what to do, in plain English with Hindi red flags.
The messages people receive are private, so Kavach checks them **on your own device**
with Gemini Nano through **Firebase AI Logic hybrid inference**, and uses the cloud
only as a fallback, after masking personal details.

## Why

Fake KYC alerts, "digital arrest" calls, power-cut threats, task jobs and lookalike bank
links reach millions of Indians every day. The people most at risk are the least likely
to know what a lookalike domain is, and the message they want to check often contains
their OTP, account number or name. Sending it to a cloud AI to ask "is this a scam?" is
itself a privacy risk. Kavach keeps it on the device.

## How it uses Firebase AI Logic

| Piece | How Kavach uses it |
| --- | --- |
| **Hybrid inference** | Two models from `getGenerativeModel`: `InferenceMode.ONLY_ON_DEVICE` (Gemini Nano via Chrome's Prompt API) and `InferenceMode.ONLY_IN_CLOUD` (`gemini-3.5-flash-lite`). Kavach routes between them itself instead of using `PREFER_ON_DEVICE`, because the SDK's automatic fallback would send the full private message to the cloud. |
| **Privacy-preserving fallback** | Before any cloud call, [`src/mask.js`](src/mask.js) replaces OTPs, account, card, Aadhaar, PAN and phone numbers, emails and UPI names with labels, while keeping links and amounts, which show the scam. The result shows exactly what was sent. |
| **Three user-chosen modes** | **Private** (device only; nothing is ever sent), **Auto** (device first, masked cloud if needed) and **Cloud** (masked, for phones and older PCs). |
| **Multimodal on device** | Screenshots (PNG/JPEG) go to Gemini Nano as image input. A screenshot can't be masked, so it is never sent to the cloud without its own click. |
| **Structured output** | A JSON Schema via `onDeviceParams.promptOptions.responseConstraint` on the device, and `responseSchema` in the cloud: verdict, scam type, explanation, red flags, steps. |
| **`inferenceSource`** | Every result shows where it ran (`on_device` or `in_cloud`) and how long it took. |
| **`initializeDeviceModel`** | Called on the Check click, with download progress shown. |
| **App Check** | reCAPTCHA Enterprise (Fraud Defense) protects the Gemini API from abuse (enforced for AI Logic). |
| **Remote Config** | A scam-alert banner and extra red-flag rules (for example fake e-challan and loan-app patterns) and link shorteners update without a new release. Template: [`firebase/remoteconfig.template.json`](firebase/remoteconfig.template.json). |

## Code checks the AI can't overrule

[`src/rules.js`](src/rules.js) runs first, on every message, offline, in every mode. It
finds OTP/PIN/CVV requests (but not real OTP deliveries that say "do not share"), "enter
PIN to receive money", account-block threats, urgency, prizes, fake police/CBI and
"digital arrest", parcel scams, remote-access apps, APK installs, task jobs, guaranteed
returns, secrecy, short links, bare-IP links, risky domain endings, and lookalike links
that use a bank or government name (SBI, HDFC, Aadhaar, EPFO, Parivahan and more) on
the wrong domain. Each finding is in English and Hindi. **The AI can raise the risk but
never lower it below what the code found.**

## Works offline

A service worker caches the app. With Gemini Nano downloaded, Kavach checks messages
with no network at all.

## Run it

```shell
npm install
npm run build      # bundles src/ into dist/app.js with esbuild
npm test           # Node tests for the red flags and the privacy mask
python3 -m http.server 8080
```

For on-device inference use Chrome on a desktop (version 139 or newer) and enable
`chrome://flags/#prompt-api-for-gemini-nano-multimodal-input`. On `localhost`, App
Check prints a debug token to register in the Firebase console.

## Files

```text
index.html, styles.css, icon.svg, manifest.webmanifest, sw.js   the app (PWA)
src/main.js     page controller: code checks, routing, results
src/ai.js       Firebase app, App Check, Remote Config, the two models, structured output
src/rules.js    red-flag engine (English + Hindi)
src/mask.js     privacy mask for the cloud fallback
src/config.js   Firebase web config (public identifiers) and reCAPTCHA site key
tests/          Node tests
firebase/       Remote Config template
dist/app.js     built bundle
```

## Limits

- Kavach is a helper, not a guarantee. When in doubt, don't click, don't pay, and call
  the bank or office on its official number.
- Names in a message are not masked; numbers and IDs are.
- Gemini Nano runs only in desktop Chrome today; phones use the masked cloud path.
- Reporting links: [Chakshu on Sanchar Saathi](https://sancharsaathi.gov.in/sfc/) for a
  suspicious message; **1930** or [cybercrime.gov.in](https://cybercrime.gov.in) if money
  was lost.

## Built for

[#BuildHybridAI 2026](https://firebasehybridaihackathon.devpost.com/). Built during the
submission period with help from an AI coding assistant (Claude). Licensed Apache-2.0.
