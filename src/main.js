// Kavach page controller: reads the message, runs the code checks, routes the AI check
// (device first, masked cloud only as a fallback), and shows the combined result.
import { isConfigured } from "./config.js";
import { PrivacyMask } from "./mask.js";
import { RedFlags } from "./rules.js";

const $ = (selector) => document.querySelector(selector);

/** Sample messages, so anyone can try Kavach in one click. All are made up. */
export const SAMPLES = {
  kyc: "Dear Customer, your SBI YONO account will be BLOCKED today due to pending KYC. Update PAN immediately: http://sbi-yono-kyc.top/update . Share the OTP received to complete verification.",
  arrest: "This is Inspector Sharma, Mumbai Cyber Cell. A FedEx parcel in your name was seized with illegal drugs. You are under digital arrest. Join the video call on WhatsApp now and do not tell anyone, or a warrant will be issued.",
  task: "Hi! Part time job from home. Earn ₹3,000 per day by liking YouTube videos. No fees. Contact HR on Telegram: t.me/earnfast_hr",
  power: "Dear consumer, your electricity connection will be disconnected tonight at 9.30 pm because your last month bill was not updated. Please immediately call our officer 9876543210.",
  otp: "482913 is your OTP to log in to Swiggy. It is valid for 10 minutes. Do not share it with anyone.",
  family: "Beta, reached Nagpur safely. Train was 2 hours late. Will call you after dinner. Eat on time!",
};

/**
 * The page.
 */
export class KavachPage {
  /**
   * Create the page controller.
   *
   * :param ai: A KavachAI, or null when Firebase is not set up.
   */
  constructor(ai) {
    this.ai = ai;
    this.extras = { alert: "", rules: [], shorteners: [] };
    this.image = null;
    this.lang = "en";
    this.last = null;
  }

  /**
   * Connect the page's controls and show the device status.
   */
  async start() {
    for (const button of document.querySelectorAll("[data-sample]")) {
      button.addEventListener("click", this.useSample.bind(this, button.dataset.sample));
    }
    $("#check").addEventListener("click", this.check.bind(this));
    $("#screenshot").addEventListener("change", this.pickImage.bind(this));
    $("#clear-image").addEventListener("click", this.clearImage.bind(this));
    $("#lang-toggle").addEventListener("click", this.toggleLanguage.bind(this));
    $("#send-image-cloud").addEventListener("click", this.sendImageToCloud.bind(this));
    $("#message").addEventListener("paste", this.pasteImage.bind(this));
    if (!this.ai) {
      $("#setup-note").hidden = false;
    }
    await this.showDeviceStatus();
    if (this.ai) {
      this.extras = await this.ai.loadRemoteExtras();
      if (this.extras.alert) {
        $("#alert-text").textContent = this.extras.alert;
        $("#alert").hidden = false;
      }
    }
  }

  /**
   * Show whether this browser has an on-device model.
   */
  async showDeviceStatus() {
    const { KavachAI } = await import("./ai.js");
    const availability = await KavachAI.deviceAvailability();
    const pill = $("#device-status");
    const labels = {
      available: "🔒 On-device AI ready: messages stay on this device",
      downloadable: "🔒 On-device AI available: downloads on first check",
      downloading: "🔒 On-device AI downloading…",
      unavailable: "☁️ No on-device AI in this browser: AI checks use the cloud, with personal details masked",
    };
    pill.textContent = labels[availability] || labels.unavailable;
    pill.dataset.state = availability === "unavailable" ? "cloud" : "device";
    this.availability = availability;
  }

  /**
   * Put a sample message in the box.
   *
   * :param key: The sample's key.
   */
  useSample(key) {
    this.clearImage();
    $("#message").value = SAMPLES[key];
    $("#message").focus();
  }

  /**
   * Keep a screenshot the visitor chose.
   *
   * :param event: The change event of the file input.
   */
  pickImage(event) {
    const file = event.target.files[0];
    if (file) {
      this.setImage(file);
    }
  }

  /**
   * Keep a screenshot pasted into the message box.
   *
   * :param event: The paste event.
   */
  pasteImage(event) {
    const item = [...(event.clipboardData?.items || [])].find((entry) => entry.type.startsWith("image/"));
    if (item) {
      event.preventDefault();
      this.setImage(item.getAsFile());
    }
  }

  /**
   * Show and keep a screenshot. Only PNG and JPEG work on the device.
   *
   * :param file: The image file.
   */
  setImage(file) {
    if (!["image/png", "image/jpeg"].includes(file.type)) {
      $("#image-note").textContent = "Use a PNG or JPEG screenshot.";
      return;
    }
    this.image = file;
    $("#image-preview").src = URL.createObjectURL(file);
    $("#image-box").hidden = false;
    $("#image-note").textContent = "";
  }

  /**
   * Forget the screenshot.
   */
  clearImage() {
    this.image = null;
    $("#image-box").hidden = true;
    $("#screenshot").value = "";
  }

  /**
   * Read the privacy mode the visitor chose.
   *
   * :return: "private", "auto" or "cloud".
   */
  static mode() {
    return document.querySelector('input[name="mode"]:checked').value;
  }

  /**
   * Turn an image file into a Firebase AI Logic inline-data part.
   *
   * :param file: The image.
   * :return: The part.
   */
  static async imagePart(file) {
    const data = await new Promise((resolve) => {
      const reader = new FileReader();
      reader.onloadend = () => resolve(String(reader.result).split(",")[1]);
      reader.readAsDataURL(file);
    });
    return { inlineData: { data, mimeType: file.type } };
  }

  /**
   * Build the prompt: the message, and the code's findings as hints.
   *
   * :param text: The message (masked for the cloud).
   * :param flags: The code's flags.
   * :return: The prompt text.
   */
  static prompt(text, flags) {
    const hints = flags.length ? `\nKavach's code checks already found: ${flags.map((flag) => flag.id).join(", ")}.` : "";
    return text
      ? `Message to check:\n"""\n${text}\n"""${hints}`
      : "Read the message in this screenshot and check it.";
  }

  /**
   * Run the whole check: code first, then the AI by the chosen route.
   */
  async check() {
    const text = $("#message").value.trim();
    if (!text && !this.image) {
      $("#input-note").textContent = "Paste a message or add a screenshot first.";
      return;
    }
    $("#input-note").textContent = "";
    const code = RedFlags.analyse(text, this.extras);
    const run = { text, code, ai: null, route: null, masked: null, error: null, imagePending: false };
    this.last = run;
    this.render(run);
    if (!this.ai) {
      run.error = "AI check is not set up on this copy of Kavach. The code checks above still ran.";
      this.render(run);
      return;
    }
    $("#check").disabled = true;
    try {
      await this.runAI(run);
    } finally {
      $("#check").disabled = false;
      this.render(run);
    }
  }

  /**
   * Route the AI check: on the device when possible; otherwise, in auto or cloud mode,
   * the cloud with personal details masked. A screenshot is never sent to the cloud
   * without its own click, because it cannot be masked.
   *
   * :param run: The check in progress, updated in place.
   */
  async runAI(run) {
    const mode = KavachPage.mode();
    if (mode !== "cloud" && this.availability !== "unavailable") {
      try {
        this.status("Preparing the on-device model…");
        await this.ai.prepareDevice((value) => this.status(`Downloading the on-device model: ${Math.round(value * 100)}%`));
        this.status("Checking on this device…");
        // The small on-device model tends to echo hint ids back, so it gets the message
        // alone; the code's findings are shown beside its answer anyway.
        const parts = [KavachPage.prompt(run.text, [])];
        if (this.image) {
          parts.push(await KavachPage.imagePart(this.image));
        }
        run.ai = await this.ai.askDevice(parts);
        run.route = "device";
        this.addTranscriptFlags(run);
        return;
      } catch (error) {
        console.warn("On-device check failed", error);
        if (mode === "private") {
          run.error = "Private mode: the on-device model could not run here, so nothing was sent anywhere. The code checks above still ran.";
          return;
        }
      }
    } else if (mode === "private") {
      run.error = "Private mode needs Chrome's on-device model (Chrome on a computer). Nothing was sent anywhere. The code checks above still ran.";
      return;
    }
    if (this.image && mode !== "cloud") {
      run.imagePending = true;
      if (!run.text) {
        return;
      }
    }
    await this.askCloud(run, mode === "cloud" && this.image);
  }

  /**
   * Ask the cloud model with the masked message.
   *
   * :param run: The check in progress.
   * :param withImage: True to include the screenshot.
   */
  async askCloud(run, withImage) {
    run.masked = PrivacyMask.mask(run.text);
    this.status("Checking in the cloud, with personal details masked…");
    try {
      const parts = [KavachPage.prompt(run.masked.masked, run.code.flags)];
      if (withImage) {
        parts.push(await KavachPage.imagePart(this.image));
        run.imageSent = true;
      }
      run.ai = await this.ai.askCloud(parts);
      run.route = "cloud";
      run.imagePending = false;
      this.addTranscriptFlags(run);
    } catch (error) {
      console.warn("Cloud check failed", error);
      run.error = "The AI check could not reach the cloud. The code checks above still ran.";
    }
  }

  /**
   * Send the screenshot to the cloud after the visitor clicks for it.
   */
  async sendImageToCloud() {
    const run = this.last;
    if (!run || !this.image) {
      return;
    }
    $("#check").disabled = true;
    try {
      await this.askCloud(run, true);
    } finally {
      $("#check").disabled = false;
      this.render(run);
    }
  }

  /**
   * Run the code checks on text the model read from a screenshot too.
   *
   * :param run: The check in progress.
   */
  addTranscriptFlags(run) {
    const transcript = run.ai?.answer.transcript;
    if (transcript && !run.text) {
      run.code = RedFlags.analyse(transcript, this.extras);
    }
  }

  /**
   * Show a progress line.
   *
   * :param text: The line.
   */
  status(text) {
    $("#progress").textContent = text;
    $("#progress").hidden = false;
  }

  /**
   * Switch the code's findings between English and Hindi.
   */
  toggleLanguage() {
    this.lang = this.lang === "en" ? "hi" : "en";
    $("#lang-toggle").textContent = this.lang === "en" ? "हिन्दी में देखें" : "Show in English";
    if (this.last) {
      this.render(this.last);
    }
  }

  /**
   * Show a check's result.
   *
   * :param run: The check.
   */
  render(run) {
    const finalLevel = RedFlags.combine(run.code.level, run.ai?.answer.verdict || null);
    const box = $("#result");
    box.hidden = false;
    box.dataset.level = finalLevel;
    const titles = {
      scam: ["Likely a scam", "यह ठगी का मैसेज लगता है"],
      suspicious: ["Be careful", "सावधान रहें"],
      safe: ["Looks safe", "सुरक्षित लगता है"],
    };
    $("#verdict").textContent = titles[finalLevel][0];
    $("#verdict-hi").textContent = titles[finalLevel][1];
    $("#scam-type").textContent = run.ai?.answer.scam_type && run.ai.answer.scam_type !== "None" ? run.ai.answer.scam_type : "";
    $("#progress").hidden = true;

    const source = $("#source");
    if (run.route === "device") {
      source.textContent = `🔒 AI check ran on this device (Gemini Nano, ${run.ai.ms} ms). Nothing left your computer.`;
      source.dataset.route = "device";
    } else if (run.route === "cloud") {
      const hidden = run.masked.count ? `${run.masked.count} personal detail${run.masked.count === 1 ? "" : "s"} masked first` : "no personal details found to mask";
      source.textContent = `☁️ AI check ran in the cloud (${run.ai.ms} ms): ${hidden}${run.imageSent ? "; your screenshot was sent as you asked" : ""}.`;
      source.dataset.route = "cloud";
    } else {
      source.textContent = "Code checks only.";
      source.dataset.route = "code";
    }
    $("#sdk-source").textContent = run.ai ? `Firebase AI Logic inferenceSource: ${run.ai.source}` : "";

    $("#explanation").textContent = run.ai?.answer.explanation || "";
    KavachPage.fillList($("#todo"), run.ai?.answer.what_to_do?.length ? run.ai.answer.what_to_do : KavachPage.defaultSteps(finalLevel));
    const codeIds = new Set(run.code.flags.map((flag) => flag.id));
    const aiFlags = (run.ai?.answer.red_flags || []).filter((flag) => !codeIds.has(flag) && !/^[a-z]+(_[a-z]+)+$/.test(flag));
    KavachPage.fillList($("#ai-flags"), aiFlags);
    $("#ai-flags-box").hidden = !aiFlags.length;

    const codeList = $("#code-flags");
    codeList.replaceChildren();
    for (const flag of run.code.flags) {
      const item = document.createElement("li");
      item.textContent = this.lang === "en" ? flag.en : flag.hi;
      item.setAttribute("lang", this.lang);
      item.dataset.weight = String(flag.weight);
      codeList.append(item);
    }
    $("#code-none").hidden = run.code.flags.length > 0;
    $("#code-count").textContent = String(run.code.flags.length);

    $("#masked-box").hidden = !run.masked;
    $("#masked-text").textContent = run.masked ? run.masked.masked : "";
    $("#image-cloud-box").hidden = !run.imagePending;
    $("#ai-error").textContent = run.error || "";
    $("#ai-error").hidden = !run.error;
    $("#report").hidden = finalLevel === "safe";
  }

  /**
   * Steps to show when the AI gave none.
   *
   * :param level: The final level.
   * :return: The steps.
   */
  static defaultSteps(level) {
    if (level === "safe") {
      return ["Nothing risky found. Still, never share an OTP or PIN with anyone."];
    }
    return [
      "Do not click links, call numbers or install apps from this message.",
      "Never share an OTP, PIN, CVV or password.",
      "Check directly with the bank or office using the number on its official website or your card.",
    ];
  }

  /**
   * Fill a list element with text items.
   *
   * :param list: The ul or ol.
   * :param items: The texts.
   */
  static fillList(list, items) {
    list.replaceChildren();
    for (const text of items) {
      const item = document.createElement("li");
      item.textContent = text;
      list.append(item);
    }
  }
}

/**
 * Start the page: Firebase only when it is configured, so the code checks always work.
 */
async function boot() {
  let ai = null;
  if (isConfigured()) {
    try {
      const { KavachAI } = await import("./ai.js");
      ai = KavachAI.start();
    } catch (error) {
      console.error("Firebase could not start", error);
    }
  }
  const page = new KavachPage(ai);
  globalThis.kavach = page;
  await page.start();
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("./sw.js").catch(() => {});
  }
}

if (typeof window !== "undefined" && document.querySelector("#check")) {
  boot();
}
