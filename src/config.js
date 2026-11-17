// Firebase web app settings. These identify the project; they are not secrets.
// Access to Firebase AI Logic is protected by App Check (reCAPTCHA v3) instead.
export const FIREBASE_CONFIG = {
  apiKey: "AIzaSyCOlkV-zPCsNyo6XhkDEr4xTuNwYjk5GYw",
  authDomain: "kavach-scam-check.firebaseapp.com",
  projectId: "kavach-scam-check",
  storageBucket: "kavach-scam-check.firebasestorage.app",
  messagingSenderId: "352363182443",
  appId: "1:352363182443:web:4f824543f3d6710a51f42e",
};

// reCAPTCHA (Fraud Defense / Enterprise) site key registered with Firebase App Check.
export const RECAPTCHA_SITE_KEY = "6LfLAiUuAAAAALYGj48NlC0hfQJ6NioXmwIqF9Sm";

// The cloud model used only when this device has no on-device model.
export const CLOUD_MODEL = "gemini-3.5-flash-lite";

/**
 * Tell whether the Firebase settings above have been filled in.
 *
 * :return: True when every value is set.
 */
export function isConfigured() {
  return !Object.values(FIREBASE_CONFIG).includes("FILL_ME") && RECAPTCHA_SITE_KEY !== "FILL_ME";
}
