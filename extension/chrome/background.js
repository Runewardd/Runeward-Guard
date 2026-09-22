const allowedOrigins = new Set(["https://chatgpt.com", "https://claude.ai"]);
const digestPattern = /^[a-f0-9]{64}$/;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  let origin;
  try {
    origin = sender.origin || new URL(sender.url).origin;
  } catch {
    sendResponse({ ok: false });
    return false;
  }
  if (!allowedOrigins.has(origin) ||
      !["file_attach", "image_paste"].includes(message?.kind) ||
      !digestPattern.test(message.digest)) {
    sendResponse({ ok: false });
    return false;
  }

  chrome.runtime.sendNativeMessage(
    "com.runeward.guard",
    { kind: message.kind, digest: message.digest, destination: origin },
    (reply) => {
      sendResponse({ ok: !chrome.runtime.lastError && reply?.ok === true });
    },
  );
  return true;
});
