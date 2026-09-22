const allowedOrigins = new Set(["https://chatgpt.com", "https://claude.ai"]);
const digestPattern = /^[a-f0-9]{64}$/;
const maxImageBytes = 32 * 1024 * 1024;
const maxAgeMs = 15 * 60 * 1000;
const recentByTab = new Map();
const pendingRequests = new Map();

function remember(tabId, origin, digest) {
  if (!Number.isInteger(tabId) || tabId < 0) return;
  if (!recentByTab.has(tabId) && recentByTab.size >= 128) {
    recentByTab.delete(recentByTab.keys().next().value);
  }
  const now = Date.now();
  const prior = (recentByTab.get(tabId) || []).filter((item) =>
    now - item.time <= maxAgeMs);
  prior.push({ origin, digest, time: now });
  recentByTab.set(tabId, prior.slice(-16));
}

function reportCompleted(requestId) {
  const pending = pendingRequests.get(requestId);
  if (!pending || !pending.completed || !pending.hashed) return;
  pendingRequests.delete(requestId);
  if (!pending.digest || pending.statusCode < 200 || pending.statusCode >= 300) return;
  chrome.runtime.sendNativeMessage("com.runeward.guard", {
    kind: "image_request_completed",
    digest: pending.digest,
    destination: pending.origin,
  });
}

async function matchRequestBody(details, candidates) {
  const chunks = details.requestBody?.raw || [];
  for (const chunk of chunks) {
    const bytes = chunk.bytes;
    if (!(bytes instanceof ArrayBuffer) || bytes.byteLength > maxImageBytes) continue;
    const hash = await crypto.subtle.digest("SHA-256", bytes);
    const digest = Array.from(new Uint8Array(hash), (byte) =>
      byte.toString(16).padStart(2, "0")).join("");
    if (candidates.has(digest)) return digest;
  }
  return null;
}

chrome.webRequest.onBeforeRequest.addListener((details) => {
  if (!["POST", "PUT"].includes(details.method)) return;
  const now = Date.now();
  for (const [id, pending] of pendingRequests) {
    if (now - pending.time > 60_000) pendingRequests.delete(id);
  }
  if (pendingRequests.size >= 128) return;
  let origin;
  try {
    origin = new URL(details.url).origin;
  } catch {
    return;
  }
  if (!allowedOrigins.has(origin) || details.initiator !== origin) return;
  const recent = (recentByTab.get(details.tabId) || []).filter((item) =>
    now - item.time <= maxAgeMs);
  recentByTab.set(details.tabId, recent);
  const candidates = new Set(recent.filter((item) => item.origin === origin)
    .map((item) => item.digest));
  if (!candidates.size || !details.requestBody?.raw?.length) return;
  const pending = { origin, digest: null, hashed: false, completed: false, statusCode: 0, time: now };
  pendingRequests.set(details.requestId, pending);
  void matchRequestBody(details, candidates).then((digest) => {
    pending.digest = digest;
    pending.hashed = true;
    reportCompleted(details.requestId);
  }).catch(() => {
    pendingRequests.delete(details.requestId);
  });
}, { urls: ["https://chatgpt.com/*", "https://claude.ai/*"] }, ["requestBody"]);

chrome.webRequest.onCompleted.addListener((details) => {
  const pending = pendingRequests.get(details.requestId);
  if (!pending) return;
  pending.completed = true;
  pending.statusCode = details.statusCode;
  reportCompleted(details.requestId);
}, { urls: ["https://chatgpt.com/*", "https://claude.ai/*"] });

chrome.webRequest.onErrorOccurred.addListener((details) => {
  pendingRequests.delete(details.requestId);
}, { urls: ["https://chatgpt.com/*", "https://claude.ai/*"] });

chrome.webRequest.onBeforeRedirect.addListener((details) => {
  pendingRequests.delete(details.requestId);
}, { urls: ["https://chatgpt.com/*", "https://claude.ai/*"] });

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

  remember(sender.tab?.id, origin, message.digest);

  chrome.runtime.sendNativeMessage(
    "com.runeward.guard",
    { kind: message.kind, digest: message.digest, destination: origin },
    (reply) => {
      sendResponse({ ok: !chrome.runtime.lastError && reply?.ok === true });
    },
  );
  return true;
});
