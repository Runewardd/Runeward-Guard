const maxImageBytes = 32 * 1024 * 1024;
const imageTypes = new Set(["image/png", "image/jpeg", "image/heic", "image/webp"]);

async function observeFile(file, kind = "file_attach") {
  if (!file || !imageTypes.has(file.type) || file.size > maxImageBytes) return;
  try {
    const bytes = await file.arrayBuffer();
    const hash = await crypto.subtle.digest("SHA-256", bytes);
    const digest = Array.from(new Uint8Array(hash), (byte) =>
      byte.toString(16).padStart(2, "0")).join("");
    chrome.runtime.sendMessage({ kind, digest });
  } catch {
    // Browser observation is best effort; never expose file bytes to page scripts.
  }
}

document.addEventListener("change", (event) => {
  if (!event.isTrusted) return;
  const input = event.target;
  if (input instanceof HTMLInputElement && input.type === "file") {
    for (const file of input.files || []) void observeFile(file);
  }
}, true);

document.addEventListener("drop", (event) => {
  if (!event.isTrusted) return;
  for (const file of event.dataTransfer?.files || []) void observeFile(file);
}, true);

document.addEventListener("paste", (event) => {
  if (!event.isTrusted) return;
  const items = Array.from(event.clipboardData?.items || []);
  if (items.length) {
    for (const item of items) {
      if (item.kind === "file") void observeFile(item.getAsFile(), "image_paste");
    }
  } else {
    for (const file of event.clipboardData?.files || []) {
      void observeFile(file, "image_paste");
    }
  }
}, true);
