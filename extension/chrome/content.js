const maxImageBytes = 32 * 1024 * 1024;
const imageTypes = new Set(["image/png", "image/jpeg", "image/heic", "image/webp"]);

async function observeFile(file) {
  if (!file || !imageTypes.has(file.type) || file.size > maxImageBytes) return;
  try {
    const bytes = await file.arrayBuffer();
    const hash = await crypto.subtle.digest("SHA-256", bytes);
    const digest = Array.from(new Uint8Array(hash), (byte) =>
      byte.toString(16).padStart(2, "0")).join("");
    chrome.runtime.sendMessage({ kind: "file_attach", digest });
  } catch {
    // Browser observation is best effort; never expose file bytes to page scripts.
  }
}

document.addEventListener("change", (event) => {
  const input = event.target;
  if (input instanceof HTMLInputElement && input.type === "file") {
    for (const file of input.files || []) void observeFile(file);
  }
}, true);

document.addEventListener("drop", (event) => {
  for (const file of event.dataTransfer?.files || []) void observeFile(file);
}, true);

document.addEventListener("paste", (event) => {
  for (const file of event.clipboardData?.files || []) void observeFile(file);
}, true);
