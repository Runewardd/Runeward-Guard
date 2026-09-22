const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { readFileSync } = require("node:fs");
const { runInNewContext } = require("node:vm");
const { join } = require("node:path");

function harness() {
  const listeners = {};
  const messages = [];
  const document = { addEventListener(name, callback) { listeners[name] = callback; } };
  const chrome = { runtime: { sendMessage(message) { messages.push(message); } } };
  const crypto = { subtle: { async digest(_algorithm, bytes) {
    return Uint8Array.from(createHash("sha256").update(Buffer.from(bytes)).digest()).buffer;
  } } };
  runInNewContext(readFileSync(join(__dirname, "content.js"), "utf8"), {
    document, chrome, crypto, Uint8Array, Array, HTMLInputElement: class {},
  });
  return { listeners, messages };
}

test("observes a clipboard-only image without forwarding its bytes", async () => {
  const { listeners, messages } = harness();
  const bytes = Buffer.from("synthetic clipboard image");
  const file = { type: "image/png", size: bytes.length,
    async arrayBuffer() { return Uint8Array.from(bytes).buffer; } };
  listeners.paste({ isTrusted: true, clipboardData: {
    items: [{ kind: "file", getAsFile: () => file }], files: [],
  } });
  await new Promise(setImmediate);
  assert.equal(messages.length, 1);
  assert.equal(messages[0].kind, "image_paste");
  assert.equal(messages[0].digest, createHash("sha256").update(bytes).digest("hex"));
  assert.equal(JSON.stringify(messages).includes("synthetic clipboard image"), false);
});

test("ignores synthetic paste events", async () => {
  const { listeners, messages } = harness();
  listeners.paste({ isTrusted: false, clipboardData: { items: [] } });
  await new Promise(setImmediate);
  assert.equal(messages.length, 0);
});
