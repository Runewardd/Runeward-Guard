const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { readFileSync } = require("node:fs");
const { runInNewContext } = require("node:vm");
const { join } = require("node:path");

function harness() {
  const listeners = {};
  const sent = [];
  const event = (name) => ({ addListener(callback) { listeners[name] = callback; } });
  const chrome = {
    runtime: {
      onMessage: event("message"),
      sendNativeMessage(_host, message, reply) {
        sent.push(message);
        if (reply) reply({ ok: true });
      },
    },
    webRequest: {
      onBeforeRequest: event("before"),
      onCompleted: event("completed"),
      onErrorOccurred: event("error"),
      onBeforeRedirect: event("redirect"),
    },
  };
  const crypto = { subtle: { async digest(_algorithm, bytes) {
    return Uint8Array.from(createHash("sha256").update(Buffer.from(bytes)).digest()).buffer;
  } } };
  runInNewContext(readFileSync(join(__dirname, "background.js"), "utf8"), {
    chrome, crypto, URL, ArrayBuffer, Uint8Array, Date, Set, Map, Number,
  });
  return { listeners, sent };
}

function attach(listeners, bytes) {
  const digest = createHash("sha256").update(bytes).digest("hex");
  listeners.message({ kind: "file_attach", digest }, {
    origin: "https://chatgpt.com", tab: { id: 3 },
  }, () => {});
  return digest;
}

test("reports exact request bytes only after a successful HTTP completion", async () => {
  const { listeners, sent } = harness();
  const image = Buffer.from("synthetic image bytes");
  const digest = attach(listeners, image);
  listeners.before({
    requestId: "1", tabId: 3, method: "POST",
    url: "https://chatgpt.com/upload", initiator: "https://chatgpt.com",
    requestBody: { raw: [{ bytes: Uint8Array.from(image).buffer }] },
  });
  listeners.completed({ requestId: "1", statusCode: 201 });
  await new Promise(setImmediate);
  assert.equal(sent.length, 2);
  assert.equal(sent[1].kind, "image_request_completed");
  assert.equal(sent[1].digest, digest);
});

test("does not report a failed or nonmatching request", async () => {
  const { listeners, sent } = harness();
  attach(listeners, Buffer.from("synthetic image bytes"));
  listeners.before({
    requestId: "2", tabId: 3, method: "POST",
    url: "https://chatgpt.com/upload", initiator: "https://chatgpt.com",
    requestBody: { raw: [{ bytes: Uint8Array.from(Buffer.from("other bytes")).buffer }] },
  });
  listeners.completed({ requestId: "2", statusCode: 200 });
  await new Promise(setImmediate);
  assert.equal(sent.length, 1);
});

test("does not treat HTTP failure as a completed image upload", async () => {
  const { listeners, sent } = harness();
  const image = Buffer.from("synthetic image bytes");
  attach(listeners, image);
  listeners.before({
    requestId: "3", tabId: 3, method: "PUT",
    url: "https://chatgpt.com/upload", initiator: "https://chatgpt.com",
    requestBody: { raw: [{ bytes: Uint8Array.from(image).buffer }] },
  });
  listeners.completed({ requestId: "3", statusCode: 500 });
  await new Promise(setImmediate);
  assert.equal(sent.length, 1);
});
