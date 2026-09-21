# Experimental macOS screenshot monitoring

This path gives Guard two real, opt-in observations: a newly seen image file with macOS screenshot metadata in a folder you select, and image selection/drop/paste on `chatgpt.com` or `claude.ai` in Google Chrome. A matching SHA-256 digest produces a warning. It does **not** prove upload completion or cover all screenshot locations, browsers, or desktop apps.

## Build and run

Build both Rust binaries from this repository:

```sh
cargo build --release --locked
```

Start the monitor with the **absolute path** to your screenshot folder. It baselines existing images at startup, then checks new or changed image files every two seconds. The folder is non-recursive; macOS file-access permissions may be needed for Desktop or another protected folder.

```sh
./target/release/guard monitor --dir /absolute/path/to/screenshots
```

Guard reads only image files up to 32 MiB in that folder and checks for the `com.apple.metadata:kMDItemIsScreenCapture` attribute. It hashes matching files locally and emits no image path or bytes in findings. A screenshot saved only to the clipboard will not be detected by the folder monitor.

## Connect Google Chrome

1. In `chrome://extensions`, enable Developer mode and load `extension/chrome` as an unpacked extension. Copy the extension's 32-letter ID.
2. In another terminal, run `./target/release/guard setup-chrome --extension-id YOUR_EXTENSION_ID --host-binary /absolute/path/to/target/release/guard-browser-host`. The command creates a private Guard host config and a user-level Chrome native-messaging manifest; it refuses to overwrite an existing one. These are the only installation files it writes.
3. Keep `guard monitor` running. Its default socket is `~/.runeward-guard/monitor.sock`, and `setup-chrome` points the native host to the same socket.
4. For a safe test, take a **non-sensitive** macOS screenshot into the watched folder, then select that file on ChatGPT or Claude without submitting a prompt. The monitor should emit `screenshot_selected_for_ai` with decision `warn`.

The content script hashes the selected image in browser memory and sends only its digest through [Chrome native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging). It does not read prompt text or transmit image bytes to Guard. Chrome may hand selected files to a site before you submit a message, so never use a real secret in a test. The extension has access only to the two host patterns listed in its manifest.

## What this does not cover

The monitor does not detect Keychain use by other processes. System-wide process/file observation needs a signed macOS Endpoint Security client with Apple's entitlement. Even then, Keychain calls served by `securityd` require careful attribution rather than treating a Keychain database open as proof that Codex, Claude, or Copilot received a password. See [the entitlement and sensor plan](endpoint-security.md).
