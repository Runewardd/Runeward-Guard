# Why the privileged macOS sensor needs Apple approval

The unprivileged Guard monitor can observe files in a chosen folder and an opt-in browser extension. It cannot reliably see system-wide process execution, direct Keychain database access, or all applications that use Security.framework.

Apple's [Endpoint Security API](https://developer.apple.com/documentation/endpointsecurity) is the supported path for system-wide process and file event monitoring. A client must carry the restricted [`com.apple.developer.endpoint-security.client` entitlement](https://developer.apple.com/documentation/BundleResources/Entitlements/com.apple.developer.endpoint-security.client), which Apple says must be requested. A distributed Guard sensor would also need an app/system-extension package, code signing, provisioning, user or MDM approval, and the relevant privacy permission. An ordinary unsigned Rust binary cannot opt itself into that entitlement.

Guard now has a Rust `guard-sensor` collector for **metadata only**: process exec/fork/exit and file-open notifications. Its platform-neutral correlation engine can be exercised without an entitlement:

```sh
cargo build --locked --bin guard-sensor
./target/debug/guard-sensor replay < examples/sensor-events.ndjson
```

`guard-sensor live` subscribes to Apple's Endpoint Security notification events on macOS. It requires a root-owned, signed and entitled installation with Full Disk Access; a plain local Cargo build cannot activate it. The current repository does **not** include a signed system-extension host app or an installer. Provisioning, activation, update, recovery, and uninstallation remain separate release work. Do not disable System Integrity Protection as a workaround.

The sensor never reads Keychain item values. It emits a low-confidence finding only when a process named like Codex, Claude, or Copilot (or a tracked descendant) **directly opens** a Keychain file. Names are spoofable and process starts before the sensor may be unknown. A Keychain database open by `securityd` is deliberately not attributed to a client: it does not identify which app requested an item. None of these events proves disclosure to an AI provider. Findings omit file paths, command arguments, and environment variables. If the sensor's bounded queue overflows, it reports dropped observations on stderr rather than implying full coverage.

You do not need the entitlement to build or try the current unprivileged monitor or the sensor replay. To run and ship the live sensor, the maintainer will need an Apple Developer Program team and an approved Endpoint Security entitlement. Packaging and signing must use that team's identity and a system-extension host app.
