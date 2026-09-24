# Device management foundation

Guard now has a local device identity and health envelope that can be tested before a fleet control plane is trusted with endpoint data. This is the first device-management slice, not remote enrollment yet.

## Initialize one test device

Build Guard, choose a private absolute state directory, and initialize the device once:

```sh
cargo build --locked
install -d -m 700 "$HOME/.runeward-guard/device"
./target/debug/guard device-init \
  --state-dir "$HOME/.runeward-guard/device" \
  --name "Developer Mac"
```

`device-init` creates an owner-only `device.json` with a random installation identifier. Re-running it returns the existing identity; it does not rotate or silently replace that identity.

Produce the metadata-only status document that a future fleet client will authenticate and send:

```sh
./target/debug/guard device-status \
  --state-dir "$HOME/.runeward-guard/device" \
  --dir "$HOME/Desktop"
```

The document includes the installation identity, Guard version, platform, and coverage health. It does not include prompts, screenshot contents, screenshot paths, browser history, secrets, or audit-log records.

## Security boundary

The identity file is not a fleet credential. Guard requires an absolute, owner-only state directory and an owner-only regular identity file, and refuses relaxed permissions or symlinks. A later enrollment exchange must issue a separate revocable device credential over authenticated TLS; copying `device.json` must not authorize a device.

Before fleet rollout, add:

1. A short-lived, single-use enrollment token created by an administrator.
2. Server identity pinning or a normal trusted TLS certificate.
3. A per-device key generated and retained on the endpoint, preferably backed by the platform key store.
4. Authenticated policy bundles with version and rollback protection.
5. Bounded status and finding upload with offline queuing and backpressure.
6. Device revocation, re-enrollment, recovery, and auditable administrator actions.

Raw prompts, screenshots, clipboard contents, Keychain values, and browser history should stay on the endpoint by default. The management service should receive coverage state and minimal findings unless an organization explicitly enables a more invasive collection policy.
