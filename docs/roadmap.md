# Build path

Guard is intentionally separate from Runeward's container control plane. The first version should earn trust as an endpoint product before any central fleet features are added.

1. **Local decision core (implemented foundation).** Versioned event schema, deterministic secret heuristics, screenshot/upload correlation, no raw-content findings, tests, and a synchronous check command. The example feed is synthetic.
2. **Trusted harness adapters (Claude Code prompt hook started).** Add one integration at a time for pre-submit prompt checks and tool-use metadata. Verify each harness's supported hook contract and fail-open/fail-closed behavior before claiming coverage. A hook is not equivalent to observing all chats or all network sends.
3. **macOS endpoint sensor.** Build a signed system extension for process and file-access metadata with Apple's Endpoint Security entitlement. Track AI-harness process identity, Keychain access metadata, and screenshot file creation. Do not read Keychain item values. Design an operator-controlled pause and clear sensor-health reporting.
4. **Disclosure correlation.** Add a supported browser/desktop upload signal, then tie capture, actor, file identity, destination, and timing together. Merely creating a screenshot or visiting an AI site is insufficient evidence of sharing. Never describe unobserved channels as protected.
5. **Management plane.** Add a Go service for signed policy distribution, device enrollment, minimal finding ingestion, audit retention, and a Runeward cross-link. Keep raw prompts and screenshots on-device by default. Define role-based access and retention before enabling remote findings.
6. **Retrospective review.** Offer an explicit, bounded scan of operator-selected local history or logs. Report only sources actually examined, with confidence labels and deletion controls. Browser history alone cannot recover prompt content.

Before shipping an EDR claim, add tamper resistance, signed updates, uninstall/recovery flow, enrollment, performance budgets, cross-user testing, security review, and a documented coverage matrix for each supported harness and OS version.
