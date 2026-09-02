# Softcurse Blackwatch — Technical Audit and Remediation Roadmap

Audit date: 2026-08-31

## Executive assessment

Blackwatch has a visually distinctive desktop shell and a useful prototype monitoring core, but it is not production-ready. The React bundle builds, while the lint gate fails. The .NET solution cannot build on this workstation because it targets the now out-of-support .NET 9 toolchain and the repository does not pin or bootstrap an SDK. There are no automated tests or CI workflows.

The largest product risk is positioning: the current implementation is a local heuristic process/network monitor, not a reliable anti-cheat. It lacks game integration, tamper resistance, trusted telemetry, signed rules, evidence persistence, server validation, and a false-positive review workflow. Destructive responses are therefore too powerful for the confidence level of the detections.

## Verified results

| Check | Result |
|---|---|
| React production build | Pass; ~302 kB JS / 93 kB gzip |
| ESLint | Fail; 10 errors and 35 warnings |
| npm audit | Fail; 10 advisories (7 high, 2 moderate, 1 low), concentrated in build tooling |
| .NET solution build | Blocked: NETSDK1045; only .NET 8 SDK is installed, projects target .NET 9 |
| Icon converter | Pass after retargeting the developer tool to .NET 8 |
| Automated tests | None found |
| CI/CD | None found |
| Installer portability | Previously broken by absolute paths; corrected to repository-relative paths |

## Findings

### P0 — Release blockers

1. **No reproducible supported .NET toolchain.** Every shipping project targets `net9.0-windows`; .NET 9 is out of support, no `global.json` exists, and the current machine cannot compile it. Move directly to .NET 10 LTS, pin the SDK, and document/bootstrap prerequisites.
2. **Resolved — the advertised background service was not installed or configured as a Windows Service.** The unused worker has been removed from the product solution and the supported architecture is now explicitly a per-user desktop application. Closing the UI intentionally ends monitoring; a privileged service will not be reintroduced without a separately reviewed authenticated IPC design.
3. **Destructive actions exceed detection confidence.** `BlackwatchCleaner.KillProcess` terminates a whole process tree, and autorun/quarantine operations can modify user/system state. Current detections are filename/path/CPU/port heuristics. Keep dry-run as the mandatory default and disable automatic action until detections carry provenance, confidence, allowlist identity, and reviewable evidence.
4. **No test safety net.** There are no unit, integration, UI, migration, installer, or false-positive corpus tests. A monitoring/security product cannot safely evolve without regression coverage.

### P1 — Correctness and reliability

1. **Silent failure is systemic.** Empty `catch` blocks occur across config persistence, monitoring, scanner enrichment, WebView messages, React JSON handlers, and window commands. This explains “not working” symptoms with no actionable log. Expected transient failures should be typed and rate-limited; unexpected failures must be logged with context.
2. **UI timer work can overlap.** `DispatcherTimer` handlers fire async work without cancellation. Scanning has a volatile Boolean guard, but monitoring and data pushes do not. Replace this with cancellable `PeriodicTimer` loops and `SemaphoreSlim`/interlocked guards.
3. **Process identity is PID-only.** PIDs are reused. Kill and purge actions should verify PID + creation time + executable identity immediately before acting to avoid terminating a different process.
4. **Displayed process rows become stale.** The scan diff only adds/removes by PID; it does not update CPU, memory, score, signature, or other fields for an existing PID. The backend may be sampling correctly while the Processes page appears frozen.
5. **Config writes are non-atomic and errors are swallowed.** A crash during `File.WriteAllText` can corrupt settings. Add validation, temp-file write + atomic replace, backup/recovery, schema versioning, and surfaced errors.
6. **Cancellation shutdown bug in the worker.** `Task.Delay(..., stoppingToken)` can throw `OperationCanceledException` outside the scan-cycle catch. Treat cancellation as normal and dispose dependencies in a deterministic lifetime path.
7. **Log refresh can miss changes.** It refreshes only when buffer count changes. Once the fixed-size buffer is full, new entries can replace old entries without changing the count, leaving the UI stale.
8. **Memory/resource costs are high.** Every scan may hash and verify many executables synchronously. Cache invalidation is path-only, so replacing a file at the same path can also retain a stale hash/signature. Cache by stable file identity plus size and modification time, cap it, and process enrichment through a bounded queue.

### P1 — Detection quality and safety

1. **High false-positive potential.** Process names, unsigned status, `%TEMP%` paths, high background CPU, command-line substrings, and common port numbers are weak signals. Several legitimate tools can cross thresholds.
2. **Whitelist matching is name-only.** Any malicious binary can adopt an allowed process name. Store publisher certificate thumbprint, file hash, canonical path, product metadata, and user rationale; support scoped and expiring exceptions.
3. **Authenticode handling collapses unknown into unsigned.** Access errors and verification errors should remain `unknown`, not add a negative security signal.
4. **Network coverage is incomplete.** Only IPv4 TCP rows are inspected; no IPv6, UDP, DNS, hostname/SNI, connection history, or endpoint reputation exists. Port-only mining detection is not trustworthy.
5. **“Quarantine strips execute permissions” is inaccurate on Windows.** The implementation only moves/renames the file. Use an access-controlled quarantine directory, persist an encrypted manifest, preserve original metadata, and prevent direct execution.
6. **Action history is in-memory only.** Restarting loses restoration evidence. Persist an append-only action journal before mutation and reconcile interrupted operations at startup.

### P1 — Desktop/WebView boundary

1. **The bridge is stringly typed and duplicated.** Each page registers global callbacks and parses JSON through `any`; commands use colon-delimited strings. Colons in values can corrupt parsing, and compile-time contracts do not exist. Use versioned JSON envelopes and generated/shared TypeScript/C# contracts.
2. **Message origin is not validated.** The WPF handler accepts commands from WebView content without checking `Source` against the Blackwatch virtual origin. Restrict source/origin and navigation, block new windows/external schemes, and use `DenyCors` host access where compatible.
3. **Data transport is inefficient.** Serializing multiple full collections and injecting them through `ExecuteScriptAsync` every second increases UI-thread and JS parsing work. Use `PostWebMessageAsJson`, deltas, backpressure, and coalesced snapshots.
4. **Production assets are generated manually.** `WebUI` is gitignored and must be copied by hand. Wire frontend build/copy into MSBuild and CI so published binaries cannot contain stale UI.

### P2 — Frontend, UX, and accessibility

1. Fix the 10 lint errors and 35 warnings; replace `any` with a typed `window.chrome.webview` declaration and eliminate empty catches.
2. Add loading, disconnected, permission-denied, stale-data, empty, and partial-capability states. “System secure” must not be shown when scanning failed or required telemetry is unavailable.
3. Add accessible names/tooltips for icon buttons, visible keyboard focus, full keyboard navigation, reduced-motion support, scalable typography, and contrast verification.
4. Virtualize large process/log/network tables and use stable keys. Add sorting, filtering, details, export, evidence, and action confirmation with target identity.
5. Split the ~302 kB JS bundle by route/page and lazy-load decoration-heavy components. Respect power-saver/reduced-motion for continuous animations.
6. Replace the template package identity and keep lockfile/tooling current. Upgrade Vite/ESLint/PostCSS through tested major-version migrations.

### P2 — Packaging and operations

1. Add semantic versioning from a single source, assembly metadata, installer upgrade testing, signing for binaries/installer, release hashes/SBOM, and provenance.
2. Decide UI/service architecture explicitly. If a privileged service is required, expose a narrowly scoped authenticated IPC API; do not run the full WebView UI elevated.
3. Add structured logs, retention by size/age, redaction, diagnostic bundles, and opt-in telemetry. Command lines and paths can contain sensitive data.
4. Remove committed historical build logs and replace them with CI artifacts.
5. Add a privacy policy, threat-model document, responsible-disclosure policy, license, support matrix, and precise product claims.

## Delivery roadmap

### Phase 0 — Stabilize and make failures visible (2–4 days)

- [x] Pin .NET 10 LTS and Node 24 LTS; create one reproducible build/test/package command.
- [x] Integrate frontend build and exact WebUI synchronization into .NET build/publish.
- Fix lint/type errors and replace silent catches with structured diagnostics.
- Add capability/health state so the UI never reports “secure” after a failed scan.
- Keep all destructive behavior dry-run-only.

Exit gate: clean restore/build/lint on a fresh Windows runner; failures visible in UI and logs.

### Phase 1 — Correctness foundation (1–2 weeks)

- Refactor polling into cancellable background services with immutable snapshots.
- Fix existing-PID updates, PID reuse protection, log refresh, config atomicity, and cache invalidation.
- Introduce versioned JSON bridge contracts and origin/navigation restrictions.
- Add unit tests for scoring/config/migration and integration tests for scanner/monitor/bridge.

Exit gate: deterministic shutdown, no overlapping loops, repeatable tests, safe identity validation before actions.

#### Phase 1 progress — first implementation slice

- [x] Prevent overlapping scan and monitor cycles with asynchronous gates.
- [x] Tie background work to application lifetime cancellation.
- [x] Refresh existing process rows instead of updating only added/removed PIDs.
- [x] Refresh logs when a full fixed-size buffer rotates.
- [x] Revalidate process name and start time before destructive termination.
- [x] Validate configuration and persist it through atomic same-directory replacement.
- [x] Surface configuration and bridge failures in Blackwatch logs/status.
- [x] Replace colon-delimited frontend commands with versioned typed JSON messages.
- [x] Validate the WebView message origin and block untrusted navigation/new windows.
- [x] Restrict virtual-host resource access with `DenyCors`.
- [x] Add frontend bridge regression tests and C# config/process-safety tests.
- [x] Propagate lifetime cancellation through system/process/network collection, scoring, and report generation.
- [x] Remove concurrent event-driven scoring; new-process events now enter the single guarded scan pipeline.
- [x] Restore a clean lint gate and verify a clean C# solution build.
- [x] Add a desktop startup smoke test; identify and eliminate stale WPF runtime artifacts.
- [x] Refactor recurring monitoring, scanning, log refresh, and WebView delivery from `DispatcherTimer` into lifetime-cancelled `PeriodicTimer` loops.
- [x] Replace injected JavaScript data callbacks with versioned typed `PostWebMessageAsJson` snapshots and suppress unchanged channel payloads.
- [ ] Expand tests for scan diffing, cancellation, config migration/recovery, and bridge rejection paths.

### Phase 2 — Detection redesign (2–4 weeks)

- Separate telemetry collection, normalized evidence, rules, scoring, decisions, and response.
- Build a signed/versioned rules schema with explainable evidence and confidence.
- Create benign/malicious fixture corpora and measure false-positive/false-negative rates.
- Replace name-only allowlisting and port-only network judgments with identity/context-aware evidence.

Exit gate: measurable quality targets and reviewable explanations for every alert.

#### Phase 2 progress — first implementation slice

- [x] Separate normalized detection observations from score/decision construction.
- [x] Introduce a validated, schema-versioned rule catalog with stable rule identifiers.
- [x] Attach evidence IDs, observed values, rule versions, and confidence to every signal.
- [x] Produce a concise explanation and overall confidence for every process decision.
- [x] Replace heuristic `AUTO-TERMINATE`/`QUARANTINE` recommendations with human-review language.
- [x] Track sustained CPU state by PID plus process start time, preventing PID-reuse contamination.
- [x] Stop treating missing executable paths as proof of injection; record them as low-confidence telemetry degradation.
- [x] Reduce weights for path, memory, and CPU-only observations that commonly create false positives.
- [x] Restrict legacy allowlisting to exact process names and add hash/path-bound trusted identities with expiry and rationale.
- [x] Add regression tests for explainable evidence, confidence, schema rejection, safe recommendations, and allowlist bypasses.
- [x] Add detached RSA-PSS/SHA-256 verification, strict schema validation, duplicate rejection, and rollback protection for external rule bundles.
- [ ] Provision the production rule-signing key, embed only its public key, and wire authenticated rule activation into startup/update flow.
- [x] Capture Authenticode publisher thumbprints during cached executable enrichment and support publisher-bound trust rules.
- [x] Capture and cache version-resource product/company metadata; expose it in Process Explorer and allow it to constrain publisher-bound trust rules.
- [x] Replace port-only mining verdicts with explainable network evidence requiring process-identity and public-endpoint corroboration.
- [x] Add stable connection identities plus bounded 30-minute first/last-seen history and observation counts.
- [x] Add PID-correlated IPv6 TCP and IPv4/IPv6 UDP local-binding telemetry with honest UDP capability labeling.
- [x] Treat IPv6 loopback, link-local, deprecated site-local, and unique-local ranges as non-public during corroboration.
- [x] Add asynchronous reverse-DNS context with request deduplication, 750 ms timeouts, negative caching, 15-minute expiry, and bounded retention.
- [x] Correlate network rows with existing process hash, signature, publisher/company metadata, and stable process evidence without re-reading executables.
- [x] Require independent process evidence plus endpoint context for high-confidence network escalation; unsigned status alone never creates an alert.
- [x] Add exact-match SHA-256/IP/hostname reputation bundles with RSA-PSS signatures, source/version provenance, expiry, schema validation, and rollback protection.
- [ ] Provision and protect the production signing key, embed only its public key, and wire feed download/atomic activation with last-known-good recovery.
- [x] Add a version-controlled labeled baseline corpus and compute confusion matrix, precision, recall, and false-positive rate in tests.
- [x] Define automated release-baseline gates: precision ≥95%, recall ≥90%, and false-positive rate ≤1%.
- [x] Expand the initial corpus to 12 balanced fixtures covering signed/unsigned apps, games, developer tools, admin scripts, miners, RAT names, impersonation, reverse shells, and encoded commands.
- [ ] Replace synthetic-only coverage with a substantially larger, legally redistributable real-world metadata/behavior corpus before treating quality metrics as representative.
- [x] Add an expandable evidence-review UI showing confidence, observed values, categories, weights, explanations, and rule-set provenance.
- [x] Replace random evidence IDs with stable SHA-256 fingerprints suitable for deduplication and durable review references.
- [ ] Add explicit analyst disposition (confirmed, false positive, trusted exception) with a durable review journal.

### Phase 3 — Safe response and service architecture (2–3 weeks)

- Persist a transactional action/quarantine journal with recovery and restore tests.
- Implement least-privilege authenticated IPC between UI and Windows Service if service mode is retained.
- Add explicit consent, target verification, rollback, and audit trail for every mutation.
- Threat-model IPC, updates, quarantine, WebView, installer, and rule supply chain.

Exit gate: interrupted operations recover safely; UI compromise cannot invoke arbitrary privileged actions.

#### Phase 3 progress — first implementation slice

- [x] Add an append-only JSONL write-ahead action journal using write-through and disk flush semantics.
- [x] Assign stable action IDs and explicit prepared/completed/failed/recovery-required states.
- [x] Journal process termination intent before mutation and terminal outcome afterward.
- [x] Block process termination when the prepare record cannot be persisted.
- [x] Detect prepared actions without terminal records on startup and surface them for recovery review.
- [x] Recover prior records when a power loss leaves only the final append truncated; reject mid-journal corruption.
- [x] Journal autorun removal, quarantine, and restore through the same prepare/terminal transaction boundary.
- [x] Persist atomic quarantine manifests with action ID, canonical source/destination, original size/hash, and quarantine/restore timestamps.
- [x] Refuse restore when the target exists, manifest identity differs, or quarantined content fails SHA-256 verification.
- [x] Add idempotent startup reconciliation for interrupted quarantine/restore transactions without automatically moving or deleting files.
- [x] Finalize only cryptographically proven completed/not-started states; retain conflicts, missing files, hash failures, process kills, and registry actions for manual review.
- [x] Add a recovery review card with action ID/type, target/quarantine paths, status, reason, confirmations, verified restore, explicit finalize, and audited dismissal.
- [x] Require native desktop consent before live process termination or purge; web content can request but cannot self-confirm a mutation.
- [x] Bind process-kill consent to PID, process name, and observed start time with a short-lived single-use capability.
- [x] Reject missing, expired, replayed, wrong-target, and wrong-action capabilities before process access, with journaled failure outcomes.
- [x] Remove the unused Windows Service from the product solution; the shipped architecture is an explicit per-user desktop app and therefore has no privileged IPC boundary to expose.
- [x] Remove the unjournaled `ProcessScanner.KillProcess(pid)` bypass so all product process termination flows pass through the cleaner consent boundary.
- [x] Centralize the protected Windows-process denylist in the cleaner so even an explicitly authorized request cannot terminate critical operating-system processes.
- [x] Change the UI-only installer from machine-wide elevation to a per-user least-privilege install location.
- [x] Complete the repository-grounded Early Alpha threat model for WebView, cleaner/recovery, quarantine, local state, distribution, and the future signed-update supply chain.
- [x] Remove the manifest-level administrator requirement, unused unsafe-code permission, remote UI assets, and external WebView network access (TM-001/TM-006).
- [x] Add native consent plus short-lived operation/action-ID-bound authorization to restore/finalize/dismiss recovery operations, with missing/wrong-scope/wrong-target tests (TM-002).
- [x] Generate an embedded build-time SHA-256 manifest for the exact WebUI file set and fail closed before WebView/bridge initialization on modified, missing, unexpected, duplicate, malformed, reparse-point, or path-escaping content (TM-001).
- [x] Replace active process-name whitelisting with user-confirmed executable trust records bound to canonical path + SHA-256 and, when available, publisher certificate; retain legacy names as visible inactive migration data (TM-004).
- [x] Apply protected Windows ACLs to configuration, logs, action journal, quarantine, and manifests, granting only the current user and LocalSystem explicit access.
- [x] Add a versioned tamper-evident action-journal hash chain with a cryptographic legacy-prefix migration boundary, valid-JSON tamper detection, and safe truncated-tail repair (TM-005).
- [x] Add target-scoped bridge cooldowns for scans, purge/kill/recovery prompts, trusted-file selection, and dry-run changes; require native confirmation before live response mode can be enabled (TM-002/TM-009).
- [ ] Sign release binaries/installers and publish checksums plus provenance for the website-to-GitHub distribution chain (TM-003).

### Phase 4 — Product UX and performance (1–2 weeks)

- Implement honest health/degraded states, evidence detail views, accessible interaction, virtualization, and reduced motion.
- Profile scan latency, UI responsiveness, memory, CPU, disk I/O, and startup on low/mid/high hardware.
- Add budgets and regression benchmarks.

Exit gate: responsive under large process/log volumes and usable without a mouse or continuous animation.

#### Phase 4 progress — first implementation slice

- [x] Add explicit healthy/degraded/error telemetry state independent from detection results.
- [x] Surface partial process, network, and system collection failures in the dashboard and status text.
- [x] Preserve the last successful scan timestamp and mark prior results stale after a failed scan.
- [x] Respect the operating-system reduced-motion preference across CSS and Framer Motion animations.
- [x] Add consistent visible keyboard focus plus Arrow/Home/End sidebar navigation.
- [x] Bound process and log table DOM size with keyboard-accessible pagination.
- [x] Redact common secrets, URL queries, user-profile paths, and line-break injection before logs reach memory or disk.
- [x] Enforce 14-day/20 MB log retention with 5 MB file rotation and Blackwatch-owned-file scoping.
- [x] Add an explicitly user-selected diagnostic ZIP export that re-redacts retained logs and includes only bounded health metadata.

### Phase 5 — Release engineering (1–2 weeks)

- CI matrix, signed artifacts, SBOM/provenance, installer upgrade/uninstall tests, crash diagnostics, release channels, and rollback.
- Documentation, privacy/security policies, support matrix, and narrowly accurate marketing claims.

Exit gate: reproducible release from a clean tag with automated smoke/install/upgrade checks and published SHA-256 checksums/provenance. Authenticode is deferred until it is commercially justified.

#### Phase 5 progress — first implementation slice

- [x] Centralize v0.1.0-alpha assembly, file, product, and installer version metadata.
- [x] Add a Windows CI gate for pinned toolchains, frontend lint/tests, .NET tests, self-contained publish, installer compilation, checksums, and artifact retention.
- [x] Add a local build script that produces the same portable and installer candidates as CI.
- [x] Generate a pinned Microsoft SPDX SBOM and GitHub provenance attestations for CI release candidates.
- [x] Upgrade the production UI to React 19, Vite 8, Motion 13, and ESLint 10 flat configuration with exact dependency pins.
- [x] Enforce TypeScript compilation, zero-warning linting, frontend tests, and a high-severity npm audit in the release pipeline.
- [x] Add a headless installed-payload self-test covering required runtime files, version identity, and exact WebUI integrity.
- [x] Add isolated CI lifecycle coverage for per-user install, in-place repair, uninstall registration cleanup, and installer ownership boundaries.
- [x] Live-test the published desktop app and add a one-second non-admin process-event fallback when WMI events are unavailable.
- [x] Isolate log files per process/logger session so a running app cannot block tests or another diagnostic process.
- [ ] Add tag-driven GitHub Release publishing for the unsigned v1 installer and document Windows SmartScreen expectations.
- [ ] Validate a real previous-version upgrade and rollback once a second public pre-release installer exists.

## Branding migration completed in this audit

- User-facing app, title bar, sidebar, tray, service messages, virtual host, frontend package, solution, installer, output filename, and Git remote use **Softcurse Blackwatch**.
- The approved transparent Blackwatch lockup is the sole branding image in project assets and the frontend.
- Windows icon was regenerated from that exact lockup at 16/20/24/32/40/48/64/128/256 px.
- App data/log paths now use `SoftcurseBlackwatch`; legacy Sentinel config is imported once for continuity.
- The legacy JavaScript callback is retained temporarily as a one-release compatibility alias and should be removed after all distributed shells are upgraded.
