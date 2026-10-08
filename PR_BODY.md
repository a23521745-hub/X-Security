# fix(p0): record identity, record dedup, and an emergency false-positive brake

Micro-hotfix for the v19 live incident (system apps flagged as threats, unreadable quarantine
records). Tiny on purpose: no engine, workflow, OTA or `SignatureVerifier` change and **no
version bump** — this lands *before* the Phase 1 vault work and is meant to be reviewed and
shipped on its own. **Do not merge until the E2E proof on the v19 OTA build (screenshots) is
attached to the gate.**

## 1. Record identity — the list shows the real file, the hash only in detail

The incident: file records were listed under a vault entry name, the staged copy name
(`<sha256>.apk`) or a bare hash — and the extension was effectively forced to `.apk` even for
files that were never APKs.

* `RecordLabel` (new, pure) is the single rule for what a record is called: the REAL file name
  from the original location (`sourcePath`, else the SAF/`file://` path decoded by
  `SourceLocator`), **with the file's own extension**. A hash, the `<hash>.apk` staged copy
  name, a `*.xsv` vault entry, an empty label or the old placeholder is a *placeholder* and is
  never shown.
* `VaultDeleteFlow.stage` labels new records through `RecordLabel.derive(...)`; a blank file
  label no longer falls back to the pseudo package name (`file-vault`).
* `QuarantineDatabase` v3 (`DATABASE_VERSION = 3`, additive `ALTER TABLE`) backfills legacy
  rows exactly once: only placeholder labels with a recoverable original location are rewritten
  (`RecordLabel.backfill`; nothing else is read or touched).
* The list now shows **name + path + size + scan date** (+ state/residue/engine). The
  SHA-256 line was removed from the list and the old `quarantine_hash` string was deleted;
  a new **Details** dialog shows every stored field: name, path, size, scan date, verdict,
  engine, SHA-256, residue, vault id, scan origin.
* Scan origin is recorded per record (`size_bytes` / `scan_origin` columns) and comes from the
  scan flow itself (`SecurityEvent.FileScan.origin`), never guessed: download watcher vs file
  picker. Rendered as text only — no content, no raw path beyond what the record already had.
* Regression locks: `RecordLabelTest` (real name with its own extension; never a vault
  name/hash; backfill), `QuarantineStringsHonestyTest` (every identity/detail/origin key
  exists in **both** EN and TR), plus device-level checks in `FileScanDispatchTest`.

## 2. Record dedup — re-scanning a file updates its record

Same `sha256` **and** same `sourcePath` (or same `sourceUri` when no path is known) is the same
case: the re-scan UPDATES that row — new timestamps, new vault copy, state back to
`QUARANTINED` + `ORIGINAL_PRESENT` — and never appends a second row.

* `RecordDedup` (new, pure) owns the identity rule; `QuarantineRepository.findFileRecordByIdentity`
  / `saveReobserved` perform the upsert (package records are never deduplicated into file
  records).
* A superseded vault copy is deleted only after the NEW copy verified (`FileVault.verify`), so
  a failed re-stage cannot destroy the surviving evidence.
* Regression locks: `RecordDedupTest` (scan twice ⇒ one record, same id; different path ⇒
  separate record), `FileScanDispatchTest#rescanningTheSameFileUpdatesTheSameRecordInsteadOfAddingASecondRow`
  (two dispatches ⇒ exactly one row, real name, real size, vault copy verifiable).
* No user-action gate changes: the original is still removed only by the explicit "Delete now"
  tap; dedup never moves or deletes a file by itself.

## 3. Emergency false-positive brake (live incident: system apps flagged)

### 3a. Rule denylist (`RuleDenylist`, applied at load time)

* `RuleDenylist.deniedPatterns` currently disables the whole family
  **`Android_Suspicious_Accessibility_Overlay_*`** (the bank-trojan permission-combo heuristic
  that fired on legitimate accessibility/overlay use in system and updated-system apps).
  Patterns are exact rule IDs, or a trailing `*` family prefix (`Foo_*` matches `Foo_Bar`,
  not `Foo` itself).
* The check runs inside `YaraRuleParser`, so **every** load path is covered at once: bundled
  assets, the signed definitions channel, community YARA sources and any user-supplied `.yar`.
  A denied rule is dropped BEFORE it can match anything and can never be re-enabled by a
  definitions/community update.
* It is skipped **and logged, never silently**: the skipped ID is reported in
  `YaraRuleSet.deniedRuleNames`, listed in `YaraRuleSet.problems`
  (`denylist: <id> skipped (emergency false-positive brake; rule ID is denylisted)`) and
  surfaced as an engine warning on the scan summary (`EngineInfo.from` →
  `WarningsBlock`), so "why is this rule not firing" is answerable from the UI/records.
* The curated rule file is **not edited**: `definitions/rules.yar` and
  `app/src/main/assets/signatures/rules.yar` stay byte-identical (CI gate) — the denylist is
  code-side and reversible.
* Regression locks: `RuleDenylistTest` (denied family matches variants but not the bare stem;
  parser drops + reports; the shipped `rules.yar` no longer contains the incident rule while
  it appears in `deniedRuleNames`; an APK fixture the incident rule would have matched is
  reported clean, and a renamed control rule proves the matcher itself still fires),
  `DefinitionsQualityTest` (`curatedYaraRulesParseWithoutAnyLoss` now asserts that every
  intentional skip is a denylist skip and the incident rule is inactive but reported).

### 3b. System-package safelist treatment (report, never act)

`SystemPackageSafelist.isSystemFlags` (FLAG_SYSTEM | FLAG_UPDATED_SYSTEM_APP, fails closed)
plus the pure `SystemPackageTreatment` decide the treatment: **"System app — no action taken /
Sistem uygulaması — işlem yok"**. Scan-result surfaces render the notice and draw **no**
Remove/Quarantine/Retry control; the wording keys are pinned so both languages must carry it.

Enforcement points (UI → action):

| Surface | Treatment |
| --- | --- |
| `DeviceScanCard` infected rows | notice instead of the old `[Kaldır]` button; `AppScanEntry.isSystemPackage` is carried from the scan (`DeviceScanSummary`, cached in `DeviceScanStore` JSON as `systemPackage`) |
| `ScanNotifications.showDeviceScanResult` | per-line notice; the uninstall action is taken from the first *actionable* entry only |
| `ScanNotifications.showInstallThreat` | notice appended; no uninstall action for a system package |
| `AutopilotNotifications.showDecision` | buttons only when the event flag AND `SystemPackageSafelist` both clear (authoritative check, not just the event field) |
| `QuarantineScreen` cards | system records show the notice; only metadata deletion stays |
| `PrivacyAdvisorScreen` rows | `isSystem` now includes updated-system apps; the notice replaces `[Kaldır]` |
| `MainActivity.requestUninstall` / `requestQuarantineUninstall` | defense in depth: a system package short-circuits to the notice toast before any intent |
| `QuarantineUserActions.uninstallIntent` | already returns `null` for a system package (choke point kept) |

Regression locks: `SystemPackageTreatmentTest` (flags → treatment; EN **and** TR notice
contain "System app" / "Sistem uygulaması" + "işlem yok"; the detail never claims a quarantine
happened) and `SystemPackageTreatmentDeviceTest` (instrumented: `android` is classified system;
the "uninstall" request returns `null` for it, non-null for a normal package).

## 4. Scan flows that create file records (inventory)

Both flows below end in the same pipeline and are the only producers of file-vault records.
In every case the identity fields come from the **original** location, the scan copy is staged
in `cacheDir/scans/<sha256>.apk`, and the copy is removed after the scan completes:

1. **User file picker** — `MainActivity` (`enqueueFromUri`, `ACTION_OPEN_DOCUMENT` result) →
   `ScanController.enqueueFromUri` (persistable SAF grant, `KEY_SOURCE_URI`) → `ApkScanWorker`
   (trigger `file_picker`) → `AutopilotRuntime.evaluate(FileScan)` → `ActionDispatcher`
   (audit-first) → `VaultDeleteFlow.stage` → record (`scan_origin = file_picker`).
2. **Download watcher (real-time protection)** — `RealtimeProtectionService` DownloadManager /
   `FileObserver` watch → `ScanController.enqueueFromUri` → `ApkScanWorker`
   (trigger `realtime`) → same pipeline → record (`scan_origin = download_watch`).

Note: an in-app **device (installed-app) scan** produces `AppScanEntry`/`ScanResult` rows in
the scan history and cache, exactly as before — it is *not* a file-record producer; the P0
change there is only that the system-package flag travels with the entry (and older caches
decode it as `false`, the conservative-but-actionable legacy rendering).

## Constraints honoured

* No changes under `engine/`, `.github/workflows/`, `ota/` or `SignatureVerifier`; no version
  bump (`versionCode = 19` untouched).
* `definitions/rules.yar` == `app/src/main/assets/signatures/rules.yar` (byte-identical).
* TR/EN strings stay symmetric; `QuarantineStringsHonestyTest` enforces the new keys and the
  notice wording in both files.
* Audit-log-first dispatch untouched: no automation path gains the ability to remove a file.

## Verification

* **Local JVM pre-flight** (pure-logic subset + their JVM tests, run with a shim JUnit/org.json
  and the Kotlin compiler — dev harness, not part of the repo): **286 passed / 0 failed**, 43 test
  classes, including every P0 regression test above and the untouched definitions/quality,
  engine, yara, clamav, matcher, ota, phishing and privacy suites.
* **CI** (this PR): `:app:testDebugUnitTest` + `:app:lintDebug` on the merge candidate + the
  signed/unsigned release build — run link is attached at the gate together with the repo head
  and the audit pack.
* **Instrumented** (`FileScanDispatchTest`, `SystemPackageTreatmentDeviceTest`) run on the
  device leg of the E2E proof.
