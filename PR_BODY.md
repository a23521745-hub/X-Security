# feat(quarantine): true cut-and-paste file quarantine with an enforced honesty rule

Phase 1 lead item. Until now a known-bad file was *copied* into the encrypted vault and the
record was shown as "quarantined" while the original stayed exactly where it was (the
E2E-proven gap: the dispatcher only ever saw our staged copy in `cacheDir/scans/`, never the
user's file). This PR turns the vault into a real move and makes it impossible for the UI to
claim otherwise.

## What changes

### Flow (`VaultDeleteFlow` + pure `VaultCutEngine`)

1. **Stage — automation, non-destructive.** `ActionDispatcher` → `VaultDeleteFlow.stage`:
   `FileVault.store` → the entry is decrypted and re-hashed (`FileVault.verify`; also checks
   the scanned hash) → record `QUARANTINED` + **`ORIGINAL_PRESENT`** with the original's
   `sourceUri`/`sourcePath` (private DB only). L2 may do nothing more than this; the
   notification says *"Threat copied to vault — original still on device"* with a
   **Delete now / Şimdi Sil** action.
2. **Cut — exactly one user tap, never zero-tap.** `QuarantineCutActivity` (notification
   action or Quarantine screen) → `VaultCutEngine.cut`:
   * vault copy must verify, original must still hash to what was scanned (else
     `original_changed_since_scan`, nothing deleted);
   * **All Files Access** (API 30+) / `WRITE_EXTERNAL_STORAGE` (API ≤ 29) or an
     app-private path ⇒ silent direct delete after our in-app tap, no system dialog
     (owner amendment);
   * SAF write grant alive ⇒ `DocumentsContract.deleteDocument`;
   * otherwise the same tap goes through `MediaStore.createDeleteRequest` (30+) or the
     `RecoverableSecurityException` prompt (29); the engine suspends with
     `NeedsUserConfirmation(IntentSender)` and resumes in `completeUserConfirmation`.
   * After any claimed success the file must no longer be visible
     (`still_present_after_confirmation` otherwise) → residue **`ORIGINAL_REMOVED`**.
3. **Denied / failed** ⇒ record stays `QUARANTINED` + `ORIGINAL_PRESENT` with a result
   code; the ongoing notification keeps offering **Delete now**; the cut screen offers
   Retry / Grant All Files Access / Open Downloads. Pending originals are re-notified on
   app start and boot.
4. **Restore** = decrypt to app-private scratch → hash check → move bytes back to the
   original path (MediaStore Downloads, then the app's Downloads folder as fallbacks; if the
   original is still there with the same hash nothing is written) → delete scratch → delete
   the vault copy → `RESTORED` (USER_ACTION, enforced by the state machine). No duplicates.
5. **Delete record** offers to delete the original first when it is still present; the
   vault copy is only dropped after that succeeds (or the user chooses "record only").

### Honesty rule (release-blocking)

* `QuarantineRecord` gains `residue` (`ORIGINAL_PRESENT` / `ORIGINAL_REMOVED`), `sourceUri`,
  `sourcePath`, `cutResult` (DB v2, additive `ALTER TABLE`; legacy file rows have `NULL`
  residue which is read as **present** — nothing was ever removed before).
* `QuarantineHonesty.displayState` is the single mapping record → wording;
  `FILE_QUARANTINED_ORIGINAL_REMOVED` is the only state allowed to say "quarantined".
* `QuarantineWording` pins the string keys; `QuarantineStringsHonestyTest` parses the real
  EN/TR `strings.xml`: symmetric key sets, `ORIGINAL_PRESENT` texts must say the original is
  still on the device and may not contain quarantined/contained (TR: karantinaya alındı /
  karantinada / dosya kaldırıldı…), `ORIGINAL_REMOVED` texts must say the original was removed.
* The old generic "Known threat contained" notification is no longer used for files.

### Plumbing

* `ScanController.enqueueFromUri` forwards the original's URI (`KEY_SOURCE_URI`) and takes a
  persistable SAF grant (released on clean/unknown verdicts and on give-up);
  `ApkScanWorker` → `SecurityEvent.FileScan.sourceUri` (in-process only, still never
  serialized). The Download watcher already passes `file://` URIs, so Download Shield reuses
  the flow unchanged.
* `SourceLocator` (pure) maps `file://`, `externalstorage.documents`, `downloads.documents`
  (`raw:` / `msf:` / legacy ids), `media.documents` and `content://media` URIs to paths /
  MediaStore ids; the Android port falls back to a `_data` lookup + media scan.
* `FileVault.verify/delete/exists`; `StorageAccess.hasDirectDeleteAccess`;
  `WRITE_EXTERNAL_STORAGE` (`maxSdkVersion=29`) declared; one-time onboarding dialog with the
  antivirus rationale for All Files Access + a Settings row (`AutopilotPermission.ALL_FILES_ACCESS`);
  graceful fallback to the system dialog when declined.
* Quarantine screen shows the honest state + residue line + hint, **Delete now**, Restore,
  Delete record; `MainActivity` restores file records through the real move-back.

## Tests

JVM (`:app:testDebugUnitTest`):
* `QuarantineHonestyTest` — every state × residue × record kind: a full claim implies
  `ORIGINAL_REMOVED`; legacy `null` residue is present; transitions preserve the new fields.
* `VaultCutPolicyTest` — route matrix (All Files Access ⇒ direct first; none ⇒ system dialog;
  API 29 prompt; app-private always direct; no route ⇒ honest reason, never silent).
* `VaultCutEngineTest` (fakes + temp files) — vault → system delete request → removed only after
  consent; denial keeps `ORIGINAL_PRESENT` + `denied_by_user` and retry succeeds; direct delete
  without any dialog; unverifiable vault / changed original never delete; restore moves bytes
  back (one plaintext copy, scratch + vault gone), no second copy when the original is still
  present, Downloads fallback; delete-record semantics; package records rejected.
* `SourceLocatorTest`, `QuarantineStringsHonestyTest`.

Instrumentation: `FileScanDispatchTest` now asserts non-destructive staging
(`ORIGINAL_PRESENT`, fixture untouched), the direct cut + byte-exact restore on an app-private
file, and that a hash mismatch is not vaulted; `FileVaultRoundTripTest` covers
`verify`/`delete`.

The sandbox cannot run Gradle (no SDK / blocked Maven hosts); the pure files and tests were
compiled and run with a standalone Kotlin 1.9.24 compiler, and the Android-side files were
type-checked against the API 35 `android.jar`. Compose screens were reviewed by hand — CI is the
gate for them.
