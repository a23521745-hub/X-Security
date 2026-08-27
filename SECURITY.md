# Security Policy

## Supported Versions

Security updates target the current pre-release line and, once published, the 1.0.x
series. Pre-release builds are explicitly *not* a sole line of defence.

| Version | Supported | Notes |
| ------- | --------- | ----- |
| 1.0.x   | :white_check_mark: | planned stable line |
| 0.91.x-pre | :white_check_mark: (best effort) | current `main`; signature-syntax coverage still partial |
| < 0.91  | :x: | no back-ported fixes |

## Reporting a Vulnerability

Security is a top priority for this project. If you discover a vulnerability, a flaw in
the scanner engine, or a *detection gap* that could make a malicious file look clean,
please disclose it privately instead of opening a public issue.

### Scope worth reporting

- Any path where a scan reports `CLEAN` while the engine did not actually load rules or
  signatures (this class of bug is treated as the highest severity).
- Parser/matcher memory-safety or DoS issues: a crafted `.yar`/`.ndb` file or a crafted
  APK that stalls or crashes the worker, the notification pipeline, or `WorkManager`.
- Signature files delivered from storage being able to make the app read files outside its
  own sandbox (the app uses SAF and stages copies in `cacheDir`; there is no storage
  permission).
- Bypasses in the YARA/ClamAV subset (e.g. a rule that is silently dropped instead of
  reported as unsupported).
- Escalation/permission issues introduced by a future native (JNI/NDK) layer — note that
  the current build has **no** native code, so `ndk.dir`/JNI-related reports do not apply
  yet.

### How to Report

1. **Private email / GitHub advisory:** contact the maintainer or open a private security
   advisory on the repository.
2. **Details to include:**
   - Type of issue (parser crash, detection bypass, unhandled exception in the worker,
     privacy leak).
   - Steps to reproduce, with the offending `.yar`/`.ndb`/APK sample if you have one
     (a reduced repro is very welcome; a unit test even more so).
   - Affected Android versions/device architectures.

### Disclosure Process

- **Acknowledgment:** initial response within **48 hours**.
- **Assessment:** reports are reproduced and fixed in an isolated branch; regressions are
  locked with a unit test under `app/src/test`.
- **Resolution:** the patch is pushed to the repository and credited in the release notes
  unless you prefer to stay anonymous.
