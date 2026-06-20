# X-Security

Basic open-source Android background scanning service structure in Kotlin with:
- Local YARA rule parsing and string-literal matching
- Local ClamAV `.ndb` signature parsing and byte-pattern matching
- Background APK scanning via `WorkManager` for low RAM/CPU usage

## Structure

- `/app/src/main/java/org/xsecurity/scanner/service/ApkScanService.kt` - service entrypoint to queue scans
- `/app/src/main/java/org/xsecurity/scanner/worker/ApkScanWorker.kt` - background worker
- `/app/src/main/java/org/xsecurity/scanner/engine/ApkScannerEngine.kt` - orchestration layer
- `/app/src/main/java/org/xsecurity/scanner/yara/*` - YARA parse/match components
- `/app/src/main/java/org/xsecurity/scanner/clamav/*` - ClamAV parse/scan components

## Resource optimization decisions

- Chunked streaming for ClamAV scanning to avoid full-file memory loads
- Byte-pattern index by first byte to reduce unnecessary comparisons
- YARA scan read cap (`8MB` default) to limit memory usage
- `WorkManager` constraints (`batteryNotLow`, no network requirement)
- Small default Gradle JVM heap (`-Xmx1024m`)

## Build notes

This repository contains a basic Android service-oriented project structure. Build requires:
- Android SDK installed
- JDK 17

Then run:

```bash
./gradlew :app:assembleDebug
```

## CI release build

On pushes to `main`, GitHub Actions runs `.github/workflows/android-release-apk.yml` to build `:app:assembleRelease` and upload the generated APK artifact.
