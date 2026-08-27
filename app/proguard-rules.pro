# X-Security ProGuard/R8 kurallari.
#
# Not: `app/build.gradle.kts` icinde `isMinifyEnabled = false`; bu kural dosyasi o
# anahtar acildiginda gecerli olmak uzere duruyor (bkz. orada aciklama).

# WorkManager worker siniflarini refleksiyonla adlandirarak olusturur: sinif adi ve
# (Context, WorkerParameters) imzali kurucu korunmali, yoksa R8 kisa ismi tatar ve
# calisma zamaninda "InstantiationException/ClassNotFoundException" alinir.
-keep class org.xsecurity.scanner.worker.** { *; }
-keep class * extends androidx.work.ListenableWorker {
    public <init>(android.content.Context, androidx.work.WorkerParameters);
}

# androidx.startup / InitializationProvider refleksiyon kullaniyor.
-keep class androidx.startup.** { *; }
-dontwarn androidx.startup.**

# Tarama motoru modelleri (ByteArray alanlari) - su an reflection yok, ama alan
# adlarinin loglama/raporlama amacli korunmasi ucuz bir sigorta.
-keepclassmembers class org.xsecurity.scanner.yara.** { *; }
-keepclassmembers class org.xsecurity.scanner.clamav.** { *; }
-keepclassmembers class org.xsecurity.scanner.engine.** { *; }

# Coroutines
-dontwarn kotlinx.coroutines.**
-dontwarn org.jetbrains.annotations.**
