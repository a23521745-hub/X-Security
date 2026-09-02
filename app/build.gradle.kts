import java.io.File

plugins {
    id("com.android.application")
    kotlin("android")
}

// Imza bilgileri yalnizca CI/gelistirici ortamindaki gizli degiskenlerden gelir;
// depoya asla keystore/parola girilmez.
val keystorePath = providers.gradleProperty("xsecKeystore").orNull
    ?: System.getenv("XSEC_KEYSTORE")
val keystoreFile: File? = keystorePath?.let { File(it) }
val hasSigningMaterial = keystoreFile != null && keystoreFile.isFile

// OTA yapilandirmasi da yalnizca derleme ortamindan (Gradle property / ortam degiskeni)
// gelir; depoya sunucu adresi ya da dogrulama anahtari sabitlenmez. Public anahtar
// zaten gizli degildir (istemcide gomulu olur) ama uretim degeri boylece disaridan
// yonetilir. Bos manifest URL'i = OTA kapali (uygulama "yapilandirilmamis" der).
val otaManifestUrl = providers.gradleProperty("xsecOtaManifestUrl").orNull
    ?: System.getenv("XSEC_OTA_MANIFEST_URL") ?: ""
val otaPublicKeyPem = providers.gradleProperty("xsecOtaPublicKeyPem").orNull
    ?: System.getenv("XSEC_OTA_PUBLIC_KEY_PEM") ?: ""
val otaAllowedHosts = providers.gradleProperty("xsecOtaAllowedHosts").orNull
    ?: System.getenv("XSEC_OTA_ALLOWED_HOSTS") ?: ""

/** BuildConfig String alani icin kacisli Java sabiti. */
fun javaStringLiteral(value: String): String =
    "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "") + "\""

android {
    namespace = "org.xsecurity.scanner"

    // compileSdk 35: targetSdk 35 (edge-to-edge zorunlulugu) icin gerekli.
    compileSdk = 35

    defaultConfig {
        applicationId = "org.xsecurity.scanner"
        minSdk = 26
        targetSdk = 35
        versionCode = 14
        versionName = "0.93.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // OTA istemcisi bu degerleri calisma zamaninda okur (bkz. OtaController).
        buildConfigField("String", "OTA_MANIFEST_URL", javaStringLiteral(otaManifestUrl))
        buildConfigField("String", "OTA_PUBLIC_KEY_PEM", javaStringLiteral(otaPublicKeyPem))
        buildConfigField("String", "OTA_ALLOWED_HOSTS", javaStringLiteral(otaAllowedHosts))
    }

    signingConfigs {
        if (hasSigningMaterial) {
            create("release") {
                storeFile = keystoreFile
                storePassword = providers.gradleProperty("xsecKeystorePassword").orNull
                    ?: System.getenv("XSEC_KEYSTORE_PASSWORD")
                keyAlias = providers.gradleProperty("xsecKeyAlias").orNull
                    ?: System.getenv("XSEC_KEY_ALIAS") ?: "xsecurity"
                keyPassword = providers.gradleProperty("xsecKeyPassword").orNull
                    ?: System.getenv("XSEC_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            // R8 bilincli olarak kapali: obfus-kasyon burada guvenlik saglamaz ve
            // dogrulanmamis bir optimizasyon tarama davranisini degistirebilir.
            // Boyutlari kucultmek isterseniz once `app/proguard-rules.pro` icindeki
            // keep kurallariyla cihazda bir QA taramasi yapin (minify acikken).
            isMinifyEnabled = false
            isShrinkResources = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            signingConfig = if (hasSigningMaterial) {
                signingConfigs.getByName("release")
            } else {
                logger.warn(
                    "X-Security: release signing not configured (set xsecKeystore / XSEC_KEYSTORE); " +
                        "the release APK will be unsigned and cannot be installed."
                )
                null
            }
        }
        debug {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.14"
    }

    testOptions {
        unitTests {
            // Motor testleri saf JVM'de calisir; Android API'lerine deginmez.
            isReturnDefaultValues = true
        }
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }

    lint {
        // Manifest'de sinifi olmayan bilesen bir daha olmamali: derlemeyi patlatsin.
        fatal += "MissingClass"
        checkReleaseBuilds = true
        abortOnError = true
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.work:work-runtime-ktx:2.9.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.3")

    // Saf Kotlin motor kodunun dogrudan kullandigi API'ler; transitif dagilima
    // guvenmek yerine acikca bildiriliyor.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material:material-icons-core")

    val composeBom = platform("androidx.compose:compose-bom:2024.04.01")
    implementation(composeBom)
    androidTestImplementation(composeBom)

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.9.0")
    debugImplementation("androidx.compose.ui:ui-tooling")

    testImplementation("junit:junit:4.13.2")
    // Saf JVM birim testlerinde org.json (Android'de platform ile gelir) kullanabilmek icin.
    testImplementation("org.json:json:20240303")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
}
