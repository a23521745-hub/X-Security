package org.xsecurity.scanner.edr

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [EdrTriggerPolicy] durum tetikleme mantığı: hangi AppOps olayı, hangi
 * ön/arka plan + ekran durumunda uyarı üretir?
 *
 * Not: `ActivityManager`/`AppOpsManager` saf JVM testine giremez; servis bu
 * politikaya delege eder, testler politikanın sözleşmesini kilitler.
 */
class BehavioralEdrTest {

    @Test
    fun onlyCameraAndMicrophoneAreWatched() {
        assertTrue(EdrTriggerPolicy.isWatchedOp(EdrTriggerPolicy.OP_CAMERA))
        assertTrue(EdrTriggerPolicy.isWatchedOp(EdrTriggerPolicy.OP_RECORD_AUDIO))
        assertFalse(EdrTriggerPolicy.isWatchedOp("android:fine_location"))
        assertFalse(EdrTriggerPolicy.isWatchedOp("android:read_contacts"))
        assertFalse(EdrTriggerPolicy.isWatchedOp(""))
        assertFalse(EdrTriggerPolicy.isWatchedOp(null))
    }

    @Test
    fun opConstantsMirrorFrameworkValues() {
        // Servis framework sabitleriyle (AppOpsManager.OPSTR_*) kaydolarak
        // politika bu aynalarla karar verir; değerler birebir aynı olmalı.
        assertEquals("android:camera", EdrTriggerPolicy.OP_CAMERA)
        assertEquals("android:record_audio", EdrTriggerPolicy.OP_RECORD_AUDIO)
        assertEquals(100, EdrTriggerPolicy.IMPORTANCE_FOREGROUND)
    }

    @Test
    fun foregroundUseWithScreenOnDoesNotAlert() {
        assertFalse(
            EdrTriggerPolicy.shouldAlert(
                op = EdrTriggerPolicy.OP_CAMERA,
                active = true,
                importance = EdrTriggerPolicy.IMPORTANCE_FOREGROUND,
                screenInteractive = true
            )
        )
        assertFalse(
            EdrTriggerPolicy.shouldAlert(
                op = EdrTriggerPolicy.OP_RECORD_AUDIO,
                active = true,
                importance = EdrTriggerPolicy.IMPORTANCE_FOREGROUND,
                screenInteractive = true
            )
        )
    }

    @Test
    fun backgroundUseAlertsEvenWithScreenOn() {
        // IMPORTANCE_BACKGROUND (400): tipik arka plan değeri.
        assertTrue(
            EdrTriggerPolicy.shouldAlert(
                op = EdrTriggerPolicy.OP_CAMERA,
                active = true,
                importance = 400,
                screenInteractive = true
            )
        )
        assertTrue(
            EdrTriggerPolicy.shouldAlert(
                op = EdrTriggerPolicy.OP_RECORD_AUDIO,
                active = true,
                importance = 400,
                screenInteractive = true
            )
        )
    }

    @Test
    fun screenOffAlertsEvenForForegroundImportance() {
        assertTrue(
            EdrTriggerPolicy.shouldAlert(
                op = EdrTriggerPolicy.OP_CAMERA,
                active = true,
                importance = EdrTriggerPolicy.IMPORTANCE_FOREGROUND,
                screenInteractive = false
            )
        )
    }

    @Test
    fun unknownImportanceFailsClosed() {
        // API 26+ getRunningAppProcesses() üçüncü parti süreçleri listelemez;
        // bulunamayan paket arka plan sayılır.
        assertTrue(
            EdrTriggerPolicy.shouldAlert(
                op = EdrTriggerPolicy.OP_CAMERA,
                active = true,
                importance = EdrTriggerPolicy.IMPORTANCE_UNKNOWN,
                screenInteractive = true
            )
        )
    }

    @Test
    fun inactiveOpOrUnwatchedOpNeverAlerts() {
        // İşlem bitişi (active=false) uyarı üretmez.
        assertFalse(
            EdrTriggerPolicy.shouldAlert(
                op = EdrTriggerPolicy.OP_CAMERA,
                active = false,
                importance = 400,
                screenInteractive = false
            )
        )
        // İzlenmeyen işlem arka planda bile uyarı üretmez.
        assertFalse(
            EdrTriggerPolicy.shouldAlert(
                op = "android:fine_location",
                active = true,
                importance = 400,
                screenInteractive = false
            )
        )
        assertFalse(
            EdrTriggerPolicy.shouldAlert(
                op = null,
                active = true,
                importance = 400,
                screenInteractive = false
            )
        )
    }

    @Test
    fun sensorLabelsMatchSpec() {
        assertEquals("Camera", EdrTriggerPolicy.sensorLabel(EdrTriggerPolicy.OP_CAMERA))
        assertEquals("Microphone", EdrTriggerPolicy.sensorLabel(EdrTriggerPolicy.OP_RECORD_AUDIO))
    }

    @Test
    fun alertTitleAndBodyMatchSpec() {
        assertEquals(
            "\uD83D\uDEA8 Şüpheli Arka Plan Erişimi Tespit Edildi",
            EdrTriggerPolicy.ALERT_TITLE
        )
        assertEquals(
            "com.ornek.supheli uygulaması arka plandayken Camera erişimi sağladı!",
            EdrTriggerPolicy.alertBody("com.ornek.supheli", EdrTriggerPolicy.OP_CAMERA, true)
        )
        assertEquals(
            "com.ornek.supheli uygulaması ekran kapalıyken Microphone erişimi sağladı!",
            EdrTriggerPolicy.alertBody("com.ornek.supheli", EdrTriggerPolicy.OP_RECORD_AUDIO, false)
        )
    }

    @Test
    fun deduplicatorSuppressesRepeatsWithinWindowOnly() {
        val dedup = EdrTriggerPolicy.Deduplicator(windowMillis = 1_000L)
        assertTrue(dedup.accept("com.a|android:camera", now = 0L))
        assertFalse(dedup.accept("com.a|android:camera", now = 500L))
        // Farklı işlem aynı pakette ayrı uyarıdır.
        assertTrue(dedup.accept("com.a|android:record_audio", now = 600L))
        // Pencere doldu: aynı anahtar yeniden kabul edilir.
        assertTrue(dedup.accept("com.a|android:camera", now = 5_000L))
    }
}
