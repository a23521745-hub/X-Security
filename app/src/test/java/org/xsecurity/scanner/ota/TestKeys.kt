package org.xsecurity.scanner.ota

/**
 * Test kurgusu anahtarlari. URETIM KODUNDA KULLANILMAZ (H-1): uretim
 * derlemelerine anahtar verilmediginde OTA/tanim kanallari "yapilandirilmamis"
 * olur ve kapanir (fail-closed); hicbir ornek anahtar derlenmez.
 *
 * Buradaki gelistirme public anahtari `tools/ota/ota-signing-dev-public.pem`
 * ile aynidir; sadece imza-dogrulama testlerinde kullanilir.
 */
object TestKeys {
    /** GELISTIRME ORNEK anahtari (RSA-2048) — test kurgusu. */
    val SAMPLE_PUBLIC_KEY_PEM: String = """
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtw43MZ13JzoRKrIgMv7Q
        wyg85532mFhs6tQcI0czOD4XUbWGAAxkf7zqFEcDx9HVdPQ7hIR3IJR/WkElihXa
        6RvfqkCqscP4qUADySgsPE7AH5gyrPtpa9E2LJXm45ZJOv0+rrQQfzCgrRP7KeRw
        poTK5DkXcwNIvfKbDFxP+EigoG4wkOP/fmTJiUe77qAIGaAQ5aWegfDyq+s5YeV5
        x9OiOIWODOXKi5zcnSbb+yb5hpWHxZ0YowM+iZXIG8GXD75PvpYZYV/Rhj9i40vI
        6yUEgkxmGV+wH3+IZtCjapxU8JIvk7ROmJPOOd2NSVAI2S4gQtINUFsVLVa7KpH9
        HwIDAQAB
        -----END PUBLIC KEY-----
    """.trimIndent()
}
