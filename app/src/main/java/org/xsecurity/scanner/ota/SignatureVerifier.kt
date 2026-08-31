package org.xsecurity.scanner.ota

import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Manifest imzalarini dogrulayan tek nokta.
 *
 * Desteklenen imza algoritmalari (anahtarin turune gore otomatik secilir):
 *  - **RSA**     -> `SHA256withRSA` (PKCS#1 v1.5; RSA-2048 onerilir),
 *  - **Ed25519** -> `Ed25519` (daha kisa imza, modern cihazlar).
 *
 * Guvenlik kontrati:
 *  - Algoritma manifestten/veriden SECILMEZ; yalnizca gomulu anahtarin turunden
 *    turenilir. Zayif algoritmaya dusurme (downgrade) yoktur.
 *  - Anahtar X.509 `SubjectPublicKeyInfo` (PEM ya da tek-parca base64) olarak verilir.
 *  - [verify] hicbir kosulda exception firlatmaz; herhangi bir hata/uyusmazlik `false`
 *    doner — yani dogrulama **fail-closed**'dur. Imza uyusmazliginda guncelleme
 *    kesinlikle reddedilir.
 *  - Ed25519 destegi cihazin Java saglayicisina baglidir; desteklenmeyen cihazda
 *    dogrulama basarisiz olur (hata olarak raporlanir, asla "gecerli" sayilmaz).
 */
object SignatureVerifier {

    private const val RSA_SIGNATURE_ALGORITHM = "SHA256withRSA"
    private const val ED25519_SIGNATURE_ALGORITHM = "Ed25519"

    /** PEM (`-----BEGIN PUBLIC KEY-----`) ya da tek-parca base64 anahtarini yukler. */
    fun loadPublicKey(pemOrBase64: String): PublicKey {
        val body = pemOrBase64
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace("""\s""".toRegex(), "")
        require(body.isNotEmpty()) { "Public key bos" }
        val der = Base64.getDecoder().decode(body)
        // SPKI govdesi hem RSA hem Ed25519 olabilir; sabit bir sirayla denenir.
        // Ikisi de cozumlenemezse istisna yukselir (yapilandirma hatasi).
        try {
            return KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(der))
        } catch (_: Throwable) {
            // Ed25519 degildi (veya saglayici yok) — RSA olarak dene.
        }
        return KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(der))
    }

    /** Ham imza baytlari ile dogrular. */
    fun verify(publicKey: PublicKey, data: ByteArray, signature: ByteArray): Boolean = try {
        Signature.getInstance(algorithmFor(publicKey)).run {
            initVerify(publicKey)
            update(data)
            verify(signature)
        }
    } catch (_: Throwable) {
        false
    }

    /**
     * `.sig` dosyasindaki base64 (satir sonlari toleransli) imza ile dogrular.
     * Donusturme veya dogrulama basarisiz ise `false`.
     */
    fun verify(publicKey: PublicKey, data: ByteArray, signatureBase64: String): Boolean = try {
        val signature = Base64.getMimeDecoder().decode(signatureBase64.trim())
        verify(publicKey, data, signature)
    } catch (_: Throwable) {
        false
    }

    /** Anahtar turune gore sabit imza algoritmasi; bilinmeyen tur = hata (fail-closed). */
    internal fun algorithmFor(publicKey: PublicKey): String = when (publicKey.algorithm.uppercase()) {
        "RSA" -> RSA_SIGNATURE_ALGORITHM
        "ED25519", "EDDSA" -> ED25519_SIGNATURE_ALGORITHM
        else -> throw IllegalArgumentException("Desteklenmeyen anahtar algoritmasi: ${publicKey.algorithm}")
    }
}
