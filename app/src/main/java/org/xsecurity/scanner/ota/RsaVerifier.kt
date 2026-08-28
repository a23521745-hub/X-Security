package org.xsecurity.scanner.ota

import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Manifest imzalarini dogrulayan tek nokta.
 *
 *  - Algoritma sabittir: **SHA256withRSA** (PKCS#1 v1.5). Zayif algoritmaya dusurme
 *    (downgrade) yok; manifest bunu secmez.
 *  - Anahtar X.509 `SubjectPublicKeyInfo` (PEM veya tek-parca base64) olarak verilir.
 *  - [verify] hicbir kosulda exception firlatmaz; herhangi bir hata/uyusuzluk `false`
 *    doner — yani dogrulama **fail-closed**'dur.
 */
object RsaVerifier {

    private const val SIGNATURE_ALGORITHM = "SHA256withRSA"
    private const val KEY_ALGORITHM = "RSA"

    /** PEM (`-----BEGIN PUBLIC KEY-----`) ya da tek-parca base64 anahtarini yukler. */
    fun loadPublicKey(pemOrBase64: String): PublicKey {
        val body = pemOrBase64
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace("""\s""".toRegex(), "")
        require(body.isNotEmpty()) { "Public key bos" }
        val der = Base64.getDecoder().decode(body)
        return KeyFactory.getInstance(KEY_ALGORITHM)
            .generatePublic(X509EncodedKeySpec(der))
    }

    /** Ham imza baytlari ile dogrular. */
    fun verify(publicKey: PublicKey, data: ByteArray, signature: ByteArray): Boolean = try {
        Signature.getInstance(SIGNATURE_ALGORITHM).run {
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
}
