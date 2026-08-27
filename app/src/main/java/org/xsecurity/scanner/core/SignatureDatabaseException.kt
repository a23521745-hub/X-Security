package org.xsecurity.scanner.core

/**
 * Imza veritabani yuklenemediginde veya format tamamen taninmadiginda firlatilir.
 *
 * Eskiden parserlar dosya yoksa `emptyList()` donduruyordu; boylece motor "0 kural" ile
 * calisiyor ve sonuc "temiz" gorunuyordu. Bir antiviiruste basarisizligi basari gibi
 * gosteren bu davranis bilincli olarak hatali sayildi: artik hata yukselir ve
 * arayüzde `ScanStatus.FAILED` olarak görünür.
 */
class SignatureDatabaseException(
    message: String,
    cause: Throwable? = null
) : Exception(message, cause)
