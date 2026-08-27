package org.xsecurity.scanner.clamav

/**
 * Tek bir ClamAV `.ndb` imzasi.
 *
 * `.ndb` satir formati: `Name:TargetType:Offset:HexSignature[:MinSize,MaxSize]`
 *
 * Onceki surum yalnizca `Name` ve `HexSignature` okuyordu; `TargetType` ile `Offset`
 * alanlari cop'e gidiyordu. Bu da "su konumda / su dosya turunda" demek olan imzalarin
 * dosyanin her yerinde aranmasina (yanlis pozitif) ve joker iceren imzalarin sessizce
 * kaybolmasina (yanlis negatif) yol aciyordu. Simdi offsetlar cozumlenip tarayiciya
 * aktariliyor, cozumlenemeyen alanlar ise sayacla raporlaniyor.
 */
class ClamAvSignature(
    val name: String,
    /** `.ndb` `TargetType` alani; -1 cozumlenemeyen demek. */
    val targetType: Int,
    val offset: OffsetConstraint,
    val bytes: ByteArray,
    /** Bayt basina bit maskesi; `null` => tum baytlar literal. */
    val mask: ByteArray? = null
) {
    /** Bu imza icin ek konum kosulu var mi? */
    val isAnchored: Boolean get() = offset is OffsetConstraint.Exact || offset is OffsetConstraint.Range

    sealed class OffsetConstraint {
        /** Konum kosulu yok (veya sembolik offset cozumlenemedi). */
        object Any : OffsetConstraint()

        /** Tam olarak bu ofsette baslamali. */
        class Exact(val position: Long) : OffsetConstraint()

        /** [from] ile [to] (dahil) arasinda bir yerde baslamali. */
        class Range(val from: Long, val to: Long) : OffsetConstraint()

        fun accepts(position: Long): Boolean = when (this) {
            is Any -> true
            is Exact -> position == this.position
            is Range -> position >= from && position <= to
        }
    }
}
