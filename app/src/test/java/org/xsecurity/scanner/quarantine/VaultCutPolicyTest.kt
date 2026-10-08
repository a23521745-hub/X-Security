package org.xsecurity.scanner.quarantine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xsecurity.scanner.quarantine.VaultCutPolicy.Route

class VaultCutPolicyTest {
    private fun caps(
        sdk: Int = 34,
        directWrite: Boolean = false,
        pathKnown: Boolean = true,
        appPrivate: Boolean = false,
        documentGrant: Boolean = false,
        mediaUri: Boolean = false
    ) = VaultCutPolicy.Capabilities(sdk, directWrite, pathKnown, appPrivate, documentGrant, mediaUri)

    @Test
    fun allFilesAccessMeansSilentDirectDeleteFirst() {
        val routes = VaultCutPolicy.routes(caps(directWrite = true, documentGrant = true, mediaUri = true))
        assertEquals(Route.DIRECT_DELETE, routes.first())
        assertTrue(routes.contains(Route.SYSTEM_DELETE_REQUEST))
        assertFalse(VaultCutPolicy.needsUserConfirmation(Route.DIRECT_DELETE))
    }

    @Test
    fun withoutAllFilesAccessTheTapRoutesThroughTheSystemDeleteDialog() {
        val routes = VaultCutPolicy.routes(caps(sdk = 34, directWrite = false, mediaUri = true))
        assertEquals(listOf(Route.SYSTEM_DELETE_REQUEST), routes)
        assertTrue(VaultCutPolicy.needsUserConfirmation(Route.SYSTEM_DELETE_REQUEST))
    }

    @Test
    fun api29UsesTheRecoverableSecurityPrompt() {
        assertEquals(
            listOf(Route.RECOVERABLE_SECURITY_PROMPT),
            VaultCutPolicy.routes(caps(sdk = 29, mediaUri = true))
        )
        assertEquals(
            listOf(Route.DIRECT_DELETE, Route.RESOLVER_DELETE, Route.RECOVERABLE_SECURITY_PROMPT),
            VaultCutPolicy.routes(caps(sdk = 29, directWrite = true, mediaUri = true))
        )
    }

    @Test
    fun legacyApiWithoutWriteHasNoSilentOrPromptedMediaRoute() {
        assertTrue(VaultCutPolicy.routes(caps(sdk = 28, mediaUri = true)).isEmpty())
        assertEquals(
            listOf(Route.RESOLVER_DELETE),
            VaultCutPolicy.routes(caps(sdk = 28, directWrite = true, pathKnown = false, mediaUri = true))
        )
    }

    @Test
    fun appPrivatePathsAreAlwaysDirectlyDeletable() {
        assertEquals(listOf(Route.DIRECT_DELETE), VaultCutPolicy.routes(caps(appPrivate = true)))
    }

    @Test
    fun safDocumentGrantIsUsedBeforeAnySystemDialog() {
        val routes = VaultCutPolicy.routes(caps(documentGrant = true, mediaUri = true))
        assertEquals(listOf(Route.DOCUMENT_PROVIDER_DELETE, Route.SYSTEM_DELETE_REQUEST), routes)
    }

    @Test
    fun noRouteNeverMeansSilentDeletionAndExplainsWhy() {
        val unknown = caps(pathKnown = false)
        assertTrue(VaultCutPolicy.routes(unknown).isEmpty())
        assertEquals(CutResultCodes.FAILED_LOCATION_UNKNOWN, VaultCutPolicy.unavailableReason(unknown))

        val knownButForbidden = caps(pathKnown = true)
        assertTrue(VaultCutPolicy.routes(knownButForbidden).isEmpty())
        assertEquals(CutResultCodes.FAILED_PERMISSION, VaultCutPolicy.unavailableReason(knownButForbidden))
    }

    @Test
    fun removedCodesAreRecognised() {
        assertTrue(CutResultCodes.isRemoved(CutResultCodes.REMOVED_SYSTEM_DIALOG))
        assertFalse(CutResultCodes.isRemoved(CutResultCodes.DENIED_BY_USER))
        assertFalse(CutResultCodes.isRemoved(null))
    }
}
