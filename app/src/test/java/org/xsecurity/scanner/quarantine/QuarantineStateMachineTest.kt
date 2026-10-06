package org.xsecurity.scanner.quarantine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class QuarantineStateMachineTest {
    private fun record(state: QuarantineState = QuarantineState.DETECTED) = QuarantineRecord(
        id = "record-1",
        packageName = "org.example.app",
        label = "Example",
        sha256 = "abc",
        verdict = "KNOWN_BAD",
        engine = "SCANNER",
        detectedAtMillis = 100,
        updatedAtMillis = 100,
        state = state
    )

    @Test
    fun validLifecycleIsDetectedPendingQuarantinedThenRestored() {
        val pending = accepted(record(), QuarantineState.PENDING, QuarantineActor.AUTOMATION, 200)
        val contained = accepted(pending, QuarantineState.QUARANTINED, QuarantineActor.AUTOMATION, 300)
        val restored = accepted(contained, QuarantineState.RESTORED, QuarantineActor.USER_ACTION, 400)
        assertEquals(QuarantineState.RESTORED, restored.state)
    }

    @Test
    fun deletedStateRequiresAnExplicitUserActionAfterAContainmentAttempt() {
        val detectedDelete = QuarantineStateMachine.transition(
            record(), QuarantineState.DELETED, 200, QuarantineActor.AUTOMATION
        )
        assertTrue(detectedDelete is QuarantineTransitionResult.Rejected)

        val pending = accepted(record(), QuarantineState.PENDING, QuarantineActor.AUTOMATION, 200)
        val pendingAutoDelete = QuarantineStateMachine.transition(
            pending, QuarantineState.DELETED, 300, QuarantineActor.AUTOMATION
        )
        assertTrue(pendingAutoDelete is QuarantineTransitionResult.Rejected)
        val pendingUserDelete = accepted(pending, QuarantineState.DELETED, QuarantineActor.USER_ACTION, 300)
        assertEquals(QuarantineState.DELETED, pendingUserDelete.state)

        val contained = accepted(pending, QuarantineState.QUARANTINED, QuarantineActor.AUTOMATION, 300)
        val autoDelete = QuarantineStateMachine.transition(
            contained, QuarantineState.DELETED, 400, QuarantineActor.AUTOMATION
        )
        assertTrue(autoDelete is QuarantineTransitionResult.Rejected)
        val userDelete = accepted(contained, QuarantineState.DELETED, QuarantineActor.USER_ACTION, 500)
        assertEquals(QuarantineState.DELETED, userDelete.state)

        val failedResult = QuarantineStateMachine.transition(
            record(), QuarantineState.FAILED, 200, QuarantineActor.AUTOMATION, "oem_denied"
        ) as QuarantineTransitionResult.Accepted
        val failedUserDelete = accepted(
            failedResult.record, QuarantineState.DELETED, QuarantineActor.USER_ACTION, 300
        )
        assertEquals(QuarantineState.DELETED, failedUserDelete.state)
    }

    @Test
    fun pendingAssistCanOnlyBeCancelledByAnExplicitUserAction() {
        val pending = accepted(record(), QuarantineState.PENDING, QuarantineActor.AUTOMATION, 200)
        assertTrue(
            QuarantineStateMachine.transition(
                pending, QuarantineState.CANCELLED, 300, QuarantineActor.AUTOMATION
            ) is QuarantineTransitionResult.Rejected
        )
        val cancelled = accepted(pending, QuarantineState.CANCELLED, QuarantineActor.USER_ACTION, 400)
        assertEquals(QuarantineState.CANCELLED, cancelled.state)
    }

    @Test
    fun invalidTransitionsAndFailedStateWithoutCodeAreRejected() {
        assertTrue(
            QuarantineStateMachine.transition(
                record(), QuarantineState.QUARANTINED, 200, QuarantineActor.AUTOMATION
            ) is QuarantineTransitionResult.Rejected
        )
        assertTrue(
            QuarantineStateMachine.transition(
                record(), QuarantineState.FAILED, 200, QuarantineActor.AUTOMATION
            ) is QuarantineTransitionResult.Rejected
        )
        val failed = QuarantineStateMachine.transition(
            record(), QuarantineState.FAILED, 200, QuarantineActor.AUTOMATION, "oem_denied"
        )
        assertTrue(failed is QuarantineTransitionResult.Accepted)
        assertEquals("oem_denied", (failed as QuarantineTransitionResult.Accepted).record.failureCode)
    }

    @Test
    fun bypassCannotBePermanentAndExpiresAtOrBefore24Hours() {
        val now = 1_000_000L
        val bypass = QuarantineBypass.issue("org.example.app", now, Long.MAX_VALUE)
        assertNotNull(bypass)
        assertEquals(now + QuarantineBypass.MAX_DURATION_MILLIS, bypass!!.expiresAtMillis)
        assertTrue(bypass.isActiveAt(bypass.expiresAtMillis - 1))
        assertFalse(bypass.isActiveAt(bypass.expiresAtMillis))
        assertEquals(null, QuarantineBypass.issue("", now, 1000))
        assertEquals(null, QuarantineBypass.issue("org.example.app", now, 0))
    }

    private fun accepted(
        start: QuarantineRecord,
        state: QuarantineState,
        actor: QuarantineActor,
        now: Long
    ): QuarantineRecord {
        val result = QuarantineStateMachine.transition(start, state, now, actor)
        assertTrue("$state should be accepted", result is QuarantineTransitionResult.Accepted)
        return (result as QuarantineTransitionResult.Accepted).record
    }
}
