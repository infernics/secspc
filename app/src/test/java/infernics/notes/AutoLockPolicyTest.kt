package infernics.notes

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AutoLockPolicyTest {
    @Test
    fun supportedIntervalsIncludeAllRequestedChoices() {
        assertEquals(setOf(-1, 0, 1, 5, 10, 15, 30), AutoLockPolicy.supportedMinutes)
    }

    @Test
    fun neverDoesNotLockWhenAppReturnsFromBackground() {
        assertEquals(0L, AutoLockPolicy.timeoutMillis(-1))
        assertFalse(AutoLockPolicy.shouldLockImmediately(-1))
        assertFalse(AutoLockPolicy.shouldLockAfterBackground(-1, 24 * 60 * 60 * 1000L))
    }

    @Test
    fun immediateLocksAsSoonAsAppGoesToBackground() {
        assertTrue(AutoLockPolicy.shouldLockImmediately(0))
        assertFalse(AutoLockPolicy.shouldLockAfterBackground(0, 0L))
    }

    @Test
    fun delayedLockUsesSelectedNumberOfMinutes() {
        assertEquals(10 * 60_000L, AutoLockPolicy.timeoutMillis(10))
        assertFalse(AutoLockPolicy.shouldLockAfterBackground(10, 9 * 60_000L))
        assertTrue(AutoLockPolicy.shouldLockAfterBackground(10, 10 * 60_000L))
    }
}
