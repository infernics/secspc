package infernics.notes

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PasswordKdfTest {
    @Test
    fun saltContainsAnExplicitSupportedProfileAndUniqueRandomMaterial() {
        val first = PasswordKdf.newSalt()
        val second = PasswordKdf.newSalt()
        try {
            assertTrue(PasswordKdf.isValidSalt(first))
            assertTrue(PasswordKdf.isValidSalt(second))
            assertNotEquals(first.toList(), second.toList())
            assertFalse(PasswordKdf.isValidSalt(first.copyOf(first.size - 1)))
            val unsupported = first.copyOf().also { it[4] = 99 }
            assertFalse(PasswordKdf.isValidSalt(unsupported))
        } finally {
            first.fill(0)
            second.fill(0)
        }
    }
}
