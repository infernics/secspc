package infernics.notes

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class PasswordKdfInstrumentedTest {
    @Test
    fun argon2idDerivationIsDeterministicAndUsesTheEntireUnicodePassphrase() {
        val salt = PasswordKdf.newSalt()
        val firstPassword = "Пароль🔐" + "длинный".repeat(150)
        val first = PasswordKdf.derive(firstPassword, salt)
        val repeated = PasswordKdf.derive(firstPassword, salt)
        val changed = PasswordKdf.derive(firstPassword + "x", salt)
        try {
            assertEquals(32, first.size)
            assertArrayEquals(first, repeated)
            assertFalse(first.contentEquals(changed))
        } finally {
            salt.fill(0)
            first.fill(0)
            repeated.fill(0)
            changed.fill(0)
        }
    }

    @Test
    fun matchesArgon2idVersion13ReferenceVector() {
        val salt = byteArrayOf(
            0x53, 0x4B, 0x44, 0x46, 0x01,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        )
        val expected = "3f27c8d9d9843167d527d7e9fa27535c4999b6cf249d0e3b765cc917bd76fb52"
            .chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val actual = PasswordKdf.derive("SecNote Argon2id test", salt)
        try {
            assertArrayEquals(expected, actual)
        } finally {
            salt.fill(0)
            expected.fill(0)
            actual.fill(0)
        }
    }
}
