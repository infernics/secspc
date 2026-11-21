package infernics.notes

import androidx.test.ext.junit.runners.AndroidJUnit4

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class PanicCredentialTest {
    @Test
    fun verifierAcceptsOnlyTheConfiguredSecret() {
        val salt = Crypto.newSalt()
        val record = PanicCredential.createRecord("emergency-code-42", salt)

        assertTrue(PanicCredential.verifyRecord("emergency-code-42", record))
        assertFalse(PanicCredential.verifyRecord("another-password", record))
    }

    @Test
    fun verifierRejectsMalformedOrTruncatedRecords() {
        val salt = Crypto.newSalt()
        val record = PanicCredential.createRecord("emergency-code-42", salt)

        assertFalse(PanicCredential.verifyRecord("emergency-code-42", record.copyOf(record.size - 1)))
        val modified = record.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertFalse(PanicCredential.verifyRecord("emergency-code-42", modified))
    }
    @Test
    fun acceptsASingleCharacterSecretAndRejectsOnlyEmptyInput() {
        val salt = Crypto.newSalt()
        val record = PanicCredential.createRecord("x", salt)
        assertTrue(PanicCredential.verifyRecord("x", record))
        assertFalse(PanicCredential.verifyRecord("", record))
    }

    @Test(expected = IllegalArgumentException::class)
    fun doesNotAllowAnEmptyEmergencySecret() {
        PanicCredential.createRecord("", Crypto.newSalt())
    }

}
