package infernics.notes

import androidx.test.ext.junit.runners.AndroidJUnit4

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

@RunWith(AndroidJUnit4::class)
class CryptoTest {
    @Test
    fun passphrasesPreserveUnicodeAndLongInputWithoutTruncation() {
        val salt = Crypto.newSalt()
        val passphrase = "Пароль🔐" + "длинный".repeat(150)
        val crypto = Crypto.fromPassphrase(passphrase, salt)
        val encrypted = crypto.encrypt("unicode password check")
        assertEquals("unicode password check", crypto.decryptToText(encrypted))
        val different = Crypto.fromPassphrase(passphrase + "x", salt)
        try {
            different.decryptToText(encrypted)
            fail("A changed long Unicode passphrase must not authenticate")
        } catch (_: Exception) {

        } finally {
            crypto.destroy()
            different.destroy()
            salt.fill(0)
        }
    }

    @Test
    fun encryptDecryptTextRoundTrip() {
        val crypto = Crypto.fromPassphrase("correct horse battery", Crypto.newSalt())
        val encrypted = crypto.encrypt("SecNote private note")
        assertEquals("SecNote private note", crypto.decryptToText(encrypted))
    }

    @Test
    fun streamingFileRoundTrip() {
        val crypto = Crypto.fromPassphrase("correct horse battery", Crypto.newSalt())
        val original = ByteArray(512 * 1024) { (it % 251).toByte() }
        val encrypted = ByteArrayOutputStream()
        crypto.encryptStream(ByteArrayInputStream(original), encrypted)

        val decrypted = ByteArrayOutputStream()
        crypto.decryptStream(ByteArrayInputStream(encrypted.toByteArray()), decrypted)
        assertArrayEquals(original, decrypted.toByteArray())
    }

    @Test
    fun portableBackupEnvelopeRoundTripsWithItsOwnPassword() {
        val archivePlaintext = ByteArray(700_000) { ((it * 31) % 251).toByte() }
        val backupPassword = "different backup phrase"
        val backupSalt = Crypto.newSalt()
        val backupCrypto = Crypto.fromPassphrase(backupPassword, backupSalt)
        val encryptedBackup = ByteArrayOutputStream()
        encryptedBackup.write("SCNBKUP2".toByteArray(Charsets.US_ASCII))
        encryptedBackup.write(backupSalt)
        backupCrypto.encryptStream(ByteArrayInputStream(archivePlaintext), encryptedBackup)

        val encoded = encryptedBackup.toByteArray()
        val headerSize = 8 + Crypto.SALT_LENGTH
        assertArrayEquals("SCNBKUP2".toByteArray(Charsets.US_ASCII), encoded.copyOfRange(0, 8))
        val importedSalt = encoded.copyOfRange(8, headerSize)
        val importedCrypto = Crypto.fromPassphrase(backupPassword, importedSalt)
        val restored = ByteArrayOutputStream()
        importedCrypto.decryptStream(ByteArrayInputStream(encoded.copyOfRange(headerSize, encoded.size)), restored)
        assertArrayEquals(archivePlaintext, restored.toByteArray())

        val wrongPassword = Crypto.fromPassphrase("another backup phrase", importedSalt)
        try {
            wrongPassword.decryptStream(ByteArrayInputStream(encoded.copyOfRange(headerSize, encoded.size)), ByteArrayOutputStream())
            fail("The backup must not decrypt with a different password")
        } catch (_: Exception) {

        }
        backupCrypto.destroy()
        importedCrypto.destroy()
        wrongPassword.destroy()
        backupSalt.fill(0)
        importedSalt.fill(0)
        archivePlaintext.fill(0)
    }

    @Test
    fun jpegPayloadSurvivesVaultStreamingEncryption() {
        val crypto = Crypto.fromPassphrase("correct horse battery", Crypto.newSalt())
        val original = ByteArray(384 * 1024) { (it % 251).toByte() }.also {
            it[0] = 0xFF.toByte()
            it[1] = 0xD8.toByte()
            it[it.lastIndex - 1] = 0xFF.toByte()
            it[it.lastIndex] = 0xD9.toByte()
        }
        val encrypted = ByteArrayOutputStream()
        crypto.encryptStream(ByteArrayInputStream(original), encrypted)
        val decrypted = ByteArrayOutputStream()
        crypto.decryptStream(ByteArrayInputStream(encrypted.toByteArray()), decrypted)
        assertArrayEquals(original, decrypted.toByteArray())
    }

    @Test
    fun tamperedCiphertextIsRejected() {
        val crypto = Crypto.fromPassphrase("correct horse battery", Crypto.newSalt())
        val encrypted = crypto.encrypt("authenticated content").also {
            it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
        }

        try {
            crypto.decryptToText(encrypted)
            fail("GCM must reject modified ciphertext")
        } catch (_: Exception) {

        }
    }

    @Test
    fun tamperedStreamIsRejected() {
        val crypto = Crypto.fromPassphrase("correct horse battery", Crypto.newSalt())
        val encrypted = ByteArrayOutputStream().also {
            crypto.encryptStream(ByteArrayInputStream(ByteArray(32_000) { it.toByte() }), it)
        }.toByteArray()
        encrypted[encrypted.lastIndex] = (encrypted.last().toInt() xor 1).toByte()

        try {
            crypto.decryptStream(ByteArrayInputStream(encrypted), ByteArrayOutputStream())
            fail("GCM must reject a modified file stream")
        } catch (_: Exception) {

        }
    }
    @Test
    fun truncatedStreamIsRejected() {
        val crypto = Crypto.fromPassphrase("correct horse battery", Crypto.newSalt())
        val encrypted = ByteArrayOutputStream().also {
            crypto.encryptStream(ByteArrayInputStream(ByteArray(150_000) { (it % 239).toByte() }), it)
        }.toByteArray()
        val truncated = encrypted.copyOf(encrypted.size - 1)

        try {
            crypto.decryptStream(ByteArrayInputStream(truncated), ByteArrayOutputStream())
            fail("Truncated encrypted stream must be rejected")
        } catch (_: Exception) {

        }
    }

    @Test
    fun destroyedContentKeyCannotBeUsedAgain() {
        val crypto = Crypto.fromPassphrase("correct horse battery", Crypto.newSalt())
        val encrypted = crypto.encrypt("private")
        assertEquals("private", crypto.decryptToText(encrypted))

        crypto.destroy()
        try {
            crypto.decryptToText(encrypted)
            fail("A destroyed in-memory content key must not decrypt data")
        } catch (_: Exception) {

        }
    }

    @Test
    fun emergencyDestroyClearsEveryLiveSessionKey() {
        val first = Crypto.fromRawKeyBytes(ByteArray(32) { 0x11 })
        val second = Crypto.fromRawKeyBytes(ByteArray(32) { 0x22 })
        val firstBlob = first.encrypt("primary")
        val secondBlob = second.encrypt("hidden")

        Crypto.destroyAll()

        try {
            first.decryptToText(firstBlob)
            fail("Emergency cleanup must destroy the primary content key")
        } catch (_: Exception) { }
        try {
            second.decryptToText(secondBlob)
            fail("Emergency cleanup must destroy the hidden content key")
        } catch (_: Exception) { }
    }

    @Test
    fun contextualRecordCannotBeMovedBetweenObjects() {
        val crypto = Crypto.fromPassphrase("correct horse battery", Crypto.newSalt())
        val firstContext = Crypto.contextAad("note-record", "note-one")
        val secondContext = Crypto.contextAad("note-record", "note-two")
        val differentDomain = Crypto.contextAad("file-metadata", "note-one")
        val encrypted = crypto.encrypt("private note", firstContext)
        assertEquals("private note", crypto.decryptToText(encrypted, firstContext))
        try {
            crypto.decryptToText(encrypted, secondContext)
            fail("Ciphertext must not authenticate under a different object ID")
        } catch (_: Exception) {

        }
        try {
            crypto.decryptToText(encrypted, differentDomain)
            fail("Ciphertext must not authenticate under a different record domain")
        } catch (_: Exception) {

        } finally {
            firstContext.fill(0)
            secondContext.fill(0)
            differentDomain.fill(0)
            encrypted.fill(0)
        }
    }

    @Test
    fun legacyRecordRemainsReadableForMigration() {
        val crypto = Crypto.fromPassphrase("correct horse battery", Crypto.newSalt())
        val legacy = crypto.encrypt("legacy record")
        val context = Crypto.contextAad("note-record", "legacy-id")
        assertEquals(false, crypto.isContextualRecord(legacy))
        assertEquals("legacy record", crypto.decryptToText(legacy, context))
        context.fill(0)
        legacy.fill(0)
    }

    @Test
    fun contextualFileStreamCannotBeMovedBetweenObjects() {
        val crypto = Crypto.fromPassphrase("correct horse battery", Crypto.newSalt())
        val original = ByteArray(150_000) { (it % 241).toByte() }
        val firstContext = Crypto.contextAad("file-data", "file-one")
        val secondContext = Crypto.contextAad("file-data", "file-two")
        val otherDomain = Crypto.contextAad("file-metadata", "file-one")
        val encrypted = ByteArrayOutputStream()
        crypto.encryptStream(ByteArrayInputStream(original), encrypted, firstContext)

        val restored = ByteArrayOutputStream()
        crypto.decryptStream(ByteArrayInputStream(encrypted.toByteArray()), restored, firstContext)
        assertArrayEquals(original, restored.toByteArray())
        listOf(secondContext, otherDomain).forEach { wrongContext ->
            try {
                crypto.decryptStream(ByteArrayInputStream(encrypted.toByteArray()), ByteArrayOutputStream(), wrongContext)
                fail("A context-bound file stream must reject another ID or domain")
            } catch (_: Exception) {

            }
        }
        try {
            crypto.decryptStream(ByteArrayInputStream(encrypted.toByteArray()), ByteArrayOutputStream())
            fail("SNF2 must require its object context")
        } catch (_: Exception) {

        } finally {
            original.fill(0)
            firstContext.fill(0)
            secondContext.fill(0)
            otherDomain.fill(0)
            encrypted.toByteArray().fill(0)
        }
    }

    @Test
    fun legacyStreamCanBeMigratedToContextBoundFormat() {
        val crypto = Crypto.fromPassphrase("correct horse battery", Crypto.newSalt())
        val original = ByteArray(180_000) { (it % 227).toByte() }
        val legacy = ByteArrayOutputStream()
        crypto.encryptStream(ByteArrayInputStream(original), legacy)

        val context = Crypto.contextAad("file-data", "migrated-file")
        val plaintext = ByteArrayOutputStream()
        crypto.decryptStream(ByteArrayInputStream(legacy.toByteArray()), plaintext, context)
        val migrated = ByteArrayOutputStream()
        crypto.encryptStream(ByteArrayInputStream(plaintext.toByteArray()), migrated, context)

        val migratedBytes = migrated.toByteArray()
        assertArrayEquals(byteArrayOf(0x53, 0x4E, 0x46, 0x32), migratedBytes.copyOfRange(0, 4))
        val restored = ByteArrayOutputStream()
        crypto.decryptStream(ByteArrayInputStream(migratedBytes), restored, context)
        assertArrayEquals(original, restored.toByteArray())

        try {
            crypto.decryptStream(
                ByteArrayInputStream(migratedBytes),
                ByteArrayOutputStream(),
                Crypto.contextAad("file-data", "different-file")
            )
            fail("Migrated content must be bound to its original file ID")
        } catch (_: Exception) {

        } finally {
            context.fill(0)
            original.fill(0)
            plaintext.toByteArray().fill(0)
            migratedBytes.fill(0)
        }
    }

    @Test
    fun legacyFileStreamRemainsReadableThroughContextAwareApi() {
        val crypto = Crypto.fromPassphrase("correct horse battery", Crypto.newSalt())
        val original = ByteArray(90_000) { (it % 233).toByte() }
        val legacy = ByteArrayOutputStream()
        crypto.encryptStream(ByteArrayInputStream(original), legacy)
        val context = Crypto.contextAad("file-data", "legacy-file")
        val restored = ByteArrayOutputStream()
        crypto.decryptStream(ByteArrayInputStream(legacy.toByteArray()), restored, context)
        assertArrayEquals(original, restored.toByteArray())
        context.fill(0)
        original.fill(0)
    }

}
