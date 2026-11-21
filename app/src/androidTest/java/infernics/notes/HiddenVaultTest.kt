package infernics.notes

import androidx.test.ext.junit.runners.AndroidJUnit4

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class HiddenVaultTest {
    @Test
    fun independentPassphraseUnlocksOnlyItsOwnVerifier() {
        val password = "separate-secret-phrase-2026"
        val salt = Crypto.newSalt()
        val record = HiddenVault.createRecord(password, salt)

        val unlocked = HiddenVault.unlockFromRecord(password, record)
        assertNotNull(unlocked)
        unlocked!!.destroy()

        assertNull(HiddenVault.unlockFromRecord("some-other-hidden-password", record))
    }

    @Test
    fun persistedVerifierDoesNotContainThePassphrase() {
        val password = "never-store-this-hidden-passphrase-2026"
        val salt = Crypto.newSalt()
        val record = HiddenVault.createRecord(password, salt)
        val serialized = String(record, Charsets.ISO_8859_1)
        assertFalse(serialized.contains(password))
        assertTrue(record.size > 16 + 4)
    }

    @Test
    fun malformedOrTamperedHiddenVerifierIsRejected() {
        val salt = Crypto.newSalt()
        val record = HiddenVault.createRecord("long-hidden-password-123", salt)

        assertNull(HiddenVault.unlockFromRecord("long-hidden-password-123", record.copyOf(record.size - 1)))
        val modified = record.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertNull(HiddenVault.unlockFromRecord("long-hidden-password-123", modified))
    }
    @Test
    fun portableVerifierRecordHasAnExactExpectedLength() {
        val salt = Crypto.newSalt()
        val record = HiddenVault.createRecord("portable-hidden-password-2026", salt)
        assertTrue(HiddenVault.isValidRecord(record))
        assertFalse(HiddenVault.isValidRecord(record.copyOf(record.size + 1)))
        assertFalse(HiddenVault.isValidRecord(record.copyOf(record.size - 1)))
    }

    @Test
    fun acceptsASingleCharacterHiddenPasswordAndRejectsOnlyEmptyInput() {
        val salt = Crypto.newSalt()
        val record = HiddenVault.createRecord("h", salt)
        val unlocked = HiddenVault.unlockFromRecord("h", record)
        assertNotNull(unlocked)
        unlocked!!.destroy()
        assertNull(HiddenVault.unlockFromRecord("", record))
    }

    @Test(expected = IllegalArgumentException::class)
    fun doesNotAllowAnEmptyHiddenPassword() {
        HiddenVault.createRecord("", Crypto.newSalt())
    }

    @Test
    fun hiddenWipeRemovesOnlyHiddenFilesAndHiddenTemporaryPreviews() {
        val root = java.nio.file.Files.createTempDirectory("secnote-hidden-wipe-test").toFile()
        val files = java.io.File(root, "files").apply { mkdirs() }
        val cache = java.io.File(root, "cache").apply { mkdirs() }
        try {
            val hidden = java.io.File(files, HiddenVault.DIRECTORY_NAME).apply { mkdirs() }
            java.io.File(hidden, "secret.data.enc").writeBytes(byteArrayOf(1, 2, 3, 4))
            java.io.File(files, HiddenVault.METADATA_FILE_NAME).writeBytes(byteArrayOf(5, 6, 7))
            java.io.File(files, "${HiddenVault.METADATA_FILE_NAME}.bak").writeBytes(byteArrayOf(7, 6, 5))
            java.io.File(files, "${HiddenVault.METADATA_FILE_NAME}.new").writeBytes(byteArrayOf(4, 3, 2))
            java.io.File(files, "file_vault").apply { mkdirs() }
                .resolve("primary.data.enc").writeBytes(byteArrayOf(8, 9))
            java.io.File(files, "notes").apply { mkdirs() }
                .resolve("primary-note.enc").writeBytes(byteArrayOf(10, 11))
            java.io.File(files, "key.salt").writeBytes(byteArrayOf(12, 13))
            java.io.File(cache, "media-thumbnail-secret.tmp").writeBytes(byteArrayOf(14, 15))
            java.io.File(cache, "secnote-thumbnail-primary.tmp").writeBytes(byteArrayOf(16, 17))

            HiddenVault.wipeLocalPayload(files, cache)

            assertFalse(hidden.exists())
            assertFalse(java.io.File(files, HiddenVault.METADATA_FILE_NAME).exists())
            assertFalse(java.io.File(files, "${HiddenVault.METADATA_FILE_NAME}.bak").exists())
            assertFalse(java.io.File(files, "${HiddenVault.METADATA_FILE_NAME}.new").exists())
            assertFalse(java.io.File(cache, "media-thumbnail-secret.tmp").exists())
            assertTrue(java.io.File(files, "file_vault/primary.data.enc").isFile)
            assertTrue(java.io.File(files, "notes/primary-note.enc").isFile)
            assertTrue(java.io.File(files, "key.salt").isFile)
            assertTrue(java.io.File(cache, "secnote-thumbnail-primary.tmp").isFile)
        } finally {
            root.deleteRecursively()
        }
    }

}
