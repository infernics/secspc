package infernics.notes

import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class BackupArchiveRulesTest {
    @Test
    fun acceptsOnlyExpectedEncryptedPayloadPaths() {
        assertTrue(BackupArchiveRules.isAllowedEntryPath("notes/7c0d9d3d-1f91-4d90-a9db-1a6f19ab67b1.enc"))
        assertTrue(BackupArchiveRules.isAllowedEntryPath("file_vault/7c0d9d3d-1f91-4d90-a9db-1a6f19ab67b1.data.enc"))
        assertTrue(BackupArchiveRules.isAllowedEntryPath("hidden/${HiddenVault.DIRECTORY_NAME}/7c0d9d3d-1f91-4d90-a9db-1a6f19ab67b1.meta.enc"))
        assertTrue(BackupArchiveRules.isAllowedEntryPath("hidden/${HiddenVault.METADATA_FILE_NAME}"))
        assertTrue(BackupArchiveRules.isAllowedEntryPath("security/main-check.enc"))
        assertFalse(BackupArchiveRules.isAllowedEntryPath("../outside.enc"))
        assertFalse(BackupArchiveRules.isAllowedEntryPath("notes/../../outside.enc"))
        assertFalse(BackupArchiveRules.isAllowedEntryPath("security/biometric-key"))
        assertFalse(BackupArchiveRules.isAllowedEntryPath("/absolute/path.enc"))
    }

    @Test
    fun usesTheCurrentPanicCredentialRecordLength() {
        assertEquals(4L + PasswordKdf.SALT_LENGTH + 32L,
            BackupArchiveRules.maximumEntrySize("security/panic.credential"))
    }

    @Test
    fun validatesPairedFilePayloads() {
        BackupArchiveRules.validateFilePairs(
            setOf(
                "security/main-check.enc",
                "file_vault/item-1.data.enc",
                "file_vault/item-1.meta.enc",
                "hidden/${HiddenVault.METADATA_FILE_NAME}",
                "hidden/${HiddenVault.DIRECTORY_NAME}/item-2.data.enc",
                "hidden/${HiddenVault.DIRECTORY_NAME}/item-2.meta.enc"
            )
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsOrphanedEncryptedFile() {
        BackupArchiveRules.validateFilePairs(
            setOf("security/main-check.enc", "file_vault/item-1.data.enc")
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsHiddenPayloadWithoutItsVerifierMetadata() {
        BackupArchiveRules.validateFilePairs(
            setOf(
                "security/main-check.enc",
                "hidden/${HiddenVault.DIRECTORY_NAME}/item-2.data.enc",
                "hidden/${HiddenVault.DIRECTORY_NAME}/item-2.meta.enc"
            )
        )
    }
}

class BackupImportInputValidationTest {
    @Test
    fun requiresBothNonEmptyPasswordsButHasNoMinimumLength() {
        assertTrue(BackupImportInputValidation.error("", "m")!!.contains("пароль резервной копии"))
        assertTrue(
            BackupImportInputValidation.error("b", "")!!
                .contains("прежний основной пароль")
        )
        assertTrue(BackupImportInputValidation.error("b", "m") == null)
    }

    @Test
    fun rejectsUsingTheSamePasswordForBothFields() {
        assertTrue(BackupImportInputValidation.error("x", "x")!!.contains("должны отличаться"))
    }
}
