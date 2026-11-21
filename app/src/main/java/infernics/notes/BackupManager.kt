package infernics.notes

import android.content.Context
import android.net.Uri
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.security.MessageDigest
import java.nio.ByteBuffer
import java.util.UUID
import java.util.concurrent.atomic.AtomicReference
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

internal data class BackupSettings(
    val darkTheme: Boolean,
    val screenshotBlocking: Boolean,
    val autoLockMinutes: Int
)

internal data class BackupRestoreResult(
    val crypto: Crypto,
    val settings: BackupSettings,
    val hiddenVaultConfigured: Boolean,
    val panicPasswordConfigured: Boolean
)

internal class BackupRestoreException(
    message: String,
    val recoveredSessionCrypto: Crypto? = null,
    cause: Throwable? = null
) : Exception(message, cause)

internal object BackupImportInputValidation {
    fun error(backupPassword: String, sourceMainPassword: String): String? = when {
        backupPassword.isEmpty() -> "Введите пароль резервной копии."
        sourceMainPassword.isEmpty() -> "Введите прежний основной пароль SecNote, которым пользовались при создании этой копии. Новый пароль после очистки данных не подойдёт."
        backupPassword == sourceMainPassword -> "Пароль архива и прежний основной пароль должны отличаться."
        else -> null
    }
}

internal object BackupArchiveRules {
    private val simpleEncryptedName = Regex("[A-Za-z0-9_-]{1,128}\\.enc")
    private val fileEncryptedName = Regex("[A-Za-z0-9_-]{1,128}\\.(data|meta)\\.enc")

    fun isAllowedEntryPath(path: String): Boolean {
        if (path.isBlank() || path.startsWith('/') || path.startsWith('\\') || path.contains('\\')) return false
        if (path.split('/').any { it.isBlank() || it == "." || it == ".." }) return false
        return when {
            path.startsWith("notes/") -> simpleEncryptedName.matches(path.removePrefix("notes/"))
            path.startsWith("file_vault/") -> fileEncryptedName.matches(path.removePrefix("file_vault/"))
            path.startsWith("hidden/${HiddenVault.DIRECTORY_NAME}/") ->
                fileEncryptedName.matches(path.removePrefix("hidden/${HiddenVault.DIRECTORY_NAME}/"))
            path == "hidden/${HiddenVault.METADATA_FILE_NAME}" -> true
            path == "security/main-check.enc" -> true
            path == "security/panic.credential" -> true
            else -> false
        }
    }

    fun maximumEntrySize(path: String): Long = when {
        path == "security/main-check.enc" -> 128L
        path == "security/panic.credential" -> (4L + PasswordKdf.SALT_LENGTH + 32L)
        path == "hidden/${HiddenVault.METADATA_FILE_NAME}" -> 4096L
        path.endsWith(".meta.enc") -> 1024L * 1024L
        path.startsWith("notes/") -> 16L * 1024L * 1024L
        else -> 1024L * 1024L * 1024L
    }

    fun validateFilePairs(paths: Set<String>) {
        require("security/main-check.enc" in paths) { "В резервной копии отсутствует проверка основного ключа." }
        val primaryIds = paths.filter { it.startsWith("file_vault/") }
            .groupBy { encryptedFileId(it.substringAfter('/')) }
        primaryIds.values.forEach { pair ->
            require(pair.size == 2 && pair.any { it.endsWith(".data.enc") } && pair.any { it.endsWith(".meta.enc") }) {
                "В резервной копии найдена неполная пара файлов основного хранилища."
            }
        }

        val hiddenPrefix = "hidden/${HiddenVault.DIRECTORY_NAME}/"
        val hiddenIds = paths.filter { it.startsWith(hiddenPrefix) }
            .groupBy { encryptedFileId(it.removePrefix(hiddenPrefix)) }
        hiddenIds.values.forEach { pair ->
            require(pair.size == 2 && pair.any { it.endsWith(".data.enc") } && pair.any { it.endsWith(".meta.enc") }) {
                "В резервной копии найдена неполная пара зашифрованных файлов."
            }
        }
        val hasHiddenFiles = paths.any { it.startsWith(hiddenPrefix) }
        require(!hasHiddenFiles || "hidden/${HiddenVault.METADATA_FILE_NAME}" in paths) {
            "В зашифрованной области файлов отсутствует ключевое описание."
        }
    }

    private fun encryptedFileId(name: String): String =
        name.removeSuffix(".data.enc").removeSuffix(".meta.enc")
}

internal object BackupManager {
    private const val BACKUP_MAGIC = "SCNBKUP2"
    private const val MANIFEST_NAME = "backup-manifest.json"
    private const val RESTORE_MARKER = "secnote_backup_restore.pending"
    private const val MAX_ENTRIES = 50_000
    private const val MAX_TOTAL_BYTES = 2L * 1024L * 1024L * 1024L
    private const val MAX_MANIFEST_BYTES = 4L * 1024L * 1024L
    private const val MAX_NOTE_BYTES = 16L * 1024L * 1024L
    private const val PIPE_BUFFER_BYTES = 256 * 1024
    private val TARGET_NAMES = listOf(
        "notes", "file_vault", HiddenVault.DIRECTORY_NAME,
        HiddenVault.METADATA_FILE_NAME, "key.salt", "key.check", "panic.credential"
    )

    private data class SourceEntry(val archivePath: String, val file: File)
    private data class ExpectedEntry(val size: Long, val sha256: String)

    fun exportBackup(context: Context, currentCrypto: Crypto, backupPassword: String, destination: Uri) {
        require(backupPassword.isNotEmpty()) { "Введите пароль резервной копии." }
        require(!Vault.matchesPassphrase(context, backupPassword)) {
            "Пароль резервной копии должен отличаться от основного пароля."
        }
        require(!HiddenVault.matchesPassphrase(context, backupPassword)) {
            "Пароль резервной копии должен отличаться от дополнительного пароля."
        }
        require(!PanicCredential.verify(context, backupPassword)) {
            "Пароль резервной копии должен отличаться от секретного пароля уничтожения."
        }
        StorageGate.withExclusiveAccess {
            val mainSalt = Vault.exportSaltForBackup(context, currentCrypto)
            val backupSalt = Crypto.newSalt()
            val backupCrypto = try {
                Crypto.fromPassphrase(backupPassword, backupSalt)
            } catch (error: Throwable) {
                mainSalt.fill(0)
                backupSalt.fill(0)
                throw error
            }

            var pipeInput: PipedInputStream? = null
            var pipeOutput: PipedOutputStream? = null
            var writer: Thread? = null
            var manifest: String? = null
            var exportComplete = false
            val writerFailure = AtomicReference<Throwable?>(null)
            try {
                val sources = collectSourceEntries(context)
                val manifestText = buildManifest(context, mainSalt, sources)
                manifest = manifestText
                val streamInput = PipedInputStream(PIPE_BUFFER_BYTES)
                val streamOutput = PipedOutputStream(streamInput)
                pipeInput = streamInput
                pipeOutput = streamOutput
                val zipWriter = Thread({
                    try {
                        ZipOutputStream(BufferedOutputStream(streamOutput, 64 * 1024)).use { zip ->
                            zip.setLevel(0)
                            writeZipEntry(zip, MANIFEST_NAME, manifestText.toByteArray(Charsets.UTF_8))
                            sources.forEach { entry ->
                                val zipEntry = ZipEntry(entry.archivePath)
                                zip.putNextEntry(zipEntry)
                                FileInputStream(entry.file).use { input -> input.copyTo(zip, 64 * 1024) }
                                zip.closeEntry()
                            }
                        }
                    } catch (error: Throwable) {
                        writerFailure.set(error)
                        runCatching { streamOutput.close() }
                    }
                }, "SecNoteBackupZipWriter")
                writer = zipWriter
                zipWriter.start()
                val rawOutput = context.contentResolver.openOutputStream(destination, "w")
                    ?: error("Не удалось открыть файл резервной копии для записи.")
                rawOutput.use { output ->
                    output.write(BACKUP_MAGIC.toByteArray(Charsets.US_ASCII))
                    output.write(backupSalt)
                    output.flush()
                    backupCrypto.encryptStream(streamInput, output)
                    output.flush()
                }
                writer.join()
                writerFailure.get()?.let {
                    throw IllegalStateException("Не удалось сформировать архив резервной копии.", it)
                }
                exportComplete = true
            } finally {
                if (!exportComplete) {
                    pipeInput?.let { runCatching { it.close() } }
                    runCatching { context.contentResolver.delete(destination, null, null) }
                }
                writer?.let { if (it.isAlive) it.join() }
                pipeOutput?.let { runCatching { it.close() } }
                pipeInput?.let { runCatching { it.close() } }
                backupCrypto.destroy()
                mainSalt.fill(0)
                backupSalt.fill(0)
                manifest?.toByteArray(Charsets.UTF_8)?.fill(0)
            }
        }
    }

    fun restoreBackup(
        context: Context,
        currentCrypto: Crypto,
        source: Uri,
        backupPassword: String,
        sourceMainPassword: String,
        onProgress: (String) -> Unit = {}
    ): BackupRestoreResult {
        BackupImportInputValidation.error(backupPassword, sourceMainPassword)?.let { error(it) }
        fun progress(stage: String) { runCatching { onProgress(stage) } }

        val oldSessionKey = currentCrypto.exportKeyForBiometricWrapping()
        val transaction = File(context.noBackupFilesDir, "secnote_restore_${UUID.randomUUID()}")
        val payload = File(transaction, "payload")
        val rollback = File(transaction, "rollback")
        var gateBlocked = false
        var keysDestroyed = false
        var primarySalt: ByteArray? = null

        try {
            progress("Подготавливаю временную область восстановления…")
            check(payload.mkdirs()) { "Не удалось подготовить временную область восстановления." }
            progress("Проверяю пароль и целостность архива…")
            val extractedManifest = decryptAndStage(context, source, backupPassword, payload).also { manifest ->
                primarySalt = Base64.decode(manifest.getString("mainSalt"), Base64.NO_WRAP)
            }
            val salt = primarySalt ?: error("В резервной копии отсутствует соль основного ключа.")
            require(PasswordKdf.isValidSalt(salt)) { "Некорректный формат основного ключа в резервной копии." }
            val settings = parseSettings(extractedManifest.getJSONObject("settings"))
            progress("Проверяю прежний основной пароль, заметки и файлы…")
            validateVaultPayload(payload, salt, sourceMainPassword)

            val hiddenConfigured = File(payload, "hidden/${HiddenVault.METADATA_FILE_NAME}").isFile
            val panicConfigured = File(payload, "security/panic.credential").isFile

            progress("Готовлю безопасный откат текущих данных…")
            StorageGate.blockAndDrain()
            gateBlocked = true
            snapshotCurrentState(context, rollback)
            writeRestoreMarker(context, transaction.name)
            progress("Восстанавливаю заметки и файлы…")
            Crypto.destroyAll()
            keysDestroyed = true

            replaceFromPayload(context, payload)
            val restoredCrypto = Crypto.fromPassphrase(sourceMainPassword, salt)
            try {
                Vault.installPortableState(context, salt, restoredCrypto)
                progress("Восстанавливаю настройки…")
                AppPreferences.applyBackupSettings(context, settings)
                BiometricVault.disable(context)
                progress("Завершаю восстановление…")
                val marker = File(context.noBackupFilesDir, RESTORE_MARKER)
                deleteAtomicStateFile(marker)

                gateBlocked = false
                StorageGate.resumeAfterUnlock()
                deleteTreeBestEffort(transaction)
                progress("Готово")
                return BackupRestoreResult(
                    crypto = restoredCrypto,
                    settings = settings,
                    hiddenVaultConfigured = hiddenConfigured,
                    panicPasswordConfigured = panicConfigured
                )
            } catch (error: Throwable) {
                restoredCrypto.destroy()
                throw error
            }
        } catch (error: Throwable) {
            var recoveredCrypto: Crypto? = null
            if (gateBlocked) {
                val rollbackSucceeded = runCatching { recoverInterruptedRestore(context) }.getOrDefault(false)
                if (rollbackSucceeded) {
                    if (keysDestroyed) recoveredCrypto = runCatching { Crypto.fromRawKeyBytes(oldSessionKey) }.getOrNull()
                    StorageGate.resumeAfterUnlock()
                    gateBlocked = false
                }
            }
            if (!gateBlocked) deleteTreeBestEffort(transaction)
            throw BackupRestoreException(
                error.message ?: "Не удалось восстановить резервную копию.",
                recoveredSessionCrypto = recoveredCrypto,
                cause = error
            )
        } finally {
            primarySalt?.fill(0)
            oldSessionKey.fill(0)
        }
    }

    fun recoverInterruptedRestore(context: Context): Boolean {
        val marker = File(context.noBackupFilesDir, RESTORE_MARKER)
        if (!AtomicFileIO.existsRecoverable(marker)) {
            context.noBackupFilesDir.listFiles { file -> file.isDirectory && file.name.startsWith("secnote_restore_") }
                ?.forEach(::deleteTreeBestEffort)
            deleteTreeBestEffort(File(context.noBackupFilesDir, "$RESTORE_MARKER.tmp"))
            deleteTreeBestEffort(File(context.noBackupFilesDir, "$RESTORE_MARKER.bak"))
            return true
        }
        val transactionName = runCatching {
            String(AtomicFileIO.readBytes(marker), Charsets.US_ASCII).trim()
        }.getOrNull() ?: return false
        if (!transactionName.matches(Regex("secnote_restore_[A-Fa-f0-9-]{36}"))) return false
        val transaction = File(context.noBackupFilesDir, transactionName)
        val rollback = File(transaction, "rollback")
        val indexFile = File(rollback, "rollback-index.json")
        if (!indexFile.isFile) return false
        return runCatching {
            val index = JSONObject(indexFile.readText(Charsets.UTF_8))
            val existing = index.optJSONArray("existing") ?: JSONArray()
            val existingNames = buildSet {
                for (i in 0 until existing.length()) {
                    val name = existing.getString(i)
                    require(name in TARGET_NAMES) { "В журнале отката найден неизвестный объект." }
                    require(add(name)) { "В журнале отката повторяется объект." }
                }
            }
            val snapshotHashes = index.optJSONObject("snapshotSha256")

            existingNames.forEach { name ->
                val snapshot = File(rollback, name)
                check(snapshot.exists()) { "Не найдена резервная копия старого состояния: $name" }
                val expectedHash = snapshotHashes?.optString(name)?.takeIf { it.isNotBlank() }
                if (expectedHash != null) {
                    check(treeSha256(snapshot) == expectedHash) {
                        "Контрольная сумма копии для отката не совпадает: $name"
                    }
                }
            }
            val prefs = index.optJSONObject("preferences") ?: JSONObject()
            val restoredSettings = parseSettings(prefs)

            TARGET_NAMES.forEach { name ->
                val target = File(context.filesDir, name)
                deleteAtomicStateFile(target)
                if (name in existingNames) {
                    val snapshot = File(rollback, name)
                    copyTree(snapshot, target)
                    val expectedHash = snapshotHashes?.optString(name)?.takeIf { it.isNotBlank() }
                    if (expectedHash != null) {
                        check(treeSha256(target) == expectedHash) {
                            "Не удалось подтвердить восстановление прежнего объекта: $name"
                        }
                    } else {
                        check(treeSha256(snapshot) == treeSha256(target)) {
                            "Копия прежнего объекта не совпадает после восстановления: $name"
                        }
                    }
                }
            }
            AppPreferences.applyBackupSettings(context, restoredSettings)
            deleteAtomicStateFile(marker)
            deleteTreeBestEffort(transaction)
            true
        }.getOrDefault(false)
    }

    private fun collectSourceEntries(context: Context): List<SourceEntry> {
        val entries = mutableListOf<SourceEntry>()
        fun add(path: String, file: File) {
            require(file.isFile && file.length() <= MAX_TOTAL_BYTES) { "Некорректный файл в локальном хранилище: $path" }
            require(BackupArchiveRules.isAllowedEntryPath(path)) { "Недопустимый файл в локальном хранилище: $path" }
            entries += SourceEntry(path, file)
        }

        val notesDirectory = File(context.filesDir, "notes")
        val fileVaultDirectory = File(context.filesDir, "file_vault")
        recoverAtomicFiles(notesDirectory) { it.endsWith(".enc") }
        recoverAtomicFiles(fileVaultDirectory) { it.endsWith(".meta.enc") }
        notesDirectory.listFiles().orEmpty()
            .filter { it.isFile && it.name.endsWith(".enc") }
            .forEach { add("notes/${it.name}", it) }
        fileVaultDirectory.listFiles().orEmpty()
            .filter { it.isFile && (it.name.endsWith(".data.enc") || it.name.endsWith(".meta.enc")) }
            .forEach { add("file_vault/${it.name}", it) }

        val hiddenMetadata = File(context.filesDir, HiddenVault.METADATA_FILE_NAME)
        val hiddenDirectory = File(context.filesDir, HiddenVault.DIRECTORY_NAME)
        recoverAtomicFiles(hiddenDirectory) { it.endsWith(".meta.enc") }
        if (AtomicFileIO.existsRecoverable(hiddenMetadata)) {

            AtomicFileIO.readBytes(hiddenMetadata).fill(0)
        }
        if (hiddenMetadata.isFile) {
            add("hidden/${HiddenVault.METADATA_FILE_NAME}", hiddenMetadata)
            hiddenDirectory.listFiles().orEmpty()
                .filter { it.isFile && (it.name.endsWith(".data.enc") || it.name.endsWith(".meta.enc")) }
                .forEach { add("hidden/${HiddenVault.DIRECTORY_NAME}/${it.name}", it) }
        } else {
            require(hiddenDirectory.listFiles().orEmpty().none { it.isFile && (it.name.endsWith(".data.enc") || it.name.endsWith(".meta.enc")) }) {
                "Найдены зашифрованные файлы без ключевого описания; резервная копия отменена."
            }
        }

        val mainCheck = File(context.filesDir, "key.check")
        if (AtomicFileIO.existsRecoverable(mainCheck)) AtomicFileIO.readBytes(mainCheck).fill(0)
        check(mainCheck.isFile) { "Не найдена проверка основного ключа." }
        add("security/main-check.enc", mainCheck)
        val panic = File(context.filesDir, "panic.credential")
        if (AtomicFileIO.existsRecoverable(panic)) AtomicFileIO.readBytes(panic).fill(0)
        if (panic.isFile) add("security/panic.credential", panic)

        val paths = entries.map { it.archivePath }.toSet()
        require(paths.size == entries.size) { "В хранилище обнаружены повторяющиеся имена файлов." }
        BackupArchiveRules.validateFilePairs(paths)
        require(entries.size <= MAX_ENTRIES) { "Слишком много файлов для одной резервной копии." }
        require(entries.sumOf { it.file.length() } <= MAX_TOTAL_BYTES) { "Размер резервной копии превышает допустимый предел 2 ГБ." }
        return entries.sortedBy { it.archivePath }
    }

    private fun buildManifest(context: Context, mainSalt: ByteArray, sources: List<SourceEntry>): String {
        val files = JSONArray()
        sources.forEach { source ->
            files.put(
                JSONObject()
                    .put("path", source.archivePath)
                    .put("size", source.file.length())
                    .put("sha256", sha256(source.file))
            )
        }
        val settings = AppPreferences.backupSettings(context)
        return JSONObject()
            .put("format", 2)
            .put("createdAt", System.currentTimeMillis())
            .put("mainSalt", Base64.encodeToString(mainSalt, Base64.NO_WRAP))
            .put("settings", settingsToJson(settings))
            .put("files", files)
            .toString()
    }

    private fun decryptAndStage(
        context: Context,
        source: Uri,
        backupPassword: String,
        payload: File
    ): JSONObject {
        val sourceStream = context.contentResolver.openInputStream(source)
            ?: error("Не удалось открыть выбранную резервную копию.")
        val input = DataInputStream(BufferedInputStream(sourceStream, 64 * 1024))
        var backupCrypto: Crypto? = null
        var pipeInput: PipedInputStream? = null
        var pipeOutput: PipedOutputStream? = null
        var decryptThread: Thread? = null
        var extractionFailure: Throwable? = null
        try {
            val header = ByteArray(BACKUP_MAGIC.length)
            try {
                input.readFully(header)
                require(header.contentEquals(BACKUP_MAGIC.toByteArray(Charsets.US_ASCII))) {
                    "Это не резервная копия SecNote или формат не поддерживается."
                }
            } finally {
                header.fill(0)
            }

            val backupSalt = ByteArray(Crypto.SALT_LENGTH)
            try {
                input.readFully(backupSalt)
                backupCrypto = Crypto.fromPassphrase(backupPassword, backupSalt)
            } finally {
                backupSalt.fill(0)
            }

            val decryptedInput = PipedInputStream(PIPE_BUFFER_BYTES)
            val decryptedOutput = PipedOutputStream(decryptedInput)
            pipeInput = decryptedInput
            pipeOutput = decryptedOutput
            val decryptFailure = AtomicReference<Throwable?>(null)
            val activeBackupCrypto = backupCrypto ?: error("Не удалось подготовить ключ резервной копии.")
            val worker = Thread({
                try {
                    activeBackupCrypto.decryptStream(input, decryptedOutput)
                } catch (error: Throwable) {
                    decryptFailure.set(error)
                } finally {
                    runCatching { decryptedOutput.close() }
                    runCatching { input.close() }
                }
            }, "SecNoteBackupDecrypt")
            decryptThread = worker
            worker.start()

            var manifest: JSONObject? = null
            val extracted = mutableSetOf<String>()
            var totalBytes = 0L
            var manifestPaths: Map<String, ExpectedEntry> = emptyMap()
            val zip = ZipInputStream(decryptedInput)
            var first = true
            while (true) {
                val entry = zip.nextEntry ?: break
                require(!entry.isDirectory) { "В резервной копии обнаружена недопустимая запись каталога." }
                if (first) {
                    require(entry.name == MANIFEST_NAME) { "В резервной копии отсутствует манифест." }
                    val bytes = readEntryLimited(zip, MAX_MANIFEST_BYTES)
                    val parsed = try {
                        JSONObject(String(bytes, Charsets.UTF_8))
                    } finally {
                        bytes.fill(0)
                    }
                    require(parsed.optInt("format", -1) == 2) { "Версия резервной копии не поддерживается." }
                    val files = parsed.getJSONArray("files")
                    require(files.length() <= MAX_ENTRIES) { "Слишком много файлов в резервной копии." }
                    val expected = linkedMapOf<String, ExpectedEntry>()
                    for (i in 0 until files.length()) {
                        val item = files.getJSONObject(i)
                        val path = item.getString("path")
                        require(BackupArchiveRules.isAllowedEntryPath(path)) { "В резервной копии найден недопустимый путь." }
                        val size = item.getLong("size")
                        require(size in 0L..BackupArchiveRules.maximumEntrySize(path)) {
                            "Недопустимый размер файла в резервной копии: $path"
                        }
                        val digest = item.getString("sha256")
                        require(digest.matches(Regex("[a-f0-9]{64}"))) { "Некорректная контрольная сумма резервной копии." }
                        require(expected.put(path, ExpectedEntry(size, digest)) == null) { "В манифесте повторяется файл." }
                    }
                    require("security/main-check.enc" in expected) { "В резервной копии нет проверки основного пароля." }
                    require(expected.values.sumOf { it.size } <= MAX_TOTAL_BYTES) { "Размер резервной копии превышает 2 ГБ." }
                    manifestPaths = expected
                    manifest = parsed
                    first = false
                } else {
                    val expected = manifestPaths[entry.name]
                        ?: error("В архиве есть файл, отсутствующий в манифесте: ${entry.name.take(80)}")
                    require(extracted.add(entry.name)) { "В архиве повторяется файл: ${entry.name}" }
                    totalBytes += expected.size
                    require(totalBytes <= MAX_TOTAL_BYTES) { "Размер распакованных данных превышает 2 ГБ." }
                    val target = safeStageFile(payload, entry.name)
                    target.parentFile?.let { check(it.exists() || it.mkdirs()) }
                    val digest = MessageDigest.getInstance("SHA-256")
                    var written = 0L
                    FileOutputStream(target, false).use { output ->
                        val buffer = ByteArray(64 * 1024)
                        try {
                            while (true) {
                                val count = zip.read(buffer)
                                if (count < 0) break
                                written += count
                                require(written <= expected.size && written <= MAX_TOTAL_BYTES) {
                                    "Файл в архиве больше заявленного размера."
                                }
                                digest.update(buffer, 0, count)
                                output.write(buffer, 0, count)
                            }
                            output.fd.sync()
                        } finally {
                            buffer.fill(0)
                        }
                    }
                    require(written == expected.size) { "Размер файла в резервной копии не совпадает с манифестом." }
                    val actualDigest = digest.digest().joinToString("") { "%02x".format(it) }
                    require(actualDigest == expected.sha256) {
                        "Контрольная сумма файла не совпадает: ${entry.name.take(80)}"
                    }
                }
                zip.closeEntry()
            }
            val extractedManifest = manifest ?: error("Резервная копия пуста.")

            val drain = ByteArray(64 * 1024)
            try {
                while (decryptedInput.read(drain) >= 0) Unit
            } finally {
                drain.fill(0)
            }
            worker.join()
            decryptFailure.get()?.let {
                throw IllegalArgumentException("Пароль резервной копии неверен или файл повреждён.", it)
            }
            require(extracted == manifestPaths.keys) { "В резервной копии отсутствуют файлы из манифеста." }
            val paths = extracted.toSet()
            BackupArchiveRules.validateFilePairs(paths)
            require(!manifestPaths.containsKey("hidden/${HiddenVault.METADATA_FILE_NAME}") ||
                File(payload, "hidden/${HiddenVault.METADATA_FILE_NAME}").isFile) {
                "Отсутствует ключевое описание защищённой области файлов."
            }
            return extractedManifest
        } catch (error: Throwable) {
            extractionFailure = error
            runCatching { pipeInput?.close() }
            decryptThread?.let { worker -> if (worker.isAlive) worker.join() }
            throw error
        } finally {
            runCatching { pipeInput?.close() }
            runCatching { pipeOutput?.close() }
            runCatching { input.close() }
            backupCrypto?.destroy()
            if (extractionFailure != null) deleteTreeBestEffort(payload)
        }
    }

    private fun validateVaultPayload(payload: File, salt: ByteArray, mainPassword: String) {
        val mainCheckFile = File(payload, "security/main-check.enc")
        require(mainCheckFile.length() in 34L..128L) { "Повреждена проверка основного ключа в резервной копии." }
        val hiddenMetadata = File(payload, "hidden/${HiddenVault.METADATA_FILE_NAME}")
        if (hiddenMetadata.exists()) {
            val record = hiddenMetadata.readBytes()
            try {
                require(HiddenVault.isValidRecord(record)) {
                    "Повреждено ключевое описание защищённой области файлов в резервной копии."
                }
            } finally {
                record.fill(0)
            }
        }
        val mainCheck = mainCheckFile.readBytes()
        val crypto = Crypto.fromPassphrase(mainPassword, salt)
        try {
            require(crypto.decryptToText(mainCheck) == "verify") {
                "Основной пароль из резервной копии не подходит."
            }
            val notesDirectory = File(payload, "notes")
            notesDirectory.listFiles().orEmpty().filter { it.isFile && it.name.endsWith(".enc") }.forEach { file ->
                require(file.length() in 1L..MAX_NOTE_BYTES) { "Некорректный размер заметки в резервной копии." }
                val encryptedNote = file.readBytes()
                val noteId = file.name.removeSuffix(".enc")
                val noteJson = try {
                    crypto.decryptToText(encryptedNote, Crypto.contextAad("note-record", noteId))
                } finally { encryptedNote.fill(0) }
                val json = JSONObject(noteJson)
                require(json.optString("id") == file.name.removeSuffix(".enc")) {
                    "Заметка не соответствует имени зашифрованной записи."
                }
            }
            val fileIds = File(payload, "file_vault").listFiles().orEmpty()
                .filter { it.name.endsWith(".meta.enc") }
                .map { it.name.removeSuffix(".meta.enc") }
            fileIds.forEach { id ->
                val encryptedMetadataBytes = File(payload, "file_vault/$id.meta.enc").readBytes()
                val metadataBytes = try {
                    crypto.decrypt(encryptedMetadataBytes, Crypto.contextAad("file-metadata", id))
                } finally { encryptedMetadataBytes.fill(0) }
                val meta = try { JSONObject(String(metadataBytes, Charsets.UTF_8)) } finally { metadataBytes.fill(0) }
                if (meta.has("id")) require(meta.getString("id") == id) {
                    "Идентификатор метаданных не соответствует файлу $id."
                }
                require(meta.optString("name").isNotBlank() && meta.optLong("sizeBytes", -1L) >= 0L) {
                    "Повреждены метаданные файла $id."
                }
                val dataFile = File(payload, "file_vault/$id.data.enc")
                require(dataFile.isFile) { "Не найдены данные файла $id." }
                val size = crypto.decryptStream(dataFile.inputStream(), NullOutputStream, Crypto.contextAad("file-data", id))
                require(size == meta.optLong("sizeBytes", -1L)) { "Размер файла $id не совпадает с метаданными." }
            }
            val panic = File(payload, "security/panic.credential")
            if (panic.exists()) require(panic.length() == (4L + PasswordKdf.SALT_LENGTH + 32L)) { "Повреждён файл секретного пароля." }
        } finally {
            mainCheck.fill(0)
            crypto.destroy()
        }
    }

    private fun recoverAtomicFiles(directory: File, acceptsBaseName: (String) -> Boolean) {
        if (!directory.exists()) return
        val children = directory.listFiles()
            ?: error("Не удалось прочитать каталог перед созданием резервной копии: ${directory.name}")
        val bases = children.mapNotNull { child ->
            val baseName = if (child.name.endsWith(".bak")) child.name.removeSuffix(".bak") else child.name
            if (acceptsBaseName(baseName)) File(directory, baseName) else null
        }.distinctBy { it.name }
        bases.forEach { base ->
            if (AtomicFileIO.existsRecoverable(base)) {
                AtomicFileIO.readBytes(base).fill(0)
            }
        }
    }

    private fun snapshotCurrentState(context: Context, rollback: File) {
        check(rollback.mkdirs()) { "Не удалось подготовить откат восстановления." }
        val existing = JSONArray()
        val snapshotHashes = JSONObject()
        val atomicFileNames = setOf(
            HiddenVault.METADATA_FILE_NAME, "key.salt", "key.check", "panic.credential"
        )
        TARGET_NAMES.forEach { name ->
            val source = File(context.filesDir, name)
            val exists = if (name in atomicFileNames) AtomicFileIO.existsRecoverable(source) else source.exists()
            if (exists) {
                val snapshot = File(rollback, name)
                existing.put(name)
                if (name in atomicFileNames) {
                    val authoritativeBytes = AtomicFileIO.readBytes(source)
                    val authoritativeHash = MessageDigest.getInstance("SHA-256").digest(authoritativeBytes)
                    try {
                        AtomicFileIO.writeBytes(snapshot, authoritativeBytes)
                        val copiedBytes = AtomicFileIO.readBytes(snapshot)
                        val copiedHash = MessageDigest.getInstance("SHA-256").digest(copiedBytes)
                        try {
                            check(MessageDigest.isEqual(authoritativeHash, copiedHash)) {
                                "Не удалось проверить резервную копию текущего объекта: $name"
                            }
                        } finally {
                            copiedBytes.fill(0)
                            copiedHash.fill(0)
                        }
                    } finally {
                        authoritativeBytes.fill(0)
                        authoritativeHash.fill(0)
                    }
                } else {
                    val sourceHash = treeSha256(source)
                    copyTree(source, snapshot)
                    check(treeSha256(snapshot) == sourceHash) {
                        "Не удалось проверить резервную копию текущего объекта: $name"
                    }
                }
                snapshotHashes.put(name, treeSha256(snapshot))
            }
        }
        val oldSettings = AppPreferences.backupSettings(context)
        val index = JSONObject()
            .put("existing", existing)
            .put("snapshotSha256", snapshotHashes)
            .put("preferences", settingsToJson(oldSettings))
        AtomicFileIO.writeBytes(
            File(rollback, "rollback-index.json"),
            index.toString().toByteArray(Charsets.UTF_8)
        )
    }

    private fun writeRestoreMarker(context: Context, transactionName: String) {
        val marker = File(context.noBackupFilesDir, RESTORE_MARKER)
        AtomicFileIO.writeBytes(marker, transactionName.toByteArray(Charsets.US_ASCII))
    }

    private fun replaceFromPayload(context: Context, payload: File) {
        fun replace(target: File, source: File) {
            deleteAtomicStateFile(target)
            if (source.exists()) {
                copyTree(source, target)
                check(treeSha256(source) == treeSha256(target)) {
                    "Не удалось проверить восстановленный объект: ${target.name}"
                }
            }
        }

        replace(File(context.filesDir, "notes"), File(payload, "notes"))
        replace(File(context.filesDir, "file_vault"), File(payload, "file_vault"))
        replace(
            File(context.filesDir, HiddenVault.DIRECTORY_NAME),
            File(payload, "hidden/${HiddenVault.DIRECTORY_NAME}")
        )
        replace(
            File(context.filesDir, HiddenVault.METADATA_FILE_NAME),
            File(payload, "hidden/${HiddenVault.METADATA_FILE_NAME}")
        )
        replace(
            File(context.filesDir, "panic.credential"),
            File(payload, "security/panic.credential")
        )
    }

    private fun safeStageFile(root: File, relativePath: String): File {
        require(BackupArchiveRules.isAllowedEntryPath(relativePath)) { "Недопустимый путь файла." }
        val base = root.canonicalFile
        val target = File(root, relativePath).canonicalFile
        require(target.path.startsWith(base.path + File.separator)) { "Путь файла выходит за пределы резервной копии." }
        return target
    }

    private fun parseSettings(json: JSONObject): BackupSettings {
        val autoLock = json.optInt("autoLockMinutes", 0)
        require(autoLock in AutoLockPolicy.supportedMinutes) { "В резервной копии указана неизвестная настройка автоблокировки." }
        return BackupSettings(
            darkTheme = json.optBoolean("darkTheme", true),
            screenshotBlocking = json.optBoolean("screenshotBlocking", false),
            autoLockMinutes = autoLock
        )
    }

    private fun settingsToJson(settings: BackupSettings): JSONObject = JSONObject()
        .put("darkTheme", settings.darkTheme)
        .put("screenshotBlocking", settings.screenshotBlocking)
        .put("autoLockMinutes", settings.autoLockMinutes)

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(64 * 1024)
            try {
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    digest.update(buffer, 0, count)
                }
            } finally {
                buffer.fill(0)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun writeZipEntry(zip: ZipOutputStream, name: String, bytes: ByteArray) {
        zip.putNextEntry(ZipEntry(name))
        zip.write(bytes)
        zip.closeEntry()
        bytes.fill(0)
    }

    private fun readEntryLimited(input: InputStream, maximum: Long): ByteArray {
        val output = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        try {
            var total = 0L
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                total += count
                require(total <= maximum) { "Манифест резервной копии слишком велик." }
                output.write(buffer, 0, count)
            }
            return output.toByteArray()
        } finally {
            buffer.fill(0)
        }
    }

    private fun copyTree(source: File, destination: File) {
        check(source.exists()) { "Источник для копирования не существует: ${source.name}" }
        if (source.isDirectory) {
            check(!destination.exists() || destination.isDirectory) {
                "Назначение каталога восстановления занято файлом: ${destination.name}"
            }
            check(destination.isDirectory || destination.mkdirs()) {
                "Не удалось создать каталог восстановления: ${destination.name}"
            }
            val children = source.listFiles()
                ?: error("Не удалось прочитать содержимое каталога: ${source.name}")
            children.sortedBy { it.name }.forEach { child ->
                copyTree(child, File(destination, child.name))
            }
        } else {
            check(source.isFile) { "Недопустимый объект в области восстановления: ${source.name}" }
            destination.parentFile?.let { parent ->
                check(parent.isDirectory || parent.mkdirs()) { "Не удалось создать каталог восстановления." }
            }
            FileInputStream(source).use { input ->
                FileOutputStream(destination, false).use { output ->
                    input.copyTo(output, 64 * 1024)
                    output.fd.sync()
                }
            }
            check(destination.isFile && destination.length() == source.length()) {
                "Скопированный файл имеет неправильный размер: ${source.name}"
            }
        }
    }

    private fun deleteTreeStrict(entry: File) {
        if (!entry.exists()) return
        if (entry.isDirectory) {
            val children = entry.listFiles()
                ?: error("Не удалось прочитать каталог перед удалением: ${entry.name}")
            children.forEach(::deleteTreeStrict)
        }
        check(entry.delete() || !entry.exists()) {
            "Не удалось удалить объект перед восстановлением: ${entry.name}"
        }
        check(!entry.exists()) { "Объект остался после удаления: ${entry.name}" }
    }

    private fun deleteAtomicStateFile(file: File) {
        deleteTreeStrict(file)
        deleteTreeStrict(File(file.path + ".bak"))
        deleteTreeStrict(File(file.path + ".new"))
    }

    private fun treeSha256(root: File): String {
        require(root.exists()) { "Объект для проверки не существует: ${root.name}" }
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(64 * 1024)

        fun visit(file: File, relativePath: String) {
            val pathBytes = relativePath.toByteArray(Charsets.UTF_8)
            digest.update(ByteBuffer.allocate(4).putInt(pathBytes.size).array())
            digest.update(pathBytes)
            if (file.isDirectory) {
                digest.update(0x44.toByte())
                val children = file.listFiles()
                    ?: error("Не удалось прочитать каталог для проверки: ${file.name}")
                children.sortedBy { it.name }.forEach { child ->
                    visit(child, if (relativePath.isEmpty()) child.name else "$relativePath/${child.name}")
                }
            } else {
                check(file.isFile) { "Неизвестный тип объекта: ${file.name}" }
                digest.update(0x46.toByte())
                digest.update(ByteBuffer.allocate(8).putLong(file.length()).array())
                FileInputStream(file).use { input ->
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        digest.update(buffer, 0, count)
                    }
                }
            }
        }

        try {
            visit(root, "")
            return digest.digest().joinToString("") { "%02x".format(it) }
        } finally {
            buffer.fill(0)
        }
    }

    private fun deleteTreeBestEffort(entry: File) {
        if (!entry.exists()) return
        if (entry.isDirectory) entry.listFiles()?.forEach(::deleteTreeBestEffort)
        entry.delete()
    }

    private object NullOutputStream : OutputStream() {
        override fun write(b: Int) = Unit
        override fun write(b: ByteArray, off: Int, len: Int) = Unit
    }
}
