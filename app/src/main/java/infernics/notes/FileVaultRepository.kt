package infernics.notes

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.MediaStore
import androidx.exifinterface.media.ExifInterface
import android.provider.OpenableColumns
import android.system.Os
import android.system.OsConstants
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStream
import java.security.DigestInputStream
import java.security.DigestOutputStream
import java.security.MessageDigest
import java.io.InputStream
import java.io.RandomAccessFile
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

data class VaultFile(
    val id: String,
    val name: String,
    val mimeType: String,
    val sizeBytes: Long,
    val addedAt: Long,

    val dateTakenAt: Long? = null,

    val photoDateResolved: Boolean = false
)

data class VaultImportResult(
    val file: VaultFile,
    val originalOverwritten: Boolean,
    val originalDeleted: Boolean
)

data class BatchExportResult(
    val exported: Int,
    val failedNames: List<String>
)

data class BatchImportResult(
    val imported: Int,
    val originalsOverwritten: Int,
    val originalsDeleted: Int,
    val failedNames: List<String>
)

class FileVaultRepository(
    private val context: Context,
    private val crypto: Crypto,
    private val storageDirectoryName: String = "file_vault"
) {
    private val generation = StorageGate.currentGeneration()
    private val cachePrefix = if (storageDirectoryName == HiddenVault.DIRECTORY_NAME) "media" else "secnote"
    private val root = StorageGate.withAccess(generation) {
        require(storageDirectoryName == "file_vault" || storageDirectoryName == HiddenVault.DIRECTORY_NAME) {
            "Недопустимое файловое пространство"
        }
        File(context.filesDir, storageDirectoryName).apply { mkdirs() }
    }

    init {
        StorageGate.withAccess(generation) {

            recoverMigrationBackupsWithoutTarget()

            root.listFiles { file -> file.name.endsWith(".tmp") || file.name.endsWith(".migrate.tmp") }
                ?.forEach(::overwriteAndDelete)
            context.cacheDir.listFiles { file ->
                file.name.startsWith("$cachePrefix-export-") ||
                    file.name.startsWith("$cachePrefix-thumbnail-") ||
                    file.name.startsWith("$cachePrefix-date-")
            }?.forEach(::overwriteAndDelete)
            cleanupOrphans()
        }
    }

    fun loadAll(): List<VaultFile> = StorageGate.withAccess(generation) {
        root.listFiles { file -> file.name.endsWith(".data.enc") }
            .orEmpty()
            .mapNotNull { dataFile ->
                val id = dataFile.name.removeSuffix(".data.enc")
                runCatching { readMetadata(id) }.getOrNull()
            }
            .map { item ->
                runCatching { migrateLegacyStream(item) }
                if (item.isPhotoLike() && !item.photoDateResolved) resolveLegacyPhotoDate(item) else item
            }
            .sortedByDescending { it.addedAt }
    }

    fun importAndRemoveOriginal(uri: Uri): VaultImportResult = StorageGate.withAccess(generation) {
        val item = importEncryptedCopy(uri)
        val overwritten = bestEffortOverwriteSource(uri)
        val deleted = bestEffortDeleteSource(uri)
        VaultImportResult(item, overwritten, deleted)
    }

    fun saveCapturedPhoto(
        jpegBytes: ByteArray,
        capturedAtMillis: Long = System.currentTimeMillis()
    ): VaultFile {
        try {
            return StorageGate.withAccess(generation) {
                require(jpegBytes.size >= 4 && jpegBytes[0] == 0xFF.toByte() && jpegBytes[1] == 0xD8.toByte()) {
                    "Получен некорректный JPEG"
                }
                require(jpegBytes.size <= 80 * 1024 * 1024) { "Размер фотографии превышает 80 МБ" }

                val id = UUID.randomUUID().toString()
                val timestamp = System.currentTimeMillis()
                val stamp = SimpleDateFormat("yyyyMMdd_HHmmss_SSS", Locale.US).format(Date(timestamp))
                val item = VaultFile(
                    id = id,
                    name = "Фото_$stamp.jpg",
                    mimeType = "image/jpeg",
                    sizeBytes = jpegBytes.size.toLong(),
                    addedAt = timestamp,
                    dateTakenAt = readPhotoDateFromStream(ByteArrayInputStream(jpegBytes)) ?: capturedAtMillis,
                    photoDateResolved = true
                )
                val dataTemp = File(root, "$id.data.tmp")
                val metaTemp = File(root, "$id.meta.tmp")
                val dataTarget = dataFile(id)
                val metaTarget = metadataFile(id)

                try {
                    val sourceDigest = MessageDigest.getInstance("SHA-256")
                    val plaintextSize = ByteArrayInputStream(jpegBytes).use { source ->
                        val digestedSource = DigestInputStream(source, sourceDigest)
                        FileOutputStream(dataTemp, false).use { encryptedOutput ->
                            crypto.encryptStream(digestedSource, encryptedOutput, Crypto.contextAad("file-data", id)).also {
                                encryptedOutput.fd.sync()
                            }
                        }
                    }
                    val expectedDigest = sourceDigest.digest()
                    try {
                        verifyEncryptedFile(dataTemp, item.id, plaintextSize, expectedDigest)
                        val encryptedMetadata = crypto.encrypt(metadataJson(item), Crypto.contextAad("file-metadata", item.id))
                        try {
                            FileOutputStream(metaTemp, false).use { metadataOutput ->
                                metadataOutput.write(encryptedMetadata)
                                metadataOutput.fd.sync()
                            }
                        } finally {
                            encryptedMetadata.fill(0)
                        }
                        verifyEncryptedMetadata(metaTemp, item)
                        commitNewVaultPair(dataTemp, metaTemp, dataTarget, metaTarget)

                        verifyEncryptedFile(dataTarget, item.id, plaintextSize, expectedDigest)
                        verifyEncryptedMetadata(metaTarget, item)
                        item
                    } finally {
                        expectedDigest.fill(0)
                    }
                } catch (error: Exception) {
                    overwriteAndDelete(dataTemp)
                    overwriteAndDelete(metaTemp)
                    overwriteAndDelete(dataTarget)
                    overwriteAndDelete(metaTarget)
                    throw error
                }
            }
        } finally {

            jpegBytes.fill(0)
        }
    }

    fun importManyAndRemoveOriginal(uris: Collection<Uri>): BatchImportResult {
        var imported = 0
        var overwritten = 0
        var deleted = 0
        val failedNames = mutableListOf<String>()
        uris.distinctBy { it.toString() }.forEach { uri ->
            val displayName = queryDisplayName(uri).ifBlank { "Выбранный файл" }
            runCatching { importAndRemoveOriginal(uri) }
                .onSuccess { result ->
                    imported++
                    if (result.originalOverwritten) overwritten++
                    if (result.originalDeleted) deleted++
                }
                .onFailure {
                    failedNames += displayName.take(120)
                }
        }
        return BatchImportResult(
            imported = imported,
            originalsOverwritten = overwritten,
            originalsDeleted = deleted,
            failedNames = failedNames
        )
    }

    private fun importEncryptedCopy(uri: Uri): VaultFile {
        val displayName = queryDisplayName(uri).ifBlank { "Файл_${System.currentTimeMillis()}" }
        val name = displayName.substringAfterLast('/').substringAfterLast('\\').take(180)
        val mime = context.contentResolver.getType(uri) ?: "application/octet-stream"
        val isPhoto = isPhotoLike(name, mime)

        val originalPhotoDate = if (isPhoto) readPhotoDateFromUri(uri) else null
        val id = UUID.randomUUID().toString()
        val dataTemp = File(root, "$id.data.tmp")
        val metaTemp = File(root, "$id.meta.tmp")
        val dataTarget = dataFile(id)
        val metaTarget = metadataFile(id)

        try {
            val input = context.contentResolver.openInputStream(uri)
                ?: error("Не удалось открыть выбранный файл")
            val sourceDigest = MessageDigest.getInstance("SHA-256")
            val size = input.use { source ->
                val digestedSource = DigestInputStream(source, sourceDigest)
                FileOutputStream(dataTemp, false).use { encryptedOutput ->
                    crypto.encryptStream(digestedSource, encryptedOutput, Crypto.contextAad("file-data", id)).also {
                        encryptedOutput.fd.sync()
                    }
                }
            }
            val expectedDigest = sourceDigest.digest()
            try {
                verifyEncryptedFile(dataTemp, id, size, expectedDigest)
                val item = VaultFile(
                    id = id,
                    name = name,
                    mimeType = mime,
                    sizeBytes = size,
                    addedAt = System.currentTimeMillis(),
                    dateTakenAt = originalPhotoDate,
                    photoDateResolved = isPhoto
                )
                val encryptedMetadata = crypto.encrypt(metadataJson(item), Crypto.contextAad("file-metadata", item.id))
                try {
                    FileOutputStream(metaTemp, false).use { metadataOutput ->
                        metadataOutput.write(encryptedMetadata)
                        metadataOutput.fd.sync()
                    }
                } finally {
                    encryptedMetadata.fill(0)
                }
                verifyEncryptedMetadata(metaTemp, item)
                commitNewVaultPair(dataTemp, metaTemp, dataTarget, metaTarget)

                verifyEncryptedFile(dataTarget, id, size, expectedDigest)
                verifyEncryptedMetadata(metaTarget, item)
                return item
            } finally {
                expectedDigest.fill(0)
            }
        } catch (error: Exception) {

            overwriteAndDelete(dataTemp)
            overwriteAndDelete(metaTemp)
            overwriteAndDelete(dataTarget)
            overwriteAndDelete(metaTarget)
            throw error
        }
    }

    private fun bestEffortOverwriteSource(uri: Uri): Boolean {
        val size = querySize(uri)
        val descriptor = try {
            context.contentResolver.openFileDescriptor(uri, "rw") ?: return false
        } catch (_: Exception) {
            return false
        }

        return try {
            descriptor.use { pfd ->
                val actualSize = size ?: pfd.statSize.takeIf { it >= 0L } ?: return false
                Os.lseek(pfd.fileDescriptor, 0L, OsConstants.SEEK_SET)
                val zeros = ByteArray(64 * 1024)
                var remaining = actualSize
                while (remaining > 0L) {
                    val count = minOf(zeros.size.toLong(), remaining).toInt()
                    var offset = 0
                    while (offset < count) {
                        val written = Os.write(pfd.fileDescriptor, zeros, offset, count - offset)
                        check(written > 0) { "Не удалось перезаписать исходный файл" }
                        offset += written
                    }
                    remaining -= count.toLong()
                }
                Os.fsync(pfd.fileDescriptor)
                true
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun bestEffortDeleteSource(uri: Uri): Boolean {
        val documentDelete = runCatching {
            if (DocumentsContract.isDocumentUri(context, uri)) {
                DocumentsContract.deleteDocument(context.contentResolver, uri)
            } else false
        }.getOrDefault(false)
        if (documentDelete) return true
        return runCatching { context.contentResolver.delete(uri, null, null) > 0 }
            .getOrDefault(false)
    }

    fun export(id: String, destination: Uri) = StorageGate.withAccess(generation) {
        val item = readMetadata(id)
        exportVerified(item, destination)
    }

    fun exportManyToTree(ids: Collection<String>, treeUri: Uri): BatchExportResult = StorageGate.withAccess(generation) {
        var exported = 0
        val failures = mutableListOf<String>()
        val treeDocumentUri = runCatching {
            DocumentsContract.buildDocumentUriUsingTree(
                treeUri,
                DocumentsContract.getTreeDocumentId(treeUri)
            )
        }.getOrElse { treeUri }
        ids.distinct().forEach { id ->
            var createdUri: Uri? = null
            val item = runCatching { readMetadata(id) }.getOrElse {
                failures += "Файл ($id)"
                return@forEach
            }
            try {
                createdUri = DocumentsContract.createDocument(
                    context.contentResolver,
                    treeDocumentUri,
                    item.mimeType.ifBlank { "application/octet-stream" },
                    safeDocumentName(item.name)
                ) ?: error("Провайдер не создал файл")
                exportVerified(item, createdUri)
                exported++
            } catch (_: Exception) {
                createdUri?.let { runCatching { DocumentsContract.deleteDocument(context.contentResolver, it) } }
                failures += item.name
            }
        }
        BatchExportResult(exported, failures)
    }

    fun delete(id: String) = StorageGate.withAccess(generation) {
        overwriteAndDelete(dataFile(id))
        overwriteAndDelete(metadataFile(id))
    }

    fun deleteMany(ids: Collection<String>): Int = StorageGate.withAccess(generation) {
        var removed = 0
        ids.distinct().forEach { id ->
            val existed = dataFile(id).exists() || metadataFile(id).exists()
            delete(id)
            if (existed && !dataFile(id).exists() && !metadataFile(id).exists()) removed++
        }
        removed
    }

    private fun migrateLegacyStream(item: VaultFile) {
        val source = dataFile(item.id)
        if (!source.isFile || isContextualStream(source)) {
            recoverCompletedMigration(item)
            return
        }

        val plaintext = File.createTempFile("$cachePrefix-migration-", ".tmp", context.cacheDir)
        val encryptedTemp = File(root, "${item.id}.data.migrate.tmp")
        val backup = File(root, "${item.id}.data.migrate.bak")
        val digest = MessageDigest.getInstance("SHA-256")
        try {
            val decryptedSize = source.inputStream().use { encryptedInput ->
                FileOutputStream(plaintext, false).use { plainOutput ->
                    val size = crypto.decryptStream(
                        encryptedInput,
                        DigestOutputStream(plainOutput, digest),
                        Crypto.contextAad("file-data", item.id)
                    )
                    plainOutput.fd.sync()
                    size
                }
            }
            check(decryptedSize == item.sizeBytes && plaintext.length() == item.sizeBytes) {
                "Размер старого файла не совпадает с метаданными; миграция отменена."
            }
            val expectedDigest = digest.digest()
            try {
                plaintext.inputStream().use { plainInput ->
                    FileOutputStream(encryptedTemp, false).use { encryptedOutput ->
                        crypto.encryptStream(
                            plainInput,
                            encryptedOutput,
                            Crypto.contextAad("file-data", item.id)
                        )
                        encryptedOutput.fd.sync()
                    }
                }
                check(isContextualStream(encryptedTemp)) { "Новый формат файла не создан." }
                verifyEncryptedFile(encryptedTemp, item.id, item.sizeBytes, expectedDigest)

                check(!backup.exists()) { "Обнаружена незавершённая миграция; исходный файл сохранён." }
                check(source.renameTo(backup)) { "Не удалось сохранить исходный файл перед миграцией." }
                syncVaultDirectory()
                try {
                    check(encryptedTemp.renameTo(source)) { "Не удалось установить новый формат файла." }
                    syncVaultDirectory()
                    verifyEncryptedFile(source, item.id, item.sizeBytes, expectedDigest)
                    check(isContextualStream(source)) { "После замены обнаружен неожиданный формат файла." }
                } catch (error: Exception) {

                    if (source.exists()) overwriteAndDelete(source)
                    if (backup.exists() && !backup.renameTo(source)) {
                        error.addSuppressed(IllegalStateException("Не удалось восстановить исходный зашифрованный файл."))
                    }
                    runCatching { syncVaultDirectory() }.onFailure(error::addSuppressed)
                    throw error
                }

                runCatching {
                    overwriteAndDelete(backup)
                    syncVaultDirectory()
                }
            } finally {
                expectedDigest.fill(0)
            }
        } finally {
            overwriteAndDelete(plaintext)
            overwriteAndDelete(encryptedTemp)
        }
    }

    private fun recoverCompletedMigration(item: VaultFile) {
        val backup = File(root, "${item.id}.data.migrate.bak")
        val source = dataFile(item.id)
        if (!backup.exists()) return
        try {
            val size = source.inputStream().use { input ->
                crypto.decryptStream(input, DiscardOutputStream, Crypto.contextAad("file-data", item.id))
            }
            check(isContextualStream(source) && size == item.sizeBytes) {
                "Новая копия не прошла проверку; исходная резервная копия сохранена."
            }
            overwriteAndDelete(backup)
            syncVaultDirectory()
        } catch (error: Exception) {
            if (backup.exists()) {
                if (source.exists()) overwriteAndDelete(source)
                check(backup.renameTo(source)) { "Не удалось восстановить исходный файл после прерванной миграции." }
                syncVaultDirectory()
            }
            throw error
        }
    }

    private fun recoverMigrationBackupsWithoutTarget() {
        root.listFiles { file -> file.name.endsWith(".data.migrate.bak") }.orEmpty().forEach { backup ->
            val id = backup.name.removeSuffix(".data.migrate.bak")
            val target = dataFile(id)
            if (!target.exists()) {
                check(backup.renameTo(target)) { "Не удалось восстановить исходный файл после прерванной миграции." }
            }
        }
        if (root.listFiles { file -> file.name.endsWith(".data.migrate.bak") }.orEmpty().isNotEmpty()) {
            syncVaultDirectory()
        }
    }

    private fun isContextualStream(file: File): Boolean = runCatching {
        file.inputStream().use { input ->
            val header = ByteArray(4)
            var offset = 0
            while (offset < header.size) {
                val count = input.read(header, offset, header.size - offset)
                if (count < 0) return@use false
                offset += count
            }
            header.contentEquals(byteArrayOf(0x53, 0x4E, 0x46, 0x32))
        }
    }.getOrDefault(false)

    private fun exportVerified(item: VaultFile, destination: Uri) {
        migrateLegacyStream(item)
        val verifiedPlaintext = File.createTempFile("$cachePrefix-export-", ".tmp", context.cacheDir)
        try {
            val decryptedSize = dataFile(item.id).inputStream().use { encryptedInput ->
                verifiedPlaintext.outputStream().use { temporaryOutput ->
                    crypto.decryptStream(encryptedInput, temporaryOutput, Crypto.contextAad("file-data", item.id))
                }
            }
            check(decryptedSize == item.sizeBytes) {
                "Размер файла не совпадает с зашифрованными метаданными. Экспорт отменён."
            }
            check(verifiedPlaintext.length() == item.sizeBytes) {
                "Проверка размера временного файла не пройдена. Экспорт отменён."
            }
            val destinationOutput = context.contentResolver.openOutputStream(destination, "w")
                ?: error("Не удалось создать файл для экспорта")
            verifiedPlaintext.inputStream().use { source ->
                destinationOutput.use { target -> source.copyTo(target) }
            }
        } finally {
            overwriteAndDelete(verifiedPlaintext)
        }
    }

    fun loadThumbnail(id: String, maxDimension: Int = 420): Bitmap? = StorageGate.withAccess(generation) {
        require(maxDimension in 64..2048) { "Invalid thumbnail dimension" }
        var temporaryPlaintext: File? = null
        try {
            val metadata = readMetadata(id)
            migrateLegacyStream(metadata)

            if (metadata.sizeBytes !in 1L..(160L * 1024L * 1024L)) return@withAccess null
            val encryptedFile = dataFile(id)
            if (!encryptedFile.isFile || encryptedFile.length() > 180L * 1024L * 1024L) {
                return@withAccess null
            }
            val tempFile = File.createTempFile("$cachePrefix-thumbnail-", ".tmp", context.cacheDir)
            temporaryPlaintext = tempFile
            encryptedFile.inputStream().use { encryptedInput ->
                tempFile.outputStream().use { output ->
                    crypto.decryptStream(encryptedInput, output, Crypto.contextAad("file-data", id))
                }
            }
            val bounds = BitmapFactory.Options().apply {
                inJustDecodeBounds = true
                inScaled = false
            }
            BitmapFactory.decodeFile(tempFile.absolutePath, bounds)
            val width = bounds.outWidth
            val height = bounds.outHeight
            if (width <= 0 || height <= 0) return@withAccess null

            val sampleSize = ThumbnailDecodePolicy.sampleSize(width, height, maxDimension)
            val options = BitmapFactory.Options().apply {
                inSampleSize = sampleSize

                inPreferredConfig = Bitmap.Config.RGB_565
                inDither = true
                inScaled = false
                inMutable = false
            }
            BitmapFactory.decodeFile(tempFile.absolutePath, options)
        } catch (_: OutOfMemoryError) {

            null
        } catch (_: Exception) {
            null
        } finally {
            temporaryPlaintext?.let(::overwriteAndDelete)
        }
    }

    private fun verifyEncryptedFile(file: File, id: String, expectedSize: Long, expectedDigest: ByteArray) {
        check(file.isFile && file.length() > 0L) { "Зашифрованная копия файла не создана." }
        val actualDigest = MessageDigest.getInstance("SHA-256")
        val actualSize = file.inputStream().use { encryptedInput ->
            crypto.decryptStream(encryptedInput, DigestOutputStream(DiscardOutputStream, actualDigest), Crypto.contextAad("file-data", id))
        }
        check(actualSize == expectedSize) { "Размер проверенной копии не совпадает с оригиналом." }
        val digest = actualDigest.digest()
        try {
            check(MessageDigest.isEqual(digest, expectedDigest)) {
                "Контрольная сумма зашифрованной копии не совпадает с оригиналом."
            }
        } finally {
            digest.fill(0)
        }
    }

    private fun verifyEncryptedMetadata(file: File, expected: VaultFile) {
        val ciphertext = file.readBytes()
        try {
            val decoded = crypto.decryptToText(ciphertext, Crypto.contextAad("file-metadata", expected.id))
            check(decoded == metadataJson(expected)) { "Проверка зашифрованных метаданных не пройдена." }
        } finally {
            ciphertext.fill(0)
        }
    }

    private fun commitNewVaultPair(
        dataTemp: File,
        metadataTemp: File,
        dataTarget: File,
        metadataTarget: File
    ) {
        check(!dataTarget.exists() && !metadataTarget.exists()) { "Идентификатор файла уже существует." }
        check(dataTemp.renameTo(dataTarget)) { "Не удалось зафиксировать зашифрованные данные." }
        try {
            check(metadataTemp.renameTo(metadataTarget)) { "Не удалось зафиксировать метаданные файла." }
            syncVaultDirectory()
        } catch (error: Exception) {
            if (metadataTarget.exists() && !metadataTarget.delete()) {
                error.addSuppressed(IllegalStateException("Не удалось удалить неполные метаданные файла."))
            }
            if (dataTarget.exists() && !dataTarget.delete()) {
                error.addSuppressed(IllegalStateException("Не удалось удалить неполные зашифрованные данные."))
            }
            runCatching { syncVaultDirectory() }
            throw error
        }
    }

    private fun syncVaultDirectory() {
        val directoryFd = Os.open(
            root.absolutePath,
            OsConstants.O_RDONLY,
            0
        )
        try {
            Os.fsync(directoryFd)
        } finally {
            Os.close(directoryFd)
        }
    }

    private object DiscardOutputStream : OutputStream() {
        override fun write(value: Int) = Unit
        override fun write(buffer: ByteArray, offset: Int, length: Int) = Unit
    }

    private fun readMetadata(id: String): VaultFile {
        val metadata = metadataFile(id)
        val encrypted = AtomicFileIO.readBytes(metadata)
        val legacy = !crypto.isContextualRecord(encrypted)
        val jsonText = try {
            crypto.decryptToText(encrypted, Crypto.contextAad("file-metadata", id))
        } finally {
            encrypted.fill(0)
        }
        val json = JSONObject(jsonText)
        if (json.has("id")) {
            require(json.getString("id") == id) { "Идентификатор файла не совпадает с именем записи." }
        }
        val sizeBytes = json.optLong("sizeBytes", -1L)
        require(sizeBytes >= 0L) { "В метаданных указан недопустимый размер файла." }
        return VaultFile(
            id = id,
            name = json.getString("name"),
            mimeType = json.optString("mimeType", "application/octet-stream"),
            sizeBytes = sizeBytes,
            addedAt = json.optLong("addedAt", 0L),
            dateTakenAt = if (json.has("dateTakenAt") && !json.isNull("dateTakenAt")) json.optLong("dateTakenAt") else null,
            photoDateResolved = json.optBoolean("photoDateResolved", json.has("dateTakenAt"))
        ).also { item ->
            if (legacy) runCatching { writeMetadataAtomically(item) }
            runCatching { recoverCompletedMigration(item) }
        }
    }

    private fun metadataJson(item: VaultFile): String = JSONObject()
        .put("id", item.id)
        .put("name", item.name)
        .put("mimeType", item.mimeType)
        .put("sizeBytes", item.sizeBytes)
        .put("addedAt", item.addedAt)
        .put("photoDateResolved", item.photoDateResolved)
        .apply { item.dateTakenAt?.let { put("dateTakenAt", it) } }
        .toString()

    private fun VaultFile.isPhotoLike(): Boolean = isPhotoLike(name, mimeType)

    private fun isPhotoLike(name: String, mimeType: String): Boolean {
        if (mimeType.lowercase(Locale.ROOT).startsWith("image/")) return true
        return name.substringAfterLast('.', "").lowercase(Locale.ROOT) in setOf(
            "jpg", "jpeg", "png", "webp", "gif", "bmp", "heic", "heif", "avif"
        )
    }

    private fun readPhotoDateFromUri(uri: Uri): Long? {
        val exifDate = runCatching {
            context.contentResolver.openInputStream(uri)?.use { readPhotoDateFromStream(it) }
        }.getOrNull()
        if (exifDate != null) return exifDate
        return runCatching {
            context.contentResolver.query(
                uri,
                arrayOf(MediaStore.Images.Media.DATE_TAKEN),
                null,
                null,
                null
            )?.use { cursor ->
                val column = cursor.getColumnIndex(MediaStore.Images.Media.DATE_TAKEN)
                if (column >= 0 && cursor.moveToFirst()) cursor.getLong(column).takeIf { it > 0L } else null
            }
        }.getOrNull()
    }

    private fun readPhotoDateFromStream(input: InputStream): Long? = runCatching {
        val exif = ExifInterface(input)
        val original = exif.getAttribute(ExifInterface.TAG_DATETIME_ORIGINAL)
            ?: exif.getAttribute(ExifInterface.TAG_DATETIME_DIGITIZED)
            ?: exif.getAttribute(ExifInterface.TAG_DATETIME)
        val offset = exif.getAttribute(ExifInterface.TAG_OFFSET_TIME_ORIGINAL)
            ?: exif.getAttribute(ExifInterface.TAG_OFFSET_TIME_DIGITIZED)
            ?: exif.getAttribute(ExifInterface.TAG_OFFSET_TIME)
        PhotoDatePolicy.parseExifTimestamp(original, offset)
    }.getOrNull()

    private fun resolveLegacyPhotoDate(item: VaultFile): VaultFile {
        var plaintext: File? = null
        return try {
            val tempFile = File.createTempFile("$cachePrefix-date-", ".tmp", context.cacheDir)
            plaintext = tempFile
            dataFile(item.id).inputStream().use { encryptedInput ->
                tempFile.outputStream().use { output -> crypto.decryptStream(encryptedInput, output, Crypto.contextAad("file-data", item.id)) }
            }
            val dateTaken = runCatching {
                val exif = ExifInterface(tempFile.absolutePath)
                val original = exif.getAttribute(ExifInterface.TAG_DATETIME_ORIGINAL)
                    ?: exif.getAttribute(ExifInterface.TAG_DATETIME_DIGITIZED)
                    ?: exif.getAttribute(ExifInterface.TAG_DATETIME)
                val offset = exif.getAttribute(ExifInterface.TAG_OFFSET_TIME_ORIGINAL)
                    ?: exif.getAttribute(ExifInterface.TAG_OFFSET_TIME_DIGITIZED)
                    ?: exif.getAttribute(ExifInterface.TAG_OFFSET_TIME)
                PhotoDatePolicy.parseExifTimestamp(original, offset)
            }.getOrNull()
            val migrated = item.copy(dateTakenAt = dateTaken, photoDateResolved = true)
            writeMetadataAtomically(migrated)
            migrated
        } catch (_: Exception) {

            item
        } finally {
            plaintext?.let(::overwriteAndDelete)
        }
    }

    private fun writeMetadataAtomically(item: VaultFile) {
        val encrypted = crypto.encrypt(metadataJson(item), Crypto.contextAad("file-metadata", item.id))
        try {
            AtomicFileIO.writeBytes(metadataFile(item.id), encrypted)
        } finally {
            encrypted.fill(0)
        }
    }

    private fun overwriteAndDelete(file: File) {
        if (!AtomicFileIO.existsRecoverable(file) && !File(file.path + ".new").exists()) return
        runCatching {
            val originalLength = file.length()
            RandomAccessFile(file, "rw").use { stream ->
                val block = ByteArray(64 * 1024)
                val random = java.security.SecureRandom()

                repeat(2) { pass ->
                    stream.seek(0L)
                    var remaining = originalLength
                    while (remaining > 0L) {
                        val count = minOf(block.size.toLong(), remaining).toInt()
                        if (pass == 0) random.nextBytes(block) else block.fill(0)
                        stream.write(block, 0, count)
                        remaining -= count.toLong()
                    }
                    stream.fd.sync()
                }
                block.fill(0)
                stream.setLength(originalLength)
                stream.fd.sync()
            }
        }
        check(AtomicFileIO.delete(file)) { "Не удалось удалить временный или зашифрованный файл: ${file.name}" }
    }

    private fun dataFile(id: String) = File(root, "$id.data.enc")
    private fun metadataFile(id: String) = File(root, "$id.meta.enc")

    private fun queryDisplayName(uri: Uri): String = runCatching {
        context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
            ?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (index >= 0) cursor.getString(index).orEmpty() else ""
                } else ""
            }.orEmpty()
    }.getOrDefault("")

    private fun querySize(uri: Uri): Long? = runCatching {
        context.contentResolver.query(uri, arrayOf(OpenableColumns.SIZE), null, null, null)
            ?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val index = cursor.getColumnIndex(OpenableColumns.SIZE)
                    if (index >= 0 && !cursor.isNull(index)) cursor.getLong(index) else null
                } else null
            }
    }.getOrNull()?.takeIf { it >= 0L }

    private fun safeDocumentName(value: String): String =
        value.substringAfterLast('/').substringAfterLast('\\').replace(Regex("[\\r\\n]"), "_").take(180)

    private fun cleanupOrphans() {
        val files = root.listFiles().orEmpty()
        val dataIds = files.filter { it.name.endsWith(".data.enc") || it.name.endsWith(".data.migrate.bak") }
            .map { it.name.removeSuffix(".data.migrate.bak").removeSuffix(".data.enc") }.toSet()

        val metadataIds = files.filter {
            it.name.endsWith(".meta.enc") || it.name.endsWith(".meta.enc.bak")
        }.map {
            it.name.removeSuffix(".bak").removeSuffix(".meta.enc")
        }.toSet()
        (dataIds - metadataIds).forEach { id ->
            overwriteAndDelete(dataFile(id))
            overwriteAndDelete(File(root, "$id.data.migrate.bak"))
            overwriteAndDelete(File(root, "$id.data.migrate.tmp"))
        }
        (metadataIds - dataIds).forEach { overwriteAndDelete(metadataFile(it)) }
    }

    companion object {

        fun cleanupAbandonedTemporaryFiles(context: Context) {
            val prefixes = listOf(
                "secnote-export-", "secnote-thumbnail-", "secnote-date-", "secnote-migration-",
                "media-export-", "media-thumbnail-", "media-date-", "media-migration-"
            )
            context.cacheDir.listFiles { file -> prefixes.any { prefix -> file.name.startsWith(prefix) } }
                ?.forEach(::overwriteAndDeleteTemporary)
        }

        private fun overwriteAndDeleteTemporary(file: File) {
            if (!file.exists() || !file.isFile) return
            runCatching {
                val originalLength = file.length()
                RandomAccessFile(file, "rw").use { stream ->
                    val block = ByteArray(32 * 1024)
                    val random = java.security.SecureRandom()
                    repeat(2) { pass ->
                        stream.seek(0L)
                        var remaining = originalLength
                        while (remaining > 0L) {
                            val count = minOf(block.size.toLong(), remaining).toInt()
                            if (pass == 0) random.nextBytes(block) else block.fill(0)
                            stream.write(block, 0, count)
                            remaining -= count
                        }
                        stream.fd.sync()
                    }
                    block.fill(0)
                    stream.setLength(originalLength)
                    stream.fd.sync()
                }
            }
            file.delete()
        }
    }
}
