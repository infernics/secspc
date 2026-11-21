package infernics.notes

import android.content.Context
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.security.MessageDigest

object PanicCredential {
    private const val FILE_NAME = "panic.credential"
    private const val MAGIC = 0x53435032
    private const val SALT_LENGTH = PasswordKdf.SALT_LENGTH
    private const val VERIFIER_LENGTH = 32
    private const val RECORD_LENGTH = 4 + SALT_LENGTH + VERIFIER_LENGTH

    fun isConfigured(context: Context): Boolean = AtomicFileIO.existsRecoverable(credentialFile(context))

    @Synchronized
    fun set(context: Context, password: String) {
        require(password.isNotEmpty()) { "Введите секретный пароль." }
        val salt = Crypto.newSalt()
        val record = try {
            createRecord(password, salt)
        } finally {
            salt.fill(0)
        }
        try {
            writeAtomically(credentialFile(context), record)
        } finally {
            record.fill(0)
        }
    }

    fun verify(context: Context, password: String): Boolean {
        if (password.isEmpty()) return false
        val file = credentialFile(context)
        if (!AtomicFileIO.existsRecoverable(file)) return false
        val record = runCatching { AtomicFileIO.readBytes(file) }.getOrNull() ?: return false
        return try {
            verifyRecord(password, record)
        } finally {
            record.fill(0)
        }
    }

    @Synchronized
    fun remove(context: Context) {
        val file = credentialFile(context)
        bestEffortOverwrite(file)
        check(AtomicFileIO.delete(file)) { "Не удалось удалить секретный пароль уничтожения." }
        val legacyTemporary = File(file.parentFile, "$FILE_NAME.tmp")
        bestEffortOverwrite(legacyTemporary)
        check(!legacyTemporary.exists() || legacyTemporary.delete()) {
            "Не удалось удалить временный файл секретного пароля уничтожения."
        }
    }

    internal fun createRecord(password: String, salt: ByteArray): ByteArray {
        require(password.isNotEmpty()) { "Введите секретный пароль." }
        require(PasswordKdf.isValidSalt(salt)) { "Некорректная соль секретного пароля." }
        val verifier = derive(password, salt)
        return try {
            ByteBuffer.allocate(RECORD_LENGTH)
                .putInt(MAGIC)
                .put(salt)
                .put(verifier)
                .array()
        } finally {
            verifier.fill(0)
        }
    }

    internal fun verifyRecord(password: String, record: ByteArray): Boolean {
        if (password.isEmpty() || record.size != RECORD_LENGTH) return false
        var salt: ByteArray? = null
        var expected: ByteArray? = null
        var actual: ByteArray? = null
        return try {
            val buffer = ByteBuffer.wrap(record)
            if (buffer.int != MAGIC) return false
            salt = ByteArray(SALT_LENGTH).also(buffer::get)
            expected = ByteArray(VERIFIER_LENGTH).also(buffer::get)
            actual = derive(password, salt)
            MessageDigest.isEqual(expected, actual)
        } catch (_: Exception) {
            false
        } finally {
            salt?.fill(0)
            expected?.fill(0)
            actual?.fill(0)
        }
    }

    private fun derive(password: String, salt: ByteArray): ByteArray {
        return PasswordKdf.derive(password, salt)
    }

    private fun credentialFile(context: Context) = File(context.filesDir, FILE_NAME)

    private fun writeAtomically(destination: File, bytes: ByteArray) {
        AtomicFileIO.writeBytes(destination, bytes)
    }

    private fun bestEffortOverwrite(file: File) {
        if (!file.isFile) return
        runCatching {
            val originalLength = file.length()
            RandomAccessFile(file, "rw").use { stream ->
                stream.seek(0L)
                val zeros = ByteArray(4096)
                var remaining = originalLength
                while (remaining > 0L) {
                    val count = minOf(zeros.size.toLong(), remaining).toInt()
                    stream.write(zeros, 0, count)
                    remaining -= count.toLong()
                }
                stream.setLength(originalLength)
                stream.fd.sync()
            }
        }
    }
}
