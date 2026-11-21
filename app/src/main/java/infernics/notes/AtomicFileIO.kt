package infernics.notes

import android.util.AtomicFile
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.security.MessageDigest

internal object AtomicFileIO {
    @Synchronized
    fun writeBytes(destination: File, bytes: ByteArray) {
        write(destination) { output ->
            output.write(bytes)

            output.fd.sync()
        }

        val actual = try {
            readBytes(destination)
        } catch (error: Throwable) {

            if (!destination.exists()) {
                val pending = File(destination.path + ".new")
                if (pending.exists() && !pending.delete()) {
                    error.addSuppressed(IOException("Не удалось удалить незавершённую запись: ${destination.name}"))
                }
            }
            throw IOException("Не удалось проверить сохранённый файл: ${destination.name}", error)
        }

        try {
            if (!MessageDigest.isEqual(bytes, actual)) {
                throw IOException("Сохранённые данные не совпадают с записываемыми: ${destination.name}")
            }
            check(!File(destination.path + ".new").exists()) {
                "Операция записи не была полностью зафиксирована: ${destination.name}"
            }
        } finally {
            actual.fill(0)
        }
    }

    @Synchronized
    fun readBytes(source: File): ByteArray = AtomicFile(source).openRead().use { it.readBytes() }

    @Synchronized
    fun delete(file: File): Boolean {
        AtomicFile(file).delete()
        val pending = File(file.path + ".new")
        if (pending.exists()) pending.delete()
        return !file.exists() && !File(file.path + ".bak").exists() && !pending.exists()
    }

    @Synchronized
    fun existsRecoverable(file: File): Boolean = file.isFile || File(file.path + ".bak").isFile

    private fun write(destination: File, writer: (FileOutputStream) -> Unit) {
        destination.parentFile?.let { parent ->
            check(parent.isDirectory || parent.mkdirs()) { "Не удалось создать каталог для записи." }
        }
        val atomic = AtomicFile(destination)
        var stream: FileOutputStream? = null
        try {
            stream = atomic.startWrite()
            writer(stream)
            atomic.finishWrite(stream)
            stream = null
        } catch (error: Throwable) {
            stream?.let { output ->
                try {
                    atomic.failWrite(output)
                } catch (cleanupError: Throwable) {
                    error.addSuppressed(cleanupError)
                }
            }
            throw error
        }
    }
}
