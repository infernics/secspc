package infernics.notes

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.RandomAccessFile
import java.util.UUID

data class ChecklistItem(
    val id: String = UUID.randomUUID().toString(),
    val text: String = "",
    val checked: Boolean = false
)

enum class NoteKind { NOTE, LIST }

data class Note(
    val id: String = UUID.randomUUID().toString(),
    val title: String = "",
    val body: String = "",
    val checklist: List<ChecklistItem> = emptyList(),
    val kind: NoteKind = NoteKind.NOTE,
    val updatedAt: Long = System.currentTimeMillis(),

    val sortOrder: Long = Long.MAX_VALUE
)

internal fun swapNotePositions(notes: List<Note>, draggedId: String, targetId: String): List<Note> {
    val draggedIndex = notes.indexOfFirst { it.id == draggedId }
    val targetIndex = notes.indexOfFirst { it.id == targetId }
    if (draggedIndex < 0 || targetIndex < 0 || draggedIndex == targetIndex) return notes

    return notes.toMutableList().apply {
        val dragged = this[draggedIndex]
        this[draggedIndex] = this[targetIndex]
        this[targetIndex] = dragged
    }
}

class NoteRepository(context: Context, private val crypto: Crypto) {
    private val generation = StorageGate.currentGeneration()
    private val dir = StorageGate.withAccess(generation) {
        File(context.filesDir, "notes").apply { mkdirs() }
    }

    @Synchronized
    fun loadAll(): List<Note> = StorageGate.withAccess(generation) {
        val noteFiles = dir.listFiles()
            .orEmpty()
            .mapNotNull { file ->
                when {
                    file.name.endsWith(".enc") -> file
                    file.name.endsWith(".enc.bak") -> File(dir, file.name.removeSuffix(".bak"))
                    else -> null
                }
            }
            .distinctBy { it.name }
        val notes = noteFiles.mapNotNull { file ->
                runCatching {
                    val expectedId = file.name.removeSuffix(".enc")
                    val encrypted = AtomicFileIO.readBytes(file)
                    val legacyRecord = !crypto.isContextualRecord(encrypted)
                    val jsonText = try {
                        crypto.decryptToText(encrypted, Crypto.contextAad("note-record", expectedId))
                    } finally {
                        encrypted.fill(0)
                    }
                    val json = JSONObject(jsonText)
                    require(json.getString("id") == expectedId) { "Идентификатор заметки не совпадает с именем файла." }
                    val checklistJson = json.optJSONArray("checklist") ?: JSONArray()
                    val checklist = buildList {
                        for (index in 0 until checklistJson.length()) {
                            val item = checklistJson.optJSONObject(index) ?: continue
                            add(
                                ChecklistItem(
                                    id = item.optString("id", UUID.randomUUID().toString()),
                                    text = item.optString("text", ""),
                                    checked = item.optBoolean("checked", false)
                                )
                            )
                        }
                    }
                    val storedKind = json.optString("kind", "").uppercase()
                    val kind = when (storedKind) {
                        "LIST" -> NoteKind.LIST
                        "NOTE" -> NoteKind.NOTE
                        else -> if (checklist.isNotEmpty()) NoteKind.LIST else NoteKind.NOTE
                    }
                    val updatedAt = json.optLong("updatedAt", file.lastModified())
                    Note(
                        id = expectedId,
                        title = json.optString("title", ""),
                        body = json.optString("body", ""),
                        checklist = checklist,
                        kind = kind,
                        updatedAt = updatedAt,
                        sortOrder = json.optLong("sortOrder", Long.MAX_VALUE)
                    ).also { note ->

                        if (legacyRecord) runCatching { writeNote(note, file) }
                    }
                }.getOrNull()
            }
        if (notes.any { it.sortOrder != Long.MAX_VALUE }) {
            notes.sortedWith(compareBy<Note> { it.sortOrder }.thenByDescending { it.updatedAt })
        } else {
            notes.sortedByDescending { it.updatedAt }
        }
    }

    @Synchronized
    fun save(note: Note) = StorageGate.withAccess(generation) {
        val target = File(dir, "${note.id}.enc")
        val effectiveSortOrder = when {
            note.sortOrder != Long.MAX_VALUE -> note.sortOrder
            target.exists() -> readStoredSortOrder(target) ?: Long.MAX_VALUE
            else -> {
                val existing = loadAll()
                if (existing.any { it.sortOrder != Long.MAX_VALUE }) {
                    (existing.minOfOrNull { it.sortOrder } ?: 0L) - 1L
                } else Long.MAX_VALUE
            }
        }
        writeNote(note.copy(sortOrder = effectiveSortOrder), target)
    }

    @Synchronized
    fun reorder(orderedNotes: List<Note>) = StorageGate.withAccess(generation) {
        orderedNotes.forEachIndexed { index, note ->
            writeNote(note.copy(sortOrder = index.toLong()), File(dir, "${note.id}.enc"))
        }
    }

    @Synchronized
    fun delete(id: String) = StorageGate.withAccess(generation) {
        overwriteAndDelete(File(dir, "$id.enc"))
    }

    private fun writeNote(note: Note, target: File) {
        val checklistJson = JSONArray().apply {
            note.checklist.forEach { item ->
                put(
                    JSONObject()
                        .put("id", item.id)
                        .put("text", item.text)
                        .put("checked", item.checked)
                )
            }
        }
        val json = JSONObject()
            .put("id", note.id)
            .put("title", note.title)
            .put("body", note.body)
            .put("checklist", checklistJson)
            .put("kind", note.kind.name)
            .put("updatedAt", note.updatedAt)
            .put("sortOrder", note.sortOrder)
        val encrypted = crypto.encrypt(json.toString(), Crypto.contextAad("note-record", note.id))
        try {
            AtomicFileIO.writeBytes(target, encrypted)
        } finally {
            encrypted.fill(0)
        }
    }

    private fun readStoredSortOrder(file: File): Long? = runCatching {
        val expectedId = file.name.removeSuffix(".enc")
        val encrypted = AtomicFileIO.readBytes(file)
        val jsonText = try {
            crypto.decryptToText(encrypted, Crypto.contextAad("note-record", expectedId))
        } finally {
            encrypted.fill(0)
        }
        val json = JSONObject(jsonText)
        require(json.getString("id") == expectedId) { "Идентификатор заметки не совпадает с именем файла." }
        json.optLong("sortOrder", Long.MAX_VALUE)
    }.getOrNull()

    private fun overwriteAndDelete(file: File) {
        if (!AtomicFileIO.existsRecoverable(file)) return
        runCatching {
            val originalLength = file.length()
            RandomAccessFile(file, "rw").use { stream ->
                stream.seek(0L)
                val zeros = ByteArray(32 * 1024)
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
        check(AtomicFileIO.delete(file)) { "Не удалось удалить заметку из хранилища." }
    }
}
