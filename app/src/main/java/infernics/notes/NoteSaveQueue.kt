package infernics.notes

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

object NoteSaveQueue {
    private val dispatcher = Dispatchers.IO.limitedParallelism(1)
    private val scope = CoroutineScope(SupervisorJob() + dispatcher)

    fun save(
        repository: NoteRepository,
        note: Note,
        onComplete: ((Result<Unit>) -> Unit)? = null
    ) {
        scope.launch {
            val result = runOperation { repository.save(note) }
            deliver(onComplete, result)
        }
    }

    fun delete(
        repository: NoteRepository,
        id: String,
        onComplete: ((Result<Unit>) -> Unit)? = null
    ) {
        scope.launch {
            val result = runOperation { repository.delete(id) }
            deliver(onComplete, result)
        }
    }

    fun reorder(
        repository: NoteRepository,
        orderedNotes: List<Note>,
        onComplete: ((Result<Unit>) -> Unit)? = null
    ) {
        scope.launch {
            val result = runOperation { repository.reorder(orderedNotes) }
            deliver(onComplete, result)
        }
    }

    private inline fun runOperation(operation: () -> Unit): Result<Unit> = try {
        operation()
        Result.success(Unit)
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (error: Exception) {
        Result.failure(error)
    }

    private suspend fun deliver(
        callback: ((Result<Unit>) -> Unit)?,
        result: Result<Unit>
    ) {
        if (callback != null) withContext(Dispatchers.Main) { callback(result) }
    }

    suspend fun awaitIdle() {
        withContext(dispatcher) { Unit }
    }
}
