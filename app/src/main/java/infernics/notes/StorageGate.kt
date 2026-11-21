package infernics.notes

import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

object StorageGate {
    private val lock = ReentrantReadWriteLock(true)
    private val accessDepth = ThreadLocal.withInitial { 0 }
    @Volatile private var blocked = false
    @Volatile private var generation = 0L

    fun currentGeneration(): Long = lock.read {
        check(!blocked) { "Локальное хранилище заблокировано для очистки" }
        generation
    }

    fun <T> withAccess(expectedGeneration: Long, action: () -> T): T {
        val readLock = lock.readLock()
        readLock.lock()
        val previousDepth = accessDepth.get()
        try {

            check(!blocked || previousDepth > 0) { "Локальное хранилище очищается" }
            check(expectedGeneration == generation) { "Эта сессия хранилища уже недействительна" }
            accessDepth.set(previousDepth + 1)
            return action()
        } finally {
            accessDepth.set(previousDepth)
            readLock.unlock()
        }
    }

    fun <T> withExclusiveAccess(action: () -> T): T {
        val writeLock = lock.writeLock()
        writeLock.lock()
        try {
            check(!blocked) { "Локальное хранилище заблокировано для очистки" }
            return action()
        } finally {
            writeLock.unlock()
        }
    }

    fun blockAndDrain() {
        blocked = true
        lock.write {
            generation += 1L
        }
    }

    fun resumeAfterUnlock() {
        lock.write {
            blocked = false
        }
    }

    fun resumeAfterNewVault() = resumeAfterUnlock()

    fun isBlocked(): Boolean = blocked
}
