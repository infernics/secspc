package infernics.notes

internal object AutoLockPolicy {
    val supportedMinutes: Set<Int> = setOf(-1, 0, 1, 5, 10, 15, 30)

    fun timeoutMillis(minutes: Int): Long =
        if (minutes > 0) minutes.toLong() * 60_000L else 0L

    fun shouldLockImmediately(minutes: Int): Boolean = minutes == 0

    fun shouldLockAfterBackground(minutes: Int, elapsedMillis: Long): Boolean =
        minutes > 0 && elapsedMillis >= timeoutMillis(minutes)
}
