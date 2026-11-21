package infernics.notes

internal object ThumbnailDecodePolicy {
    fun sampleSize(width: Int, height: Int, maxDimension: Int): Int {
        require(maxDimension in 64..2048) { "Invalid thumbnail dimension" }
        if (width <= 0 || height <= 0) return 1

        var sampleSize = 1L
        val limit = maxDimension.toLong()
        while (
            maxOf(
                (width.toLong() + sampleSize - 1L) / sampleSize,
                (height.toLong() + sampleSize - 1L) / sampleSize
            ) > limit
        ) {
            if (sampleSize >= (1L shl 30)) break
            sampleSize *= 2L
        }
        return sampleSize.toInt()
    }
}
