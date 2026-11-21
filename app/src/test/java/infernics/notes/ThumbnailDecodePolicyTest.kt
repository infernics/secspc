package infernics.notes

import org.junit.Assert.assertEquals
import org.junit.Test

class ThumbnailDecodePolicyTest {
    @Test
    fun cameraSizedPhotoIsDecodedWithBoundedSampling() {
        assertEquals(32, ThumbnailDecodePolicy.sampleSize(8000, 6000, 420))
    }

    @Test
    fun standardPhotoUsesSamplingAppropriateToPreviewSize() {
        assertEquals(8, ThumbnailDecodePolicy.sampleSize(1920, 1080, 420))
    }

    @Test
    fun alreadySmallImagesAreNotUpsampled() {
        assertEquals(1, ThumbnailDecodePolicy.sampleSize(320, 240, 420))
    }

    @Test
    fun invalidBoundsAreHandledWithoutDivisionByZero() {
        assertEquals(1, ThumbnailDecodePolicy.sampleSize(0, 0, 420))
    }
}
