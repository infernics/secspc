package infernics.notes

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone

class PhotoDatePolicyTest {
    @Test
    fun exifOriginalDateUsesRecordedUtcOffset() {
        val actual = PhotoDatePolicy.parseExifTimestamp("2024:03:12 13:45:00", "+03:00")
        val expected = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }.parse("2024-03-12 10:45:00")!!.time
        assertEquals(expected, actual)
    }

    @Test
    fun invalidExifDateDoesNotCreateAnInventedTimestamp() {
        assertNull(PhotoDatePolicy.parseExifTimestamp("not-a-date", null))
    }

    @Test
    fun filesCapturedOnSameLocalDayShareOneGroupKey() {
        val format = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
        val first = format.parse("2024-08-12 08:15:00")!!.time
        val second = format.parse("2024-08-12 23:50:00")!!.time
        assertEquals(PhotoDatePolicy.dayKey(first), PhotoDatePolicy.dayKey(second))
    }

    @Test
    fun searchMatchesNamesAndSeveralDateFormats() {
        val timestamp = SimpleDateFormat("yyyy-MM-dd", Locale.US)
            .parse("2024-08-12")!!.time
        assertTrue(PhotoDatePolicy.matches("Photo_001.jpg", timestamp, "photo_001"))
        assertTrue(PhotoDatePolicy.matches("Photo_001.jpg", timestamp, "12.08.2024"))
        assertTrue(PhotoDatePolicy.matches("Photo_001.jpg", timestamp, "12 августа"))
        assertFalse(PhotoDatePolicy.matches("Photo_001.jpg", timestamp, "13.08.2024"))
    }

    @Test
    fun sourceDateCanRemainDifferentFromImportDate() {
        val capture = SimpleDateFormat("yyyy-MM-dd", Locale.US).parse("2024-03-12")!!.time
        val imported = SimpleDateFormat("yyyy-MM-dd", Locale.US).parse("2024-08-12")!!.time
        assertTrue(PhotoDatePolicy.dayKey(capture) != PhotoDatePolicy.dayKey(imported))
        assertEquals("12 марта 2024", PhotoDatePolicy.groupLabel(capture))
    }
}
