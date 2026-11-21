package infernics.notes

import java.text.ParsePosition
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import java.util.TimeZone

internal object PhotoDatePolicy {
    fun dayKey(timestampMillis: Long, timeZone: TimeZone = TimeZone.getDefault()): Long {
        val calendar = Calendar.getInstance(timeZone).apply {
            timeInMillis = timestampMillis
            set(Calendar.HOUR_OF_DAY, 0)
            set(Calendar.MINUTE, 0)
            set(Calendar.SECOND, 0)
            set(Calendar.MILLISECOND, 0)
        }
        return calendar.timeInMillis
    }

    fun groupLabel(timestampMillis: Long): String =
        SimpleDateFormat("d MMMM yyyy", Locale.forLanguageTag("ru")).format(Date(timestampMillis))

    fun matches(name: String, timestampMillis: Long, rawQuery: String): Boolean {
        val query = rawQuery.trim().lowercase(Locale.ROOT)
        if (query.isEmpty()) return true
        if (name.lowercase(Locale.ROOT).contains(query)) return true
        val date = Date(timestampMillis)
        val formats = listOf(
            "dd.MM.yyyy", "d.M.yyyy", "d MMMM yyyy", "d MMM yyyy", "yyyy-MM-dd", "dd.MM"
        )
        return formats.any { pattern ->
            SimpleDateFormat(pattern, Locale.forLanguageTag("ru")).format(date).lowercase(Locale.ROOT).contains(query)
        }
    }

    fun parseExifTimestamp(dateTime: String?, offset: String?): Long? {
        val value = dateTime?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        val formatter = SimpleDateFormat("yyyy:MM:dd HH:mm:ss", Locale.US).apply {
            isLenient = false
            if (!offset.isNullOrBlank() && offset.matches(Regex("[+-]\\d{2}:\\d{2}"))) {
                timeZone = TimeZone.getTimeZone("GMT$offset")
            }
        }
        val position = ParsePosition(0)
        val parsed = formatter.parse(value, position) ?: return null
        if (position.index != value.length) return null
        return parsed.time
    }
}
