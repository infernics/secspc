package infernics.notes

import android.content.Context

object AppPreferences {
    private const val FILE_NAME = "secnote_preferences"
    private const val KEY_DARK_THEME = "dark_theme"
    private const val KEY_SCREENSHOT_BLOCKING = "screenshot_blocking"
    private const val KEY_AUTO_LOCK_MINUTES = "auto_lock_minutes"
    private const val KEY_INITIAL_BIOMETRIC_OFFER_PENDING = "initial_biometric_offer_pending"

    fun isDarkTheme(context: Context): Boolean =
        preferences(context).getBoolean(KEY_DARK_THEME, true)

    fun setDarkTheme(context: Context, enabled: Boolean) {
        preferences(context).edit().putBoolean(KEY_DARK_THEME, enabled).apply()
    }

    fun isScreenshotBlockingEnabled(context: Context): Boolean =
        preferences(context).getBoolean(KEY_SCREENSHOT_BLOCKING, false)

    fun setScreenshotBlockingEnabled(context: Context, enabled: Boolean) {
        preferences(context).edit().putBoolean(KEY_SCREENSHOT_BLOCKING, enabled).apply()
    }

    fun isInitialBiometricOfferPending(context: Context): Boolean =
        preferences(context).getBoolean(KEY_INITIAL_BIOMETRIC_OFFER_PENDING, false)

    fun setInitialBiometricOfferPending(context: Context, pending: Boolean) {
        preferences(context).edit().putBoolean(KEY_INITIAL_BIOMETRIC_OFFER_PENDING, pending).commit()
    }

    fun getAutoLockMinutes(context: Context): Int =
        preferences(context).getInt(KEY_AUTO_LOCK_MINUTES, 0).let { value ->
            if (value in AutoLockPolicy.supportedMinutes) value else 0
        }

    fun setAutoLockMinutes(context: Context, minutes: Int) {
        require(minutes in AutoLockPolicy.supportedMinutes)
        preferences(context).edit().putInt(KEY_AUTO_LOCK_MINUTES, minutes).apply()
    }

    internal fun backupSettings(context: Context): BackupSettings = BackupSettings(
        darkTheme = isDarkTheme(context),
        screenshotBlocking = isScreenshotBlockingEnabled(context),
        autoLockMinutes = getAutoLockMinutes(context)
    )

    internal fun applyBackupSettings(context: Context, settings: BackupSettings) {
        require(settings.autoLockMinutes in AutoLockPolicy.supportedMinutes)
        check(
            preferences(context).edit()
                .putBoolean(KEY_DARK_THEME, settings.darkTheme)
                .putBoolean(KEY_SCREENSHOT_BLOCKING, settings.screenshotBlocking)
                .putInt(KEY_AUTO_LOCK_MINUTES, settings.autoLockMinutes)
                .commit()
        ) { "Не удалось восстановить настройки приложения." }
    }

    fun reset(context: Context) {
        preferences(context).edit().clear().commit()
    }

    private fun preferences(context: Context) =
        context.getSharedPreferences(FILE_NAME, Context.MODE_PRIVATE)
}
