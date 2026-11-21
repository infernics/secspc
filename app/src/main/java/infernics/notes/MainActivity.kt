package infernics.notes

import kotlinx.coroutines.delay
import kotlinx.coroutines.Job
import android.os.SystemClock
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.material3.FilterChip
import androidx.compose.material.icons.filled.DragHandle
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.gestures.detectDragGesturesAfterLongPress
import androidx.compose.foundation.gestures.detectTapGestures
import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import android.os.Bundle
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.view.WindowCompat
import androidx.fragment.app.FragmentActivity
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckBox
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.InsertDriveFile
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PhotoCamera
import androidx.compose.material.icons.filled.SaveAlt
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SmallFloatingActionButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.draw.clip
import androidx.compose.ui.zIndex
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalViewConfiguration
import androidx.compose.ui.platform.ViewConfiguration
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : FragmentActivity() {

    @Volatile var allowTemporarySystemUi: Boolean = false
    @Volatile var stoppedDuringTemporarySystemUi: Boolean = false

    @Volatile var preserveSessionOnTemporaryUiReturn: Boolean = false
    @Volatile var backupOperationInProgress: Boolean = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        check(HiddenVault.recoverInterruptedWipe(this)) {
            "Не удалось завершить защищённую очистку отдельного файлового пространства."
        }

        check(BackupManager.recoverInterruptedRestore(this)) {
            "Не удалось восстановить прежнее состояние после прерванного импорта резервной копии."
        }

        runCatching { FileVaultRepository.cleanupAbandonedTemporaryFiles(this) }
        if (AppPreferences.isScreenshotBlockingEnabled(this)) {
            window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        }
        setContent { SecNoteApp(this) }
    }
}

@Composable
private fun SecNoteApp(activity: MainActivity) {
    val context = LocalContext.current
    val appScope = rememberCoroutineScope()
    var crypto by remember { mutableStateOf<Crypto?>(null) }
    var needsSetup by remember { mutableStateOf(!Vault.isSetup(context)) }
    var darkTheme by remember { mutableStateOf(AppPreferences.isDarkTheme(context)) }
    var biometricEnabled by remember { mutableStateOf(BiometricVault.isEnabled(context)) }
    var biometricOfferPending by remember { mutableStateOf(AppPreferences.isInitialBiometricOfferPending(context)) }
    var biometricOfferBusy by remember { mutableStateOf(false) }
    var biometricOfferError by remember { mutableStateOf<String?>(null) }
    var panicPasswordConfigured by remember { mutableStateOf(PanicCredential.isConfigured(context)) }
    var hiddenVaultConfigured by remember { mutableStateOf(HiddenVault.isConfigured(context)) }
    var screenshotBlockingEnabled by remember {
        mutableStateOf(AppPreferences.isScreenshotBlockingEnabled(context))
    }
    var autoLockMinutes by remember { mutableStateOf(AppPreferences.getAutoLockMinutes(context)) }
    var wipePending by remember { mutableStateOf(EmergencyWipe.isPending(context)) }
    var wipeFailed by remember { mutableStateOf(false) }
    var wipeAttempt by remember { mutableStateOf(0) }
    var lockCleanupPending by remember { mutableStateOf(false) }
    val lockMainVault: () -> Unit = {
        if (crypto != null && !lockCleanupPending) {
            lockCleanupPending = true
            appScope.launch {

                delay(75)
                val storageBlocked = withContext(Dispatchers.IO) {

                    runCatching { NoteSaveQueue.awaitIdle() }
                    val blocked = runCatching { StorageGate.blockAndDrain() }.isSuccess
                    if (blocked) Crypto.destroyAll()
                    blocked
                }
                if (!storageBlocked) {

                    Crypto.destroyAll()
                }
                crypto = null
                lockCleanupPending = false
            }
        }
    }

    LaunchedEffect(wipePending, wipeAttempt) {
        if (wipePending) {
            val completed = withContext(Dispatchers.IO) {
                runCatching { EmergencyWipe.complete(context) }.getOrDefault(false)
            }
            if (completed) {
                crypto = null
                needsSetup = true
                biometricEnabled = false
                panicPasswordConfigured = false
                hiddenVaultConfigured = false
                darkTheme = true
                screenshotBlockingEnabled = false
                autoLockMinutes = 0
                wipeFailed = false
                wipePending = false
            } else {
                wipeFailed = true
            }
        }
    }

    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner, autoLockMinutes) {
        var backgroundAtElapsed = 0L
        var pendingLockJob: Job? = null
        val timeoutMs = AutoLockPolicy.timeoutMillis(autoLockMinutes)
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_STOP -> {
                    if (activity.allowTemporarySystemUi) {
                        activity.stoppedDuringTemporarySystemUi = true
                    } else {
                        backgroundAtElapsed = SystemClock.elapsedRealtime()
                        pendingLockJob?.cancel()
                        when {
                            AutoLockPolicy.shouldLockImmediately(autoLockMinutes) && !activity.backupOperationInProgress -> lockMainVault()
                            autoLockMinutes > 0 -> {
                                pendingLockJob = appScope.launch {
                                    delay(timeoutMs)
                                    if (backgroundAtElapsed != 0L && !activity.allowTemporarySystemUi &&
                                        !activity.backupOperationInProgress) {
                                        lockMainVault()
                                    }
                                }
                            }

                            else -> Unit
                        }
                    }
                }
                Lifecycle.Event.ON_RESUME -> {
                    if (activity.stoppedDuringTemporarySystemUi) {

                        val preserveSession = activity.preserveSessionOnTemporaryUiReturn
                        activity.stoppedDuringTemporarySystemUi = false
                        activity.allowTemporarySystemUi = false
                        activity.preserveSessionOnTemporaryUiReturn = false
                        backgroundAtElapsed = 0L
                        pendingLockJob?.cancel()
                        if (!preserveSession && !activity.backupOperationInProgress) lockMainVault()
                    } else if (backgroundAtElapsed != 0L) {
                        pendingLockJob?.cancel()
                        val elapsed = SystemClock.elapsedRealtime() - backgroundAtElapsed
                        if (!activity.backupOperationInProgress &&
                            AutoLockPolicy.shouldLockAfterBackground(autoLockMinutes, elapsed)) lockMainVault()
                        backgroundAtElapsed = 0L
                    }
                }
                else -> Unit
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose {
            pendingLockJob?.cancel()
            lifecycleOwner.lifecycle.removeObserver(observer)
        }
    }

    val scheme = if (darkTheme) secNoteDarkColors() else secNoteLightColors()
    SideEffect {
        val barColor = scheme.background.toArgb()
        activity.window.statusBarColor = barColor
        activity.window.navigationBarColor = barColor
        WindowCompat.getInsetsController(activity.window, activity.window.decorView).apply {
            isAppearanceLightStatusBars = !darkTheme
            isAppearanceLightNavigationBars = !darkTheme
        }
        if (screenshotBlockingEnabled) {
            activity.window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            activity.window.clearFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        }
    }

    MaterialTheme(
        colorScheme = scheme,
        typography = Typography(
            titleLarge = TextStyle(fontSize = 22.sp, fontFamily = FontFamily.SansSerif),
            titleMedium = TextStyle(fontSize = 17.sp, fontFamily = FontFamily.SansSerif)
        )
    ) {
        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            when {
                wipePending -> EmergencyWipeScreen(
                    failed = wipeFailed,
                    onRetry = { wipeFailed = false; wipeAttempt++ }
                )
                lockCleanupPending -> LockingScreen()
                crypto == null && needsSetup -> SetupScreen(onCreated = {
                    crypto = it
                    needsSetup = false
                    AppPreferences.setInitialBiometricOfferPending(context, true)
                    biometricOfferPending = true
                    biometricOfferError = null
                })
                crypto == null -> LockScreen(
                    biometricEnabled = biometricEnabled,
                    onUnlocked = {
                        StorageGate.resumeAfterUnlock()
                        panicPasswordConfigured = PanicCredential.isConfigured(context)
                        hiddenVaultConfigured = HiddenVault.isConfigured(context)
                        crypto = it
                    },
                    onEmergencyWipe = { wipePending = true },
                    onBiometricUnlock = { report ->
                        BiometricVault.unlock(
                            activity,
                            onUnlocked = { unlocked ->
                                appScope.launch {
                                    val vaultReady = withContext(Dispatchers.IO) {
                                        Vault.ensureSaltWrapped(context, unlocked)
                                    }
                                    if (vaultReady) {
                                        StorageGate.resumeAfterUnlock()
                                        panicPasswordConfigured = PanicCredential.isConfigured(context)
                                        hiddenVaultConfigured = HiddenVault.isConfigured(context)
                                        crypto = unlocked
                                    } else {
                                        unlocked.destroy()
                                        report("Не удалось проверить ключ защищённого хранилища. Войдите по основному паролю.")
                                    }
                                }
                            },
                            onError = { message ->
                                biometricEnabled = BiometricVault.isEnabled(context)
                                report(message)
                            }
                        )
                    }
                )
                else -> MainScreen(
                    activity = activity,
                    crypto = crypto!!,
                    darkTheme = darkTheme,
                    biometricEnabled = biometricEnabled,
                    panicPasswordConfigured = panicPasswordConfigured,
                    hiddenVaultConfigured = hiddenVaultConfigured,
                    lockCleanupPending = lockCleanupPending,
                    screenshotBlockingEnabled = screenshotBlockingEnabled,
                    autoLockMinutes = autoLockMinutes,
                    onLock = lockMainVault,
                    onThemeChange = { enabled ->
                        darkTheme = enabled
                        AppPreferences.setDarkTheme(context, enabled)
                    },
                    onScreenshotBlockingChange = { enabled ->
                        screenshotBlockingEnabled = enabled
                        AppPreferences.setScreenshotBlockingEnabled(context, enabled)
                    },
                    onAutoLockChange = { minutes ->
                        autoLockMinutes = minutes
                        AppPreferences.setAutoLockMinutes(context, minutes)
                    },
                    onPanicPasswordConfiguredChange = { panicPasswordConfigured = it },
                    onHiddenVaultConfiguredChange = { hiddenVaultConfigured = it },
                    onBackupRestored = { restored ->
                        crypto = restored.crypto
                        darkTheme = restored.settings.darkTheme
                        screenshotBlockingEnabled = restored.settings.screenshotBlocking
                        autoLockMinutes = restored.settings.autoLockMinutes
                        hiddenVaultConfigured = restored.hiddenVaultConfigured
                        panicPasswordConfigured = restored.panicPasswordConfigured
                        biometricEnabled = false
                    },
                    onBackupSessionRecovered = { recovered -> crypto = recovered },
                    onBiometricChange = { enabled, report ->
                        if (enabled) {
                            BiometricVault.enable(
                                activity,
                                crypto!!,
                                onEnabled = {
                                    biometricEnabled = true
                                    report("Вход по биометрии включён.")
                                },
                                onError = { message ->
                                    val lockAfterPrompt = activity.stoppedDuringTemporarySystemUi
                                    activity.stoppedDuringTemporarySystemUi = false
                                    if (lockAfterPrompt) lockMainVault()
                                    report(message)
                                }
                            )
                        } else {
                            BiometricVault.disable(context)
                            biometricEnabled = false
                            report("Вход по биометрии отключён. Основной пароль продолжает работать.")
                        }
                    }
                )
            }

            if (crypto != null && biometricOfferPending && !biometricEnabled && !wipePending) {
                val availability = BiometricVault.canAuthenticate(context)
                val available = availability == androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS
                AlertDialog(
                    onDismissRequest = {
                        if (!biometricOfferBusy) {
                            AppPreferences.setInitialBiometricOfferPending(context, false)
                            biometricOfferPending = false
                            biometricOfferError = null
                        }
                    },
                    title = { Text("Включить биометрический вход?") },
                    text = {
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(
                                if (available) "Можно разблокировать основное хранилище отпечатком или другой сильной биометрией Android. Основной пароль останется доступен. Скрытое хранилище биометрией не открывается."
                                else "На устройстве пока недоступна сильная биометрия. Можно настроить её в Android и включить позднее в настройках SecNote."
                            )
                            biometricOfferError?.let {
                                Text(it, color = MaterialTheme.colorScheme.error,
                                    style = MaterialTheme.typography.bodySmall)
                            }
                        }
                    },
                    confirmButton = {
                        if (available) {
                            TextButton(
                                enabled = !biometricOfferBusy,
                                onClick = {
                                    val activeCrypto = crypto ?: return@TextButton
                                    biometricOfferBusy = true
                                    biometricOfferError = null
                                    BiometricVault.enable(
                                        activity,
                                        activeCrypto,
                                        onEnabled = {
                                            biometricEnabled = true
                                            biometricOfferBusy = false
                                            biometricOfferPending = false
                                            AppPreferences.setInitialBiometricOfferPending(context, false)
                                        },
                                        onError = { error ->
                                            val lockAfterPrompt = activity.stoppedDuringTemporarySystemUi
                                            activity.stoppedDuringTemporarySystemUi = false
                                            activity.preserveSessionOnTemporaryUiReturn = false
                                            if (lockAfterPrompt) lockMainVault()
                                            biometricOfferBusy = false
                                            biometricOfferError = error
                                        }
                                    )
                                }
                            ) { Text(if (biometricOfferBusy) "Ожидание…" else "Включить") }
                        }
                    },
                    dismissButton = {
                        TextButton(
                            enabled = !biometricOfferBusy,
                            onClick = {
                                AppPreferences.setInitialBiometricOfferPending(context, false)
                                biometricOfferPending = false
                                biometricOfferError = null
                            }
                        ) { Text("Позже") }
                    }
                )
            }
        }
    }
}

@Composable
private fun LockingScreen() {
    Column(
        Modifier.fillMaxSize(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        CircularProgressIndicator()
        Spacer(Modifier.height(14.dp))
        Text("Блокировка защищённого хранилища")
    }
}

@Composable
private fun EmergencyWipeScreen(failed: Boolean, onRetry: () -> Unit) {
    Column(
        Modifier.fillMaxSize().padding(32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Icon(Icons.Default.Lock, contentDescription = null, modifier = Modifier.size(38.dp))
        Spacer(Modifier.height(18.dp))
        Text("Попытки исчерпаны", style = MaterialTheme.typography.titleLarge)
        Spacer(Modifier.height(10.dp))
        if (failed) {
            Text(
                "Очистка ещё не завершена. SecNote заблокирован и продолжит её после повтора.",
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.height(18.dp))
            Button(onClick = onRetry) { Text("Повторить очистку") }
        } else {
            CircularProgressIndicator()
            Spacer(Modifier.height(10.dp))
            Text("Выполняется очистка хранилища…", color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

private fun secNoteDarkColors() = darkColorScheme(
    primary = Color(0xFFC5C8CC),
    onPrimary = Color(0xFF17191B),
    primaryContainer = Color(0xFF303438),
    onPrimaryContainer = Color(0xFFE5E7E9),
    secondary = Color(0xFFB8BDC1),
    onSecondary = Color(0xFF1B1D1F),
    secondaryContainer = Color(0xFF292D31),
    onSecondaryContainer = Color(0xFFE0E3E5),
    tertiary = Color(0xFFADB3B8),
    onTertiary = Color(0xFF191B1D),
    background = Color(0xFF101112),
    onBackground = Color(0xFFF1F1F1),
    surface = Color(0xFF151719),
    onSurface = Color(0xFFF1F1F1),
    surfaceVariant = Color(0xFF202326),
    onSurfaceVariant = Color(0xFFB5B9BD),
    outline = Color(0xFF42474B),
    outlineVariant = Color(0xFF303438),
    error = Color(0xFFD6A09B),
    onError = Color(0xFF351F1D)
)

private fun secNoteLightColors() = lightColorScheme(
    primary = Color(0xFF51585E),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFE0E3E5),
    onPrimaryContainer = Color(0xFF252A2E),
    secondary = Color(0xFF62696F),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFE8EAEC),
    onSecondaryContainer = Color(0xFF292E32),
    tertiary = Color(0xFF686E73),
    onTertiary = Color.White,
    background = Color(0xFFF2F3F3),
    onBackground = Color(0xFF202326),
    surface = Color(0xFFFAFAFA),
    onSurface = Color(0xFF202326),
    surfaceVariant = Color(0xFFE6E8E9),
    onSurfaceVariant = Color(0xFF565D62),
    outline = Color(0xFF8D9499),
    outlineVariant = Color(0xFFD1D5D8),
    error = Color(0xFF8A3A34),
    onError = Color.White
)

@Composable
private fun SetupScreen(onCreated: (Crypto) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var password by remember { mutableStateOf("") }
    var repeatedPassword by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    Column(
        Modifier.fillMaxSize().padding(28.dp),
        verticalArrangement = Arrangement.Center
    ) {
        Text("SecNote", style = MaterialTheme.typography.headlineMedium)
        Text("infernics.ru", color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(30.dp))
        Text("Создайте основной пароль", style = MaterialTheme.typography.titleLarge)
        Spacer(Modifier.height(8.dp))
        Text(
            "Он защищает заметки и файлы. После создания пароля можно сразу включить биометрический вход или отказаться.",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            style = MaterialTheme.typography.bodyMedium
        )
        Spacer(Modifier.height(22.dp))
        OutlinedTextField(
            value = password,
            onValueChange = { password = it; errorMessage = null },
            label = { Text("Пароль") },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(
            value = repeatedPassword,
            onValueChange = { repeatedPassword = it; errorMessage = null },
            label = { Text("Повторите пароль") },
            singleLine = true,
            isError = repeatedPassword.isNotEmpty() && password != repeatedPassword,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth()
        )
        if (errorMessage != null) {
            Spacer(Modifier.height(8.dp))
            Text(errorMessage!!, color = MaterialTheme.colorScheme.error)
        }
        Spacer(Modifier.height(22.dp))
        Button(
            onClick = {
                busy = true
                scope.launch {
                    val result = withContext(Dispatchers.Default) {
                        runCatching { Vault.create(context, password) }
                    }
                    busy = false
                    result.onSuccess { createdCrypto ->

                        StorageGate.resumeAfterNewVault()
                        onCreated(createdCrypto)
                    }.onFailure {
                        errorMessage = it.message ?: "Не удалось создать хранилище"
                    }
                }
            },
            enabled = !busy && password.isNotEmpty() && password == repeatedPassword,
            modifier = Modifier.fillMaxWidth()
        ) {
            if (busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
            else Text("Создать защищённое хранилище")
        }
        Spacer(Modifier.height(14.dp))
        Text(
            "Пароль не сохраняется. Если вы его забудете, восстановить данные будет невозможно.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun LockScreen(
    biometricEnabled: Boolean,
    onUnlocked: (Crypto) -> Unit,
    onEmergencyWipe: () -> Unit,
    onBiometricUnlock: ((String) -> Unit) -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var password by remember { mutableStateOf("") }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    Column(
        Modifier.fillMaxSize().padding(28.dp),
        verticalArrangement = Arrangement.Center
    ) {
        IconButton(
            onClick = { if (biometricEnabled) onBiometricUnlock { errorMessage = it } },
            enabled = biometricEnabled && !busy,
            modifier = Modifier.size(54.dp)
        ) {
            Icon(
                Icons.Default.Lock,
                contentDescription = if (biometricEnabled) "Разблокировать SecNote по биометрии" else "SecNote заблокирован",
                modifier = Modifier.size(34.dp)
            )
        }
        Spacer(Modifier.height(14.dp))
        Text("SecNote", style = MaterialTheme.typography.headlineMedium)
        Text("infernics.ru", color = MaterialTheme.colorScheme.onSurfaceVariant)
        if (biometricEnabled) {
            Spacer(Modifier.height(4.dp))
            Text(
                "Нажмите на замок для входа по биометрии",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodySmall
            )
        }
        Spacer(Modifier.height(28.dp))
        Text("Введите пароль", style = MaterialTheme.typography.titleLarge)
        Spacer(Modifier.height(16.dp))
        OutlinedTextField(
            value = password,
            onValueChange = { password = it; errorMessage = null },
            label = { Text("Пароль") },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth()
        )
        if (errorMessage != null) {
            Spacer(Modifier.height(8.dp))
            Text(errorMessage!!, color = MaterialTheme.colorScheme.error)
        }
        Spacer(Modifier.height(16.dp))
        Button(
            onClick = {
                busy = true
                errorMessage = null
                scope.launch {
                    val isPanicPassword = withContext(Dispatchers.Default) {
                        PanicCredential.verify(context, password)
                    }
                    if (isPanicPassword) {
                        val markerWritten = withContext(Dispatchers.IO) {
                            runCatching { EmergencyWipe.markPending(context) }.isSuccess
                        }
                        if (!markerWritten) {
                            errorMessage = "Не удалось начать защищённую очистку. Повторите попытку."
                            busy = false
                        } else {

                            errorMessage = "Попытки исчерпаны"
                            password = ""
                            delay(4_000)
                            onEmergencyWipe()
                        }
                    } else {
                        val unlocked = withContext(Dispatchers.Default) {
                            Vault.unlock(context, password)
                        }
                        busy = false
                        if (unlocked == null) {
                            errorMessage = "Неверный пароль или повреждённое хранилище."
                        } else {
                            password = ""
                            onUnlocked(unlocked)
                        }
                    }
                }
            },
            enabled = !busy && password.isNotEmpty(),
            modifier = Modifier.fillMaxWidth()
        ) {
            if (busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
            else Text("Разблокировать")
        }
    }
}

private enum class MainPage { NOTES, FILES, SETTINGS }

@Composable
private fun MainScreen(
    activity: MainActivity,
    crypto: Crypto,
    darkTheme: Boolean,
    biometricEnabled: Boolean,
    panicPasswordConfigured: Boolean,
    hiddenVaultConfigured: Boolean,
    lockCleanupPending: Boolean,
    screenshotBlockingEnabled: Boolean,
    autoLockMinutes: Int,
    onLock: () -> Unit,
    onThemeChange: (Boolean) -> Unit,
    onScreenshotBlockingChange: (Boolean) -> Unit,
    onAutoLockChange: (Int) -> Unit,
    onPanicPasswordConfiguredChange: (Boolean) -> Unit,
    onHiddenVaultConfiguredChange: (Boolean) -> Unit,
    onBackupRestored: (BackupRestoreResult) -> Unit,
    onBackupSessionRecovered: (Crypto) -> Unit,
    onBiometricChange: (Boolean, (String) -> Unit) -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var page by remember { mutableStateOf(MainPage.NOTES) }
    var cameraVisible by remember { mutableStateOf(false) }
    var hiddenCrypto by remember { mutableStateOf<Crypto?>(null) }
    var showHiddenUnlock by remember { mutableStateOf(false) }
    var hiddenPassword by remember { mutableStateOf("") }
    var hiddenPasswordError by remember { mutableStateOf<String?>(null) }
    var hiddenUnlockBusy by remember { mutableStateOf(false) }

    DisposableEffect(hiddenCrypto) {

        val sessionKey = hiddenCrypto
        onDispose { sessionKey?.destroy() }
    }

    if (showHiddenUnlock) {
        AlertDialog(
            onDismissRequest = {
                if (!hiddenUnlockBusy) {
                    showHiddenUnlock = false
                    hiddenPassword = ""
                    hiddenPasswordError = null
                }
            },
            title = { Text("Введите пароль") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = hiddenPassword,
                        onValueChange = { hiddenPassword = it; hiddenPasswordError = null },
                        label = { Text("Пароль") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        enabled = !hiddenUnlockBusy
                    )
                    if (hiddenPasswordError != null) {
                        Text(hiddenPasswordError!!, color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall)
                    }
                }
            },
            confirmButton = {
                TextButton(
                    enabled = !hiddenUnlockBusy && hiddenPassword.isNotEmpty(),
                    onClick = {
                        hiddenUnlockBusy = true
                        val suppliedPassword = hiddenPassword
                        hiddenPassword = ""
                        scope.launch {
                            val isEmergencySecret = withContext(Dispatchers.Default) {
                                PanicCredential.verify(context, suppliedPassword)
                            }
                            if (isEmergencySecret) {
                                val erased = withContext(Dispatchers.IO) {
                                    runCatching { HiddenVault.destroy(context) }.isSuccess
                                }
                                if (erased) onHiddenVaultConfiguredChange(false)
                                hiddenUnlockBusy = false

                                hiddenPasswordError = "Неверный пароль или хранилище повреждено."
                            } else {
                                val result = withContext(Dispatchers.Default) {
                                    HiddenVault.unlock(context, suppliedPassword)
                                }
                                hiddenUnlockBusy = false
                                if (result == null) {
                                    hiddenPasswordError = "Неверный пароль или хранилище повреждено."
                                } else if (lockCleanupPending || StorageGate.isBlocked()) {
                                    result.destroy()
                                } else {
                                    hiddenCrypto = result
                                    showHiddenUnlock = false
                                    hiddenPasswordError = null
                                }
                            }
                            suppliedPassword.toCharArray().fill('\u0000')
                        }
                    }
                ) { if (hiddenUnlockBusy) Text("Проверка…") else Text("Открыть") }
            },
            dismissButton = {
                TextButton(enabled = !hiddenUnlockBusy, onClick = {
                    showHiddenUnlock = false
                    hiddenPassword = ""
                    hiddenPasswordError = null
                }) { Text("Отмена") }
            }
        )
    }

    BackHandler(enabled = cameraVisible || page != MainPage.NOTES) {
        if (cameraVisible) cameraVisible = false else page = MainPage.NOTES
    }

    if (hiddenCrypto != null) {
        val sessionCrypto = hiddenCrypto!!
        if (cameraVisible) {
            CameraCaptureScreen(
                activity = activity,
                crypto = sessionCrypto,
                storageDirectoryName = HiddenVault.DIRECTORY_NAME,
                onClose = { cameraVisible = false }
            )
        } else {
            FileVaultScreen(
                activity = activity,
                crypto = sessionCrypto,
                onBack = { hiddenCrypto = null },
                onLock = onLock,
                onOpenCamera = { cameraVisible = true },
                storageDirectoryName = HiddenVault.DIRECTORY_NAME
            )
        }
        return
    }

    if (cameraVisible) {
        CameraCaptureScreen(
            activity = activity,
            crypto = crypto,
            storageDirectoryName = "file_vault",
            onClose = { cameraVisible = false }
        )
    } else when (page) {
        MainPage.NOTES -> NotesHomeScreen(
            crypto = crypto,
            onOpenFiles = { page = MainPage.FILES },
            onOpenSettings = { page = MainPage.SETTINGS },
            onOpenCamera = { cameraVisible = true },
            onLock = onLock,
            onHiddenVaultRequest = {
                if (hiddenVaultConfigured) {
                    hiddenPassword = ""
                    hiddenPasswordError = null
                    showHiddenUnlock = true
                }
            }
        )
        MainPage.FILES -> FileVaultScreen(
            activity = activity,
            crypto = crypto,
            onBack = { page = MainPage.NOTES },
            onLock = onLock,
            onOpenCamera = { cameraVisible = true }
        )
        MainPage.SETTINGS -> SettingsScreen(
            activity = activity,
            crypto = crypto,
            onBackupRestored = onBackupRestored,
            onBackupSessionRecovered = onBackupSessionRecovered,
            darkTheme = darkTheme,
            biometricEnabled = biometricEnabled,
            panicPasswordConfigured = panicPasswordConfigured,
            hiddenVaultConfigured = hiddenVaultConfigured,
            screenshotBlockingEnabled = screenshotBlockingEnabled,
            autoLockMinutes = autoLockMinutes,
            onThemeChange = onThemeChange,
            onScreenshotBlockingChange = onScreenshotBlockingChange,
            onAutoLockChange = onAutoLockChange,
            onPanicPasswordConfiguredChange = onPanicPasswordConfiguredChange,
            onHiddenVaultConfiguredChange = onHiddenVaultConfiguredChange,
            onBiometricChange = onBiometricChange,
            onBack = { page = MainPage.NOTES }
        )
    }
}

@Composable
private fun NotesHomeScreen(
    crypto: Crypto,
    onOpenFiles: () -> Unit,
    onOpenSettings: () -> Unit,
    onOpenCamera: () -> Unit,
    onLock: () -> Unit,
    onHiddenVaultRequest: () -> Unit
) {
    val context = LocalContext.current
    val repository = remember(crypto) { NoteRepository(context, crypto) }
    val scope = rememberCoroutineScope()
    var notes by remember { mutableStateOf<List<Note>>(emptyList()) }
    var loaded by remember { mutableStateOf(false) }
    var editing by remember { mutableStateOf<Note?>(null) }
    var editingIsNew by remember { mutableStateOf(true) }

    suspend fun reload() {
        notes = withContext(Dispatchers.IO) { repository.loadAll() }
        loaded = true
    }
    LaunchedEffect(crypto) { reload() }

    val current = editing
    if (current != null) {
        NoteEditorScreen(
            note = current,
            isNew = editingIsNew,
            onAutoSave = { changed, complete -> NoteSaveQueue.save(repository, changed, complete) },
            onFinish = { finalNote, complete ->
                if (finalNote == null) {
                    editing = null
                    complete(Result.success(Unit))
                } else {
                    NoteSaveQueue.save(repository, finalNote) { result ->
                        if (result.isSuccess) {
                            scope.launch {
                                reload()
                                complete(result)
                                editing = null
                            }
                        } else {
                            complete(result)
                        }
                    }
                }
            },
            onDeleted = { id, complete ->
                NoteSaveQueue.delete(repository, id) { result ->
                    if (result.isSuccess) {
                        scope.launch {
                            reload()
                            complete(result)
                            editing = null
                        }
                    } else {
                        complete(result)
                    }
                }
            },
            onDiscard = { editing = null }
        )
    } else {
        NotesListScreen(
            notes = notes,
            loaded = loaded,
            onNew = { kind ->
                editing = Note(
                    kind = kind,
                    checklist = if (kind == NoteKind.LIST) listOf(ChecklistItem()) else emptyList()
                )
                editingIsNew = true
            },
            onOpen = { editing = it; editingIsNew = false },
            onReorder = { fromId, toId ->
                val reordered = swapNotePositions(notes, fromId, toId)
                if (reordered !== notes) {
                    notes = reordered
                    NoteSaveQueue.reorder(repository, reordered) { result ->
                        if (result.isFailure) {
                            scope.launch { reload() }
                            Toast.makeText(
                                context,
                                "Не удалось сохранить новый порядок заметок.",
                                Toast.LENGTH_LONG
                            ).show()
                        }
                    }
                }
            },
            onOpenFiles = onOpenFiles,
            onOpenSettings = onOpenSettings,
            onOpenCamera = onOpenCamera,
            onLock = onLock,
            onHiddenVaultRequest = onHiddenVaultRequest
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
private fun NotesListScreen(
    notes: List<Note>,
    loaded: Boolean,
    onNew: (NoteKind) -> Unit,
    onOpen: (Note) -> Unit,
    onReorder: (String, String) -> Unit,
    onOpenFiles: () -> Unit,
    onOpenSettings: () -> Unit,
    onOpenCamera: () -> Unit,
    onLock: () -> Unit,
    onHiddenVaultRequest: () -> Unit
) {
    var showCreateDialog by remember { mutableStateOf(false) }
    val listState = rememberLazyListState()
    var draggedId by remember { mutableStateOf<String?>(null) }
    var dragOffset by remember { mutableStateOf(0f) }
    val reorderCallback by rememberUpdatedState(onReorder)
    val lockCallback by rememberUpdatedState(onLock)
    val hiddenVaultCallback by rememberUpdatedState(onHiddenVaultRequest)

    if (showCreateDialog) {
        AlertDialog(
            onDismissRequest = { showCreateDialog = false },
            title = { Text("Что создаём?") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = { showCreateDialog = false; onNew(NoteKind.NOTE) },
                        modifier = Modifier.fillMaxWidth()
                    ) { Text("Обычная заметка") }
                    Button(
                        onClick = { showCreateDialog = false; onNew(NoteKind.LIST) },
                        modifier = Modifier.fillMaxWidth()
                    ) { Text("Список") }
                }
            },
            confirmButton = {},
            dismissButton = {
                TextButton(onClick = { showCreateDialog = false }) { Text("Отмена") }
            }
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("SecNote")
                        Text("infernics.ru", style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                },
                actions = {
                    IconButton(onClick = onOpenSettings) {
                        Icon(Icons.Default.Settings, contentDescription = "Настройки", modifier = Modifier.size(24.dp))
                    }
                    IconButton(onClick = onOpenFiles) {
                        Icon(Icons.Default.FolderOpen, contentDescription = "Зашифрованные файлы")
                    }
                    val baseViewConfiguration = LocalViewConfiguration.current
                    val fiveSecondViewConfiguration = remember(baseViewConfiguration) {
                        object : ViewConfiguration by baseViewConfiguration {
                            override val longPressTimeoutMillis: Long = 5_000L
                        }
                    }
                    CompositionLocalProvider(
                        LocalViewConfiguration provides fiveSecondViewConfiguration
                    ) {
                        Icon(
                            Icons.Default.Lock,
                            contentDescription = "Заблокировать",
                            modifier = Modifier
                                .size(48.dp)
                                .pointerInput(Unit) {
                                    detectTapGestures(
                                        onTap = { lockCallback() },
                                        onLongPress = { hiddenVaultCallback() }
                                    )
                                }
                                .padding(12.dp)
                        )
                    }
                }
            )
        },
        floatingActionButton = {
            Column(
                horizontalAlignment = Alignment.End,
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                SmallFloatingActionButton(onClick = onOpenCamera) {
                    Icon(
                        Icons.Default.PhotoCamera,
                        contentDescription = "Снять фото в зашифрованное хранилище"
                    )
                }
                FloatingActionButton(onClick = { showCreateDialog = true }) {
                    Icon(Icons.Default.Add, contentDescription = "Создать")
                }
            }
        }
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when {
                !loaded -> CircularProgressIndicator(Modifier.align(Alignment.Center))
                notes.isEmpty() -> Column(
                    Modifier.align(Alignment.Center).padding(32.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Icon(Icons.Default.CheckBox, contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(38.dp))
                    Spacer(Modifier.height(12.dp))
                    Text("Пока нет записей", color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text("Нажмите +, чтобы создать заметку или список.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        style = MaterialTheme.typography.bodySmall)
                }
                else -> LazyColumn(
                    state = listState,
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(horizontal = 16.dp, vertical = 10.dp),
                    verticalArrangement = Arrangement.spacedBy(9.dp)
                ) {
                    items(notes, key = { it.id }) { note ->
                        Card(
                            modifier = Modifier
                                .animateItem()
                                .fillMaxWidth()
                                .zIndex(if (draggedId == note.id) 1f else 0f)
                                .graphicsLayer {
                                    translationY = if (draggedId == note.id) dragOffset else 0f
                                    shadowElevation = if (draggedId == note.id) 12.dp.toPx() else 0f
                                },
                            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant)
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Column(
                                    Modifier.weight(1f)
                                        .clickable { onOpen(note) }
                                        .padding(horizontal = 16.dp, vertical = 14.dp)
                                ) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Text(
                                            note.title.ifBlank { if (note.kind == NoteKind.LIST) "Список" else "Без названия" },
                                            style = MaterialTheme.typography.titleMedium,
                                            modifier = Modifier.weight(1f)
                                        )
                                        if (note.kind == NoteKind.LIST) {
                                            Text(
                                                "СПИСОК",
                                                style = MaterialTheme.typography.labelSmall,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant
                                            )
                                        }
                                    }
                                    val preview = if (note.kind == NoteKind.LIST) {
                                        val tasks = note.checklist.filter { it.text.isNotBlank() }
                                        if (tasks.isEmpty()) "Пустой список"
                                        else "${tasks.count { it.checked }}/${tasks.size} выполнено"
                                    } else note.body.trim()
                                    if (preview.isNotBlank()) {
                                        Spacer(Modifier.height(5.dp))
                                        Text(preview, maxLines = 2,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                            style = MaterialTheme.typography.bodyMedium)
                                    }
                                    Spacer(Modifier.height(8.dp))
                                    Text(
                                        SimpleDateFormat("d MMM yyyy · HH:mm", Locale("ru")).format(Date(note.updatedAt)),
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                                Box(
                                    modifier = Modifier
                                        .size(52.dp)
                                        .pointerInput(note.id) {
                                            detectDragGesturesAfterLongPress(
                                                onDragStart = {
                                                    draggedId = note.id
                                                    dragOffset = 0f
                                                },
                                                onDrag = { change, amount ->
                                                    change.consume()
                                                    if (draggedId == note.id) {
                                                        dragOffset += amount.y
                                                        val visible = listState.layoutInfo.visibleItemsInfo
                                                        val draggedInfo = visible.firstOrNull { it.key == note.id }
                                                        if (draggedInfo != null && amount.y != 0f) {
                                                            val draggedCenter = draggedInfo.offset + draggedInfo.size / 2f + dragOffset
                                                            val target = if (amount.y > 0f) {
                                                                visible.firstOrNull { it.index == draggedInfo.index + 1 }
                                                            } else {
                                                                visible.firstOrNull { it.index == draggedInfo.index - 1 }
                                                            }
                                                            if (target != null) {
                                                                val targetCenter = target.offset + target.size / 2f
                                                                val crossed = if (amount.y > 0f) draggedCenter > targetCenter
                                                                    else draggedCenter < targetCenter
                                                                if (crossed) {
                                                                    reorderCallback(note.id, target.key.toString())

                                                                    dragOffset -= (target.offset - draggedInfo.offset).toFloat()
                                                                }
                                                            }
                                                        }
                                                    }
                                                },
                                                onDragEnd = {
                                                    draggedId = null
                                                    dragOffset = 0f
                                                },
                                                onDragCancel = {
                                                    draggedId = null
                                                    dragOffset = 0f
                                                }
                                            )
                                        },
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(
                                        Icons.Default.DragHandle,
                                        contentDescription = "Перетащить заметку",
                                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun NoteEditorScreen(
    note: Note,
    isNew: Boolean,
    onAutoSave: (Note, (Result<Unit>) -> Unit) -> Unit,
    onFinish: (Note?, (Result<Unit>) -> Unit) -> Unit,
    onDeleted: (String, (Result<Unit>) -> Unit) -> Unit,
    onDiscard: () -> Unit
) {
    var title by remember(note.id) { mutableStateOf(note.title) }
    var body by remember(note.id) { mutableStateOf(note.body) }
    var checklist by remember(note.id) {
        mutableStateOf(
            if (note.kind == NoteKind.LIST) {
                val legacyBody = note.body.trim()
                when {
                    legacyBody.isNotEmpty() -> listOf(ChecklistItem(text = legacyBody)) + note.checklist
                    note.checklist.isEmpty() -> listOf(ChecklistItem())
                    else -> note.checklist
                }
            } else note.checklist
        )
    }
    var focusNextId by remember(note.id) { mutableStateOf<String?>(null) }
    var askDelete by remember { mutableStateOf(false) }
    var dirty by remember(note.id) { mutableStateOf(false) }
    var hasBeenEdited by remember(note.id) { mutableStateOf(false) }
    var saveStatus by remember(note.id) { mutableStateOf("Автосохранение включено") }
    var editRevision by remember(note.id) { mutableStateOf(0) }
    val isList = note.kind == NoteKind.LIST
    val visibleTasks = checklist.filter { it.text.isNotBlank() }

    fun markDirty() {
        dirty = true
        hasBeenEdited = true
        editRevision++
        saveStatus = "Есть несохранённые изменения"
    }

    fun currentNote(): Note {
        val savedChecklist = if (isList) checklist.filter { it.text.isNotBlank() } else emptyList()
        val savedBody = if (isList) "" else body
        return note.copy(
            title = title.trim(),
            body = savedBody,
            checklist = savedChecklist,
            updatedAt = if (hasBeenEdited) System.currentTimeMillis() else note.updatedAt
        )
    }

    fun appendChecklistRow() {
        val newItem = ChecklistItem()
        checklist = checklist + newItem
        focusNextId = newItem.id
        markDirty()
    }

    fun finishEditing() {
        val current = currentNote()
        val hasContent = if (isList) current.checklist.isNotEmpty() else current.body.isNotBlank()
        if (isNew && current.title.isBlank() && !hasContent) {
            onDiscard()
        } else {
            saveStatus = "Сохранение…"
            onFinish(current) { result ->
                if (result.isFailure) {
                    saveStatus = "Не удалось сохранить. Изменения остались в редакторе; попробуйте ещё раз."
                }
            }
        }
    }

    LaunchedEffect(title, body, checklist, dirty, editRevision) {
        if (!dirty) return@LaunchedEffect
        val candidate = currentNote()
        if (isNew && candidate.title.isBlank() && candidate.body.isBlank() && candidate.checklist.isEmpty()) {
            return@LaunchedEffect
        }
        saveStatus = "Сохранение…"
        val revision = editRevision
        delay(400)
        onAutoSave(candidate) { result ->
            if (revision == editRevision) {
                if (result.isSuccess) {
                    dirty = false
                    saveStatus = "Сохранено"
                } else {
                    dirty = true
                    saveStatus = "Не удалось сохранить. Изменения остаются в редакторе; измените текст или выйдите и вернитесь, чтобы повторить попытку."
                }
            }
        }
    }

    val lifecycleOwner = LocalLifecycleOwner.current
    val latestCandidate by rememberUpdatedState(currentNote())
    val latestDirty by rememberUpdatedState(dirty)
    val latestHasBeenEdited by rememberUpdatedState(hasBeenEdited)
    val latestRevision by rememberUpdatedState(editRevision)
    val latestAutoSave by rememberUpdatedState(onAutoSave)
    DisposableEffect(lifecycleOwner, note.id) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP && (latestDirty || latestHasBeenEdited)) {
                val revision = latestRevision
                latestAutoSave(latestCandidate) { result ->
                    if (revision == latestRevision) {
                        if (result.isSuccess) {
                            dirty = false
                            saveStatus = "Сохранено"
                        } else {
                            dirty = true
                            saveStatus = "Не удалось сохранить изменения перед сворачиванием приложения."
                        }
                    }
                }
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    BackHandler { finishEditing() }
    if (askDelete) {
        AlertDialog(
            onDismissRequest = { askDelete = false },
            title = { Text(if (isList) "Удалить список?" else "Удалить заметку?") },
            text = { Text("Это действие нельзя отменить.") },
            confirmButton = {
                TextButton(onClick = {
                    askDelete = false
                    saveStatus = "Удаление…"
                    onDeleted(note.id) { result ->
                        if (result.isFailure) {
                            saveStatus = "Не удалось удалить запись. Она осталась в хранилище."
                        }
                    }
                }) { Text("Удалить") }
            },
            dismissButton = {
                TextButton(onClick = { askDelete = false }) { Text("Отмена") }
            }
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        when {
                            isNew && isList -> "Новый список"
                            isNew -> "Новая заметка"
                            isList -> "Список"
                            else -> "Заметка"
                        }
                    )
                },
                navigationIcon = {
                    IconButton(onClick = ::finishEditing) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Назад")
                    }
                },
                actions = {
                    if (!isNew) {
                        IconButton(onClick = { askDelete = true }) {
                            Icon(Icons.Default.Delete, contentDescription = "Удалить")
                        }
                    }
                }
            )
        }
    ) { padding ->
        Column(
            Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState())
                .padding(horizontal = 18.dp, vertical = 10.dp)
        ) {
            OutlinedTextField(
                value = title,
                onValueChange = { title = it; markDirty() },
                label = { Text(if (isList) "Название списка" else "Заголовок") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )

            if (!isList) {
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    value = body,
                    onValueChange = { body = it; markDirty() },
                    label = { Text("Текст заметки") },
                    minLines = 7,
                    modifier = Modifier.fillMaxWidth()
                )
            } else {
                Spacer(Modifier.height(10.dp))
                checklist.forEach { item ->
                    key(item.id) {
                        InlineChecklistRow(
                            item = item,
                            requestFocus = focusNextId == item.id,
                            onFocusHandled = { if (focusNextId == item.id) focusNextId = null },
                            onTextChange = { newText ->
                                checklist = checklist.map { current ->
                                    if (current.id == item.id) current.copy(text = newText) else current
                                }
                                markDirty()
                            },
                            onCheckedChange = { checked ->
                                checklist = checklist.map { current ->
                                    if (current.id == item.id) current.copy(checked = checked) else current
                                }
                                markDirty()
                            },
                            onNext = ::appendChecklistRow,
                            onDelete = {
                                checklist = checklist.filterNot { it.id == item.id }
                                markDirty()
                            }
                        )
                    }
                }
                TextButton(onClick = ::appendChecklistRow, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Новая строка")
                }
                if (visibleTasks.isNotEmpty()) {
                    Text(
                        "${visibleTasks.count { it.checked }} из ${visibleTasks.size} выполнено",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(start = 8.dp, top = 2.dp)
                    )
                }
            }

            Spacer(Modifier.height(18.dp))
            Text(
                saveStatus,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 4.dp)
            )
            Spacer(Modifier.height(12.dp))
        }
    }
}

@Composable
private fun InlineChecklistRow(
    item: ChecklistItem,
    requestFocus: Boolean,
    onFocusHandled: () -> Unit,
    onTextChange: (String) -> Unit,
    onCheckedChange: (Boolean) -> Unit,
    onNext: () -> Unit,
    onDelete: () -> Unit
) {
    val requester = remember(item.id) { FocusRequester() }
    LaunchedEffect(requestFocus) {
        if (requestFocus) {
            requester.requestFocus()
            onFocusHandled()
        }
    }
    Row(
        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Checkbox(checked = item.checked, onCheckedChange = onCheckedChange)
        BasicTextField(
            value = item.text,
            onValueChange = onTextChange,
            singleLine = true,
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
            keyboardActions = KeyboardActions(onNext = { onNext() }),
            textStyle = MaterialTheme.typography.bodyLarge.copy(
                color = MaterialTheme.colorScheme.onSurface,
                textDecoration = if (item.checked) TextDecoration.LineThrough else TextDecoration.None
            ),
            modifier = Modifier.weight(1f).focusRequester(requester).padding(vertical = 12.dp),
            decorationBox = { innerTextField ->
                Box(Modifier.fillMaxWidth()) {
                    if (item.text.isEmpty()) {
                        Text(
                            "Новая строка",
                            style = MaterialTheme.typography.bodyLarge,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    innerTextField()
                }
            }
        )
        IconButton(onClick = onDelete, modifier = Modifier.size(38.dp)) {
            Icon(
                Icons.Default.Delete,
                contentDescription = "Удалить строку",
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(18.dp)
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
private fun SettingsScreen(
    activity: MainActivity,
    crypto: Crypto,
    onBackupRestored: (BackupRestoreResult) -> Unit,
    onBackupSessionRecovered: (Crypto) -> Unit,
    darkTheme: Boolean,
    biometricEnabled: Boolean,
    panicPasswordConfigured: Boolean,
    hiddenVaultConfigured: Boolean,
    screenshotBlockingEnabled: Boolean,
    autoLockMinutes: Int,
    onThemeChange: (Boolean) -> Unit,
    onScreenshotBlockingChange: (Boolean) -> Unit,
    onAutoLockChange: (Int) -> Unit,
    onPanicPasswordConfiguredChange: (Boolean) -> Unit,
    onHiddenVaultConfiguredChange: (Boolean) -> Unit,
    onBiometricChange: (Boolean, (String) -> Unit) -> Unit,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val biometricStatus = remember { BiometricVault.canAuthenticate(context) }
    var message by remember { mutableStateOf<String?>(null) }
    var panicConfigured by remember(panicPasswordConfigured) { mutableStateOf(panicPasswordConfigured) }
    var showPanicDialog by remember { mutableStateOf(false) }
    var showRemovePanicDialog by remember { mutableStateOf(false) }
    var panicPassword by remember { mutableStateOf("") }
    var repeatedPanicPassword by remember { mutableStateOf("") }
    var panicBusy by remember { mutableStateOf(false) }
    var panicError by remember { mutableStateOf<String?>(null) }
    var showHiddenSetupDialog by remember { mutableStateOf(false) }
    var hiddenPassword by remember { mutableStateOf("") }
    var repeatedHiddenPassword by remember { mutableStateOf("") }
    var hiddenSetupBusy by remember { mutableStateOf(false) }
    var hiddenSetupError by remember { mutableStateOf<String?>(null) }
    var showBackupExportDialog by remember { mutableStateOf(false) }
    var showBackupImportDialog by remember { mutableStateOf(false) }
    var backupExportPassword by remember { mutableStateOf("") }
    var backupExportRepeat by remember { mutableStateOf("") }
    var backupImportPassword by remember { mutableStateOf("") }
    var backupSourceMainPassword by remember { mutableStateOf("") }
    var backupImportError by remember { mutableStateOf<String?>(null) }
    var backupImportProgress by remember { mutableStateOf<String?>(null) }
    var backupStatus by remember { mutableStateOf<String?>(null) }
    var pendingExportPassword by remember { mutableStateOf<String?>(null) }
    var pendingBackupUri by remember { mutableStateOf<Uri?>(null) }
    var backupBusy by remember { mutableStateOf(false) }
    val currentCrypto by rememberUpdatedState(crypto)

    BackHandler(enabled = backupBusy) { }

    val backupExportLauncher = androidx.activity.compose.rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        activity.allowTemporarySystemUi = false
        activity.preserveSessionOnTemporaryUiReturn = false
        activity.stoppedDuringTemporarySystemUi = false
        val password = pendingExportPassword
        pendingExportPassword = null
        if (uri != null && password != null) {
            backupBusy = true
            activity.backupOperationInProgress = true
            scope.launch {
                try {
                    val result = runCatching {
                        NoteSaveQueue.awaitIdle()
                        withContext(Dispatchers.IO) {
                            BackupManager.exportBackup(context, currentCrypto, password, uri)
                        }
                    }
                    password.toCharArray().fill('\u0000')
                    message = result.fold(
                        onSuccess = { "Зашифрованная резервная копия создана." },
                        onFailure = { "Не удалось создать резервную копию: ${it.message ?: "ошибка"}" }
                    )
                } finally {
                    activity.backupOperationInProgress = false
                    backupBusy = false
                    password.toCharArray().fill('\u0000')
                }
            }
        } else if (password != null) {
            password.toCharArray().fill('\u0000')
            message = "Создание резервной копии отменено."
        }
    }
    val backupImportLauncher = androidx.activity.compose.rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        activity.allowTemporarySystemUi = false
        activity.preserveSessionOnTemporaryUiReturn = false
        activity.stoppedDuringTemporarySystemUi = false
        if (uri != null) {
            runCatching {
                context.contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            pendingBackupUri = uri
            backupImportPassword = ""
            backupSourceMainPassword = ""
            backupImportError = null
            backupImportProgress = null
            backupStatus = null
            showBackupImportDialog = true
        }
    }
    val biometricAvailable = biometricStatus == androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS
    val functionalSwitchColors = SwitchDefaults.colors(
        checkedThumbColor = if (darkTheme) Color(0xFF17191B) else Color.White,
        checkedTrackColor = if (darkTheme) Color(0xFFC5CDD3) else Color(0xFF51585E),
        checkedBorderColor = if (darkTheme) Color(0xFFC5CDD3) else Color(0xFF51585E),
        uncheckedThumbColor = if (darkTheme) Color(0xFFE4E8EB) else Color(0xFF5D656B),
        uncheckedTrackColor = if (darkTheme) Color(0xFF46505A) else Color(0xFFD7DDE1),
        uncheckedBorderColor = if (darkTheme) Color(0xFF9AA5AE) else Color(0xFF808A91),
        disabledUncheckedThumbColor = if (darkTheme) Color(0xFF9AA3AA) else Color(0xFFB4BAC0),
        disabledUncheckedTrackColor = if (darkTheme) Color(0xFF333A40) else Color(0xFFE5E8EA),
        disabledUncheckedBorderColor = if (darkTheme) Color(0xFF59636B) else Color(0xFFB5BCC1)
    )

    if (showBackupExportDialog) {
        AlertDialog(
            onDismissRequest = { if (!backupBusy) { showBackupExportDialog = false; backupExportPassword = ""; backupExportRepeat = "" } },
            title = { Text("Создать резервную копию") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("Архив включает заметки, фотографии, файлы и настройки SecNote. Он защищён отдельным паролем, который не должен совпадать с другими паролями приложения. Для будущего импорта понадобятся пароль архива и прежний основной пароль SecNote, действовавший на момент создания копии. Биометрическая привязка к устройству не переносится и на новом телефоне настраивается заново.", style = MaterialTheme.typography.bodySmall)
                    OutlinedTextField(
                        value = backupExportPassword,
                        onValueChange = { backupExportPassword = it },
                        label = { Text("Пароль резервной копии") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        enabled = !backupBusy
                    )
                    OutlinedTextField(
                        value = backupExportRepeat,
                        onValueChange = { backupExportRepeat = it },
                        label = { Text("Повторите пароль") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        enabled = !backupBusy
                    )
                }
            },
            confirmButton = {
                TextButton(
                    enabled = !backupBusy && backupExportPassword.isNotEmpty() && backupExportPassword == backupExportRepeat,
                    onClick = {
                        pendingExportPassword = backupExportPassword
                        backupExportPassword = ""
                        backupExportRepeat = ""
                        showBackupExportDialog = false
                        val stamp = SimpleDateFormat("yyyyMMdd_HHmm", Locale.US).format(Date())
                        activity.allowTemporarySystemUi = true
                        activity.preserveSessionOnTemporaryUiReturn = true
                        backupExportLauncher.launch("SecNote-backup-$stamp.snb")
                    }
                ) { Text("Продолжить") }
            },
            dismissButton = {
                TextButton(enabled = !backupBusy, onClick = {
                    showBackupExportDialog = false
                    backupExportPassword = ""
                    backupExportRepeat = ""
                }) { Text("Отмена") }
            }
        )
    }

    if (showBackupImportDialog) {
        AlertDialog(
            onDismissRequest = { if (!backupBusy) { showBackupImportDialog = false; backupImportPassword = ""; backupSourceMainPassword = ""; backupImportError = null; backupImportProgress = null; pendingBackupUri = null } },
            title = { Text("Восстановить резервную копию") },
            text = {
                Column(
                    modifier = Modifier.heightIn(max = 440.dp).verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Text("Для восстановления нужны ДВА разных пароля. Первый — отдельный пароль резервной копии, заданный при экспорте. Второй — ПРЕЖНИЙ основной пароль SecNote, которым были зашифрованы данные в момент создания копии. Если после очистки данных вы создали новое пустое хранилище, пароль от него не подойдёт: укажите прежний пароль из исходного приложения. Биометрическая привязка к прежнему устройству не переносится.", style = MaterialTheme.typography.bodySmall)
                    OutlinedTextField(
                        value = backupImportPassword,
                        onValueChange = { backupImportPassword = it; backupImportError = null },
                        label = { Text("1. Пароль резервной копии") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        enabled = !backupBusy
                    )
                    OutlinedTextField(
                        value = backupSourceMainPassword,
                        onValueChange = { backupSourceMainPassword = it; backupImportError = null },
                        label = { Text("2. Прежний основной пароль SecNote") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        enabled = !backupBusy
                    )
                    if (backupBusy && backupImportProgress != null) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                            Text(backupImportProgress!!, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                    if (backupImportError != null) {
                        Text(backupImportError!!, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                    }
                }
            },
            confirmButton = {
                TextButton(
                    enabled = !backupBusy && pendingBackupUri != null,
                    onClick = {
                        val uri = pendingBackupUri ?: return@TextButton
                        val backupPassword = backupImportPassword
                        val mainPassword = backupSourceMainPassword
                        val validationError = BackupImportInputValidation.error(backupPassword, mainPassword)
                        if (validationError != null) {
                            backupImportError = validationError
                            return@TextButton
                        }
                        backupImportError = null
                        backupImportProgress = "Запускаю проверку…"
                        backupBusy = true
                        activity.backupOperationInProgress = true
                        scope.launch {
                            try {
                                val result = runCatching {
                                    NoteSaveQueue.awaitIdle()
                                    withContext(Dispatchers.IO) {
                                        BackupManager.restoreBackup(
                                            context, currentCrypto, uri, backupPassword, mainPassword,
                                            onProgress = { stage -> activity.runOnUiThread { backupImportProgress = stage } }
                                        )
                                    }
                                }
                                result.onSuccess { restored ->
                                    onBackupRestored(restored)
                                    showBackupImportDialog = false
                                    pendingBackupUri = null
                                    backupImportPassword = ""
                                    backupSourceMainPassword = ""
                                    backupImportProgress = null
                                    backupStatus = "Резервная копия успешно восстановлена. Биометрию можно включить заново."
                                    message = "Резервная копия восстановлена. Биометрию можно включить заново на этом устройстве."
                                }.onFailure { error ->
                                    (error as? BackupRestoreException)?.recoveredSessionCrypto?.let(onBackupSessionRecovered)
                                    val detail = generateSequence(error as Throwable?) { it.cause }
                                        .mapNotNull { it.message?.takeIf(String::isNotBlank) }
                                        .firstOrNull() ?: error.javaClass.simpleName
                                    backupImportError = "Восстановление не выполнено: $detail"
                                    backupImportProgress = null
                                    backupImportPassword = ""
                                    backupSourceMainPassword = ""
                                }
                            } finally {
                                backupPassword.toCharArray().fill('\u0000')
                                mainPassword.toCharArray().fill('\u0000')
                                activity.backupOperationInProgress = false
                                backupBusy = false
                            }
                        }
                    }
                ) { if (backupBusy) Text("Восстановление…") else Text("Проверить и восстановить") }
            },
            dismissButton = {
                TextButton(enabled = !backupBusy, onClick = {
                    showBackupImportDialog = false
                    backupImportPassword = ""
                    backupSourceMainPassword = ""
                    backupImportError = null
                    backupImportProgress = null
                    pendingBackupUri = null
                }) { Text("Отмена") }
            }
        )
    }

    if (showHiddenSetupDialog) {
        AlertDialog(
            onDismissRequest = {
                if (!hiddenSetupBusy) {
                    showHiddenSetupDialog = false
                    hiddenPassword = ""
                    repeatedHiddenPassword = ""
                    hiddenSetupError = null
                }
            },
            title = { Text("Отдельный пароль") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        "Пароль не сохраняется в приложении и не может быть восстановлен. Биометрический вход для этой области не применяется.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    OutlinedTextField(
                        value = hiddenPassword,
                        onValueChange = { hiddenPassword = it; hiddenSetupError = null },
                        label = { Text("Новый пароль") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        enabled = !hiddenSetupBusy
                    )
                    OutlinedTextField(
                        value = repeatedHiddenPassword,
                        onValueChange = { repeatedHiddenPassword = it; hiddenSetupError = null },
                        label = { Text("Повторите пароль") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        enabled = !hiddenSetupBusy
                    )
                    if (hiddenSetupError != null) {
                        Text(hiddenSetupError!!, color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall)
                    }
                }
            },
            confirmButton = {
                TextButton(
                    enabled = !hiddenSetupBusy && hiddenPassword.isNotEmpty() && hiddenPassword == repeatedHiddenPassword,
                    onClick = {
                        hiddenSetupBusy = true
                        val passphrase = hiddenPassword
                        hiddenPassword = ""
                        repeatedHiddenPassword = ""
                        scope.launch {
                            val conflictCheck = withContext(Dispatchers.Default) {
                                runCatching {
                                    val generation = StorageGate.currentGeneration()
                                    StorageGate.withAccess(generation) {
                                        val primaryKey = Vault.unlock(context, passphrase)
                                        val matchesPrimary = primaryKey != null
                                        primaryKey?.destroy()
                                        matchesPrimary || PanicCredential.verify(context, passphrase)
                                    }
                                }
                            }
                            val result: Result<Unit> = when {
                                conflictCheck.isFailure -> Result.failure(
                                    conflictCheck.exceptionOrNull() ?: IllegalStateException("Хранилище занято")
                                )
                                conflictCheck.getOrThrow() -> Result.failure(
                                    IllegalArgumentException("Используйте пароль, отличный от основного и аварийного.")
                                )
                                else -> withContext(Dispatchers.IO) {
                                    runCatching { HiddenVault.configure(context, passphrase) }
                                }
                            }
                            hiddenSetupBusy = false
                            result.onSuccess {
                                onHiddenVaultConfiguredChange(true)
                                showHiddenSetupDialog = false
                                message = "Настройки сохранены."
                            }.onFailure { error ->
                                hiddenSetupError = error.message ?: "Не удалось настроить хранилище."
                            }
                        }
                    }
                ) { if (hiddenSetupBusy) Text("Создание…") else Text("Создать") }
            },
            dismissButton = {
                TextButton(enabled = !hiddenSetupBusy, onClick = {
                    showHiddenSetupDialog = false
                    hiddenPassword = ""
                    repeatedHiddenPassword = ""
                    hiddenSetupError = null
                }) { Text("Отмена") }
            }
        )
    }

    if (showPanicDialog) {
        AlertDialog(
            onDismissRequest = {
                if (!panicBusy) {
                    showPanicDialog = false
                    panicPassword = ""
                    repeatedPanicPassword = ""
                    panicError = null
                }
            },
            title = { Text(if (panicConfigured) "Изменить секретный пароль" else "Секретный пароль уничтожения") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        "Этот пароль вводится в то же поле, что и основной. При его вводе SecNote покажет «Попытки исчерпаны» и без подтверждения начнёт необратимое уничтожение всех локальных данных и ключей.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    OutlinedTextField(
                        value = panicPassword,
                        onValueChange = { panicPassword = it; panicError = null },
                        label = { Text("Секретный пароль") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        enabled = !panicBusy
                    )
                    OutlinedTextField(
                        value = repeatedPanicPassword,
                        onValueChange = { repeatedPanicPassword = it; panicError = null },
                        label = { Text("Повторите секретный пароль") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        enabled = !panicBusy
                    )
                    if (panicError != null) {
                        Text(panicError!!, color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall)
                    }
                }
            },
            confirmButton = {
                TextButton(
                    enabled = !panicBusy && panicPassword.isNotEmpty() && panicPassword == repeatedPanicPassword,
                    onClick = {
                        panicBusy = true
                        panicError = null
                        scope.launch {
                            val isPrimaryPassword = withContext(Dispatchers.Default) {
                                val testCrypto = Vault.unlock(context, panicPassword)
                                val matchesPrimary = testCrypto != null
                                testCrypto?.destroy()
                                matchesPrimary
                            }
                            val isHiddenPassword = if (isPrimaryPassword) false else {
                                withContext(Dispatchers.Default) {
                                    HiddenVault.matchesPassphrase(context, panicPassword)
                                }
                            }
                            if (isPrimaryPassword) {
                                panicError = "Задайте другой секретный пароль."
                                panicBusy = false
                            } else if (isHiddenPassword) {
                                panicError = "Задайте другой секретный пароль."
                                panicBusy = false
                            } else {
                                val saved = withContext(Dispatchers.IO) {
                                    runCatching {
                                        val generation = StorageGate.currentGeneration()
                                        StorageGate.withAccess(generation) {
                                            PanicCredential.set(context, panicPassword)
                                        }
                                    }
                                }
                                panicBusy = false
                                saved.onSuccess {
                                    panicConfigured = true
                                    onPanicPasswordConfiguredChange(true)
                                    showPanicDialog = false
                                    panicPassword = ""
                                    repeatedPanicPassword = ""
                                    message = "Секретный пароль уничтожения установлен."
                                }.onFailure {
                                    panicError = it.message ?: "Не удалось сохранить секретный пароль."
                                }
                            }
                        }
                    }
                ) { if (panicBusy) Text("Сохранение…") else Text("Сохранить") }
            },
            dismissButton = {
                TextButton(
                    enabled = !panicBusy,
                    onClick = {
                        showPanicDialog = false
                        panicPassword = ""
                        repeatedPanicPassword = ""
                        panicError = null
                    }
                ) { Text("Отмена") }
            }
        )
    }

    if (showRemovePanicDialog) {
        AlertDialog(
            onDismissRequest = { showRemovePanicDialog = false },
            title = { Text("Отключить самоуничтожение?") },
            text = { Text("Секретный пароль будет удалён. Основной пароль и данные останутся без изменений.") },
            confirmButton = {
                TextButton(onClick = {
                    val removal = runCatching { PanicCredential.remove(context) }
                    if (removal.isSuccess) {
                        panicConfigured = false
                        onPanicPasswordConfiguredChange(false)
                        showRemovePanicDialog = false
                        message = "Секретный пароль уничтожения удалён."
                    } else {
                        panicConfigured = PanicCredential.isConfigured(context)
                        message = removal.exceptionOrNull()?.message
                            ?: "Не удалось удалить секретный пароль уничтожения."
                    }
                }) { Text("Отключить") }
            },
            dismissButton = {
                TextButton(onClick = { showRemovePanicDialog = false }) { Text("Отмена") }
            }
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Настройки") },
                navigationIcon = {
                    IconButton(onClick = onBack, enabled = !backupBusy) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Назад")
                    }
                }
            )
        }
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).padding(20.dp).verticalScroll(rememberScrollState())) {
            Text("SecNote · версия 1.4.15", style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text("Пакет: infernics.notes", style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(22.dp))
            Text("Внешний вид", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            SettingRow(
                title = "Оформление",
                subtitle = if (darkTheme) "Выбрана тёмная графитовая тема" else "Выбрана светлая нейтральная тема"
            ) {
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    FilterChip(
                        selected = !darkTheme,
                        onClick = { onThemeChange(false) },
                        label = { Text("Светлая") }
                    )
                    FilterChip(
                        selected = darkTheme,
                        onClick = { onThemeChange(true) },
                        label = { Text("Тёмная") }
                    )
                }
            }
            Spacer(Modifier.height(26.dp))
            Text("Безопасность", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            if (!hiddenVaultConfigured) {
                SettingRow(
                    title = "Дополнительное файловое хранилище",
                    subtitle = "Можно создать отдельную область с независимым паролем."
                ) {
                    TextButton(onClick = { showHiddenSetupDialog = true }) { Text("Настроить") }
                }
                Spacer(Modifier.height(18.dp))
            }
            SettingRow(
                title = "Вход по отпечатку",
                subtitle = when {
                    biometricEnabled -> "Включён. Основной пароль остаётся доступен."
                    biometricAvailable -> "Можно разблокировать приложение сильной биометрией Android."
                    biometricStatus == androidx.biometric.BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED ->
                        "Сначала добавьте отпечаток или биометрию в настройках Android."
                    else -> "На устройстве нет доступной сильной биометрии."
                }
            ) {
                Switch(
                    checked = biometricEnabled,
                    enabled = biometricAvailable || biometricEnabled,
                    onCheckedChange = { enabled -> onBiometricChange(enabled) { message = it } },
                    colors = functionalSwitchColors
                )
            }
            Spacer(Modifier.height(18.dp))
            SettingRow(
                title = "Блокировка скриншотов",
                subtitle = if (screenshotBlockingEnabled)
                    "Снимки экрана и запись экрана заблокированы для окна приложения"
                else "Снимки экрана разрешены"
            ) {
                Switch(
                    checked = screenshotBlockingEnabled,
                    onCheckedChange = onScreenshotBlockingChange,
                    colors = functionalSwitchColors
                )
            }
            Spacer(Modifier.height(18.dp))
            SettingRow(
                title = "Секретный пароль уничтожения",
                subtitle = if (panicConfigured)
                    "Установлен. Ввод на экране блокировки уничтожает все локальные хранилища и ключи."
                else "Не установлен. При необходимости задайте отдельный пароль."
            ) {
                TextButton(onClick = { showPanicDialog = true }) {
                    Text(if (panicConfigured) "Изменить" else "Установить")
                }
            }
            if (panicConfigured) {
                TextButton(onClick = { showRemovePanicDialog = true }) {
                    Text("Отключить секретный пароль")
                }
            }
            if (message != null) {
                Spacer(Modifier.height(8.dp))
                Text(message!!, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall)
            }
            Spacer(Modifier.height(26.dp))
            Text("Автоблокировка", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(6.dp))
            Text(
                "Выберите задержку блокировки после сворачивания. При значении «Никогда» приложение останется открытым, пока Android не завершит его процесс; после перезапуска пароль потребуется снова.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodySmall
            )
            Spacer(Modifier.height(10.dp))
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                listOf(
                    -1 to "Никогда",
                    0 to "Мгновенно",
                    1 to "1 мин",
                    5 to "5 мин",
                    10 to "10 мин",
                    15 to "15 мин",
                    30 to "30 мин"
                ).forEach { (minutes, label) ->
                    FilterChip(
                        selected = autoLockMinutes == minutes,
                        onClick = { onAutoLockChange(minutes) },
                        label = { Text(label) }
                    )
                }
            }
            Spacer(Modifier.height(25.dp))
            Text("Резервное копирование", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            Text(
                "Создайте переносимый зашифрованный архив или восстановите данные. При импорте нужны пароль архива и прежний основной пароль SecNote, действовавший при создании копии.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodySmall
            )
            Spacer(Modifier.height(10.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxWidth()) {
                Button(
                    onClick = { showBackupExportDialog = true },
                    enabled = !backupBusy,
                    modifier = Modifier.weight(1f)
                ) { Text("Экспорт") }
                Button(
                    onClick = {
                        activity.allowTemporarySystemUi = true
                        activity.preserveSessionOnTemporaryUiReturn = true
                        backupImportLauncher.launch(arrayOf("application/octet-stream", "application/x-secnote-backup", "*/*"))
                    },
                    enabled = !backupBusy,
                    modifier = Modifier.weight(1f)
                ) { Text("Импорт") }
            }
            if (backupBusy) {
                Spacer(Modifier.height(10.dp))
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                    Text("Обработка резервной копии…", style = MaterialTheme.typography.bodySmall)
                }
            }
            if (backupStatus != null) {
                Spacer(Modifier.height(8.dp))
                Text(backupStatus!!, color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.bodySmall)
            }
            Spacer(Modifier.height(25.dp))
            Text("Хранилище", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            Text(
                "Заметки и файлы хранятся в зашифрованном виде в приватной памяти приложения. При экстренной очистке приложение уничтожает ключевые материалы и очищает внутренние данные. Физическое стирание старых блоков flash-памяти не может быть гарантировано обычным приложением Android.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodyMedium
            )
        }
    }
}

@Composable
private fun SettingRow(
    title: String,
    subtitle: String,
    control: @Composable () -> Unit
) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 9.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f).padding(end = 14.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Spacer(Modifier.height(3.dp))
            Text(subtitle, color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodySmall)
        }
        control()
    }
}

private fun selectedDocumentUris(data: Intent?): List<Uri> {
    if (data == null) return emptyList()
    val selected = mutableListOf<Uri>()
    data.data?.let { selected.add(it) }
    val clip = data.clipData
    if (clip != null) {
        for (index in 0 until clip.itemCount) {
            clip.getItemAt(index).uri?.let { selected.add(it) }
        }
    }
    return selected.distinctBy { it.toString() }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FileVaultScreen(
    activity: MainActivity,
    crypto: Crypto,
    onBack: () -> Unit,
    onLock: () -> Unit,
    onOpenCamera: () -> Unit,
    storageDirectoryName: String = "file_vault"
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val repository = remember(crypto, storageDirectoryName) {
        FileVaultRepository(context, crypto, storageDirectoryName)
    }
    var files by remember { mutableStateOf<List<VaultFile>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }
    var pendingExport by remember { mutableStateOf<VaultFile?>(null) }
    var deleteTarget by remember { mutableStateOf<VaultFile?>(null) }
    var previewTarget by remember { mutableStateOf<VaultFile?>(null) }
    var selectedIds by remember { mutableStateOf<Set<String>>(emptySet()) }
    var selectionMode by remember { mutableStateOf(false) }
    var confirmBatchDelete by remember { mutableStateOf(false) }
    var pendingBatchExportIds by remember { mutableStateOf<List<String>>(emptyList()) }
    var showSearch by remember(storageDirectoryName) { mutableStateOf(false) }
    var searchQuery by remember(storageDirectoryName) { mutableStateOf("") }

    BackHandler {
        if (selectionMode) {
            selectedIds = emptySet()
            selectionMode = false
        } else {
            onBack()
        }
    }

    suspend fun reload() {
        files = withContext(Dispatchers.IO) { repository.loadAll() }
        selectedIds = selectedIds.intersect(files.map { it.id }.toSet())
        if (files.isEmpty()) selectionMode = false
        loading = false
    }

    fun toggleSelection(id: String) {
        selectedIds = if (id in selectedIds) selectedIds - id else selectedIds + id
        selectionMode = true
    }

    fun finishTemporaryPicker() {
        activity.allowTemporarySystemUi = false
        activity.stoppedDuringTemporarySystemUi = false
        activity.preserveSessionOnTemporaryUiReturn = false
    }

    LaunchedEffect(crypto) { reload() }

    val importLauncher = androidx.activity.compose.rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        finishTemporaryPicker()
        val data = result.data
        val uris = if (result.resultCode == Activity.RESULT_OK) {
            selectedDocumentUris(data)
        } else emptyList()

        if (uris.isNotEmpty()) {
            val grantFlags = (data?.flags ?: 0) and
                (Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
            val persistableGrant = data?.let {
                it.flags and Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION != 0
            } == true
            if (persistableGrant && grantFlags != 0) {
                uris.forEach { uri ->
                    runCatching { context.contentResolver.takePersistableUriPermission(uri, grantFlags) }
                }
            }

            busy = true
            message = null
            scope.launch {
                val resultBatch = withContext(Dispatchers.IO) {
                    runCatching { repository.importManyAndRemoveOriginal(uris) }
                }
                busy = false
                resultBatch.onSuccess { batch ->
                    message = buildString {
                        append("Добавлено в защищённое хранилище: ${batch.imported}.")
                        append(" Оригиналы перезаписаны: ${batch.originalsOverwritten}; удалены провайдером: ${batch.originalsDeleted}.")
                        if (batch.failedNames.isNotEmpty()) {
                            append(" Не удалось обработать: ${batch.failedNames.joinToString()}")
                        }
                        if (batch.imported > batch.originalsDeleted) {
                            append(" Некоторые исходники могли остаться — проверьте исходное расположение.")
                        }
                    }
                }.onFailure { error ->
                    message = "Не удалось выполнить импорт: ${error.message ?: "ошибка чтения"}. Исходные файлы не удалялись этим шагом."
                }
                reload()
            }
        } else {

            message = null
        }
    }

    val exportLauncher = androidx.activity.compose.rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        finishTemporaryPicker()
        val item = pendingExport
        pendingExport = null
        if (uri != null && item != null) {
            busy = true
            message = null
            scope.launch {
                val result = withContext(Dispatchers.IO) { runCatching { repository.export(item.id, uri) } }
                busy = false
                result.onSuccess { message = "Файл расшифрован и сохранён в выбранное место." }
                    .onFailure { message = "Не удалось экспортировать файл: ${it.message ?: "ошибка записи"}" }
                reload()
            }
        }
    }

    val treeLauncher = androidx.activity.compose.rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocumentTree()
    ) { treeUri ->
        finishTemporaryPicker()
        val ids = pendingBatchExportIds
        pendingBatchExportIds = emptyList()
        if (treeUri != null && ids.isNotEmpty()) {
            val flags = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            runCatching { context.contentResolver.takePersistableUriPermission(treeUri, flags) }
            busy = true
            message = null
            scope.launch {
                val result = withContext(Dispatchers.IO) {
                    runCatching { repository.exportManyToTree(ids, treeUri) }
                }
                busy = false
                result.onSuccess { batch ->
                    message = buildString {
                        append("Расшифровано: ${batch.exported}.")
                        if (batch.failedNames.isNotEmpty()) {
                            append(" Не удалось: ${batch.failedNames.joinToString()}")
                        }
                    }
                }.onFailure { message = "Ошибка массовой расшифровки: ${it.message ?: "неизвестная ошибка"}" }
                selectedIds = emptySet()
                selectionMode = false
            }
        }
    }

    fun requestExport(item: VaultFile) {
        pendingExport = item
        activity.allowTemporarySystemUi = true
        activity.preserveSessionOnTemporaryUiReturn = true
        exportLauncher.launch(item.name)
    }

    fun requestBatchExport() {
        if (selectedIds.isEmpty()) return
        pendingBatchExportIds = selectedIds.toList()
        activity.allowTemporarySystemUi = true
        activity.preserveSessionOnTemporaryUiReturn = true
        treeLauncher.launch(null)
    }

    if (deleteTarget != null) {
        val item = deleteTarget!!
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            title = { Text("Удалить файл из хранилища?") },
            text = { Text("Зашифрованная копия «${item.name}» будет удалена.") },
            confirmButton = {
                TextButton(onClick = {
                    deleteTarget = null
                    if (previewTarget?.id == item.id) previewTarget = null
                    busy = true
                    scope.launch {
                        withContext(Dispatchers.IO) { repository.delete(item.id) }
                        reload()
                        busy = false
                    }
                }) { Text("Удалить") }
            },
            dismissButton = {
                TextButton(onClick = { deleteTarget = null }) { Text("Отмена") }
            }
        )
    }

    if (confirmBatchDelete) {
        AlertDialog(
            onDismissRequest = { confirmBatchDelete = false },
            title = { Text("Удалить выбранные файлы?") },
            text = { Text("Будет удалено зашифрованных объектов: ${selectedIds.size}. Это действие нельзя отменить.") },
            confirmButton = {
                TextButton(onClick = {
                    confirmBatchDelete = false
                    val ids = selectedIds.toList()
                    busy = true
                    scope.launch {
                        val removed = withContext(Dispatchers.IO) { repository.deleteMany(ids) }
                        selectedIds = emptySet()
                        selectionMode = false
                        reload()
                        busy = false
                        message = "Удалено из защищённого хранилища: $removed."
                    }
                }) { Text("Удалить") }
            },
            dismissButton = { TextButton(onClick = { confirmBatchDelete = false }) { Text("Отмена") } }
        )
    }

    previewTarget?.let { item ->
        VaultImagePreviewDialog(
            item = item,
            repository = repository,
            onDismiss = { previewTarget = null },
            onExport = { previewTarget = null; requestExport(item) },
            onDelete = { previewTarget = null; deleteTarget = item }
        )
    }

    val imageFiles = files.filter { it.isImageFile() }
    val otherFiles = files.filterNot { it.isImageFile() }
    val filteredImageFiles = imageFiles.filter { item ->
        PhotoDatePolicy.matches(item.name, item.dateTakenAt ?: item.addedAt, searchQuery)
    }
    val filteredOtherFiles = otherFiles.filter { item ->
        PhotoDatePolicy.matches(item.name, item.addedAt, searchQuery)
    }
    val imageGroups = filteredImageFiles
        .groupBy { item -> PhotoDatePolicy.dayKey(item.dateTakenAt ?: item.addedAt) }
        .toSortedMap(compareByDescending { it })
    var selectedTab by remember(storageDirectoryName) { mutableStateOf(0) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    if (selectionMode) Text("Выбрано: ${selectedIds.size}") else Column {
                        Text("Файловое хранилище")
                        Text("Файлы шифруются отдельно от заметок",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                },
                navigationIcon = {
                    IconButton(onClick = {
                        if (selectionMode) {
                            selectedIds = emptySet()
                            selectionMode = false
                        } else onBack()
                    }) {
                        Icon(Icons.Default.ArrowBack,
                            contentDescription = if (selectionMode) "Отменить выбор" else "К заметкам")
                    }
                },
                actions = {
                    if (selectionMode) {
                        IconButton(onClick = { selectedIds = files.map { it.id }.toSet() }) {
                            Icon(Icons.Default.CheckBox, contentDescription = "Выбрать все")
                        }
                        IconButton(onClick = ::requestBatchExport, enabled = selectedIds.isNotEmpty()) {
                            Icon(Icons.Default.SaveAlt, contentDescription = "Расшифровать выбранные")
                        }
                        IconButton(onClick = { confirmBatchDelete = true }, enabled = selectedIds.isNotEmpty()) {
                            Icon(Icons.Default.Delete, contentDescription = "Удалить выбранные")
                        }
                    } else if (files.isNotEmpty()) {
                        IconButton(onClick = { selectionMode = true }) {
                            Icon(Icons.Default.CheckBox, contentDescription = "Выбрать файлы")
                        }
                    }
                    if (!selectionMode) {
                        IconButton(onClick = {
                            showSearch = !showSearch
                            if (!showSearch) searchQuery = ""
                        }) {
                            Icon(
                                if (showSearch) Icons.Default.Close else Icons.Default.Search,
                                contentDescription = if (showSearch) "Закрыть поиск" else "Поиск по названию или дате"
                            )
                        }
                        IconButton(onClick = onLock) {
                            Icon(Icons.Default.Lock, contentDescription = "Заблокировать")
                        }
                    }
                }
            )
        },
        floatingActionButton = {
            Column(
                horizontalAlignment = Alignment.End,
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                if (!selectionMode) {
                    SmallFloatingActionButton(onClick = onOpenCamera) {
                        Icon(Icons.Default.PhotoCamera, contentDescription = "Открыть камеру")
                    }
                }
                FloatingActionButton(
                    onClick = {
                        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                            addCategory(Intent.CATEGORY_OPENABLE)
                            type = "*/*"
                            putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true)
                            addFlags(
                                Intent.FLAG_GRANT_READ_URI_PERMISSION or
                                    Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                                    Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION
                            )
                        }
                        activity.allowTemporarySystemUi = true
                        activity.preserveSessionOnTemporaryUiReturn = true
                        importLauncher.launch(intent)
                    }
                ) {
                    Icon(Icons.Default.Add, contentDescription = "Добавить файл")
                }
            }
        }
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            if (message != null) {
                Text(
                    message!!,
                    modifier = Modifier.padding(horizontal = 18.dp, vertical = 7.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall
                )
            }
            TabRow(selectedTabIndex = selectedTab) {
                Tab(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    text = { Text("Фото (${imageFiles.size})") }
                )
                Tab(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    text = { Text("Документы (${otherFiles.size})") }
                )
            }
            if (showSearch) {
                OutlinedTextField(
                    value = searchQuery,
                    onValueChange = { searchQuery = it },
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 8.dp),
                    singleLine = true,
                    label = { Text("Название или дата") },
                    placeholder = { Text("Например, 12.08.2026") },
                    trailingIcon = {
                        if (searchQuery.isNotEmpty()) {
                            IconButton(onClick = { searchQuery = "" }) {
                                Icon(Icons.Default.Close, contentDescription = "Очистить поиск")
                            }
                        }
                    }
                )
            }
            when {
                loading || busy -> Box(Modifier.fillMaxWidth().weight(1f), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator()
                }
                selectedTab == 0 && filteredImageFiles.isEmpty() -> Box(
                    Modifier.fillMaxWidth().weight(1f), contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.padding(28.dp)) {
                        Icon(Icons.Default.PhotoCamera, contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(38.dp))
                        Spacer(Modifier.height(10.dp))
                        Text(if (imageFiles.isEmpty()) "Фотографий пока нет" else "Ничего не найдено")
                        Text(if (imageFiles.isEmpty()) "Сделайте снимок камерой или добавьте фотографию кнопкой «+»." else "Измените название или дату поиска.",
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            style = MaterialTheme.typography.bodySmall)
                    }
                }
                selectedTab == 1 && filteredOtherFiles.isEmpty() -> Box(
                    Modifier.fillMaxWidth().weight(1f), contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.padding(28.dp)) {
                        Icon(Icons.Default.FolderOpen, contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(38.dp))
                        Spacer(Modifier.height(10.dp))
                        Text(if (otherFiles.isEmpty()) "Документов пока нет" else "Ничего не найдено")
                        Text(if (otherFiles.isEmpty()) "Добавьте документ кнопкой «+»." else "Измените название или дату поиска.",
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            style = MaterialTheme.typography.bodySmall)
                    }
                }
                selectedTab == 0 -> LazyColumn(
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(horizontal = 14.dp, vertical = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(9.dp)
                ) {
                    imageGroups.forEach { (dayKey, dayFiles) ->
                        item(key = "photo-date-$dayKey") {
                            Text(
                                PhotoDatePolicy.groupLabel(dayKey),
                                modifier = Modifier.fillMaxWidth().padding(start = 2.dp, top = 8.dp, bottom = 2.dp),
                                style = MaterialTheme.typography.titleSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        items(
                            dayFiles.sortedByDescending { it.dateTakenAt ?: it.addedAt }.chunked(3),
                            key = { row -> "images-${row.first().id}" }
                        ) { rowFiles ->
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(9.dp)
                            ) {
                                rowFiles.forEach { item ->
                                    VaultImageTile(
                                        item = item,
                                        repository = repository,
                                        modifier = Modifier.weight(1f),
                                        selected = item.id in selectedIds,
                                        selectionMode = selectionMode,
                                        onToggleSelection = { toggleSelection(item.id) },
                                        onLongSelect = { toggleSelection(item.id) },
                                        onPreview = { previewTarget = item },
                                        onExport = { requestExport(item) },
                                        onDelete = { deleteTarget = item }
                                    )
                                }
                                repeat(3 - rowFiles.size) { Spacer(Modifier.weight(1f)) }
                            }
                        }
                    }
                }
                else -> LazyColumn(
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(horizontal = 14.dp, vertical = 10.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    items(filteredOtherFiles, key = { it.id }) { item ->
                        VaultDocumentRow(
                            item = item,
                            selected = item.id in selectedIds,
                            selectionMode = selectionMode,
                            onToggleSelection = { toggleSelection(item.id) },
                            onLongSelect = { toggleSelection(item.id) },
                            onExport = { requestExport(item) },
                            onDelete = { deleteTarget = item }
                        )
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun VaultImageTile(
    item: VaultFile,
    repository: FileVaultRepository,
    modifier: Modifier = Modifier,
    selected: Boolean,
    selectionMode: Boolean,
    onToggleSelection: () -> Unit,
    onLongSelect: () -> Unit,
    onPreview: () -> Unit,
    onExport: () -> Unit,
    onDelete: () -> Unit
) {
    val thumbnail by androidx.compose.runtime.produceState<android.graphics.Bitmap?>(
        null,
        item.id,
        repository
    ) {
        value = withContext(Dispatchers.IO) { repository.loadThumbnail(item.id, 420) }
    }

    Card(
        modifier = modifier.combinedClickable(
            onClick = { if (selectionMode) onToggleSelection() else onPreview() },
            onLongClick = onLongSelect
        ),
        border = BorderStroke(
            if (selected) 2.dp else 1.dp,
            if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant
        )
    ) {
        Column(Modifier.padding(5.dp)) {
            Box(
                modifier = Modifier.fillMaxWidth().aspectRatio(1f)
                    .clip(RoundedCornerShape(7.dp))
                    .background(MaterialTheme.colorScheme.surfaceVariant),
                contentAlignment = Alignment.Center
            ) {
                if (thumbnail != null) {
                    Image(
                        bitmap = thumbnail!!.asImageBitmap(),
                        contentDescription = item.name,
                        modifier = Modifier.fillMaxSize(),
                        contentScale = ContentScale.Crop
                    )
                } else {
                    Icon(Icons.Default.InsertDriveFile, contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(30.dp))
                }
                if (selectionMode) {
                    Checkbox(
                        checked = selected,
                        onCheckedChange = { onToggleSelection() },
                        modifier = Modifier.align(Alignment.TopEnd)
                            .background(MaterialTheme.colorScheme.surface.copy(alpha = 0.85f), RoundedCornerShape(50))
                    )
                }
            }
            Spacer(Modifier.height(5.dp))
            Text(item.name, maxLines = 1, style = MaterialTheme.typography.labelSmall)
            if (!selectionMode) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    IconButton(onClick = onExport, modifier = Modifier.size(34.dp)) {
                        Icon(Icons.Default.SaveAlt, contentDescription = "Экспортировать фото",
                            modifier = Modifier.size(18.dp))
                    }
                    IconButton(onClick = onDelete, modifier = Modifier.size(34.dp)) {
                        Icon(Icons.Default.Delete, contentDescription = "Удалить фото",
                            modifier = Modifier.size(18.dp))
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun VaultDocumentRow(
    item: VaultFile,
    selected: Boolean,
    selectionMode: Boolean,
    onToggleSelection: () -> Unit,
    onLongSelect: () -> Unit,
    onExport: () -> Unit,
    onDelete: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth().combinedClickable(
            onClick = { if (selectionMode) onToggleSelection() },
            onLongClick = onLongSelect
        ),
        border = BorderStroke(
            if (selected) 2.dp else 1.dp,
            if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant
        )
    ) {
        Row(
            Modifier.fillMaxWidth().padding(start = 10.dp, end = 4.dp, top = 7.dp, bottom = 7.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            if (selectionMode) {
                Checkbox(checked = selected, onCheckedChange = { onToggleSelection() })
            } else {
                Icon(Icons.Default.InsertDriveFile, contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(27.dp))
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(item.name, style = MaterialTheme.typography.bodyLarge, maxLines = 2)
                Text(
                    "${formatBytes(item.sizeBytes)} · ${SimpleDateFormat("d MMM yyyy", Locale("ru")).format(Date(item.addedAt))}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            if (!selectionMode) {
                IconButton(onClick = onExport) {
                    Icon(Icons.Default.SaveAlt, contentDescription = "Экспортировать файл")
                }
                IconButton(onClick = onDelete) {
                    Icon(Icons.Default.Delete, contentDescription = "Удалить файл")
                }
            }
        }
    }
}

@Composable
private fun VaultImagePreviewDialog(
    item: VaultFile,
    repository: FileVaultRepository,
    onDismiss: () -> Unit,
    onExport: () -> Unit,
    onDelete: () -> Unit
) {
    var previewLoadFinished by remember(item.id) { mutableStateOf(false) }
    val bitmap by androidx.compose.runtime.produceState<android.graphics.Bitmap?>(
        null,
        item.id,
        repository
    ) {
        previewLoadFinished = false
        value = withContext(Dispatchers.IO) {
            runCatching { repository.loadThumbnail(item.id, 1800) }.getOrNull()
        }
        previewLoadFinished = true
    }

    androidx.compose.ui.window.Dialog(onDismissRequest = onDismiss) {
        Surface(
            shape = RoundedCornerShape(16.dp),
            color = MaterialTheme.colorScheme.surface,
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(Modifier.padding(12.dp)) {
                Text(item.name, style = MaterialTheme.typography.titleMedium, maxLines = 2)
                Spacer(Modifier.height(10.dp))
                Box(
                    Modifier.fillMaxWidth().heightIn(max = 560.dp),
                    contentAlignment = Alignment.Center
                ) {
                    if (bitmap != null) {
                        Image(
                            bitmap = bitmap!!.asImageBitmap(),
                            contentDescription = item.name,
                            modifier = Modifier.fillMaxWidth().heightIn(max = 560.dp),
                            contentScale = ContentScale.Fit
                        )
                    } else if (previewLoadFinished) {
                        Text(
                            "Не удалось создать предпросмотр. Файл можно экспортировать или удалить.",
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            style = MaterialTheme.typography.bodyMedium
                        )
                    } else {
                        CircularProgressIndicator()
                    }
                }
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.End, modifier = Modifier.fillMaxWidth()) {
                    TextButton(onClick = onDelete) { Text("Удалить") }
                    TextButton(onClick = onExport) { Text("Экспортировать") }
                    TextButton(onClick = onDismiss) { Text("Закрыть") }
                }
            }
        }
    }
}

private fun VaultFile.isImageFile(): Boolean {
    val mime = mimeType.lowercase(Locale.ROOT)
    if (mime.startsWith("image/")) return true
    return name.substringAfterLast('.', "").lowercase(Locale.ROOT) in setOf(
        "jpg", "jpeg", "png", "webp", "gif", "bmp", "heic", "heif", "avif"
    )
}

private fun formatBytes(value: Long): String = when {
    value < 1024 -> "$value Б"
    value < 1024L * 1024 -> "${String.format(Locale.US, "%.1f", value / 1024.0)} КБ"
    else -> "${String.format(Locale.US, "%.1f", value / (1024.0 * 1024.0))} МБ"
}
