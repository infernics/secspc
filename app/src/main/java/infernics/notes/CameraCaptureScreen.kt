package infernics.notes

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.ImageFormat
import android.graphics.Matrix
import android.view.Surface
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageCapture
import androidx.camera.core.ImageCaptureException
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.PhotoCamera
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

@Composable
internal fun CameraCaptureScreen(
    activity: MainActivity,
    crypto: Crypto,
    storageDirectoryName: String = "file_vault",
    onClose: () -> Unit
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current

    val repository = remember(crypto, storageDirectoryName) {
        FileVaultRepository(context, crypto, storageDirectoryName)
    }
    val cameraExecutor = remember { Executors.newSingleThreadExecutor() }
    val providerState = remember { mutableStateOf<ProcessCameraProvider?>(null) }
    val screenActive = remember { AtomicBoolean(true) }

    var hasCameraPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED
        )
    }
    var imageCapture by remember { mutableStateOf<ImageCapture?>(null) }
    var cameraReady by remember { mutableStateOf(false) }
    var capturing by remember { mutableStateOf(false) }
    var cameraError by remember { mutableStateOf<String?>(null) }
    var statusMessage by remember { mutableStateOf("Фотографии сохраняются сразу в зашифрованное хранилище.") }

    BackHandler {
        if (!capturing) onClose()
    }

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->

        if (!activity.stoppedDuringTemporarySystemUi) {
            activity.allowTemporarySystemUi = false
            activity.preserveSessionOnTemporaryUiReturn = false
        }
        hasCameraPermission = granted
        cameraError = if (granted) null else "Для съёмки необходимо разрешить доступ к камере."
    }

    fun requestCameraPermission() {
        activity.allowTemporarySystemUi = true
        activity.preserveSessionOnTemporaryUiReturn = true
        permissionLauncher.launch(Manifest.permission.CAMERA)
    }

    LaunchedEffect(Unit) {
        if (!hasCameraPermission) requestCameraPermission()
    }

    DisposableEffect(cameraExecutor) {
        onDispose {
            screenActive.set(false)
            runCatching { providerState.value?.unbindAll() }
            cameraExecutor.shutdown()
        }
    }

    Column(
        modifier = Modifier.fillMaxSize().background(Color.Black),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        if (!hasCameraPermission) {
            Column(
                modifier = Modifier.weight(1f).fillMaxWidth().padding(28.dp),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Icon(Icons.Default.PhotoCamera, contentDescription = null, tint = Color.White,
                    modifier = Modifier.size(48.dp))
                Spacer(Modifier.height(18.dp))
                Text("Доступ к камере", color = Color.White, style = MaterialTheme.typography.titleLarge)
                Spacer(Modifier.height(8.dp))
                Text(
                    "SecNote использует камеру только для создания снимков, которые сразу шифруются и сохраняются в файловом хранилище приложения.",
                    color = Color.White,
                    style = MaterialTheme.typography.bodyMedium
                )
                Spacer(Modifier.height(20.dp))
                Button(onClick = ::requestCameraPermission) { Text("Разрешить доступ") }
                Button(onClick = onClose) { Text("Назад") }
            }
        } else {
            Box(modifier = Modifier.weight(1f).fillMaxWidth()) {
                AndroidView(
                    factory = { viewContext ->
                        PreviewView(viewContext).apply {
                            scaleType = PreviewView.ScaleType.FILL_CENTER
                            implementationMode = PreviewView.ImplementationMode.COMPATIBLE
                            val cameraProviderFuture = ProcessCameraProvider.getInstance(viewContext)
                            cameraProviderFuture.addListener({
                                if (screenActive.get()) {
                                    try {
                                        val provider = cameraProviderFuture.get()
                                        val selector = when {
                                            provider.hasCamera(CameraSelector.DEFAULT_BACK_CAMERA) ->
                                                CameraSelector.DEFAULT_BACK_CAMERA
                                            provider.hasCamera(CameraSelector.DEFAULT_FRONT_CAMERA) ->
                                                CameraSelector.DEFAULT_FRONT_CAMERA
                                            else -> error("Камера не найдена на этом устройстве")
                                        }
                                        val preview = Preview.Builder().build().also {
                                            it.setSurfaceProvider(surfaceProvider)
                                        }
                                        val capture = ImageCapture.Builder()
                                            .setCaptureMode(ImageCapture.CAPTURE_MODE_MINIMIZE_LATENCY)
                                            .setJpegQuality(94)
                                            .setTargetRotation(display?.rotation ?: Surface.ROTATION_0)
                                            .build()
                                        provider.unbindAll()
                                        provider.bindToLifecycle(lifecycleOwner, selector, preview, capture)
                                        if (screenActive.get()) {
                                            providerState.value = provider
                                            imageCapture = capture
                                            cameraReady = true
                                            cameraError = null
                                        } else {
                                            provider.unbind(preview, capture)
                                        }
                                    } catch (error: Exception) {
                                        if (screenActive.get()) {
                                            cameraError = error.message?.take(180)
                                                ?.let { "Не удалось запустить камеру: $it" }
                                                ?: "Не удалось запустить камеру."
                                        }
                                    }
                                }
                            }, ContextCompat.getMainExecutor(viewContext))
                        }
                    },
                    modifier = Modifier.fillMaxSize()
                )

                Row(
                    modifier = Modifier.fillMaxWidth().align(Alignment.TopCenter)
                        .background(Color.Black.copy(alpha = 0.42f)).padding(horizontal = 8.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    IconButton(onClick = onClose, enabled = !capturing) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Назад", tint = Color.White)
                    }
                    Text("Камера SecNote", color = Color.White, style = MaterialTheme.typography.titleMedium)
                }

                if (!cameraReady && cameraError == null) {
                    CircularProgressIndicator(
                        modifier = Modifier.align(Alignment.Center),
                        color = Color.White
                    )
                }
                cameraError?.let { message ->
                    Column(
                        modifier = Modifier.align(Alignment.Center).padding(24.dp)
                            .background(Color.Black.copy(alpha = 0.78f)).padding(20.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(message, color = Color.White)
                        Spacer(Modifier.height(12.dp))
                        Button(onClick = onClose, enabled = !capturing) { Text("Закрыть") }
                    }
                }
            }

            Column(
                modifier = Modifier.fillMaxWidth().background(Color.Black).padding(horizontal = 16.dp, vertical = 10.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(statusMessage, color = Color.White, style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    FloatingActionButton(
                        onClick = {
                            val capture = imageCapture
                            if (capture == null || !cameraReady || capturing || cameraError != null) return@FloatingActionButton
                            capturing = true
                            statusMessage = "Снимаем и шифруем фотографию…"
                            capture.takePicture(cameraExecutor, object : ImageCapture.OnImageCapturedCallback() {
                                override fun onCaptureSuccess(image: ImageProxy) {
                                    val jpeg = try {
                                        CameraJpegEncoder.toUprightJpeg(image)
                                    } catch (error: Exception) {
                                        null
                                    } finally {
                                        image.close()
                                    }
                                    if (jpeg == null) {
                                        activity.lifecycleScope.launch {
                                            if (screenActive.get()) {
                                                capturing = false
                                                statusMessage = "Не удалось обработать снимок. Попробуйте ещё раз."
                                            }
                                        }
                                        return
                                    }
                                    val capturedAtMillis = System.currentTimeMillis()
                                    activity.lifecycleScope.launch {
                                        try {
                                            withContext(Dispatchers.IO) {
                                                repository.saveCapturedPhoto(jpeg, capturedAtMillis)
                                            }
                                            if (screenActive.get()) {
                                                statusMessage = "Фото зашифровано и сохранено в файловом хранилище."
                                            }
                                        } catch (error: Exception) {
                                            if (screenActive.get()) {
                                                statusMessage = "Не удалось сохранить фото: ${error.message ?: "ошибка"}"
                                            }
                                        } finally {
                                            jpeg.fill(0)
                                            if (screenActive.get()) capturing = false
                                        }
                                    }
                                }

                                override fun onError(exception: ImageCaptureException) {
                                    activity.lifecycleScope.launch {
                                        if (screenActive.get()) {
                                            capturing = false
                                            statusMessage = "Ошибка съёмки: ${exception.message ?: "попробуйте ещё раз"}"
                                        }
                                    }
                                }
                            })
                        },
                        modifier = Modifier.size(68.dp),
                        containerColor = Color.White,
                        contentColor = Color.Black
                    ) {
                        if (capturing) {
                            CircularProgressIndicator(modifier = Modifier.size(28.dp), color = Color.Black)
                        } else {
                            Icon(Icons.Default.PhotoCamera, contentDescription = "Сделать снимок",
                                modifier = Modifier.size(30.dp))
                        }
                    }
                }
            }
        }
    }
}

private object CameraJpegEncoder {
    fun toUprightJpeg(image: ImageProxy): ByteArray {
        require(image.format == ImageFormat.JPEG || image.format == ImageFormat.JPEG_R) {
            "Камера вернула неподдерживаемый формат изображения"
        }
        val buffer = image.planes.firstOrNull()?.buffer?.duplicate()
            ?: error("Камера не вернула данные изображения")
        val capturedJpeg = ByteArray(buffer.remaining())
        buffer.get(capturedJpeg)
        val rotation = ((image.imageInfo.rotationDegrees % 360) + 360) % 360
        if (rotation == 0) return capturedJpeg

        val bitmap = try {
            BitmapFactory.decodeByteArray(capturedJpeg, 0, capturedJpeg.size)
        } finally {
            capturedJpeg.fill(0)
        }
        requireNotNull(bitmap) { "Не удалось декодировать снимок" }
        var rotated: Bitmap? = null
        try {
            val matrix = Matrix().apply { postRotate(rotation.toFloat()) }
            val rotatedBitmap = Bitmap.createBitmap(bitmap, 0, 0, bitmap.width, bitmap.height, matrix, true)
            rotated = rotatedBitmap
            return WipingByteArrayOutputStream().use { output ->
                check(rotatedBitmap.compress(Bitmap.CompressFormat.JPEG, 94, output)) {
                    "Не удалось подготовить JPEG"
                }
                output.copyAndWipe()
            }
        } finally {
            rotated?.recycle()
            bitmap.recycle()
        }
    }
}

private class WipingByteArrayOutputStream : ByteArrayOutputStream() {
    fun copyAndWipe(): ByteArray = toByteArray().also {
        buf.fill(0)
        reset()
    }

    override fun close() {
        buf.fill(0)
        super.close()
    }
}
