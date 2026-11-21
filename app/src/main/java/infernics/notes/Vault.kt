package infernics.notes

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.nio.ByteBuffer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

object Vault {
    private const val SALT_KEY_ALIAS = "SecNoteVaultSaltKey"
    private const val SALT_MAGIC = 0x53434B33
    private val SALT_AAD = "SecNote/Keystore/salt/v3".toByteArray(Charsets.UTF_8)
    private const val GCM_IV_LENGTH = 12
    private const val TAG_BITS = 128

    private fun saltFile(context: Context) = File(context.filesDir, "key.salt")
    private fun checkFile(context: Context) = File(context.filesDir, "key.check")

    fun isSetup(context: Context): Boolean =
        AtomicFileIO.existsRecoverable(saltFile(context)) && AtomicFileIO.existsRecoverable(checkFile(context))

    @Synchronized
    fun create(context: Context, passphrase: String): Crypto {
        require(passphrase.isNotEmpty()) { "Введите пароль основного хранилища." }
        deleteSaltWrappingKey()
        val salt = Crypto.newSalt()
        val crypto = try {
            Crypto.fromPassphrase(passphrase, salt)
        } catch (error: Exception) {
            salt.fill(0)
            throw error
        }
        var created = false
        try {
            val wrappedSalt = wrapSalt(salt)
            try {
                writeAtomically(saltFile(context), wrappedSalt)
            } finally {
                wrappedSalt.fill(0)
            }
            val verificationBlob = crypto.encrypt("verify")
            try {
                writeAtomically(checkFile(context), verificationBlob)
            } finally {
                verificationBlob.fill(0)
            }
            created = true
            return crypto
        } finally {
            salt.fill(0)
            if (!created) crypto.destroy()
        }
    }

    @Synchronized
    fun unlock(context: Context, passphrase: String): Crypto? {
        if (!isSetup(context)) return null
        var storedSalt: ByteArray? = null
        var salt: ByteArray? = null
        return try {
            val storedBytes = AtomicFileIO.readBytes(saltFile(context))
            storedSalt = storedBytes
            val recoveredSalt = unwrapSalt(storedBytes)
            salt = recoveredSalt
            if (!PasswordKdf.isValidSalt(recoveredSalt)) return null

            val crypto = Crypto.fromPassphrase(passphrase, recoveredSalt)
            if (!ensureSaltWrapped(context, crypto)) {
                crypto.destroy()
                return null
            }
            crypto
        } catch (_: Exception) {
            null
        } finally {
            storedSalt?.fill(0)
            salt?.fill(0)
        }
    }

    @Synchronized
    fun ensureSaltWrapped(context: Context, crypto: Crypto): Boolean {
        var storedSalt: ByteArray? = null
        var recoveredSalt: ByteArray? = null
        var checkBlob: ByteArray? = null
        return try {
            val salt = saltFile(context)
            val check = checkFile(context)
            if (!AtomicFileIO.existsRecoverable(salt) || !AtomicFileIO.existsRecoverable(check)) return false

            val storedBytes = AtomicFileIO.readBytes(salt)
            storedSalt = storedBytes
            val saltBytes = unwrapSalt(storedBytes)
            recoveredSalt = saltBytes
            if (!PasswordKdf.isValidSalt(saltBytes)) return false

            val checkBytes = AtomicFileIO.readBytes(check)
            checkBlob = checkBytes
            if (crypto.decryptToText(checkBytes) != "verify") return false

            true
        } catch (_: Exception) {
            false
        } finally {
            storedSalt?.fill(0)
            recoveredSalt?.fill(0)
            checkBlob?.fill(0)
        }
    }

    @Synchronized
    internal fun matchesPassphrase(context: Context, passphrase: String): Boolean {
        var stored: ByteArray? = null
        var salt: ByteArray? = null
        var checkBlob: ByteArray? = null
        var candidate: Crypto? = null
        return try {
            if (!isSetup(context)) return false
            val storedBytes = AtomicFileIO.readBytes(saltFile(context))
            stored = storedBytes
            val rawSalt = unwrapSalt(storedBytes)
            salt = rawSalt
            checkBlob = AtomicFileIO.readBytes(checkFile(context))
            val crypto = Crypto.fromPassphrase(passphrase, rawSalt)
            candidate = crypto
            crypto.decryptToText(checkBlob) == "verify"
        } catch (_: Exception) {
            false
        } finally {
            candidate?.destroy()
            stored?.fill(0)
            salt?.fill(0)
            checkBlob?.fill(0)
        }
    }

    @Synchronized
    internal fun exportSaltForBackup(context: Context, crypto: Crypto): ByteArray {
        var stored: ByteArray? = null
        var salt: ByteArray? = null
        var checkBlob: ByteArray? = null
        return try {
            check(AtomicFileIO.existsRecoverable(File(context.filesDir, "key.check"))) { "Основное хранилище не настроено." }
            val storedBytes = AtomicFileIO.readBytes(saltFile(context))
            stored = storedBytes
            val rawSalt = unwrapSalt(storedBytes)
            salt = rawSalt
            check(PasswordKdf.isValidSalt(rawSalt)) { "Некорректная соль основного хранилища." }
            val checkBytes = AtomicFileIO.readBytes(checkFile(context))
            checkBlob = checkBytes
            require(crypto.decryptToText(checkBytes) == "verify") { "Ключ текущего хранилища не подтверждён." }
            rawSalt.copyOf()
        } finally {
            stored?.fill(0)
            salt?.fill(0)
            checkBlob?.fill(0)
        }
    }

    @Synchronized
    internal fun installPortableState(context: Context, salt: ByteArray, crypto: Crypto) {
        require(PasswordKdf.isValidSalt(salt)) { "Некорректная соль резервной копии." }
        val wrappedSalt = wrapSalt(salt)
        val checkBlob = crypto.encrypt("verify")
        try {
            writeAtomically(saltFile(context), wrappedSalt)
            writeAtomically(checkFile(context), checkBlob)
        } finally {
            wrappedSalt.fill(0)
            checkBlob.fill(0)
        }
    }

    private fun wrapSalt(salt: ByteArray): ByteArray {
        require(PasswordKdf.isValidSalt(salt))
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateSaltWrappingKey())
        cipher.updateAAD(SALT_AAD)
        val encrypted = cipher.doFinal(salt)
        return try {
            ByteBuffer.allocate(4 + GCM_IV_LENGTH + encrypted.size)
                .putInt(SALT_MAGIC)
                .put(cipher.iv)
                .put(encrypted)
                .array()
        } finally {
            encrypted.fill(0)
        }
    }

    private fun unwrapSalt(blob: ByteArray): ByteArray {
        require(blob.size == 4 + GCM_IV_LENGTH + PasswordKdf.SALT_LENGTH + 16) { "Повреждён ключевой материал" }
        val buffer = ByteBuffer.wrap(blob)
        val magic = buffer.int
        require(magic == SALT_MAGIC) { "Неизвестный формат ключевого материала" }
        val iv = ByteArray(GCM_IV_LENGTH).also { buffer.get(it) }
        val encrypted = ByteArray(buffer.remaining()).also { buffer.get(it) }
        return try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val key = keyStore.getKey(SALT_KEY_ALIAS, null) as? SecretKey
                ?: error("Ключ хранилища Android недоступен")
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
                updateAAD(SALT_AAD)
                doFinal(encrypted)
            }
        } finally {
            iv.fill(0)
            encrypted.fill(0)
        }
    }

    private fun getOrCreateSaltWrappingKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keyStore.getKey(SALT_KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(
            SALT_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .build()
        generator.init(spec)
        return generator.generateKey()
    }

    private fun deleteSaltWrappingKey() {
        runCatching {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (keyStore.containsAlias(SALT_KEY_ALIAS)) keyStore.deleteEntry(SALT_KEY_ALIAS)
        }
    }

    private fun writeAtomically(destination: File, bytes: ByteArray) {
        AtomicFileIO.writeBytes(destination, bytes)
    }
}
