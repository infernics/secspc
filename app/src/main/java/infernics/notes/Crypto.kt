package infernics.notes

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.security.auth.Destroyable
import java.util.Collections
import java.util.IdentityHashMap

class Crypto private constructor(rawKey: ByteArray) {
    private val key: SecretKey = WipeableAesKey(rawKey)

    init {
        synchronized(LIVE_INSTANCES) { LIVE_INSTANCES.add(this) }
    }

    fun destroy() {
        (key as? Destroyable)?.let { runCatching { it.destroy() } }
        synchronized(LIVE_INSTANCES) { LIVE_INSTANCES.remove(this) }
    }

    fun encrypt(plain: ByteArray): ByteArray {
        val iv = ByteArray(IV_LEN).also(SECURE_RANDOM::nextBytes)
        return try {
            val cipher = newCipher(Cipher.ENCRYPT_MODE, iv)
            iv + cipher.doFinal(plain)
        } finally {
            iv.fill(0)
        }
    }

    fun decrypt(blob: ByteArray): ByteArray {
        require(blob.size >= IV_LEN + TAG_LEN_BYTES) { "Encrypted data is incomplete" }
        val iv = blob.copyOfRange(0, IV_LEN)
        return try {
            val cipher = newCipher(Cipher.DECRYPT_MODE, iv)
            cipher.doFinal(blob, IV_LEN, blob.size - IV_LEN)
        } finally {
            iv.fill(0)
        }
    }

    fun encrypt(plain: ByteArray, aad: ByteArray): ByteArray {
        val iv = ByteArray(IV_LEN).also(SECURE_RANDOM::nextBytes)
        val cipher = newCipher(Cipher.ENCRYPT_MODE, iv).apply { updateAAD(aad) }
        val encrypted = cipher.doFinal(plain)
        return try {
            RECORD_MAGIC + iv + encrypted
        } finally {
            iv.fill(0)
            encrypted.fill(0)
        }
    }

    fun decrypt(blob: ByteArray, aad: ByteArray): ByteArray {
        if (!isContextualRecord(blob)) return decrypt(blob)
        require(blob.size >= RECORD_MAGIC.size + IV_LEN + TAG_LEN_BYTES) { "Encrypted data is incomplete" }
        val ivOffset = RECORD_MAGIC.size
        val iv = blob.copyOfRange(ivOffset, ivOffset + IV_LEN)
        return try {
            val cipher = newCipher(Cipher.DECRYPT_MODE, iv).apply { updateAAD(aad) }
            cipher.doFinal(blob, ivOffset + IV_LEN, blob.size - ivOffset - IV_LEN)
        } finally {
            iv.fill(0)
        }
    }

    fun isContextualRecord(blob: ByteArray): Boolean {
        if (blob.size < RECORD_MAGIC.size) return false
        for (index in RECORD_MAGIC.indices) {
            if (blob[index] != RECORD_MAGIC[index]) return false
        }
        return true
    }

    fun encrypt(text: String): ByteArray = encrypt(text.toByteArray(Charsets.UTF_8))

    fun encrypt(text: String, aad: ByteArray): ByteArray = encrypt(text.toByteArray(Charsets.UTF_8), aad)

    fun decryptToText(blob: ByteArray): String {
        val plaintext = decrypt(blob)
        return try {
            String(plaintext, Charsets.UTF_8)
        } finally {
            plaintext.fill(0)
        }
    }

    fun decryptToText(blob: ByteArray, aad: ByteArray): String {
        val plaintext = decrypt(blob, aad)
        return try {
            String(plaintext, Charsets.UTF_8)
        } finally {
            plaintext.fill(0)
        }
    }

    fun encryptStream(input: InputStream, output: OutputStream): Long =
        encryptStreamInternal(input, output, null)

    fun encryptStream(input: InputStream, output: OutputStream, aad: ByteArray): Long =
        encryptStreamInternal(input, output, aad)

    private fun encryptStreamInternal(input: InputStream, output: OutputStream, aad: ByteArray?): Long {
        val magic = if (aad == null) FILE_MAGIC else FILE_CONTEXT_MAGIC
        val data = DataOutputStream(output)
        data.write(magic)
        val buffer = ByteArray(FILE_CHUNK_SIZE)
        var chunkIndex = 0
        var totalBytes = 0L

        try {
            while (true) {
                var count = input.read(buffer)
                if (count < 0) break
                if (count == 0) {

                    val singleByte = input.read()
                    if (singleByte < 0) break
                    buffer[0] = singleByte.toByte()
                    count = 1
                }

                val iv = ByteArray(IV_LEN).also(SECURE_RANDOM::nextBytes)
                val cipher = fileCipher(Cipher.ENCRYPT_MODE, iv).apply {
                    updateAAD(streamChunkAad(magic, aad, chunkIndex, count))
                }
                val encrypted = cipher.doFinal(buffer, 0, count)
                try {
                    data.writeInt(count)
                    data.write(iv)
                    data.write(encrypted)
                } finally {
                    encrypted.fill(0)
                    iv.fill(0)
                }
                chunkIndex++
                totalBytes += count
            }

            val footer = ByteBuffer.allocate(12).putInt(chunkIndex).putLong(totalBytes).array()
            val footerIv = ByteArray(IV_LEN).also(SECURE_RANDOM::nextBytes)
            val footerCipher = fileCipher(Cipher.ENCRYPT_MODE, footerIv).apply {
                updateAAD(streamFooterAad(magic, aad, chunkIndex))
            }
            val encryptedFooter = footerCipher.doFinal(footer)
            try {
                data.writeInt(0)
                data.write(footerIv)
                data.write(encryptedFooter)
                data.flush()
            } finally {
                footer.fill(0)
                footerIv.fill(0)
                encryptedFooter.fill(0)
            }
            return totalBytes
        } finally {
            buffer.fill(0)
        }
    }

    fun decryptStream(input: InputStream, output: OutputStream): Long =
        decryptStreamInternal(input, output, null)

    fun decryptStream(input: InputStream, output: OutputStream, aad: ByteArray): Long =
        decryptStreamInternal(input, output, aad)

    private fun decryptStreamInternal(input: InputStream, output: OutputStream, aad: ByteArray?): Long {
        val data = DataInputStream(input)
        val magic = ByteArray(FILE_MAGIC.size)
        data.readFully(magic)
        val contextual = magic.contentEquals(FILE_CONTEXT_MAGIC)
        require(contextual || magic.contentEquals(FILE_MAGIC)) { "Unknown encrypted file format" }
        require(!contextual || aad != null) { "Encrypted file requires its object context" }
        val effectiveAad = if (contextual) aad else null

        var chunkIndex = 0
        var totalBytes = 0L
        while (true) {
            val plainLength = data.readInt()
            require(plainLength in 0..FILE_CHUNK_SIZE) { "Invalid encrypted file block" }
            val iv = ByteArray(IV_LEN)
            data.readFully(iv)
            val encryptedLength = if (plainLength == 0) 12 + TAG_LEN_BYTES else plainLength + TAG_LEN_BYTES
            val encrypted = ByteArray(encryptedLength)
            data.readFully(encrypted)

            if (plainLength == 0) {
                var footerBytes: ByteArray? = null
                try {
                    val footerCipher = fileCipher(Cipher.DECRYPT_MODE, iv).apply {
                        updateAAD(streamFooterAad(magic, effectiveAad, chunkIndex))
                    }
                    footerBytes = footerCipher.doFinal(encrypted)
                    val footer = ByteBuffer.wrap(footerBytes)
                    val expectedChunks = footer.int
                    val expectedBytes = footer.long
                    require(expectedChunks == chunkIndex && expectedBytes == totalBytes) {
                        "Encrypted file footer does not match its contents"
                    }
                    require(data.read() == -1) { "Unexpected data after encrypted file footer" }
                    output.flush()
                    return totalBytes
                } finally {
                    footerBytes?.fill(0)
                    iv.fill(0)
                    encrypted.fill(0)
                }
            }

            val cipher = fileCipher(Cipher.DECRYPT_MODE, iv).apply {
                updateAAD(streamChunkAad(magic, effectiveAad, chunkIndex, plainLength))
            }
            val plain = cipher.doFinal(encrypted)
            try {
                require(plain.size == plainLength) { "Invalid decrypted block length" }
                output.write(plain)
                totalBytes += plain.size
                chunkIndex++
            } finally {
                plain.fill(0)
                iv.fill(0)
                encrypted.fill(0)
            }
        }
    }

    private fun fileCipher(mode: Int, iv: ByteArray): Cipher =
        Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(mode, key, GCMParameterSpec(TAG_BITS, iv))
        }

    private fun streamChunkAad(magic: ByteArray, context: ByteArray?, index: Int, length: Int): ByteArray {
        val suffix = ByteBuffer.allocate(8).putInt(index).putInt(length).array()
        return if (context == null) magic + suffix else magic + context + suffix
    }

    private fun streamFooterAad(magic: ByteArray, context: ByteArray?, chunkCount: Int): ByteArray {
        val suffix = byteArrayOf(0x45, 0x4E, 0x44) + ByteBuffer.allocate(4).putInt(chunkCount).array()
        return if (context == null) magic + suffix else magic + context + suffix
    }

    internal fun exportKeyForBiometricWrapping(): ByteArray {
        val encoded = key.encoded ?: error("Vault key cannot be exported")
        return try {
            encoded.copyOf()
        } finally {
            encoded.fill(0)
        }
    }

    private fun newCipher(mode: Int, iv: ByteArray): Cipher =
        Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(mode, key, GCMParameterSpec(TAG_BITS, iv))
        }

    companion object {
        private val SECURE_RANDOM = SecureRandom()
        private val LIVE_INSTANCES = Collections.newSetFromMap(IdentityHashMap<Crypto, Boolean>())

        internal fun destroyAll() {
            val instances = synchronized(LIVE_INSTANCES) {
                LIVE_INSTANCES.toList().also { LIVE_INSTANCES.clear() }
            }
            instances.forEach { it.destroy() }
        }
        private val RECORD_MAGIC = byteArrayOf(0x53, 0x4E, 0x45, 0x32)

        fun contextAad(domain: String, objectId: String): ByteArray {
            require(domain.isNotBlank() && domain.length <= 64)
            require(objectId.isNotBlank() && objectId.length <= 256)
            return ("SecNote/AAD/v2\u0000" + domain + "\u0000" + objectId).toByteArray(Charsets.UTF_8)
        }

        private const val KEY_BITS = 256
        internal const val SALT_LENGTH = PasswordKdf.SALT_LENGTH
        private const val IV_LEN = 12
        private const val TAG_BITS = 128
        private const val TAG_LEN_BYTES = TAG_BITS / 8
        private const val FILE_CHUNK_SIZE = 64 * 1024
        private val FILE_MAGIC = byteArrayOf(0x53, 0x4E, 0x46, 0x31)
        private val FILE_CONTEXT_MAGIC = byteArrayOf(0x53, 0x4E, 0x46, 0x32)

        fun newSalt(): ByteArray = PasswordKdf.newSalt()

        internal fun isValidSalt(salt: ByteArray): Boolean = PasswordKdf.isValidSalt(salt)

        fun fromPassphrase(passphrase: String, salt: ByteArray): Crypto {
            require(passphrase.isNotEmpty())
            val keyBytes = PasswordKdf.derive(passphrase, salt)
            return try {
                fromRawKeyBytes(keyBytes)
            } finally {
                keyBytes.fill(0)
            }
        }

        internal fun fromRawKeyBytes(rawKey: ByteArray): Crypto {
            require(rawKey.size == KEY_BITS / 8) { "Invalid vault key length" }
            return Crypto(rawKey)
        }
    }
}

private class WipeableAesKey(rawKey: ByteArray) : SecretKey, Destroyable {
    @Volatile private var destroyed = false
    private val lock = Any()
    private var material: ByteArray = rawKey.copyOf()

    override fun getAlgorithm(): String = "AES"
    override fun getFormat(): String = "RAW"

    override fun getEncoded(): ByteArray? = synchronized(lock) {
        if (destroyed) null else material.copyOf()
    }

    override fun destroy() {
        synchronized(lock) {
            if (!destroyed) {
                material.fill(0)
                destroyed = true
            }
        }
    }

    override fun isDestroyed(): Boolean = destroyed
}
