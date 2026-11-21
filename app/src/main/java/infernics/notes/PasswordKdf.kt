package infernics.notes

import com.lambdapioneer.argon2kt.Argon2Kt
import com.lambdapioneer.argon2kt.Argon2Mode
import com.lambdapioneer.argon2kt.Argon2Version
import java.nio.ByteBuffer
import java.security.SecureRandom

internal object PasswordKdf {
    internal const val SALT_LENGTH = 21
    private const val HEADER_LENGTH = 5
    private const val RAW_SALT_LENGTH = 16
    private const val PROFILE_ARGON2ID_V1 = 1
    private const val MEMORY_KIB = 19_456
    private const val ITERATIONS = 2
    private const val PARALLELISM = 1
    private const val OUTPUT_LENGTH = 32
    private val MAGIC = byteArrayOf(0x53, 0x4B, 0x44, 0x46)
    private val RANDOM = SecureRandom()
    private val engine by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { Argon2Kt() }

    fun newSalt(): ByteArray {
        val salt = ByteArray(SALT_LENGTH)
        MAGIC.copyInto(salt, 0)
        salt[4] = PROFILE_ARGON2ID_V1.toByte()
        val randomSalt = ByteArray(RAW_SALT_LENGTH)
        return try {
            RANDOM.nextBytes(randomSalt)
            randomSalt.copyInto(salt, HEADER_LENGTH)
            salt
        } finally {
            randomSalt.fill(0)
        }
    }

    fun isValidSalt(salt: ByteArray): Boolean =
        salt.size == SALT_LENGTH &&
            MAGIC.indices.all { salt[it] == MAGIC[it] } &&
            (salt[4].toInt() and 0xFF) == PROFILE_ARGON2ID_V1

    @Synchronized
    fun derive(passphrase: String, salt: ByteArray): ByteArray {
        require(passphrase.isNotEmpty())
        require(isValidSalt(salt))
        var passwordBytes: ByteArray? = null
        var rawSalt: ByteArray? = null
        var passwordBuffer: ByteBuffer? = null
        var saltBuffer: ByteBuffer? = null
        var rawHash: ByteBuffer? = null
        var encodedOutput: ByteBuffer? = null
        var output: ByteArray? = null
        var completed = false
        try {
            val password = passphrase.toByteArray(Charsets.UTF_8)
            passwordBytes = password
            val saltBytes = salt.copyOfRange(HEADER_LENGTH, SALT_LENGTH)
            rawSalt = saltBytes
            val passwordInput = ByteBuffer.allocateDirect(password.size).put(password).apply { rewind() }
            passwordBuffer = passwordInput
            val saltInput = ByteBuffer.allocateDirect(saltBytes.size).put(saltBytes).apply { rewind() }
            saltBuffer = saltInput
            val keyBytes = ByteArray(OUTPUT_LENGTH)
            output = keyBytes
            val result = engine.hash(
                mode = Argon2Mode.ARGON2_ID,
                password = passwordInput,
                salt = saltInput,
                tCostInIterations = ITERATIONS,
                mCostInKibibyte = MEMORY_KIB,
                parallelism = PARALLELISM,
                hashLengthInBytes = OUTPUT_LENGTH,
                version = Argon2Version.V13
            )
            rawHash = result.rawHash
            encodedOutput = result.encodedOutput
            val hashView = result.rawHash.duplicate()
            hashView.rewind()
            require(hashView.remaining() == OUTPUT_LENGTH)
            hashView.get(keyBytes)
            completed = true
            return keyBytes
        } finally {
            if (!completed) output?.fill(0)
            passwordBytes?.fill(0)
            rawSalt?.fill(0)
            passwordBuffer?.let(::wipeDirect)
            saltBuffer?.let(::wipeDirect)
            rawHash?.let(::wipeDirect)
            encodedOutput?.let(::wipeDirect)
        }
    }

    private fun wipeDirect(buffer: ByteBuffer) {
        val view = buffer.duplicate()
        view.clear()
        while (view.hasRemaining()) view.put(0)
    }
}
