package sn.kaolack.fluxsync

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * DIR-P2-02: encrypts the daemon's long-term Noise identity at rest on
 * Android using an AndroidKeyStore-backed AES-256-GCM key.
 *
 * Before this, the identity secret sat as a plaintext 32-byte file
 * (`identity.bin`) under the app's private data dir — `fluxsyncd::keystore`
 * only has a plaintext-file branch for Android because the `keyring`
 * crate it uses everywhere else has no Android backend. Anything that
 * reaches app-private storage (rooted device, a debuggable-build `adb
 * backup`, a scoped-storage bug) could lift the raw secret and impersonate
 * the device to every paired peer.
 *
 * Design:
 *  - Key: AES-256-GCM, generated inside `AndroidKeyStore`, non-exportable.
 *    StrongBox (`setIsStrongBoxBacked(true)`, API 28+) is tried first and
 *    falls back to the TEE-backed key on devices/emulators without a
 *    StrongBox chip. No user-authentication requirement — the daemon must
 *    boot unattended, both from cold start and from the
 *    AccessibilityService's own process, before the user has unlocked
 *    the screen.
 *  - File: `identity.enc` = 12-byte GCM IV followed by the ciphertext
 *    (auth tag included, standard `Cipher` framing), written atomically
 *    (`*.tmp` + rename) so a crash mid-write can't corrupt it.
 *  - Migration: [readOrMigrate] looks for the legacy plaintext
 *    `identity.bin` first. If present, it is encrypted to `identity.enc`,
 *    the write is verified by decrypting it straight back and comparing
 *    byte-for-byte, and ONLY THEN is the plaintext file deleted. Losing
 *    the identity unpairs the device from every peer, so the plaintext
 *    file is never removed on an unverified write.
 *  - Fallback: if `AndroidKeyStore` itself is unusable (rare OEM firmware
 *    bugs), [readOrMigrate] returns null and the caller falls back to the
 *    legacy plaintext `IdentitySource.Keystore` path with a loud log —
 *    the residual risk being that on those devices the identity stays in
 *    plaintext exactly as before this change.
 */
object KeystoreIdentityStore {
    private const val TAG = "FluxSync"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "fluxsync_identity_key"
    private const val ENC_FILE_NAME = "identity.enc"
    private const val LEGACY_FILE_NAME = "identity.bin"
    private const val TRANSFORM = "AES/GCM/NoPadding"
    private const val GCM_IV_BYTES = 12
    private const val GCM_TAG_BITS = 128
    internal const val SECRET_LEN = 32

    /**
     * Returns the 32-byte identity secret, migrating from the legacy
     * plaintext file or generating a fresh identity if neither file
     * exists yet. Returns null if `AndroidKeyStore` is unusable on this
     * device — the caller must fall back to the plaintext
     * `IdentitySource.Keystore` path in that case.
     */
    @JvmStatic
    fun readOrMigrate(dataDir: File): ByteArray? = try {
        val key = getOrCreateKey()
        val encFile = File(dataDir, ENC_FILE_NAME)
        val legacyFile = File(dataDir, LEGACY_FILE_NAME)

        when {
            encFile.exists() -> decryptBytes(key, encFile.readBytes())
            legacyFile.exists() -> migrateLegacy(key, legacyFile, encFile)
            else -> {
                val fresh = ByteArray(SECRET_LEN).also { SecureRandom().nextBytes(it) }
                writeEncryptedAtomic(key, encFile, fresh)
                fresh
            }
        }
    } catch (e: Exception) {
        Log.e(TAG, "AndroidKeyStore identity path unusable, caller must fall back to plaintext: ${e.message}", e)
        null
    }

    /**
     * Encrypts the legacy plaintext secret to `identity.enc`, verifies the
     * write by decrypting it straight back, and only deletes the
     * plaintext file once that readback matches byte-for-byte. Throws
     * (leaving the plaintext file in place) if the length is wrong or the
     * verification fails, so a botched migration can never lose the
     * identity — the legacy file is the caller's fallback.
     */
    internal fun migrateLegacy(key: SecretKey, legacyFile: File, encFile: File): ByteArray {
        val plaintext = legacyFile.readBytes()
        try {
            check(plaintext.size == SECRET_LEN) {
                "legacy identity.bin has length ${plaintext.size}, expected $SECRET_LEN"
            }
            writeEncryptedAtomic(key, encFile, plaintext)

            val readBack = decryptBytes(key, encFile.readBytes())
            try {
                check(readBack.contentEquals(plaintext)) {
                    "post-migration readback mismatch; keeping legacy plaintext file"
                }
            } catch (e: Exception) {
                // Fail-safe: never leave a half-verified identity.enc
                // around to be picked up on a later boot.
                encFile.delete()
                throw e
            }

            if (!legacyFile.delete()) {
                Log.w(TAG, "Encrypted migration verified but failed to delete legacy identity.bin; will retry deletion next boot")
            } else {
                Log.i(TAG, "Migrated identity.bin to Keystore-encrypted identity.enc")
            }
            return readBack
        } finally {
            Arrays.fill(plaintext, 0)
        }
    }

    /** Encrypt-then-atomic-write: `*.tmp` + rename, mirroring the Rust keystore's write pattern. */
    internal fun writeEncryptedAtomic(key: SecretKey, file: File, plaintext: ByteArray) {
        val tmp = File(file.parentFile, "${file.name}.tmp")
        tmp.writeBytes(encryptBytes(key, plaintext))
        check(tmp.renameTo(file)) { "failed to rename ${tmp.name} -> ${file.name}" }
    }

    /** AES-256-GCM encrypt; returns `iv (12B) || ciphertext+tag`. */
    internal fun encryptBytes(key: SecretKey, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext)
        return iv + ciphertext
    }

    /** Inverse of [encryptBytes]. Throws on a too-short buffer or a failed auth tag. */
    internal fun decryptBytes(key: SecretKey, ivAndCiphertext: ByteArray): ByteArray {
        require(ivAndCiphertext.size > GCM_IV_BYTES) { "identity.enc too short: ${ivAndCiphertext.size}B" }
        val iv = ivAndCiphertext.copyOfRange(0, GCM_IV_BYTES)
        val ciphertext = ivAndCiphertext.copyOfRange(GCM_IV_BYTES, ivAndCiphertext.size)
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(ciphertext)
    }

    /**
     * Fetches the existing `AndroidKeyStore` key or generates a new one.
     * Tries StrongBox first (dedicated secure element — most devices and
     * all emulators don't have one, so this routinely falls back) and
     * regenerates the spec without it on failure. No user-authentication
     * requirement: the daemon boots unattended, often before first unlock.
     */
    private fun getOrCreateKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (ks.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        return try {
            generator.init(keySpec(strongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P))
            generator.generateKey()
        } catch (e: Exception) {
            Log.w(TAG, "StrongBox-backed identity key unavailable, falling back to TEE-backed key: ${e.message}")
            generator.init(keySpec(strongBox = false))
            generator.generateKey()
        }
    }

    private fun keySpec(strongBox: Boolean): KeyGenParameterSpec {
        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(false)
        if (strongBox) {
            builder.setIsStrongBoxBacked(true)
        }
        return builder.build()
    }
}
