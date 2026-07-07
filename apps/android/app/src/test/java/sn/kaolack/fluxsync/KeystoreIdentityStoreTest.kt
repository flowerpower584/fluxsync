package sn.kaolack.fluxsync

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.nio.file.Files
import javax.crypto.AEADBadTagException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * DIR-P2-02: exercises the encrypt/decrypt framing and the legacy-file
 * migration logic without touching `AndroidKeyStore` — that provider
 * doesn't exist on a plain JVM (no Robolectric in this project), but
 * every method under test here takes its [SecretKey] as a parameter, so
 * a plain `KeyGenerator.getInstance("AES")` key exercises the same code
 * `getOrCreateKey()` would hand it on-device.
 */
class KeystoreIdentityStoreTest {

    private fun plainAesKey(): SecretKey =
        KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()

    private fun tempDir(): File = Files.createTempDirectory("kis-test").toFile()

    @Test
    fun encryptDecryptRoundTrips() {
        val key = plainAesKey()
        val secret = ByteArray(KeystoreIdentityStore.SECRET_LEN) { it.toByte() }

        val encrypted = KeystoreIdentityStore.encryptBytes(key, secret)
        val decrypted = KeystoreIdentityStore.decryptBytes(key, encrypted)

        assertArrayEquals(secret, decrypted)
    }

    @Test
    fun decryptRejectsTooShortBuffer() {
        val key = plainAesKey()
        try {
            KeystoreIdentityStore.decryptBytes(key, ByteArray(4))
            fail("expected an exception for a too-short buffer")
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }

    @Test
    fun decryptRejectsWrongKey() {
        val encrypted = KeystoreIdentityStore.encryptBytes(plainAesKey(), ByteArray(32) { 0x42 })
        try {
            KeystoreIdentityStore.decryptBytes(plainAesKey(), encrypted)
            fail("decrypting with a different key must fail the GCM auth tag")
        } catch (e: AEADBadTagException) {
            // expected: GCM detects the tampered/mismatched key
        }
    }

    @Test
    fun tryDecryptExistingReturnsReadyOnValidFile() {
        val dir = tempDir()
        val key = plainAesKey()
        val encFile = File(dir, "identity.enc")
        val secret = ByteArray(KeystoreIdentityStore.SECRET_LEN) { (it * 5).toByte() }
        encFile.writeBytes(KeystoreIdentityStore.encryptBytes(key, secret))

        val result = KeystoreIdentityStore.tryDecryptExisting(key, encFile)

        assertTrue(result is KeystoreIdentityStore.IdentityResult.Ready)
        assertArrayEquals(secret, (result as KeystoreIdentityStore.IdentityResult.Ready).secret)
    }

    /**
     * The core of the bug this store must fail closed on: an
     * `identity.enc` that EXISTS but fails to decrypt (e.g. the
     * AndroidKeyStore key that encrypted it is gone — the common case
     * after a factory-reset/restore-to-new-device, since the file survives
     * backup/restore but the hardware-backed key never does) must come
     * back as [KeystoreIdentityStore.IdentityResult.Unreadable], never as
     * something a caller could mistake for "no identity yet, generate a
     * fresh one" — that would silently orphan every paired peer.
     */
    @Test
    fun tryDecryptExistingFailsClosedOnBadKey() {
        val dir = tempDir()
        val encFile = File(dir, "identity.enc")
        val secret = ByteArray(KeystoreIdentityStore.SECRET_LEN) { (it * 7).toByte() }
        encFile.writeBytes(KeystoreIdentityStore.encryptBytes(plainAesKey(), secret))

        // A different key stands in for "the AndroidKeyStore key no longer
        // validates" — GCM auth fails exactly as it would on-device.
        val result = KeystoreIdentityStore.tryDecryptExisting(plainAesKey(), encFile)

        assertTrue(
            "expected Unreadable, got $result",
            result is KeystoreIdentityStore.IdentityResult.Unreadable,
        )
        assertTrue(
            (result as KeystoreIdentityStore.IdentityResult.Unreadable).cause is AEADBadTagException,
        )
    }

    @Test
    fun tryDecryptExistingFailsClosedOnCorruptFile() {
        val dir = tempDir()
        val encFile = File(dir, "identity.enc")
        encFile.writeBytes(ByteArray(20) { 0x99.toByte() }) // garbage, not a real GCM frame

        val result = KeystoreIdentityStore.tryDecryptExisting(plainAesKey(), encFile)

        assertTrue(
            "a corrupt identity.enc must never be treated as decryptable or absent",
            result is KeystoreIdentityStore.IdentityResult.Unreadable,
        )
    }

    @Test
    fun migrateLegacyEncryptsVerifiesAndDeletesPlaintext() {
        val dir = tempDir()
        val key = plainAesKey()
        val legacy = File(dir, "identity.bin")
        val enc = File(dir, "identity.enc")
        val secret = ByteArray(KeystoreIdentityStore.SECRET_LEN) { (it * 3).toByte() }
        legacy.writeBytes(secret)

        val result = KeystoreIdentityStore.migrateLegacy(key, legacy, enc)

        assertArrayEquals(secret, result)
        assertTrue("identity.enc must exist after migration", enc.exists())
        assertFalse("legacy identity.bin must be deleted after a verified migration", legacy.exists())
        assertFalse("no .tmp file must survive the atomic rename", File(dir, "identity.enc.tmp").exists())

        // Re-decrypting the file directly (not via the returned array)
        // proves the on-disk ciphertext is the source of truth, not just
        // the in-memory return value.
        assertArrayEquals(secret, KeystoreIdentityStore.decryptBytes(key, enc.readBytes()))
    }

    @Test
    fun migrateLegacyRejectsWrongLengthAndKeepsPlaintext() {
        val dir = tempDir()
        val key = plainAesKey()
        val legacy = File(dir, "identity.bin")
        val enc = File(dir, "identity.enc")
        legacy.writeBytes(ByteArray(16) { 0x11 }) // wrong length

        try {
            KeystoreIdentityStore.migrateLegacy(key, legacy, enc)
            fail("expected an exception for a wrong-length legacy identity")
        } catch (e: IllegalStateException) {
            // expected
        }

        assertTrue("a rejected migration must never delete the plaintext fallback", legacy.exists())
        assertFalse("a rejected migration must not leave a half-written identity.enc", enc.exists())
    }

    @Test
    fun writeEncryptedAtomicLeavesNoTmpFile() {
        val dir = tempDir()
        val key = plainAesKey()
        val file = File(dir, "identity.enc")

        KeystoreIdentityStore.writeEncryptedAtomic(key, file, ByteArray(32) { 0x7 })

        assertTrue(file.exists())
        assertFalse(File(dir, "identity.enc.tmp").exists())
    }
}
