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
