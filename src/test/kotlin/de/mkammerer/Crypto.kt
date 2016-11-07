package de.mkammerer

import org.hamcrest.CoreMatchers
import org.junit.Assert
import org.junit.Test

class CBCTests {
    /**
     * Uses AES CBC with PKCS5 padding and a SHA256 HMAC.
     *
     * If you use AES CBC mode, you have to protect it with a HMAC!
     */
    @Test fun testCbcAndHmac() {
        // Generate two keys: one for CBC, one for the HMAC
        val cbcKey = generateKey(256)
        val hmacKey = generateKey(256)

        val plaintext = "This is the CBC test"

        // Encrypt the plaintext using AES CBC, the IV is generated automatically
        val ciphertext = encryptCbc(plaintext.toByteArray(), cbcKey)
        val hmac = createHmac(ciphertext.iv + ciphertext.ciphertext, hmacKey)

        // Now send the IV, the ciphertext and the HMAC over wire, or store it somewhere. It doesn't contain any secret information.

        // Before decrypting, check the HMAC. If it doesn't match, someone has tampered the data!
        if (!checkHmac(ciphertext.iv + ciphertext.ciphertext, hmacKey, hmac)) throw IllegalStateException("HMAC failed")
        // Decrypt the ciphertext. The decrypt message uses the IV which is stored in the ciphertext object
        val decrypted = String(decryptCbc(ciphertext, cbcKey), Charsets.UTF_8)

        Assert.assertThat(decrypted, CoreMatchers.equalTo(plaintext))
    }

    /**
     * Uses AES GCM.
     */
    @Test fun testGcm() {
        // GCM only needs one key. If you can use GCM, prefer that over CBC + HMAC
        val key = generateKey(256)
        val plaintext = "This is the GCM test"

        // GCM uses a nonce. The encrypt message uses a random nonce. NEVER REUSE A NONCE!
        val ciphertext = encryptGcm(plaintext.toByteArray(), key)

        val decrypted = String(decryptGcm(ciphertext, key), Charsets.UTF_8)

        Assert.assertThat(decrypted, CoreMatchers.equalTo(plaintext))
    }
}

