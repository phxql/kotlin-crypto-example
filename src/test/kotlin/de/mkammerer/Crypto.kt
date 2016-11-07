package de.mkammerer

import org.hamcrest.CoreMatchers
import org.junit.Assert
import org.junit.Test

class CBCTests {
    @Test fun testCbcAndHmac() {
        val cbcKey = generateKey(256)
        val hmacKey = generateKey(256)
        val plaintext = "This is the CBC test"

        val ciphertext = encryptCbc(plaintext.toByteArray(), cbcKey)
        val hmac = createHmac(ciphertext.iv + ciphertext.ciphertext, hmacKey)

        if (!checkHmac(ciphertext.iv + ciphertext.ciphertext, hmacKey, hmac)) throw IllegalStateException("HMAC failed")
        val decrypted = String(decryptCbc(ciphertext, cbcKey), Charsets.UTF_8)

        Assert.assertThat(decrypted, CoreMatchers.equalTo(plaintext))
    }

    @Test fun testGcm() {
        val key = generateKey(256)
        val plaintext = "This is the GCM test"

        val ciphertext = encryptGcm(plaintext.toByteArray(), key)

        val decrypted = String(decryptGcm(ciphertext, key), Charsets.UTF_8)

        Assert.assertThat(decrypted, CoreMatchers.equalTo(plaintext))
    }
}

