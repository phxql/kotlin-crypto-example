package de.mkammerer

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

val secureRandom = SecureRandom()

/**
 * Generates a key with [sizeInBits] bits.
 */
fun generateKey(sizeInBits: Int): ByteArray {
    val result = ByteArray(sizeInBits / 8)
    secureRandom.nextBytes(result)
    return result
}

/**
 * Generates an IV. The IV is always 128 bit long.
 */
fun generateIv(): ByteArray {
    val result = ByteArray(128 / 8)
    secureRandom.nextBytes(result)
    return result
}

/**
 * Generates a nonce for GCM mode. The nonce is always 96 bit long.
 */
fun generateNonce(): ByteArray {
    val result = ByteArray(96 / 8)
    secureRandom.nextBytes(result)
    return result
}

class Ciphertext(val ciphertext: ByteArray, val iv: ByteArray)

/**
 * Encrypts the given [plaintext] with the given [key] under AES CBC with PKCS5 padding.
 *
 * This method generates a random IV.
 *
 * @return Ciphertext and IV
 */
fun encryptCbc(plaintext: ByteArray, key: ByteArray): Ciphertext {
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val keySpec = SecretKeySpec(key, "AES")

    val iv = generateIv()
    val ivSpec = IvParameterSpec(iv)

    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)

    val ciphertext = cipher.doFinal(plaintext)

    return Ciphertext(ciphertext, iv)
}

/**
 * Encrypts the given [plaintext] with the given [key] under AES GCM.
 *
 * This method generates a random nonce.
 *
 * @return Ciphertext and nonce
 */
fun encryptGcm(plaintext: ByteArray, key: ByteArray): Ciphertext {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val keySpec = SecretKeySpec(key, "AES")

    val nonce = generateNonce()
    val gcmSpec = GCMParameterSpec(128, nonce)

    cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)

    val ciphertext = cipher.doFinal(plaintext)

    return Ciphertext(ciphertext, nonce)
}

/**
 * Generates a HMAC for the given [data] with the given [key] using HMAC-SHA256.
 *
 * @returns HMAC
 */
fun createHmac(data: ByteArray, key: ByteArray): ByteArray {
    val keySpec = SecretKeySpec(key, "HmacSHA256")
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(keySpec)

    val hmac = mac.doFinal(data)
    return hmac
}

/**
 * Checks the HMAC for the given [data] and the given [key] to match the [expectedHmac].
 *
 * The HMAC comparison is done in a timing attack proof way.
 *
 * @return True if the HMAC matches, false otherwise.
 */
fun checkHmac(data: ByteArray, key: ByteArray, expectedHmac: ByteArray): Boolean {
    val hmac = createHmac(data, key)

    // Check for equality in a timing attack proof way
    if (hmac.size != expectedHmac.size) return false
    var result = 0
    for (i in 0 until hmac.size) {
        result = result.or(hmac[i].toInt().xor(expectedHmac[i].toInt()))
    }

    return result == 0
}

/**
 * Decrypts the given [ciphertext] using the given [key] under AES CBC with PKCS5 padding.
 *
 * @return Plaintext
 */
fun decryptCbc(ciphertext: Ciphertext, key: ByteArray): ByteArray {
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val keySpec = SecretKeySpec(key, "AES")
    val ivSpec = IvParameterSpec(ciphertext.iv)

    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)

    val plaintext = cipher.doFinal(ciphertext.ciphertext)
    return plaintext
}

/**
 * Decrypts the given [ciphertext] using the given [key] under AES GCM.
 *
 * @return Plaintext
 */
fun decryptGcm(ciphertext: Ciphertext, key: ByteArray): ByteArray {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val keySpec = SecretKeySpec(key, "AES")

    val gcmSpec = GCMParameterSpec(128, ciphertext.iv)

    cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)

    val plaintext = cipher.doFinal(ciphertext.ciphertext)
    return plaintext
}
