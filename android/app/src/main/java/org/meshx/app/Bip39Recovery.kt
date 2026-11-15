package org.meshx.app

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.text.Normalizer
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * BIP-39 English mnemonic primitives.
 *
 * This file deliberately does not store, log, display, or transmit a phrase.
 * The caller is responsible for secure UI handling and backup confirmation.
 */
internal object Bip39Recovery {
    private const val WORD_COUNT = 2048
    private const val PBKDF2_ROUNDS = 2048
    private const val SEED_BITS = 512

    fun generate24(words: List<String>, random: SecureRandom = SecureRandom()): List<String> {
        require(words.size == WORD_COUNT) { "BIP-39 English wordlist must contain exactly 2048 words." }
        val entropy = ByteArray(32).also(random::nextBytes)
        return try {
            encodeEntropy(entropy, words)
        } finally {
            entropy.fill(0)
        }
    }

    internal fun encodeEntropy(entropy: ByteArray, words: List<String>): List<String> {
        require(words.size == WORD_COUNT) { "BIP-39 English wordlist must contain exactly 2048 words." }
        require(entropy.size == 32) { "A 24-word recovery phrase requires exactly 256 bits of entropy." }
        val checksum = MessageDigest.getInstance("SHA-256").digest(entropy)[0].toInt() and 0xff
        val bits = BooleanArray(264)
        for (i in 0 until 256) {
            bits[i] = ((entropy[i / 8].toInt() ushr (7 - (i % 8))) and 1) == 1
        }
        for (i in 0 until 8) bits[256 + i] = ((checksum ushr (7 - i)) and 1) == 1
        return (0 until 24).map { wordIndex ->
            var index = 0
            for (bit in 0 until 11) {
                index = (index shl 1) or if (bits[wordIndex * 11 + bit]) 1 else 0
            }
            words[index]
        }
    }

    fun validate24(phrase: String, words: List<String>): Boolean {
        if (words.size != WORD_COUNT) return false
        val normalized = Normalizer.normalize(phrase.trim(), Normalizer.Form.NFKD)
        val parts = normalized.split(Regex("\\s+")).filter { it.isNotBlank() }
        if (parts.size != 24) return false
        val index = words.withIndex().associate { it.value to it.index }
        val bits = BooleanArray(264)
        for (i in parts.indices) {
            val wordIndex = index[parts[i]] ?: return false
            for (bit in 0 until 11) {
                bits[i * 11 + bit] = ((wordIndex ushr (10 - bit)) and 1) == 1
            }
        }
        val entropy = ByteArray(32)
        for (i in 0 until 256) {
            if (bits[i]) entropy[i / 8] = (entropy[i / 8].toInt() or (1 shl (7 - (i % 8)))).toByte()
        }
        val expected = MessageDigest.getInstance("SHA-256").digest(entropy)[0].toInt() and 0xff
        entropy.fill(0)
        var actual = 0
        for (i in 0 until 8) actual = (actual shl 1) or if (bits[256 + i]) 1 else 0
        return actual == expected
    }

    /** Returns the standard 512-bit BIP-39 seed; caller must zero it after use. */
    fun toSeed(phrase: String, passphrase: String = ""): ByteArray {
        val mnemonic = Normalizer.normalize(phrase.trim().split(Regex("\\s+")).joinToString(" "), Normalizer.Form.NFKD)
        val salt = Normalizer.normalize("mnemonic$passphrase", Normalizer.Form.NFKD)
        val spec = PBEKeySpec(mnemonic.toCharArray(), salt.toByteArray(Charsets.UTF_8), PBKDF2_ROUNDS, SEED_BITS)
        return try {
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }
}
