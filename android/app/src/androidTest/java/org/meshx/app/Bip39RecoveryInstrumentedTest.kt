package org.meshx.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Bip39RecoveryInstrumentedTest {
    private fun wordlist(): List<String> {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        return context.assets.open("bip39-english.txt").bufferedReader().use { it.readLines() }
    }

    @Test
    fun officialEnglishWordlistAndTwentyFourWordChecksumRoundTrip() {
        val words = wordlist()
        assertEquals(2048, words.size)
        val entropy = ByteArray(32)
        val phrase = Bip39Recovery.encodeEntropy(entropy, words).joinToString(" ")
        assertEquals(24, phrase.split(" ").size)
        assertTrue(Bip39Recovery.validate24(phrase, words))
        val altered = phrase.split(" ").toMutableList().also { it[23] = if (it[23] == words[0]) words[1] else words[0] }
        assertFalse(Bip39Recovery.validate24(altered.joinToString(" "), words))
    }

    @Test
    fun bip39SeedMatchesPublishedTrezorTestVector() {
        val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        val expected = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553" +
            "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        val seed = Bip39Recovery.toSeed(phrase, "TREZOR")
        try {
            val actual = seed.joinToString("") { "%02x".format(it.toInt() and 0xff) }
            assertEquals(expected, actual)
        } finally {
            seed.fill(0)
        }
    }
}
