package org.meshx.app

/**
 * JNI boundary for the native libp2p transport and bounded opaque-ciphertext
 * request/response API. Ciphertext send/receive is not yet connected to the chat
 * UI or MLS group encryption, and delivery is direct-peer/volatile only.
 */
internal object NativeMeshx {
    private val loadError: String? = try {
        System.loadLibrary("meshx_android_ffi")
        null
    } catch (error: UnsatisfiedLinkError) {
        error.message ?: "Native MESHX library could not be loaded."
    } catch (error: SecurityException) {
        error.message ?: "Native MESHX library load was blocked."
    }

    private external fun nativeTransportStatus(): String
    private external fun nativeGenerateIdentity(): ByteArray
    private external fun nativeTransportPublicKey(identity: ByteArray): ByteArray
    private external fun nativeTransportPeerId(publicKey: ByteArray): String
    private external fun nativeFindPeer(peerId: String): String
    private external fun nativeSendCiphertext(peerId: String, ciphertext: ByteArray): String
    private external fun nativePollIncomingCiphertexts(): String
    private external fun nativeStartTransport(identity: ByteArray): String
    private external fun nativeAddBootstrapPeers(addresses: String): String
    private external fun nativeMlsCreateSignerSnapshot(): ByteArray
    private external fun nativeMlsValidateSignerSnapshot(snapshot: ByteArray): Boolean
    private external fun nativeMlsCreateGroupSnapshot(identity: ByteArray): ByteArray
    private external fun nativeMlsValidateGroupSnapshot(snapshot: ByteArray): Boolean
    private external fun nativeMlsTwoMemberRoundTripSelfTest(): Boolean

    fun generateIdentity(): ByteArray {
        check(loadError == null) { "Native bridge unavailable: $loadError" }
        return try {
            nativeGenerateIdentity().also {
                check(it.isNotEmpty()) { "Native MESHX identity generation returned no key." }
            }
        } catch (error: UnsatisfiedLinkError) {
            throw IllegalStateException("Native identity generator unavailable: ${error.message ?: "unknown JNI error"}", error)
        }
    }

    fun transportPublicKey(identity: ByteArray): ByteArray {
        check(loadError == null) { "Native bridge unavailable: $loadError" }
        return try {
            nativeTransportPublicKey(identity).also {
                check(it.isNotEmpty()) { "Native MESHX transport public key is empty." }
            }
        } catch (error: UnsatisfiedLinkError) {
            throw IllegalStateException("Native public-key method unavailable: ${error.message ?: "unknown JNI error"}", error)
        }
    }

    fun transportPeerId(publicKey: ByteArray): String {
        check(loadError == null) { "Native bridge unavailable: $loadError" }
        return try {
            nativeTransportPeerId(publicKey).also {
                check(it.isNotBlank()) { "Native MESHX transport public key is invalid." }
            }
        } catch (error: UnsatisfiedLinkError) {
            throw IllegalStateException("Native peer-ID method unavailable: ${error.message ?: "unknown JNI error"}", error)
        }
    }

    fun findPeer(peerId: String): String = loadError?.let {
        "MESHX peer discovery error: Native bridge unavailable: $it"
    } ?: try {
        nativeFindPeer(peerId)
    } catch (error: UnsatisfiedLinkError) {
        "MESHX peer discovery error: Native method unavailable: ${error.message ?: "unknown JNI error"}"
    }

    /**
     * Sends opaque MLS/application ciphertext to a directly reachable libp2p peer.
     * This does not encrypt plaintext, discover a route, or provide offline delivery.
     */
    fun sendCiphertext(peerId: String, ciphertext: ByteArray): String = loadError?.let {
        "MESHX send error: Native bridge unavailable: $it"
    } ?: try {
        nativeSendCiphertext(peerId, ciphertext)
    } catch (error: UnsatisfiedLinkError) {
        "MESHX send error: Native method unavailable: ${error.message ?: "unknown JNI error"}"
    }

    /** Returns and clears ciphertext envelopes waiting in the bounded volatile receive queue. */
    fun pollIncomingCiphertexts(): String = loadError?.let {
        "[]"
    } ?: try {
        nativePollIncomingCiphertexts()
    } catch (error: UnsatisfiedLinkError) {
        "[]"
    }

    fun start(identity: ByteArray): String = loadError?.let {
        "Native bridge unavailable: $it"
    } ?: try {
        nativeStartTransport(identity)
    } catch (error: UnsatisfiedLinkError) {
        "Native bridge method unavailable: ${error.message ?: "unknown JNI error"}"
    }

    fun addBootstrapPeers(addresses: String): String = loadError?.let {
        "Native bridge unavailable: $it"
    } ?: try {
        nativeAddBootstrapPeers(addresses)
    } catch (error: UnsatisfiedLinkError) {
        "Native bootstrap method unavailable: ${error.message ?: "unknown JNI error"}"
    }


    /** Creates a real OpenMLS provider snapshot containing an MLS signing key. */
    fun createMlsSignerSnapshot(): ByteArray {
        check(loadError == null) { "Native bridge unavailable: $loadError" }
        return try {
            nativeMlsCreateSignerSnapshot().also {
                check(it.isNotEmpty()) { "Native OpenMLS provider returned an empty snapshot." }
            }
        } catch (error: UnsatisfiedLinkError) {
            throw IllegalStateException("Native OpenMLS snapshot method unavailable: ${error.message ?: "unknown JNI error"}", error)
        }
    }

    /** Restores and verifies the MLS signing key from a vault-authenticated snapshot. */
    fun validateMlsSignerSnapshot(snapshot: ByteArray): Boolean {
        check(loadError == null) { "Native bridge unavailable: $loadError" }
        return try {
            nativeMlsValidateSignerSnapshot(snapshot)
        } catch (error: UnsatisfiedLinkError) {
            throw IllegalStateException("Native OpenMLS restore method unavailable: ${error.message ?: "unknown JNI error"}", error)
        }
    }


    /** Creates a real RFC 9420 group snapshot for encrypted vault persistence. */
    fun createMlsGroupSnapshot(identity: ByteArray): ByteArray {
        check(loadError == null) { "Native bridge unavailable: $loadError" }
        return try {
            nativeMlsCreateGroupSnapshot(identity).also {
                check(it.isNotEmpty()) { "Native OpenMLS group engine returned an empty snapshot." }
            }
        } catch (error: UnsatisfiedLinkError) {
            throw IllegalStateException("Native OpenMLS group creation unavailable: ${error.message ?: "unknown JNI error"}", error)
        }
    }

    /** Restores a group snapshot and validates its group plus private signer. */
    fun validateMlsGroupSnapshot(snapshot: ByteArray): Boolean {
        check(loadError == null) { "Native bridge unavailable: $loadError" }
        return try {
            nativeMlsValidateGroupSnapshot(snapshot)
        } catch (error: UnsatisfiedLinkError) {
            throw IllegalStateException("Native OpenMLS group restore unavailable: ${error.message ?: "unknown JNI error"}", error)
        }
    }

    /** Runs a real Alice/Bob MLS encrypted-message round trip inside native code. */
    fun mlsTwoMemberRoundTripSelfTest(): Boolean {
        check(loadError == null) { "Native bridge unavailable: $loadError" }
        return try {
            nativeMlsTwoMemberRoundTripSelfTest()
        } catch (error: UnsatisfiedLinkError) {
            throw IllegalStateException("Native MLS self-test unavailable: ${error.message ?: "unknown JNI error"}", error)
        }
    }

    fun status(): String {
        val value = loadError?.let {
            "Native bridge unavailable: $it"
        } ?: try {
            nativeTransportStatus()
        } catch (error: UnsatisfiedLinkError) {
            "Native bridge method unavailable: ${error.message ?: "unknown JNI error"}"
        }
        android.util.Log.i("MESHX_NATIVE", value)
        return value
    }
}
