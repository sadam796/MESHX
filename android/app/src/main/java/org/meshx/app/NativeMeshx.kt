package org.meshx.app

/**
 * JNI boundary for the native libp2p transport, direct ciphertext delivery,
 * and the experimental durable relay mailbox client. The relay mailbox requires
 * a live compatible server and is not a proof of recipient delivery.
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
    private external fun nativePollIncomingCiphertexts(peerId: String): String
    private external fun nativeAckIncomingCiphertext(messageId: String): Boolean
    private external fun nativeStartTransport(identity: ByteArray): String
    private external fun nativeAddBootstrapPeers(addresses: String): String
    private external fun nativeAddRelayPeer(address: String): String
    private external fun nativeMlsCreateSignerSnapshot(): ByteArray
    private external fun nativeMlsValidateSignerSnapshot(snapshot: ByteArray): Boolean
    private external fun nativeMlsCreateGroupSnapshot(identity: ByteArray): ByteArray
    private external fun nativeMlsCreateKeyPackageSnapshot(identity: ByteArray): ByteArray
    private external fun nativeMlsExtractKeyPackage(snapshot: ByteArray): ByteArray
    private external fun nativeMlsAddMemberToGroup(groupSnapshot: ByteArray, keyPackage: ByteArray): ByteArray
    private external fun nativeMlsJoinGroupFromWelcome(keyPackageState: ByteArray, welcome: ByteArray, ratchetTree: ByteArray): ByteArray
    private external fun nativeMlsEncryptApplicationMessage(groupSnapshot: ByteArray, plaintext: ByteArray): ByteArray
    private external fun nativeMlsDecryptApplicationMessage(groupSnapshot: ByteArray, ciphertext: ByteArray): ByteArray
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
     * Sends opaque MLS/application ciphertext directly and also requests durable
     * storage from each configured, connected mailbox relay. This does not
     * encrypt plaintext or mean the recipient has received the message.
     */
    fun sendCiphertext(peerId: String, ciphertext: ByteArray): String = loadError?.let {
        "MESHX send error: Native bridge unavailable: $it"
    } ?: try {
        nativeSendCiphertext(peerId, ciphertext)
    } catch (error: UnsatisfiedLinkError) {
        "MESHX send error: Native method unavailable: ${error.message ?: "unknown JNI error"}"
    }

    /** Returns only ciphertext envelopes from this contact, leaving other senders queued. */
    fun pollIncomingCiphertexts(peerId: String): String = loadError?.let {
        "[]"
    } ?: try {
        nativePollIncomingCiphertexts(peerId)
    } catch (error: UnsatisfiedLinkError) {
        "[]"
    }

    /** Acknowledge only after the caller has authenticated and saved a message. */
    fun ackIncomingCiphertext(messageId: String): Boolean = loadError == null && try {
        nativeAckIncomingCiphertext(messageId)
    } catch (_: UnsatisfiedLinkError) {
        false
    }

    fun start(identity: ByteArray): String = loadError?.let {
        "Native bridge unavailable: $it"
    } ?: try {
        nativeStartTransport(identity)
    } catch (error: UnsatisfiedLinkError) {
        "Native bridge method unavailable: ${error.message ?: "unknown JNI error"}"
    }

    fun addRelayPeer(address: String): String = loadError?.let {
        "MESHX relay error: Native bridge unavailable: $it"
    } ?: try {
        nativeAddRelayPeer(address)
    } catch (error: UnsatisfiedLinkError) {
        "MESHX relay error: Native method unavailable: ${error.message ?: "unknown JNI error"}"
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



    /** Creates a signed one-use MLS KeyPackage; persist the private snapshot in the Keystore vault. */
    fun createMlsKeyPackageSnapshot(identity: ByteArray): ByteArray {
        check(loadError == null) { "Native bridge unavailable: $loadError" }
        return nativeMlsCreateKeyPackageSnapshot(identity).also {
            check(it.isNotEmpty()) { "Native OpenMLS KeyPackage generation returned an empty snapshot." }
        }
    }

    /** Restores private KeyPackage material and validates its public signature before export. */
    fun extractMlsKeyPackage(snapshot: ByteArray): ByteArray {
        check(loadError == null) { "Native bridge unavailable: $loadError" }
        return nativeMlsExtractKeyPackage(snapshot).also {
            check(it.isNotEmpty()) { "Native OpenMLS KeyPackage validation returned no public package." }
        }
    }

    /** Adds a contact's verified one-use KeyPackage and returns an invitation bundle. */
    fun addMlsMemberToGroup(groupSnapshot: ByteArray, keyPackage: ByteArray): ByteArray {
        check(loadError == null) { "Native bridge unavailable: $loadError" }
        return try {
            nativeMlsAddMemberToGroup(groupSnapshot, keyPackage).also {
                check(it.isNotEmpty()) { "Native OpenMLS member invitation returned no bundle." }
            }
        } catch (error: UnsatisfiedLinkError) {
            throw IllegalStateException("Native MLS member invitation unavailable: ${error.message ?: "unknown JNI error"}", error)
        }
    }

    /** Joins a received MLS Welcome using the locally saved KeyPackage private state. */
    fun joinMlsGroupFromWelcome(keyPackageState: ByteArray, welcome: ByteArray, ratchetTree: ByteArray): ByteArray {
        check(loadError == null) { "Native bridge unavailable: $loadError" }
        return try {
            nativeMlsJoinGroupFromWelcome(keyPackageState, welcome, ratchetTree).also {
                check(it.isNotEmpty()) { "Native OpenMLS group join returned no group state." }
            }
        } catch (error: UnsatisfiedLinkError) {
            throw IllegalStateException("Native MLS group join unavailable: ${error.message ?: "unknown JNI error"}", error)
        }
    }

    /** Encrypts plaintext with the persisted MLS group and returns updated state plus ciphertext. */
    fun encryptMlsApplicationMessage(groupSnapshot: ByteArray, plaintext: ByteArray): ByteArray {
        check(loadError == null) { "Native bridge unavailable: $loadError" }
        return try {
            nativeMlsEncryptApplicationMessage(groupSnapshot, plaintext).also {
                check(it.isNotEmpty()) { "Native MLS encryption returned no result." }
            }
        } catch (error: UnsatisfiedLinkError) {
            throw IllegalStateException("Native MLS encryption unavailable: ${error.message ?: "unknown JNI error"}", error)
        }
    }

    /** Authenticates and decrypts MLS ciphertext, returning updated state plus plaintext. */
    fun decryptMlsApplicationMessage(groupSnapshot: ByteArray, ciphertext: ByteArray): ByteArray {
        check(loadError == null) { "Native bridge unavailable: $loadError" }
        return try {
            nativeMlsDecryptApplicationMessage(groupSnapshot, ciphertext).also {
                check(it.isNotEmpty()) { "Native MLS decryption returned no result." }
            }
        } catch (error: UnsatisfiedLinkError) {
            throw IllegalStateException("Native MLS decryption unavailable: ${error.message ?: "unknown JNI error"}", error)
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
