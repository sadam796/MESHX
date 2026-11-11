package org.meshx.app

/**
 * JNI boundary for the native libp2p transport.
 * The current native milestone starts a TCP/Noise/Yamux peer only; it does not
 * yet discover contacts or deliver application messages.
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
    private external fun nativeStartTransport(identity: ByteArray): String
    private external fun nativeAddBootstrapPeers(addresses: String): String

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
