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
    private external fun nativeStartTransport(): String

    fun start(): String = loadError?.let {
        "Native bridge unavailable: $it"
    } ?: try {
        nativeStartTransport()
    } catch (error: UnsatisfiedLinkError) {
        "Native bridge method unavailable: ${error.message ?: "unknown JNI error"}"
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
