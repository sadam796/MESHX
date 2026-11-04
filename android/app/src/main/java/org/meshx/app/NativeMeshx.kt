package org.meshx.app

/**
 * Thin JNI boundary for the Rust transport spike.
 *
 * This currently reports native-library availability only. It does not start
 * libp2p, establish peers, or send messages.
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

    fun status(): String = loadError?.let {
        "Native bridge unavailable: $it"
    } ?: try {
        nativeTransportStatus()
    } catch (error: UnsatisfiedLinkError) {
        "Native bridge method unavailable: ${error.message ?: "unknown JNI error"}"
    }
}
