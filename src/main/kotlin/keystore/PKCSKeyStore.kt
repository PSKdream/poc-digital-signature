package io.pongsakorn.keystore

import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.util.HashMap


class TestExternalStore(val config: SignatureConfig) : ExternalKeystoreInterface {

    data class SignatureConfig(
        val keystore: KeyStore,
        val keystorePassword: String,
    )

    private class PerpetualCache<T, V> {
        private val cache = HashMap<T, V>()

        val size: Int
            get() = cache.size


        operator fun set(key: T, value: V) {
            this.cache[key] = value
        }

        fun remove(key: T) = this.cache.remove(key)

        fun get(key: T) = this.cache[key]

        fun clear() = this.cache.clear()
    }

    companion object {
        private var cache: PerpetualCache<String, ByteArray> = PerpetualCache<String, ByteArray>()
    }

    override fun loadCert(keyAlias: String): ByteArray {
        cache.get(keyAlias)?.let {
            return it
        }
        val certificate = config.keystore.getCertificate(keyAlias)
        cache.set(keyAlias, certificate.encoded)
        return certificate.encoded
    }

    override fun sign(data: ByteArray, keyAlias: String): ByteArray {
        val privateKey = config.keystore.getKey(keyAlias, config.keystorePassword.toCharArray()) as PrivateKey
        val signature = Signature.getInstance("NONEwithRSA").apply {
            initSign(privateKey)
            update(data)
        }
        return signature.sign()
    }
}
