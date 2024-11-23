package io.pongsakorn.keystore

interface ExternalKeystoreInterface {
    fun loadCert(keyAlias: String): ByteArray

    fun sign(data: ByteArray, keyAlias: String): ByteArray
}
