package keystore

import io.pongsakorn.keystore.ExternalKeystoreInterface

class HSMKeyStore: ExternalKeystoreInterface {
    override fun loadCert(keyAlias: String): ByteArray {
        TODO("Not yet implemented")
    }

    override fun sign(data: ByteArray, keyAlias: String): ByteArray {
        TODO("Not yet implemented")
    }
}
