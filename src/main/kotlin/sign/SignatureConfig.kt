package sign

import java.security.KeyStore

data class SignatureConfig(
    val keystore: KeyStore,
    val keystorePassword: String,
    val keyAlias: String,
)
