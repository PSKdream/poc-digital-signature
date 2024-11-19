package sign

import org.apache.pdfbox.examples.signature.ValidationTimeStamp
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import java.io.InputStream
import java.security.PrivateKey
import java.security.cert.Certificate
import java.security.cert.X509Certificate

abstract class SignatureBase(
    config: SignatureConfig
) : SignatureInterface {

    private lateinit var privateKey: PrivateKey
    private lateinit var certificateChain: Array<Certificate>
    private var tsaUrl: String? = null

    init {
        privateKey = config.keystore.getKey(config.keyAlias, config.keystorePassword.toCharArray()) as PrivateKey
        certificateChain = config.keystore.getCertificateChain(config.keyAlias)
    }

    fun setTsaUrl(tsaUrl: String) {
        this.tsaUrl = tsaUrl
    }

    override fun sign(content: InputStream): ByteArray {
        val gen = CMSSignedDataGenerator()
        val cert = certificateChain[0] as X509Certificate
        val sha1Signer = JcaContentSignerBuilder("SHA1withRSA").build(privateKey)

        gen.addSignerInfoGenerator(
            JcaSignerInfoGeneratorBuilder(JcaDigestCalculatorProviderBuilder().build()).build(
                sha1Signer,
                cert
            )
        )
        gen.addCertificates(JcaCertStore(certificateChain.asList()))

        val msg = CMSProcessableByteArray(content.readBytes())
        var signedData: CMSSignedData = gen.generate(msg, false)

        if (!tsaUrl.isNullOrEmpty()) {
            val validation = ValidationTimeStamp(tsaUrl)
            signedData = validation.addSignedTimeStamp(signedData)
        }

        return signedData.encoded
    }

}
