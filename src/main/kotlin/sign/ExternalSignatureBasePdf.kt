package sign

import io.pongsakorn.keystore.ExternalKeystoreInterface
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.cms.AttributeTable
import org.bouncycastle.asn1.ess.ESSCertIDv2
import org.bouncycastle.asn1.ess.SigningCertificateV2
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.Attribute
import org.bouncycastle.asn1.x509.DigestInfo
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator
import org.bouncycastle.cms.SignerInfoGenerator
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.security.MessageDigest
import java.security.cert.Certificate
import java.security.cert.X509Certificate

abstract class ExternalSignaturePdfBase(
    val externalKeystore: ExternalKeystoreInterface,
    val keyAlias: String, certAliasChain: Array<String>
) {

    private var certificateChain: List<Certificate>

    init {
        certificateChain = certAliasChain.map { alias ->
            val certBytes = externalKeystore.loadCert(alias)
            parseCertificate(certBytes)
        }
    }

    fun sign(contentToSign: ByteArray): ByteArray {

        // Create signed attributes and signing certificate chain
        val signedDataGenerator = createSignedDataGenerator(contentToSign)

        // Perform cryptographic signing
        val cmsProcessable = CMSProcessableByteArray(contentToSign)
        val signedData = signedDataGenerator.generate(cmsProcessable, false)

        return signedData.encoded
    }

    private fun parseCertificate(certBytes: ByteArray): Certificate {
        return java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(certBytes))
    }


    private fun createSignedDataGenerator(
        contentToSign: ByteArray
    ): CMSSignedDataGenerator {
        val gen = CMSSignedDataGenerator()
        val signingCert = certificateChain[0]

        // Create the signing certificate attributes
        val signingCertificateV2 = createSigningCertificateV2(signingCert)
        val attrTable = createAttributeTable(signingCertificateV2)

        // Create signer info generator
        val signerInfoGenerator = createSignerInfoGenerator(attrTable, signingCert, contentToSign)
        gen.addSignerInfoGenerator(signerInfoGenerator)

        // Add certificates to the generator
        val certStore = JcaCertStore(certificateChain)
        gen.addCertificates(certStore)

        return gen
    }

    private fun createSigningCertificateV2(signingCert: Certificate): SigningCertificateV2 {
        val certHash = if (signingCert is X509Certificate) {
            MessageDigest.getInstance("SHA-256").digest(signingCert.encoded)
        } else {
            MessageDigest.getInstance("SHA-256").digest()
        }

        val essCertIDv2 = ESSCertIDv2(
            AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256),
            certHash
        )

        return SigningCertificateV2(essCertIDv2)
    }

    private fun createAttributeTable(signingCertificateV2: SigningCertificateV2): AttributeTable {
        val attributes = ASN1EncodableVector().apply {
            add(Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2, DERSet(signingCertificateV2)))
        }

        return AttributeTable(attributes)
    }

    private fun createSignerInfoGenerator(
        attrTable: AttributeTable,
        signingCert: Certificate,
        contentToSign: ByteArray
    ): SignerInfoGenerator {
        val digestCalculatorProvider = JcaDigestCalculatorProviderBuilder().build()
        val attrGen = DefaultSignedAttributeTableGenerator(attrTable)
        val signerBuilder = JcaSignerInfoGeneratorBuilder(digestCalculatorProvider)
        signerBuilder.setSignedAttributeGenerator(attrGen)
        signerBuilder.setDirectSignature(true)

        // Hash content
        val contentHash = MessageDigest.getInstance("SHA-256").digest(contentToSign)
        val sha256Aid = AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE)
        val di = DigestInfo(sha256Aid, contentHash)
        val _hashBytes = di.toASN1Primitive().encoded

        // Sign the hash
        val signedHash = externalKeystore.sign(_hashBytes, keyAlias)

        // Create ContentSigner
        val contentSigner = createContentSigner(contentHash, signedHash)
        val certHolder = JcaX509CertificateHolder(signingCert as X509Certificate)

        return signerBuilder.build(contentSigner, certHolder)
    }

    private fun createContentSigner(hashBytes: ByteArray, signatureBytes: ByteArray): ContentSigner {
        return object : ContentSigner {
            private val outputStream = ByteArrayOutputStream()

            override fun getOutputStream(): OutputStream {
                outputStream.write(hashBytes)
                return outputStream
            }

            override fun getSignature(): ByteArray {
                return signatureBytes
            }

            override fun getAlgorithmIdentifier(): AlgorithmIdentifier {
                return AlgorithmIdentifier(ASN1ObjectIdentifier("1.2.840.113549.1.1.11")) // SHA-256 with RSA
            }
        }
    }
}
