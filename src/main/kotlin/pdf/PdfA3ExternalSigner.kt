package io.pongsakorn.pdf

import io.pongsakorn.sign.getMDPPermission
import io.pongsakorn.sign.setMDPPermission
import org.apache.pdfbox.Loader
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature
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
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedData
import pdf.PdfToA3Converter
import sign.SignatureConfig
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.util.*
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import java.io.*
import org.bouncycastle.asn1.x509.Attribute
import org.bouncycastle.asn1.x509.DigestInfo
import java.security.MessageDigest
import java.security.cert.Certificate
import java.security.cert.X509Certificate

class ExternalKeystore(val config: SignatureConfig) {

    fun externalLoadCert(): ByteArray {
        val certificate = config.keystore.getCertificate(config.keyAlias)
        return certificate.encoded
    }

//    fun externalLoadCert(): Certificate {
//        val certificate = config.keystore.getCertificate(config.keyAlias)
//        return certificate
//    }

    fun externalSigning(externalSigningContent: ByteArray): ByteArray {
        val privateKey = config.keystore.getKey(config.keyAlias, config.keystorePassword.toCharArray()) as PrivateKey
        val signedData = Signature.getInstance("NONEwithRSA").apply {
            initSign(privateKey)
            update(externalSigningContent)
        }.sign()
        return signedData
    }

}




class PdfA3Signer {

    val config = SignatureConfig(
        keystore = KeyStore.getInstance("PKCS12").apply {
            load(
                FileInputStream("./keystore.p12"),
                "dream123".toCharArray()
            )
        },
        keystorePassword = "dream123",
        keyAlias = "pdf_signer"
    )

    fun signPdf(inputPath: String, outputPath: String, docClose: Boolean = false) {


        val document = Loader.loadPDF(File(inputPath))

        // Check permission PDF
        val accessPermissions = getMDPPermission(document)
        if (accessPermissions == 1) {
            throw IllegalStateException("No changes to the document are permitted due to DocMDP transform parameters dictionary")
        }


        val xmlContent = """
        <?xml version="1.0" encoding="UTF-8"?>
        <root>
            <data>
                <name>Attachment</name>
                <value>Attachment content</value>
            </data>
        </root>
    """.trimIndent()
        PdfToA3Converter().convertToPdfA3(document, xmlContent.toByteArray(), "attachment.xml")

        val signature = PDSignature().apply {
            setFilter(PDSignature.FILTER_ADOBE_PPKLITE)
            setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED)
            name = "Example User"
            location = "Los Angeles, CA"
            reason = "Testing"
            signDate = Calendar.getInstance()
        }

        if (accessPermissions == 0 && docClose)
            setMDPPermission(document, signature, 2)


        document.addSignature(signature)
        val result = ByteArrayOutputStream()

        val externalSigning: ExternalSigningSupport = document.saveIncrementalForExternalSigning(result)
        val externalSigningContent = externalSigning.content
        val externalSigningContentBytes = externalSigningContent.readBytes()
        val cmsSignature = externalSigning(externalSigningContentBytes)
        externalSigning.setSignature(cmsSignature)

        File(outputPath).outputStream().use {
            it.write(result.toByteArray())
        }

        document.close()
    }


    fun externalSigning(externalSigningContent: ByteArray): ByteArray? {
        class ContentSigner(val hashBytes: ByteArray, val signatureSign: ByteArray) :
            org.bouncycastle.operator.ContentSigner {
            override fun getSignature(): ByteArray {
                return signatureSign
            }

            override fun getOutputStream(): ByteArrayOutputStream {
                val byteArrayOutputStream = ByteArrayOutputStream()
                byteArrayOutputStream.write(hashBytes)
                return byteArrayOutputStream
            }

            override fun getAlgorithmIdentifier(): AlgorithmIdentifier {
                return AlgorithmIdentifier(ASN1ObjectIdentifier("1.2.840.113549.1.1.11"))
            }
        }

        val externalKeystore = ExternalKeystore(config)

        val certBytes = externalKeystore.externalLoadCert()
        val cert: Certificate = java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(certBytes))
        val gen = CMSSignedDataGenerator()


        val certid = ESSCertIDv2(
            AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256),
            if (cert is X509Certificate) MessageDigest.getInstance("SHA-256").digest(cert.encoded)
            else MessageDigest.getInstance("SHA-256").digest()
        )
        val sigCert = SigningCertificateV2(certid)
        val attr = Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2, DERSet(sigCert))

        // Set Attribute Table
        val v = ASN1EncodableVector()
        v.add(attr)
        val attributeTable = AttributeTable(v)
        val attrGen = DefaultSignedAttributeTableGenerator(attributeTable)

        // Set Signer Info
        val sigb = JcaSignerInfoGeneratorBuilder(JcaDigestCalculatorProviderBuilder().build())
        sigb.setSignedAttributeGenerator(attrGen)
        sigb.setDirectSignature(true)

        val certX509 = org.bouncycastle.asn1.x509.Certificate.getInstance(certBytes)
        val X509CertHolder = X509CertificateHolder(certX509)

        // Hash Data sign
        val digest = MessageDigest.getInstance("SHA-256")
        val hashBytes = digest.digest(externalSigningContent)
        val sha256Aid = AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE)
        val di = DigestInfo(sha256Aid, hashBytes)
        val _hashBytes = di.toASN1Primitive().encoded

        val signatureSign = externalKeystore.externalSigning(_hashBytes)

        val nonSigner_signedHashProvided = ContentSigner(hashBytes, signatureSign)

        gen.addSignerInfoGenerator(sigb.build(nonSigner_signedHashProvided, X509CertHolder))

        val certList = ArrayList<Certificate>()
        certList.add(cert)
        gen.addCertificates(JcaCertStore(certList))


        // Set Certificate Holder
        gen.addCertificate(X509CertHolder)


        val msg = CMSProcessableByteArray(externalSigningContent)
        val signedData: CMSSignedData = gen.generate(msg, false)
        return signedData.getEncoded()
    }


}


fun main() {


    // Configuration
    val signer = PdfA3Signer()

    // Create and sign document
    signer.signPdf("document.pdf", "signed_document_A3_external.pdf", true)
}
