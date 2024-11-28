package pdf

import io.pongsakorn.keystore.ExternalKeystoreInterface
import io.pongsakorn.keystore.PKCSKeyStore
import sign.PdfExternalSignatureBase
import pdf.facade.getMDPPermission
import pdf.facade.setMDPPermission
import org.apache.pdfbox.Loader
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature
import pdf.facade.PdfToA3Converter
import java.security.KeyStore
import java.util.*
import java.io.*


class PdfA3Signer(externalKeystore: ExternalKeystoreInterface, keyAlias: String, certAliasChain: Array<String>) :
    PdfExternalSignatureBase(externalKeystore, keyAlias, certAliasChain) {

    fun signPdf(document: PDDocument, xmlContent: String, docClose: Boolean = false): ByteArray {

        // Check PDF permissions
        val accessPermissions = getMDPPermission(document)
        println(accessPermissions)
        validatePermissions(accessPermissions)

        // Convert document to PDF/A-3 and attach XML metadata
        convertToPdfA3(document, xmlContent)

        val signature = PDSignature().apply {
            setFilter(PDSignature.FILTER_ADOBE_PPKLITE)
            setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED)
            name = "Example User"
            location = "Los Angeles, CA"
            reason = "Testing"
            signDate = Calendar.getInstance()
        }

        // Optionally set permissions to restrict future changes
        if (accessPermissions == 0 && docClose)
            setMDPPermission(document, signature, 1)
//            setMDPPermission(document, signature, 2)

        // Add the signature to the document
        document.addSignature(signature)

        // Perform incremental external signing
        val signedPdfBytes = performExternalSigning(document)

        document.close()

        return signedPdfBytes
    }

    private fun performExternalSigning(document: PDDocument): ByteArray {
        val result = ByteArrayOutputStream()

        // Prepare for external signing
        val externalSigningSupport = document.saveIncrementalForExternalSigning(result)
        val unsignedContent = externalSigningSupport.content.readBytes()

        // Generate CMS signature
        val cmsSignature = sign(unsignedContent)

        // Set the signature
        externalSigningSupport.setSignature(cmsSignature)

        return result.toByteArray()
    }

    private fun validatePermissions(accessPermissions: Int) {
        if (accessPermissions == 1) {
            throw IllegalStateException("No changes to the document are permitted due to DocMDP transform parameters dictionary")
        }
    }

    private fun convertToPdfA3(document: PDDocument, xmlContent: String) {
        val xmlBytes = xmlContent.toByteArray()
        PdfToA3Converter().convertToPdfA3(document, xmlBytes, "attachment.xml")
    }

}


fun main() {


    // Configuration
    val keystore = PKCSKeyStore(
        PKCSKeyStore.KeystoreConfig(
            keystore = KeyStore.getInstance("PKCS12").apply {
                load(
                    FileInputStream("./intermediateca.p12"),
                    "password".toCharArray()
                )
            },
            keystorePassword = "password",
        )
    )
    val signer = PdfA3Signer(
        keystore,
        "intermediateca",
        arrayOf("intermediateca", "rootca")
    )

    val xmlContent = """
        <?xml version="1.0" encoding="UTF-8"?>
        <root>
            <data>
                <name>Attachment</name>
                <value>Attachment content</value>
            </data>
        </root>
    """.trimIndent()

    // Create and sign document
    val document = Loader.loadPDF(File("signed_document_A3_external.pdf"))

    val documentWithSigning = signer.signPdf(document, xmlContent, true)

    File("signed_document_A3_external2.pdf").outputStream().use {
        it.write(documentWithSigning)
    }
}
