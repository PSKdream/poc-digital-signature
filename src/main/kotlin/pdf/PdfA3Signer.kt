package pdf

import org.apache.pdfbox.Loader
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions
import sign.SignatureBase
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.KeyStore
import java.util.*

class PdfA3Signer(config: SignatureConfig) : SignatureBase(config) {

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

        val signatureOptions = SignatureOptions().apply {
            preferredSignatureSize = 2048
        }

        document.addSignature(signature, this, signatureOptions)
        document.saveIncremental(FileOutputStream(outputPath))
        document.close()
    }

}


fun main() {


    // Configuration
    val config = SignatureBase.SignatureConfig(
        keystore = KeyStore.getInstance("PKCS12").apply {
            load(
                FileInputStream("./keystore.p12"),
                "dream123".toCharArray()
            )
        },
        keystorePassword = "dream123",
        keyAlias = "pdf_signer"
    )

    val signer = PdfA3Signer(config)

    // Create and sign document
    signer.signPdf("document.pdf", "signed_document_A3.pdf", true)
}
