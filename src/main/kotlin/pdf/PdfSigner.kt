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

class PdfSigner(config: SignatureConfig) : SignatureBase(config) {

    fun signPdf(inputPath: String, outputPath: String) {
        val document = Loader.loadPDF(File(inputPath))
        val signature = PDSignature().apply {
            setFilter(PDSignature.FILTER_ADOBE_PPKLITE)
            setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED)
            name = "Example User"
            location = "Los Angeles, CA"
            reason = "Testing"
            signDate = Calendar.getInstance()
        }

        val signatureOptions = SignatureOptions().apply {
            preferredSignatureSize = 2048
        }

        document.addSignature(signature, this, signatureOptions)
        document.saveIncremental(FileOutputStream(outputPath))
        document.close()
    }

}


fun main(){


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

    val signer = PdfSigner(config)

    // Create and sign document
    signer.signPdf("document.pdf", "signed_document.pdf")
}
