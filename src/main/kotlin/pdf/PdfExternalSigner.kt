package pdf

import io.pongsakorn.keystore.ExternalKeystoreInterface
import io.pongsakorn.keystore.PKCSKeyStore
import sign.ExternalSignaturePdfBase
import pdf.facade.getMDPPermission
import pdf.facade.setMDPPermission
import org.apache.pdfbox.Loader
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature
import java.security.KeyStore
import java.util.*
import java.io.*


class PdfExternalSigner(externalKeystore: ExternalKeystoreInterface, keyAlias: String, certAliasChain: Array<String>) :
    ExternalSignaturePdfBase(externalKeystore, keyAlias, certAliasChain) {

    fun signPdf(document: PDDocument, docClose: Boolean = false): ByteArray {

        // Check PDF permissions
        val accessPermissions = getMDPPermission(document)
        validatePermissions(accessPermissions)


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
            setMDPPermission(document, signature, 2)

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
}


fun main() {


    // Configuration
    val keystore = PKCSKeyStore(
        PKCSKeyStore.KeystoreConfig(
            keystore = KeyStore.getInstance("PKCS12").apply {
                load(
                    FileInputStream("./intermediateca.jks"),
                    "password".toCharArray()
                )
            },
            keystorePassword = "password",
        )
    )
    val signer = PdfExternalSigner(
        keystore,
        "intermediateca",
        arrayOf("intermediateca", "rootca")
    )

    // Create and sign document
    val document = Loader.loadPDF(File("document.pdf"))

    val documentWithSigning = signer.signPdf(document, true)

    File("signed_document_A3_external.pdf").outputStream().use {
        it.write(documentWithSigning)
    }
}
