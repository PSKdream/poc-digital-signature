import io.pongsakorn.keystore.ExternalKeystoreInterface
import io.pongsakorn.keystore.PKCSKeyStore
import org.apache.pdfbox.Loader
import org.apache.pdfbox.cos.COSName
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.PDPage
import org.apache.pdfbox.pdmodel.PDPageContentStream
import org.apache.pdfbox.pdmodel.PDResources
import org.apache.pdfbox.pdmodel.common.PDRectangle
import org.apache.pdfbox.pdmodel.common.PDStream
import org.apache.pdfbox.pdmodel.graphics.form.PDFormXObject
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField
import org.apache.pdfbox.util.Matrix
import sign.PdfExternalSignatureBase
import java.awt.geom.AffineTransform
import java.awt.geom.Rectangle2D
import java.io.*
import java.security.KeyStore
import java.util.Calendar
import java.util.GregorianCalendar
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

class VisualSigner(externalKeystore: ExternalKeystoreInterface, keyAlias: String, certAliasChain: Array<String>) :
    PdfExternalSignatureBase(externalKeystore, keyAlias, certAliasChain) {
    @Throws(IOException::class)
    fun addVisibleSignatureToPdf(
        signaturePath: String,
        document: PDDocument,
        humanRect: Rectangle2D = Rectangle2D.Float(20f, 10f, 200f, 100f)
    ): ByteArray {
        val signatureImage = File(signaturePath).readBytes()

        val signature = PDSignature().apply {
            setFilter(PDSignature.FILTER_ADOBE_PPKLITE)
            setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED)
            signDate = Calendar.getInstance()
        }

        // The code for visible signature starts here
        val pageNum = 0 // Page numbering starts from zero.

        val rect = createSignatureRectangle(document, humanRect)

        val options = SignatureOptions().apply {
            preferredSignatureSize = SignatureOptions.DEFAULT_SIGNATURE_SIZE
            page = pageNum
            setVisualSignature(
                createVisualSignatureTemplate(
                    document,
                    pageNum,
                    rect,
                    signatureImage
                )
            )
        }
        document.addSignature(signature, options)

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

    private fun createSignatureRectangle(doc: PDDocument, humanRect: Rectangle2D): PDRectangle {
        val x = humanRect.x.toFloat()
        val y = humanRect.y.toFloat()
        val width = humanRect.width.toFloat()
        val height = humanRect.height.toFloat()
        val page = doc.getPage(0)
        val pageRect = page.cropBox
        val rect = PDRectangle()

        when (page.rotation) {
            90 -> {
                rect.lowerLeftX = pageRect.width - y - height
                rect.upperRightX = pageRect.width - y
                rect.lowerLeftY = x
                rect.upperRightY = x + width
            }

            180 -> {
                rect.lowerLeftX = pageRect.width - x - width
                rect.upperRightX = pageRect.width - x
                rect.lowerLeftY = pageRect.height - y - height
                rect.upperRightY = pageRect.height - y
            }

            270 -> {
                rect.lowerLeftX = y
                rect.upperRightX = y + height
                rect.lowerLeftY = pageRect.height - x - width
                rect.upperRightY = pageRect.height - x
            }

            0 -> {
                rect.lowerLeftX = x
                rect.upperRightX = x + width
                rect.lowerLeftY = y
                rect.upperRightY = y + height
            }

            else -> {
                rect.lowerLeftX = x
                rect.upperRightX = x + width
                rect.lowerLeftY = y
                rect.upperRightY = y + height
            }
        }
        return rect
    }

    // Create a template PDF document with empty signature and return it as a stream.
    @OptIn(ExperimentalEncodingApi::class)
    @Throws(IOException::class)
    private fun createVisualSignatureTemplate(
        srcDoc: PDDocument,
        pageNum: Int,
        rect: PDRectangle,
        imageByte: ByteArray
    ): InputStream {
        PDDocument().use { doc ->
            val page = PDPage(srcDoc.getPage(pageNum).mediaBox)
            doc.addPage(page)
            val acroForm = PDAcroForm(doc)
            doc.documentCatalog.acroForm = acroForm
            val signatureField = PDSignatureField(acroForm)
            val widget = signatureField.widgets[0]
            val acroFormFields = acroForm.fields
            acroForm.isSignaturesExist = true
            acroForm.isAppendOnly = true
            acroForm.cosObject.isDirect = true
            acroFormFields.add(signatureField)

            widget.rectangle = rect

            // from PDVisualSigBuilder.createHolderForm()
            val stream = PDStream(doc)
            val form = PDFormXObject(stream)
            val res = PDResources()
            form.resources = res
            form.formType = 1
            val bbox = PDRectangle(rect.width, rect.height)
            var initialScale: Matrix? = null
            val pageRotation = srcDoc.getPage(0).rotation
            when (pageRotation) {
                90 -> {
                    form.setMatrix(AffineTransform.getQuadrantRotateInstance(1))
                    initialScale =
                        Matrix.getScaleInstance(bbox.width / bbox.height, bbox.height / bbox.width)
                }

                180 -> form.setMatrix(AffineTransform.getQuadrantRotateInstance(2))
                270 -> {
                    form.setMatrix(AffineTransform.getQuadrantRotateInstance(3))
                    initialScale =
                        Matrix.getScaleInstance(bbox.width / bbox.height, bbox.height / bbox.width)
                }

                else -> {}
            }
            form.bBox = bbox

            // From PDVisualSigBuilder.createAppearanceDictionary()
            val appearance = PDAppearanceDictionary()
            appearance.cosObject.isDirect = true
            val appearanceStream = PDAppearanceStream(form.cosObject)
            appearance.setNormalAppearance(appearanceStream)
            widget.appearance = appearance

            PDPageContentStream(doc, appearanceStream).use { cs ->
                if (initialScale != null) {
                    cs.transform(initialScale)
                }
                if (imageByte != null) {
                    val image: ByteArray = imageByte
                    cs.saveGraphicsState()
                    val img = PDImageXObject.createFromByteArray(doc, image, "signature.png")

                    var imageWidth = bbox.width
                    var imageHeight = bbox.height
                    if (pageRotation == 90 || pageRotation == 270) {
                        imageWidth = bbox.height
                        imageHeight = bbox.width
                    }
                    cs.drawImage(img, 0f, 0f, imageWidth, imageHeight)
                    cs.restoreGraphicsState()
                }
            }
            val baos: ByteArrayOutputStream = ByteArrayOutputStream()
            doc.save(baos)
            return ByteArrayInputStream(baos.toByteArray())
        }
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

    val document = Loader.loadPDF(File("document.pdf"))

    var signer = VisualSigner(
        keystore,
        "intermediateca",
        arrayOf("intermediateca", "rootca")
    )
    val doc1 = signer.addVisibleSignatureToPdf(
        "signature.jpeg",
        document,
        Rectangle2D.Float(220f, 120f, 200f, 100f)
    )

    signer = VisualSigner(
        keystore,
        "pdf_signer",
        arrayOf("pdf_signer")
    )

    val doc2 = signer.addVisibleSignatureToPdf(
        "signature2.jpeg",
        Loader.loadPDF(doc1)
    )

    File("signed_document.pdf").outputStream().use {
        it.write(doc2)
    }

}
