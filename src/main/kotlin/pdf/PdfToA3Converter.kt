package pdf

import org.apache.pdfbox.Loader
import org.apache.pdfbox.cos.COSArray
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.PDDocumentNameDictionary
import org.apache.pdfbox.pdmodel.PDEmbeddedFilesNameTreeNode
import org.apache.pdfbox.pdmodel.common.PDMetadata
import org.apache.pdfbox.pdmodel.common.filespecification.PDComplexFileSpecification
import org.apache.pdfbox.pdmodel.common.filespecification.PDEmbeddedFile
import org.apache.pdfbox.pdmodel.graphics.color.PDOutputIntent
import org.apache.xmpbox.XMPMetadata
import org.apache.xmpbox.type.BadFieldValueException
import org.apache.xmpbox.xml.XmpSerializer
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.*


class PdfToA3Converter {
    companion object {
        private const val SRGB_ICC_PROFILE = "/sRGB_CS_profile.icm" // You need to provide this ICC profile
    }

    fun convertToPdfA3(document: PDDocument, attachmentByte: ByteArray, attachmentFileName: String) {

        // Set up PDF/A-3b metadata
        val catalog = document.documentCatalog
        val xmp = XMPMetadata.createXMPMetadata()

        try {
            // Add PDF/A identification schema
            val pdfaSchema = xmp.createAndAddPDFAIdentificationSchema()
            pdfaSchema.part = 3
            pdfaSchema.conformance = "B"

            // Add basic Dublin Core schema
            val dcSchema = xmp.createAndAddDublinCoreSchema().apply {
                title = "Title"
                addCreator("Creator")
                addDate(Calendar.getInstance())
            }
            // Add basic XMP schema
            val xmpBasicSchema = xmp.createAndAddXMPBasicSchema().apply {
                createDate = Calendar.getInstance()
                modifyDate = Calendar.getInstance()
                creatorTool = "PDF/A-3 Converter"
            }

            // Add PDF/A extension schema
            val pdfSchema = xmp.createAndAddAdobePDFSchema()
            pdfSchema.producer = "Apache PDFBox 3.0"
            pdfSchema.pdfVersion = "2.0"

            // Serialize metadata
            val serializer = XmpSerializer()
            val baos = ByteArrayOutputStream()
            serializer.serialize(xmp, baos, true)

            // Set metadata in document
            val metadata = PDMetadata(document)
            metadata.importXMPMetadata(baos.toByteArray())
            catalog.metadata = metadata


            val colorProfile = javaClass.getResourceAsStream(SRGB_ICC_PROFILE)
                ?: throw IllegalStateException("ICC profile not found")

            val intent = PDOutputIntent(document, colorProfile)
            intent.info = "sRGB IEC61966-2.1"
            intent.outputCondition = "sRGB IEC61966-2.1"
            intent.outputConditionIdentifier = "sRGB IEC61966-2.1"
            intent.registryName = "http://www.color.org"
            catalog.addOutputIntent(intent)

            // Add attachment if provided
            attachFile(document, attachmentByte, attachmentFileName)
        } catch (e: BadFieldValueException) {
            throw RuntimeException("Error converting to PDF/A-3", e)
        }

    }

    fun attachFile(doc: PDDocument, embbedFileByteXML: ByteArray, getDocumentFileName: String) {
        val efTree = PDEmbeddedFilesNameTreeNode()

        val fs = PDComplexFileSpecification()
        fs.setFile(getDocumentFileName)
        val dict = fs.cosObject

        // Relation "Source" for linking with eg. catalog
        dict.setString("AFRelationship", "Alternative")
        dict.setString("UF", getDocumentFileName)
        val _is = ByteArrayInputStream(embbedFileByteXML)
        val ef = PDEmbeddedFile(doc, _is).apply {
            modDate = GregorianCalendar()
            creationDate = GregorianCalendar()
            size = embbedFileByteXML.size
        }

        fs.setEmbeddedFile(ef)

        // now add the entry to the embedded file tree and set in the document.
        efTree.setNames(Collections.singletonMap(getDocumentFileName, fs))

        // attachments are stored as part of the "names" dictionary in the
        val catalog = doc.documentCatalog
        val names = PDDocumentNameDictionary(doc.documentCatalog)
        names.setEmbeddedFiles(efTree)
        catalog.setNames(names)
        val dict2 = catalog.cosObject
        val array = COSArray()
        array.add(fs.cosObject)
        dict2.setItem("AF", array)
    }
}


fun main() {
    val pdfToA3Converter = PdfToA3Converter()
    val document = Loader.loadPDF(File("document.pdf"))

    val xmlContent = """
        <?xml version="1.0" encoding="UTF-8"?>
        <root>
            <data>
                <name>Attachment</name>
                <value>Attachment content</value>
            </data>
        </root>
    """.trimIndent()

    pdfToA3Converter.convertToPdfA3(document, xmlContent.toByteArray(), "attachment.xml")
    document.save("converted_document.pdf")
    document.close()
}
