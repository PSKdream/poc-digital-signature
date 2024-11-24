import java.io.FileInputStream
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import javax.xml.crypto.dsig.*
import javax.xml.crypto.dsig.dom.DOMSignContext
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec
import javax.xml.crypto.dsig.spec.TransformParameterSpec
import javax.xml.parsers.DocumentBuilderFactory
import java.io.ByteArrayInputStream
import java.io.StringWriter
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult

class XmlSignature {
    companion object {
        private const val KEYSTORE_TYPE = "PKCS12"
        private const val KEYSTORE_FILE = "keystore.p12"
        private const val KEYSTORE_PASSWORD = "dream123"
        private const val KEY_ALIAS = "pdf_signer"
    }

    // Load the KeyStore
    private fun loadKeyStore(): KeyStore {
        val keyStore = KeyStore.getInstance(KEYSTORE_TYPE)
        FileInputStream(KEYSTORE_FILE).use { fis ->
            keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray())
        }
        return keyStore
    }

    // Get private key from KeyStore
    private fun getPrivateKey(keyStore: KeyStore): PrivateKey {
        return keyStore.getKey(KEY_ALIAS, KEYSTORE_PASSWORD.toCharArray()) as PrivateKey
    }

    // Get certificate from KeyStore
    private fun getCertificate(keyStore: KeyStore): X509Certificate {
        return keyStore.getCertificate(KEY_ALIAS) as X509Certificate
    }

    // Sign XML using KeyStore credentials
    fun signXmlWithKeyStore(xmlContent: String): String {
        // Load KeyStore
        val keyStore = loadKeyStore()
        val privateKey = getPrivateKey(keyStore)
        val certificate = getCertificate(keyStore)

        // Parse XML document
        val dbf = DocumentBuilderFactory.newInstance().apply {
            isNamespaceAware = true
        }
        val doc = dbf.newDocumentBuilder().parse(ByteArrayInputStream(xmlContent.toByteArray()))

        // Create XML signature factory
        val fac = XMLSignatureFactory.getInstance("DOM")

        // Create reference
        val ref = fac.newReference(
            "",
            fac.newDigestMethod(DigestMethod.SHA256, null),
            listOf(
                fac.newTransform(
                    Transform.ENVELOPED,
                    null as TransformParameterSpec?
                )
            ),
            null,
            null
        )

        // Create SignedInfo
        val si = fac.newSignedInfo(
            fac.newCanonicalizationMethod(
                CanonicalizationMethod.INCLUSIVE,
                null as C14NMethodParameterSpec?
            ),
            fac.newSignatureMethod(SignatureMethod.RSA_SHA256, null),
            listOf(ref)
        )

        // Create KeyInfo with X509Data
        val kif = fac.keyInfoFactory
        val x509Content = kif.newX509Data(listOf(certificate))
        val keyInfo = kif.newKeyInfo(listOf(x509Content))

        // Create signature
        val signature = fac.newXMLSignature(si, keyInfo)

        // Sign the document
        val signContext = DOMSignContext(privateKey, doc.documentElement)
        signature.sign(signContext)

        // Convert signed document to string
        val transformerFactory = TransformerFactory.newInstance()
        val transformer = transformerFactory.newTransformer()
        val writer = StringWriter()
        transformer.transform(DOMSource(doc), StreamResult(writer))
        
        return writer.toString()
    }
}

fun main() {
    val signer = XmlSignature()
    val xmlContent = """
            <?xml version="1.0" encoding="UTF-8"?>
            <purchase>
                <item>Laptop</item>
                <price>999.99</price>
                <currency>USD</currency>
            </purchase>
        """.trimIndent()

    try {
        val signedXml = signer.signXmlWithKeyStore(xmlContent)
        println("Signed XML:")
        println(signedXml)
    } catch (e: Exception) {
        println("Error signing XML: ${e.message}")
        e.printStackTrace()
    }
}
