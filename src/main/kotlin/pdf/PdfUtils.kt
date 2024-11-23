package io.pongsakorn.sign

import org.apache.pdfbox.cos.COSArray
import org.apache.pdfbox.cos.COSDictionary
import org.apache.pdfbox.cos.COSName
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature

fun getMDPPermission(doc: PDDocument): Int {
    val permsDict = doc.documentCatalog.cosObject.getCOSDictionary(COSName.PERMS) ?: return 0
    val signatureDict = permsDict.getCOSDictionary(COSName.DOCMDP) ?: return 0
    val refArray = signatureDict.getCOSArray(COSName.REFERENCE) ?: return 0
    refArray.forEach { base ->
        (base is COSDictionary).let {
            val sigRefDict = base as COSDictionary
            if (sigRefDict.getDictionaryObject(COSName.TRANSFORM_METHOD) == COSName.DOCMDP) {
                val transformDict = sigRefDict.getDictionaryObject(COSName.TRANSFORM_PARAMS)
                if (transformDict is COSDictionary) {
                    var accessPermissions = transformDict.getInt(COSName.P, 2)
                    if (accessPermissions < 1 || accessPermissions > 3) accessPermissions = 2
                    return accessPermissions
                }
            }
        }

    }
    return 0
}

fun setMDPPermission(doc: PDDocument, signature: PDSignature, accessPermissions: Int){
    val sigDict = signature.cosObject
    // DocMDP specific stuff
    val transformParameters = COSDictionary().apply {
        setItem(COSName.TYPE, COSName.TRANSFORM_PARAMS)
        setInt(COSName.P, accessPermissions)
        setName(COSName.V, "1.2")
        setNeedToBeUpdated(true)
    }

    val referenceDict = COSDictionary().apply {
        setItem(COSName.TYPE, COSName.SIG_REF)
        setItem(COSName.TRANSFORM_METHOD, COSName.DOCMDP)
        setItem(COSName.DIGEST_METHOD, COSName.getPDFName("SHA1"))
        setItem(COSName.TRANSFORM_PARAMS, transformParameters)
        setNeedToBeUpdated(true)
    }


    val referenceArray =  COSArray().apply {
        add(referenceDict)
        setNeedToBeUpdated(true)

    }

    sigDict.setItem(COSName.REFERENCE, referenceArray)

    // Catalog
    val permsDict =  COSDictionary().apply {
        setItem(COSName.TYPE, COSName.PERMS)
        setNeedToBeUpdated(true)
    }

    doc.documentCatalog.cosObject.apply {
        setItem(COSName.PERMS, permsDict)
        setNeedToBeUpdated(true)
    }
}

