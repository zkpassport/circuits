import { Binary } from "@/lib/binary"
import { ASN } from "./asn"
import { AsnConvert, AsnParser, AsnSerializer } from "@peculiar/asn1-schema"
import { decodeOID, getHashAlgorithmName, getOIDName } from "./oids"
import { inspect } from "util"

export type DigestAlgorithm = "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512"
export type SignatureAlgorithm =
  | "rsaEncryption"
  | "rsassa-pss"
  | "P256"
  | "P384"
  | "P521"
  | "BrainpoolP160r1"
  | "BrainpoolP160t1"
  | "BrainpoolP192r1"
  | "BrainpoolP192t1"
  | "BrainpoolP224r1"
  | "BrainpoolP224t1"
  | "BrainpoolP256r1"
  | "BrainpoolP256t1"
  | "BrainpoolP320r1"
  | "BrainpoolP320t1"
  | "BrainpoolP384r1"
  | "BrainpoolP384t1"
  | "BrainpoolP512r1"
  | "BrainpoolP512t1"

export class DataGroupHashValues {
  public values: { [key: number]: Binary }

  constructor(values: { [key: number]: Binary }) {
    this.values = values
  }

  [inspect.custom](): Map<number, Binary> {
    return new Map(Object.entries(this.values).map(([key, value]) => [Number(key), value]))
  }
}

// The Document Security Object (SOD) is implemented as a SignedData type as specified in Cryptographic Message Syntax (CMS) [RFC 3369]
export class SODSignedData {
  // CMS version of the SOD
  // 0=v0, 1=v1, 2=v2, 3=v3, 4=v4, 5=v5
  version: number

  // Lists all the hash algorithms used in the SOD
  // These are the hash algorithms needed to verify the integrity of the passport
  // Includes the algorithms used to hash the:
  // - Data groups DG1-DG16 (hash algorithm specified at SOD.encapContentInfo.eContent.hashAlgorithm)
  // - SOD.encapContentInfo.eContent structure
  // - SOD.signerInfo.signedAttrs structure
  digestAlgorithms: DigestAlgorithm[]

  // Encapsulates the content that is being signed
  // For passports this is the hash of the data groups and the hash algorithm used to hash them
  encapContentInfo: {
    // The OID specifying the content type for eContent
    // Should always be mRTDSignatureData (2.23.136.1.1.1)
    // Corresponds with the value at SOD.signerInfo.signedAttrs.contentType
    eContentType: string
    // The encapsulated content
    // For ePassports this is ASN type LDSSecurityObject
    // Contains the concatenated hashes of the ePassport data groups
    eContent: {
      // LDSSecurityObject version: v0(0), v1(1)
      version: number
      // Hash algorithm used to hash the data groups
      hashAlgorithm: DigestAlgorithm
      // Mapping of data group numbers to their corresponding hash values
      dataGroupHashValues: DataGroupHashValues
      // The bytes of eContent
      bytes: Binary
    }
  }

  // Contains the signedAttrs region that is signed by the DSC (Document Signing Certificate)
  // Includes information about the signer, and the hashing and signing algorithms used for signing
  signerInfo: {
    // The CMS version of the signerInfo: v0(0), v1(1), v2(2), v3(3), v4(4), v5(5)
    version: number
    // The signedAttrs region that the DSC signs over
    // The resulting signature is stored at SOD.signerInfo.signature
    signedAttrs: {
      // The OID specifying the content type being signed
      // Should always be mRTDSignatureData (2.23.136.1.1.1)
      // Corresponds to eContent and is the same value as SOD.encapContentInfo.eContentType
      contentType: string
      // Hash of SOD.encapContentInfo.eContent using the SOD.signerInfo.digestAlgorithm hash algorithm
      messageDigest: Binary
      // Time the signature was created by the DSC
      signingTime?: Date
      // The bytes of signedAttrs
      bytes: Binary
    }
    // The hash algorithm used to produce the hash value over eContent and signedAttrs (e.g. sha256)
    // The resulting hash of eContent is stored at SOD.signerInfo.signedAttrs.messageDigest
    // The hashing algorithm used for signedAttrs will actually be the signatureAlgorithm specified at
    // SOD.signerInfo.signatureAlgorithm (e.g. sha256WithRSAEncryption) and should be used instead for hashing signedAttrs
    digestAlgorithm: DigestAlgorithm
    // The hash and signature algorithm used by the DSC to sign the signedAttrs (e.g. sha256WithRSAEncryption)
    signatureAlgorithm: {
      name: SignatureAlgorithm
      parameters?: Binary
    }
    // The signature over the signedAttrs by the DSC using SOD.signerInfo.signatureAlgorithm
    signature: Binary
    // Signer identifier used to identify the signer (the DSC)
    // Can be based on issuer and serial number, or subject key identifier
    sid: {
      // Distinguished name and serial number of the CSC that issued this TBS certificate
      issuerAndSerialNumber?: {
        // Distinguished name of the issuer of the DSC (Matches the subject field of the CSC)
        issuer: string
        // The serial number of the CSC
        serialNumber: Binary
      }
      // Subject Key Identifier
      // An alternative identifier derived from the signer's (the CSC) public key
      // TODO: Consider removing this field
      subjectKeyIdentifier?: string
    }
  }

  // The DSC (Document Signing Certificate) that is signed by the CSC (Country Signing Certificate)
  certificate: {
    // TBS (To-Be-Signed) certificate
    // The region of the DSC signed by the CSC
    tbs: {
      // Version of this TBS certificate
      // Specifies certificate format and types of fields/extensions supported
      version: number
      // The serial number of this TBS certificate, which uniquely identifies it within the issuing authority
      serialNumber: Binary

      // Hash and signature algorithm used by the CSC to sign this TBS certificate (e.g. sha256WithRSAEncryption)
      // Actual signature is stored at SOD.certificate.signature
      // This field is the same as the SOD.certificate.signatureAlgorithm field
      // While in most cases the two fields will match, it is possible they may not, indicating a malformed or tampered certificate
      // This field should be ignored, because the SOD.certificate.signatureAlgorithm field indicates which algorithm the CSC decided to use
      // TODO: Consider removing this field
      signatureAlgorithm: {
        name: SignatureAlgorithm
        parameters?: Binary
      }

      // Distinguished name of the issuer of this TBS certificate (Matches the subject field of the CSC)
      issuer: string
      // Validity period of the TBS certificate, indicating the dates during which it is valid
      validity: { notBefore: Date; notAfter: Date }
      // Distinguished name of this TBS certificate (DSC)
      subject: string

      // Info about the DSC public key
      subjectPublicKeyInfo: {
        // Type of public key (e.g. rsaEncryption, ecPublicKey)
        signatureAlgorithm: {
          name: SignatureAlgorithm
          parameters?: Binary
        }
        // The DSC public key
        subjectPublicKey: Binary
      }
      // Optional set of extensions providing additional information or capabilities for the TBS certificate
      // e.g. authorityKeyIdentifier, subjectKeyIdentifier, privateKeyUsagePeriod, cRLDistributionPoints, subjectAltName, documentTypeList, keyUsage, issuerAltName
      // extensions?: { id: string; critical?: boolean; value: Binary }[]
      extensions?: Map<string, { critical?: boolean; value: Binary }>

      // Optional unique identifier for the issuer, used in cases where issuer's name is not unique
      // TODO: Consider removing this field
      issuerUniqueID?: Binary
      // Optional unique identifier for the subject, used in cases where subject's name is not unique
      // TODO: Consider removing this field
      subjectUniqueID?: Binary
      // The bytes of TBS certificate
      bytes: Binary
    }
    // Hash and signature algorithm used by the CSC to sign the TBS certificate (e.g. sha256WithRSAEncryption)
    // This field is the same as the TBS certificate.signatureAlgorithm field
    // While in most cases the two fields will match, it is possible they may not, indicating a malformed or tampered certificate
    // This field indicates which algorithm the CSC decided to use, and therefore TBS certificate.signatureAlgorithm should be ignored
    signatureAlgorithm: {
      name: SignatureAlgorithm
      parameters?: Binary
    }
    // Signature over the TBS certificate by the CSC
    // The actual signature used to verify the TBS certificate
    signature: Binary
  }
  // The bytes of the SOD
  bytes: Binary
}

function formatDN(issuer: any[]): string {
  return issuer
    .map((i) =>
      i
        .map(
          (j: { type: string; value: { toString: () => any } }) =>
            `${getOIDName(j.type)}=${j.value.toString()}`,
        )
        .join(", "),
    )
    .join(", ")
}

export class SOD extends SODSignedData {
  constructor(sod: SODSignedData) {
    super()
    Object.assign(this, sod)
  }

  static fromDER(der: Binary): SOD {
    der = der.slice(0, 2).equals(Binary.from([119, 130])) ? der.slice(4) : der

    const contentInfo = AsnParser.parse(der.toUInt8Array(), ASN.ContentInfo)
    const signedData = AsnParser.parse(contentInfo.content, ASN.SignedData)
    const eContent = AsnConvert.parse(
      signedData.encapContentInfo.eContent.single,
      ASN.LDSSecurityObject,
    )
    const cert = signedData.certificates[0].certificate
    const tbs = cert.tbsCertificate
    const signerInfo = signedData.signerInfos[0]
    if (signedData.signerInfos.length > 1) console.warn("Warning: Found multiple SignerInfos")
    const signedAttrsMap = new Map<string, Binary>(
      signerInfo.signedAttrs.map((v) => [getOIDName(v.attrType), Binary.from(v.attrValues[0])]),
    )
    // Reconstruct signed attributes using AttributeSet to get the correct bytes that are signed
    const reconstructedSignedAttrs = new ASN.AttributeSet(signerInfo.signedAttrs.map((v) => v))
    const signedAttrs = {
      bytes: Binary.from(AsnSerializer.serialize(reconstructedSignedAttrs)),
      contentType: getOIDName(
        decodeOID((signedAttrsMap.get("contentType") as Binary).toNumberArray()),
      ),
      messageDigest: signedAttrsMap.get("messageDigest"),
      ...(signedAttrsMap.get("signingTime") && {
        signingTime: new Date(parseInt(signedAttrsMap.get("signingTime").toBigInt().toString())),
      }),
    }

    return new SOD({
      bytes: der,
      version: signedData.version,

      digestAlgorithms: signedData.digestAlgorithms.map(
        (v) => getHashAlgorithmName(v.algorithm) as DigestAlgorithm,
      ),

      encapContentInfo: {
        eContentType: getOIDName(signedData.encapContentInfo.eContentType),
        eContent: {
          bytes: Binary.from(signedData.encapContentInfo.eContent.single.buffer),
          version: eContent.version,
          hashAlgorithm: getHashAlgorithmName(eContent.hashAlgorithm.algorithm) as DigestAlgorithm,
          dataGroupHashValues: new DataGroupHashValues(
            Object.fromEntries(
              eContent.dataGroups.map((v) => [v.number as number, Binary.from(v.hash)]),
            ),
          ),
        },
      },

      signerInfo: {
        version: signerInfo.version,
        signedAttrs: signedAttrs,
        digestAlgorithm: getHashAlgorithmName(
          signerInfo.digestAlgorithm.algorithm,
        ) as DigestAlgorithm,
        signatureAlgorithm: {
          name: getOIDName(signerInfo.signatureAlgorithm.algorithm) as SignatureAlgorithm,
          parameters: signerInfo.signatureAlgorithm.parameters
            ? Binary.from(signerInfo.signatureAlgorithm.parameters)
            : null,
        },
        signature: signerInfo.signature ? Binary.from(signerInfo.signature.buffer) : null,
        sid: {
          issuerAndSerialNumber: {
            issuer: formatDN(signerInfo.sid.issuerAndSerialNumber.issuer),
            serialNumber: signerInfo.sid.issuerAndSerialNumber.serialNumber
              ? Binary.from(signerInfo.sid.issuerAndSerialNumber.serialNumber)
              : null,
          },
          subjectKeyIdentifier: signerInfo.sid.subjectKeyIdentifier
            ? Binary.from(signerInfo.sid.subjectKeyIdentifier.buffer).toString("hex")
            : null,
        },
      },

      certificate: {
        tbs: {
          bytes: Binary.from(AsnSerializer.serialize(tbs)),
          version: tbs.version,
          serialNumber: tbs.serialNumber ? Binary.from(tbs.serialNumber) : null,
          signatureAlgorithm: {
            name: getOIDName(tbs.signature.algorithm) as SignatureAlgorithm,
            parameters: tbs.signature.parameters ? Binary.from(tbs.signature.parameters) : null,
          },
          issuer: formatDN(tbs.issuer),
          validity: {
            notBefore: tbs.validity.notBefore.utcTime,
            notAfter: tbs.validity.notAfter.utcTime,
          },
          subject: formatDN(tbs.subject),
          subjectPublicKeyInfo: {
            signatureAlgorithm: {
              name: getOIDName(tbs.subjectPublicKeyInfo.algorithm.algorithm) as SignatureAlgorithm,
              parameters: tbs.subjectPublicKeyInfo.algorithm.parameters
                ? Binary.from(tbs.subjectPublicKeyInfo.algorithm.parameters)
                : null,
            },
            subjectPublicKey: tbs.subjectPublicKeyInfo.subjectPublicKey
              ? Binary.from(tbs.subjectPublicKeyInfo.subjectPublicKey)
              : null,
          },
          issuerUniqueID: tbs.issuerUniqueID ? Binary.from(tbs.issuerUniqueID) : null,
          subjectUniqueID: tbs.subjectUniqueID ? Binary.from(tbs.subjectUniqueID) : null,
          extensions: new Map<string, { critical?: boolean; value: Binary }>(
            tbs.extensions.map((v) => [
              getOIDName(v.extnID),
              { critical: v.critical, value: Binary.from(v.extnValue.buffer) },
            ]),
          ),
        },
        signatureAlgorithm: {
          name: getOIDName(cert.signatureAlgorithm.algorithm) as SignatureAlgorithm,
          parameters: cert.signatureAlgorithm.parameters
            ? Binary.from(cert.signatureAlgorithm.parameters)
            : null,
        },
        signature: cert.signatureValue ? Binary.from(cert.signatureValue) : null,
      },
    })
  }

  [inspect.custom](): string {
    let sod: SODSignedData = new SOD(this)
    delete sod.bytes
    delete sod.encapContentInfo.eContent.bytes
    delete sod.signerInfo.signedAttrs.bytes
    delete sod.certificate.tbs.bytes
    return inspect(
      {
        version: sod.version,
        digestAlgorithms: sod.digestAlgorithms,
        encapContentInfo: sod.encapContentInfo,
        signerInfo: sod.signerInfo,
        certificate: sod.certificate,
      },
      { depth: null, colors: true },
    )
  }
}
