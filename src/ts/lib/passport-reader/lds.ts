import { Binary } from "@/lib/binary"
import {
  Attribute as AsnAttribute,
  ContentInfo as AsnContentInfo,
  DigestAlgorithmIdentifier as AsnDigestAlgorithmIdentifier,
  EncapsulatedContent as ASNEncapsulatedContent,
  SignedAttributes as AsnSignedAttributes,
  SignedData as AsnSignedData,
  SignerInfo as AsnSignerInfo,
} from "@peculiar/asn1-cms"
import {
  AsnArray,
  AsnConvert,
  AsnParser,
  AsnProp,
  AsnPropTypes,
  AsnSerializer,
  AsnType,
  AsnTypeTypes,
} from "@peculiar/asn1-schema"
import { TBSCertificate as ASNTBSCertificate } from "@peculiar/asn1-x509"
import { createHash } from "crypto"
import { getECDSAInfo, getRSAInfo } from "./passport-reader"
import { decodeOID, getOIDName } from "./oids"

const OID_MRTD_SIGNATURE_DATA = "2.23.136.1.1.1"

/**
 * ```asn
 * AsnLDSSecurityObjectVersion ::= INTEGER  { v0(0), v1(1) }
 * ```
 */
export enum AsnLDSSecurityObjectVersion {
  v0 = 0,
  v1 = 1,
  v2 = 2,
}

/**
 * ```asn
 * AsnDataGroupNumber ::= INTEGER
 * ```
 */
export enum AsnDataGroupNumber {
  dataGroup1 = 1,
  dataGroup2 = 2,
  dataGroup3 = 3,
  dataGroup4 = 4,
  dataGroup5 = 5,
  dataGroup6 = 6,
  dataGroup7 = 7,
  dataGroup8 = 8,
  dataGroup9 = 9,
  dataGroup10 = 10,
  dataGroup11 = 11,
  dataGroup12 = 12,
  dataGroup13 = 13,
  dataGroup14 = 14,
  dataGroup15 = 15,
  dataGroup16 = 16,
}

/**
 * ```asn
 * AsnAttributeSet ::= SET OF AsnAttribute
 * ```
 */
@AsnType({ type: AsnTypeTypes.Set, itemType: AsnAttribute })
class AsnAttributeSet extends AsnArray<AsnAttribute> {
  constructor(items?: AsnAttribute[]) {
    super(items)

    Object.setPrototypeOf(this, AsnAttributeSet.prototype)
  }
}

/**
 * DataGroupHash ::= SEQUENCE {
 *  AsndataGroupNumber AsnDataGroupNumber,
 *  dataGroupHashValue OCTET STRING }
 */
class AsnParsedDataGroupHash {
  @AsnProp({ type: AsnPropTypes.Integer })
  public number: AsnDataGroupNumber = AsnDataGroupNumber.dataGroup1

  @AsnProp({ type: AsnPropTypes.OctetString })
  public hash: ArrayBuffer = new ArrayBuffer(0)

  public constructor(params: Partial<AsnParsedDataGroupHash> = {}) {
    Object.assign(this, params)
  }
}

// This is for ASN parsing signedData.encapContentInfo.eContent
/**
 * AsnLDSSecurityObject ::= SEQUENCE {
 *  version AsnLDSSecurityObjectVersion,
 *  hashAlgorithm DigestAlgorithmIdentifier,
 *  dataGroupHashValues SEQUENCE SIZE (2..ub-DataGroups) OF DataGroupHash}
 */
export class AsnLDSSecurityObject {
  @AsnProp({ type: AsnPropTypes.Integer })
  public version: AsnLDSSecurityObjectVersion = AsnLDSSecurityObjectVersion.v1

  @AsnProp({ type: AsnDigestAlgorithmIdentifier })
  public hashAlgorithm: AsnDigestAlgorithmIdentifier = new AsnDigestAlgorithmIdentifier()

  @AsnProp({ type: AsnParsedDataGroupHash, repeated: "sequence" })
  public dataGroups: AsnParsedDataGroupHash[] = []

  public constructor(params: Partial<AsnLDSSecurityObject> = {}) {
    Object.assign(this, params)
  }
}

export class OID {
  public value: string = ""
  public name: string = ""
  constructor(value: string) {
    this.value = value
    this.name = getOIDName(value)
  }
  toString(): string {
    return `${this.name} (${this.value})`
  }
}

// export class Passport {
//   public dg1: Binary
//   public sod: Binary
//   public signedAttributes: Binary
//   public signedAttributesHashAlgorithm: string
//   public eContent: Binary
//   public eContentHashAlgorithm: string
//   public cmsVersion: string
//   public sodSignature: Binary
//   public sodSignatureAlgorithm: string
//   public tbsSignature: Binary
//   public tbsSignatureAlgorithm: string
//   public tbsCertificate: Binary
// }

export class LDS {
  // The LDS version (from eContent)
  public ldsVersion: number
  // The CMS version in SignedData
  public cmsVersion: number
  // The hash algorithm used to hash the data groups (from eContent)
  public dataGroupsHashAlgorithm: OID
  // The data groups (1-16) in the LDS (from eContent)
  public dataGroups: DataGroup[]
  // The encapsulated content
  public eContent: EContent
  // The signed attributes (signed by DSC)
  public signedAttr: SignedAttr
  // The TBS certificate (signed by CSC)
  public tbs: TBS
  // The SOD binary data
  public sod: Binary
  // The DG1 data group binary data
  public dg1: Binary

  constructor(dg1: Binary, sod: Binary) {
    // Strip first 4 bytes of SOD if needed
    sod = sod.slice(0, 2).equals(Binary.from([119, 130])) ? sod.slice(4) : sod

    const contentInfo = AsnParser.parse(sod.toUInt8Array(), AsnContentInfo)
    const signedData = AsnParser.parse(contentInfo.content, AsnSignedData)
    // TODO: What is this actually used for?
    const digestAlgorithms = signedData.digestAlgorithms.map((v) => new OID(v.algorithm))

    // ------------------------------------------------------------------------
    // Encapsulated Content
    // ------------------------------------------------------------------------
    const { eContentType } = signedData.encapContentInfo
    if (eContentType !== OID_MRTD_SIGNATURE_DATA) throw new Error("Invalid SOD")
    const eContent = new EContent(signedData.encapContentInfo.eContent)

    // ------------------------------------------------------------------------
    // Signer Info
    // ------------------------------------------------------------------------
    const signerInfo = new SignerInfo(signedData.signerInfos[0])
    if (signedData.signerInfos.length > 1) console.warn("Warning: Found multiple SignerInfos")

    // ------------------------------------------------------------------------
    // Signed Attributes (signed by DSC)
    // ------------------------------------------------------------------------
    // Ensure the SignedAttrs contentType is mRTDSignatureData
    for (const attr of signedData.signerInfos[0].signedAttrs) {
      if (
        getOIDName(attr.attrType) === "contentType" &&
        decodeOID(Array.from(Binary.from(attr.attrValues[0]))) !== OID_MRTD_SIGNATURE_DATA
      ) {
        throw new Error("Invalid LDS")
      }
    }
    const signedAttr = new SignedAttr(signedData.signerInfos[0].signedAttrs, signerInfo)

    // ------------------------------------------------------------------------
    // TBS (To Be Signed) (signed by CSC)
    // ------------------------------------------------------------------------
    const tbs = new TBS(
      signedData.certificates[0].certificate.tbsCertificate,
      Binary.from(signedData.certificates[0].certificate.signatureValue),
      new OID(signedData.certificates[0].certificate.signatureAlgorithm.algorithm),
    )

    this.sod = sod
    this.eContent = eContent
    this.ldsVersion = eContent.ldsVersion
    this.dataGroups = eContent.dataGroups
    this.dataGroupsHashAlgorithm = eContent.hashAlgorithm
    this.signedAttr = signedAttr
    this.cmsVersion = signedData.version
    this.tbs = tbs
    this.dg1 = dg1
  }

  idSignatureAlgorithmType(): "RSA" | "ECDSA" | "" {
    if (this.signedAttr.signatureAlgorithm.name.toLowerCase().includes("rsa")) {
      return "RSA"
    } else if (this.signedAttr.signatureAlgorithm.name.toLowerCase().includes("ecdsa")) {
      return "ECDSA"
    }
    return ""
  }

  dscSignatureAlgorithmType(): "RSA" | "ECDSA" | "" {
    if (this.tbs.signatureAlgorithm.name.toLowerCase().includes("rsa")) {
      return "RSA"
    } else if (this.tbs.signatureAlgorithm.name.toLowerCase().includes("ecdsa")) {
      return "ECDSA"
    }
    return ""
  }

  toString(): string {
    return [
      `LDS Version: ${this.ldsVersion}`,
      `Data Groups Hash Algorithm: ${this.dataGroupsHashAlgorithm.name}`,
      `Data Groups Hashes:`,
      ...this.dataGroups.map((v) => `DG${v.number}: ${v.hash.toString("hex")}`),
      `\nSigned Attributes:`,
      this.signedAttr.toString(),
      `\nTBS Certificate:`,
      this.tbs.toString(),
    ].join("\n")
  }
}

export class SignerInfo {
  // The hash algorithm used to hash both `encapsulatedContent` and `SignedAttr`
  public hashAlgorithm: OID
  // The signature algorithm used to produce the signature value, and any associated parameters
  public signatureAlgorithm: OID
  // The signature of the DSC signer
  public signature: Binary

  public constructor(signerInfo: AsnSignerInfo) {
    this.hashAlgorithm = new OID(signerInfo.digestAlgorithm.algorithm)
    this.signatureAlgorithm = new OID(signerInfo.signatureAlgorithm.algorithm)
    this.signature = Binary.from(signerInfo.signature.buffer)
  }
  toString(): string {
    return [
      `Hash Algorithm: ${this.hashAlgorithm.name}`,
      `Signature Algorithm: ${this.signatureAlgorithm.name}`,
      `Signature: ${this.signature.toString("hex")}`,
    ].join("\n")
  }
}

export class DataGroup {
  public number: number
  public hash: Binary
  constructor(number: number, hash: Binary) {
    this.number = number
    this.hash = hash
  }
}

export class EContent {
  // Raw bytes of the eContent region
  public bytes: Binary
  // The hash algorithm used to hash the data groups
  public hashAlgorithm: OID
  // The data groups (1-16) in the LDS
  public dataGroups: DataGroup[] = []
  // The LDS version (v1 = 0, v2 = 1)
  public ldsVersion: number

  constructor(eContent: ASNEncapsulatedContent) {
    const parsed = AsnConvert.parse(eContent.single, AsnLDSSecurityObject)
    this.ldsVersion = parsed.version
    this.hashAlgorithm = new OID(parsed.hashAlgorithm.algorithm)
    this.dataGroups = parsed.dataGroups.map((v) => new DataGroup(v.number, Binary.from(v.hash)))
    this.bytes = Binary.from(eContent.single.buffer)
  }
}

export class SignedAttr {
  // Raw bytes of the SignedAttr region
  public bytes: Binary
  // The signed attributes
  public attributes: [string, Binary][] = []
  // The the hash of eContent (aka SignedAttr.messageDigest)
  public eContentHash: Binary
  // The hash algorithm used to hash eContent (same hash algorithm used to hash SignedAttr)
  public eContentHashAlgorithm: OID
  // The hash algorithm used to hash SignedAttr (same hash algorithm used to hash eContent)
  public hashAlgorithm: OID
  // The signature algorithm used to produce the signature value, and any associated parameters
  public signatureAlgorithm: OID
  // The signature over the signed attributes by the signing DSC
  public signature: Binary
  // The signer info (of the signing DSC)
  public signerInfo: SignerInfo
  // The hash of SignedAttr (hashed using hashAlgorithm)
  public hash: Binary

  constructor(asnSignedAttributes: AsnSignedAttributes, signerInfo: SignerInfo) {
    // TODO: Add support for other attributes, like signingTime
    this.attributes = asnSignedAttributes.map((v) => [
      getOIDName(v.attrType),
      Binary.from(v.attrValues[0]),
    ])
    this.eContentHash = this.attributes.find((v) => v[0] === "messageDigest")?.[1]
    this.eContentHashAlgorithm = signerInfo.hashAlgorithm
    this.hashAlgorithm = signerInfo.hashAlgorithm
    this.signatureAlgorithm = signerInfo.signatureAlgorithm
    this.signature = signerInfo.signature
    // Reconstruct signed attributes using AsnAttributeSet to get the correct bytes that are signed
    const reconstructedAsnSignedAttributes = new AsnAttributeSet(asnSignedAttributes.map((v) => v))
    this.bytes = Binary.from(AsnSerializer.serialize(reconstructedAsnSignedAttributes))
    // Get hash of SignedAttr ASN bytes depending on the hash specified by signerInfo.hashAlgorithm
    if (this.hashAlgorithm.name === "sha-256") {
      this.hash = Binary.from(createHash("sha256").update(this.bytes.toBuffer()).digest())
    } else if (this.hashAlgorithm.name === "sha-512") {
      this.hash = Binary.from(createHash("sha512").update(this.bytes.toBuffer()).digest())
    } else {
      throw new Error(`Unsupported hash algorithm: ${this.hashAlgorithm}`)
    }
  }

  toString(): string {
    return [
      `eContent Hash: ${this.eContentHash.toString("hex")}`,
      `eContent Hash Algorithm: ${this.eContentHashAlgorithm.name}`,
      `SignedAttr Hash Algorithm: ${this.hashAlgorithm.name}`,
      `SignedAttr Signature Algorithm: ${this.signatureAlgorithm.name}`,
      `SignedAttr Signature: ${this.signature.toString("hex")}`,
      `SignedAttr Hash: ${this.hash.toString("hex")}`,
    ].join("\n")
  }
}

export class TBS {
  public bytes: Binary
  // The certificate version (v1 = 0, v2 = 1, v3 = 2)
  public version: number
  // The serial number of the TBS certificate
  public serialNumber: any
  // The CSCA issuer
  public issuer: [string, string][]
  // The RSA public key of the DSC that's inside the TBS
  public rsaPublicKey: { modulus: bigint; exponent: bigint }
  // The ECDSA public key of the DSC that's inside the TBS
  public ecdsaPublicKey: { curve: string; publicKey: Uint8Array }
  // The signature algorithm used by the CSC to sign the TBS certificate
  public signatureAlgorithm: OID
  // The signature algorithm parameters
  public signatureParameters: ArrayBuffer
  // The signature algorithm type
  public signatureAlgorithmType: "RSA" | "ECDSA" | ""
  // The signature over the TBS by the CSC
  public signature: Binary
  // The signature algorithm used by the CSC to sign the TBS certificate
  // public signatureAlgorithm: OID

  // constructor(tbs: ASNTBSCertificate) {
  constructor(tbs: ASNTBSCertificate, signature: Binary, signatureAlgorithm: OID) {
    this.bytes = Binary.from(AsnSerializer.serialize(tbs))
    this.version = tbs.version
    this.serialNumber = Binary.from(tbs.serialNumber).toString("hex")
    this.issuer = tbs.issuer.flatMap((i) =>
      i.map((j): [string, string] => [getOIDName(j.type), j.value.toString()]),
    )
    this.signatureAlgorithm = new OID(tbs.subjectPublicKeyInfo.algorithm.algorithm)
    this.signatureParameters = tbs.subjectPublicKeyInfo.algorithm.parameters

    this.signature = signature

    if (this.signatureAlgorithm.name.toLowerCase().includes("rsa")) {
      this.signatureAlgorithmType = "RSA"
      this.rsaPublicKey = getRSAInfo(tbs)
    } else if (this.signatureAlgorithm.name.toLowerCase().includes("ecdsa")) {
      this.signatureAlgorithmType = "ECDSA"
      this.ecdsaPublicKey = getECDSAInfo(tbs)
    }
  }

  toString(): string {
    return [
      `TBS Version: ${this.version}`,
      `Serial Number: ${this.serialNumber}`,
      `Issuer: ${this.issuer.map((v) => `${v[0]}: ${v[1]}`).join(", ")}`,
      `RSA Public Key: 0x${this.rsaPublicKey.modulus.toString(16)}`,
      `RSA Public Exponent: ${this.rsaPublicKey.exponent}`,
    ].join("\n")
  }
}
