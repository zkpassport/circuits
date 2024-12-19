import { Certificate as ASNCertificate } from "@peculiar/asn1-x509"
import { AsnArray, AsnProp, AsnPropTypes, AsnType, AsnTypeTypes } from "@peculiar/asn1-schema"
import {
  Attribute as AsnAttribute,
  ContentInfo as AsnContentInfo,
  DigestAlgorithmIdentifier as AsnDigestAlgorithmIdentifier,
  EncapsulatedContent as ASNEncapsulatedContent,
  SignedAttributes as AsnSignedAttributes,
  SignedData as AsnSignedData,
  SignerIdentifier as AsnSignerIdentifier,
  SignerInfo as AsnSignerInfo,
} from "@peculiar/asn1-cms"

export namespace ASN {
  export const Attribute = AsnAttribute
  export type Attribute = AsnAttribute
  export const ContentInfo = AsnContentInfo
  export type ContentInfo = AsnContentInfo
  export const DigestAlgorithmIdentifier = AsnDigestAlgorithmIdentifier
  export type DigestAlgorithmIdentifier = AsnDigestAlgorithmIdentifier
  export const EncapsulatedContent = ASNEncapsulatedContent
  export type EncapsulatedContent = ASNEncapsulatedContent
  export const SignedData = AsnSignedData
  export type SignedData = AsnSignedData
  export const SignerInfo = AsnSignerInfo
  export type SignerInfo = AsnSignerInfo
  export const SignerIdentifier = AsnSignerIdentifier
  export type SignerIdentifier = AsnSignerIdentifier
  export type SignedAttributes = AsnSignedAttributes
  export const Certificate = ASNCertificate
  export type Certificate = ASNCertificate

  /**
   * ```asn
   * AttributeSet ::= SET OF Attribute
   * ```
   */
  @AsnType({ type: AsnTypeTypes.Set, itemType: AsnAttribute })
  export class AttributeSet extends AsnArray<AsnAttribute> {
    constructor(items?: AsnAttribute[]) {
      super(items)

      Object.setPrototypeOf(this, AttributeSet.prototype)
    }
  }

  /**
   * ```asn
   * DataGroupHash ::= SEQUENCE {
   *  dataGroupNumber DataGroupNumber,
   *  dataGroupHashValue OCTET STRING }
   * ```
   */
  export class DataGroupHash {
    @AsnProp({ type: AsnPropTypes.Integer })
    public number: DataGroupNumber = DataGroupNumber.dataGroup1

    @AsnProp({ type: AsnPropTypes.OctetString })
    public hash: ArrayBuffer = new ArrayBuffer(0)

    public constructor(params: Partial<DataGroupHash> = {}) {
      Object.assign(this, params)
    }
  }

  /**
   * ```asn
   * LDSSecurityObjectVersion ::= INTEGER  { v0(0), v1(1) }
   * ```
   */
  export enum LDSSecurityObjectVersion {
    v0 = 0,
    v1 = 1,
    v2 = 2,
  }

  /**
   * ```asn
   * DataGroupNumber ::= INTEGER
   * ```
   */
  export enum DataGroupNumber {
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
   * LDSVersionInfo ::= SEQUENCE {
   *  ldsVersion PrintableString,
   *  unicodeVersion PrintableString }
   * ```
   */
  export class LDSVersionInfo {
    @AsnProp({ type: AsnPropTypes.PrintableString })
    public ldsVersion: string = ""

    @AsnProp({ type: AsnPropTypes.PrintableString })
    public unicodeVersion: string = ""

    public constructor(params: Partial<LDSVersionInfo> = {}) {
      Object.assign(this, params)
    }
  }

  /**
   * ```asn
   * LDSSecurityObjectIdentifier ::= OBJECT IDENTIFIER
   * ```
   */
  @AsnType({ type: AsnTypeTypes.Choice })
  export class LDSSecurityObjectIdentifier {
    @AsnProp({ type: AsnPropTypes.ObjectIdentifier })
    public value: string = ""

    constructor(value?: string) {
      if (value) {
        if (typeof value === "string") {
          this.value = value
        } else {
          Object.assign(this, value)
        }
      }
    }
  }

  /**
   * This is for parsing the ASN of signedData.encapContentInfo.eContent
   *
   * ```asn
   * LDSSecurityObject ::= SEQUENCE {
   *  version LDSSecurityObjectVersion,
   *  hashAlgorithm DigestAlgorithmIdentifier,
   *  dataGroupHashValues SEQUENCE SIZE (2..ub-DataGroups) OF DataGroupHash,
   *  ldsVersionInfo LDSVersionInfo OPTIONAL -- If present, version MUST be V1
   * }
   * ```
   */
  export class LDSSecurityObject {
    @AsnProp({ type: AsnPropTypes.Integer })
    public version: LDSSecurityObjectVersion = LDSSecurityObjectVersion.v1

    @AsnProp({ type: AsnDigestAlgorithmIdentifier })
    public hashAlgorithm: AsnDigestAlgorithmIdentifier = new AsnDigestAlgorithmIdentifier()

    @AsnProp({ type: DataGroupHash, repeated: "sequence" })
    public dataGroups: DataGroupHash[] = []

    @AsnProp({ type: LDSVersionInfo, optional: true })
    public versionInfo?: LDSVersionInfo

    public constructor(params: Partial<LDSSecurityObject> = {}) {
      Object.assign(this, params)
    }
  }
}

export const id_ldsSecurityObject = "2.23.136.1.1.1"
export const id_sha256 = "2.16.840.1.101.3.4.2.1"
