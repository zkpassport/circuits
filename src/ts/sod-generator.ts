import { ASN, id_ldsSecurityObject } from "./asn"
import { Binary } from "@zkpassport/utils"
import {
  Attribute,
  CertificateChoices,
  CertificateSet,
  ContentInfo,
  DigestAlgorithmIdentifier,
  DigestAlgorithmIdentifiers,
  EncapsulatedContent,
  EncapsulatedContentInfo,
  id_signedData,
  SignedData,
  SignerIdentifier,
  SignerInfo,
  SignerInfos,
  SigningTime,
} from "@peculiar/asn1-cms"
import {
  AsnConvert,
  AsnOctetStringConverter,
  AsnSerializer,
  BitString,
  OctetString,
} from "@peculiar/asn1-schema"
import { id_sha1, id_sha224, id_sha256, id_sha384, id_sha512 } from "@peculiar/asn1-rsa"
import {
  AlgorithmIdentifier,
  AttributeTypeAndValue,
  AttributeValue,
  BasicConstraints,
  Certificate,
  Extension,
  Extensions,
  KeyUsage,
  Name,
  RelativeDistinguishedName,
  SubjectKeyIdentifier,
  SubjectPublicKeyInfo,
  TBSCertificate,
  Validity,
  Version,
} from "@peculiar/asn1-x509"
import { createHash } from "crypto"
import { HashAlgorithm } from "./passport-generator"

function getHashAlgorithmIdentifier(hashAlgorithm: HashAlgorithm) {
  switch (hashAlgorithm) {
    case "SHA-1":
      return id_sha1
    case "SHA-224":
      return id_sha224
    case "SHA-256":
      return id_sha256
    case "SHA-384":
      return id_sha384
    case "SHA-512":
      return id_sha512
    default:
      throw new Error(`Unsupported hash algorithm: ${hashAlgorithm}`)
  }
}

export function generateSampleDSC(): Certificate {
  // Create subject and issuer names
  const subjectName = new Name([
    new RelativeDistinguishedName([
      new AttributeTypeAndValue({
        type: "2.5.4.6", // countryName
        value: new AttributeValue({ ia5String: "DE" }),
      }),
      new AttributeTypeAndValue({
        type: "2.5.4.10", // organizationName
        value: new AttributeValue({
          ia5String: "Test Country",
        }),
      }),
    ]),
  ])

  // Create extensions
  const extensions = new Extensions([
    new Extension({
      extnID: "2.5.29.19", // basicConstraints
      critical: true,
      extnValue: new OctetString(AsnConvert.serialize(new BasicConstraints({ cA: false }))),
    }),
    new Extension({
      extnID: "2.5.29.15", // keyUsage
      critical: true,
      extnValue: new OctetString(AsnConvert.serialize(new KeyUsage(0x03))), // digitalSignature | keyCertSign
    }),
  ])

  // Create dummy public key
  const dummyPublicKey = new Uint8Array(256)
  for (let i = 0; i < dummyPublicKey.length; i++) {
    dummyPublicKey[i] = i % 256
  }

  // Create certificate
  const tbsCertificate = new TBSCertificate({
    version: Version.v3,
    // @ts-ignore-error
    serialNumber: new Uint8Array([1, 2, 3, 4, 5]),
    signature: new AlgorithmIdentifier({
      algorithm: "1.2.840.113549.1.1.11", // sha256WithRSAEncryption
    }),
    issuer: subjectName, // Self-signed for this example
    validity: new Validity({
      notBefore: new Date(),
      notAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // 1 year
    }),
    subject: subjectName,
    subjectPublicKeyInfo: new SubjectPublicKeyInfo({
      algorithm: new AlgorithmIdentifier({
        algorithm: "1.2.840.113549.1.1.1", // rsaEncryption
      }),
      subjectPublicKey: AsnConvert.serialize(new BitString(dummyPublicKey)),
    }),
    extensions,
  })
  const certificate = new Certificate({
    tbsCertificate,
    signatureAlgorithm: new AlgorithmIdentifier({
      algorithm: "1.2.840.113549.1.1.11", // sha256WithRSAEncryption
    }),
    signatureValue: AsnConvert.serialize(new BitString(dummyPublicKey)),
  })
  return certificate
}

export function generateSod(
  dg1: Binary,
  certificates: Certificate[] = [],
  hashAlgorithm: HashAlgorithm = "SHA-256",
) {
  // Digest Algorithms
  const digestAlgorithms = new DigestAlgorithmIdentifiers([
    new DigestAlgorithmIdentifier({
      algorithm: getHashAlgorithmIdentifier(hashAlgorithm),
    }),
  ])

  const parsedHashAlgorithm = hashAlgorithm.toLowerCase().replace("-", "")

  // Encapsulated Content Info
  const dg1Hash = createHash(parsedHashAlgorithm).update(dg1.toBuffer()).digest()
  const encapContentInfo = generateEncapContentInfo(dg1Hash, hashAlgorithm)
  const eContentHash = Binary.from(
    createHash(parsedHashAlgorithm)
      .update(Binary.from(encapContentInfo!.eContent!.single!.buffer).toBuffer())
      .digest(),
  )

  // Signed Attributes
  const signedAttrs = generateSignedAttrs(eContentHash)

  // Create SignerInfo
  const signerInfo = new SignerInfo({
    version: 1,
    sid: new SignerIdentifier({
      subjectKeyIdentifier: new SubjectKeyIdentifier(new Uint8Array(32)),
    }),
    digestAlgorithm: new DigestAlgorithmIdentifier({
      algorithm: getHashAlgorithmIdentifier(hashAlgorithm),
    }),
    signedAttrs: signedAttrs,
    signatureAlgorithm: new AlgorithmIdentifier({
      algorithm: certificates[0]?.signatureAlgorithm?.algorithm || "1.2.840.113549.1.1.11", // sha256WithRSAEncryption
    }),
    signature: new OctetString(new Uint8Array(256)),
  })

  // Create SOD (SignedData) structure
  const sod = new SignedData({
    version: 3,
    digestAlgorithms,
    encapContentInfo,
    signerInfos: new SignerInfos([signerInfo]),
    certificates: new CertificateSet(
      certificates.map(
        (cert) =>
          new CertificateChoices({
            certificate: cert,
          }),
      ),
    ),
  })

  // Create the final ContentInfo wrapper
  const contentInfo = new ContentInfo({
    contentType: id_signedData,
    content: AsnSerializer.serialize(sod),
  })
  return { contentInfo, sod }
}

export function wrapSodInContentInfo(sod: SignedData) {
  const contentInfo = new ContentInfo({
    contentType: id_signedData,
    content: AsnSerializer.serialize(sod),
  })
  return contentInfo
}

export function generateEncapContentInfo(dg1Hash: Uint8Array, hashAlgorithm: HashAlgorithm) {
  // Create LDS Security Object (SOD.encapContentInfo.eContent)
  const ldsSecurityObject = new ASN.LDSSecurityObject()
  ldsSecurityObject.version = ASN.LDSSecurityObjectVersion.v0
  ldsSecurityObject.hashAlgorithm = new DigestAlgorithmIdentifier({
    algorithm: getHashAlgorithmIdentifier(hashAlgorithm),
  })

  // Add some sample data group hashes
  ldsSecurityObject.dataGroups = [
    new ASN.DataGroupHash({
      number: ASN.DataGroupNumber.dataGroup1,
      // @ts-ignore-error
      hash: dg1Hash,
    }),
    new ASN.DataGroupHash({
      number: ASN.DataGroupNumber.dataGroup2,
      // @ts-ignore-error
      hash: new Uint8Array(32).buffer, // 32-byte zero buffer for testing
    }),
  ]

  // Create EncapsulatedContentInfo container
  const encapContentInfo = new EncapsulatedContentInfo({
    eContentType: id_ldsSecurityObject,
    eContent: new EncapsulatedContent({
      single: new OctetString(AsnSerializer.serialize(ldsSecurityObject)),
    }),
  })
  return encapContentInfo
}

export function generateSignedAttrs(eContentHash: Binary) {
  const contentType = new Attribute({
    attrType: "1.2.840.113549.1.9.3", // id_contentType
    attrValues: [
      AsnSerializer.serialize(new ASN.LDSSecurityObjectIdentifier(id_ldsSecurityObject)),
    ],
  })
  const signingTime = new Attribute({
    attrType: "1.2.840.113549.1.9.5", // id_signingTime
    // Fix the time in UTC to avoid timezone issues
    attrValues: [AsnConvert.serialize(new SigningTime(new Date("2024-05-01T00:00:00Z")))],
  })
  const messageDigest = new Attribute({
    attrType: "1.2.840.113549.1.9.4", // id_messageDigest
    // @ts-ignore-error
    attrValues: [AsnConvert.serialize(AsnOctetStringConverter.toASN(eContentHash.toBuffer()))],
  })
  const signedAttrs: ASN.AttributeSet = new ASN.AttributeSet([
    contentType,
    signingTime,
    messageDigest,
  ])
  return signedAttrs
}
