import { Binary } from "@zkpassport/utils"
import { SignedData, SignerInfo, SignerInfos } from "@peculiar/asn1-cms"
import { AsnConvert, AsnSerializer, OctetString } from "@peculiar/asn1-schema"
import {
  Certificate,
  TBSCertificate,
  BasicConstraints,
  KeyUsage,
  SubjectKeyIdentifier,
  AuthorityKeyIdentifier,
  KeyIdentifier,
  AlgorithmIdentifier as X509AlgorithmIdentifier,
  SubjectPublicKeyInfo,
  Name,
  AttributeTypeAndValue,
  AttributeValue,
  RelativeDistinguishedName,
  Validity,
  Extensions,
  Extension as X509Extension,
} from "@peculiar/asn1-x509"
import { Version } from "@peculiar/asn1-x509"
import { cryptoProvider, PemConverter, X509CertificateGenerator, Extension } from "@peculiar/x509"
import { ASN } from "./asn"
import { wrapSodInContentInfo } from "./sod-generator"
import { Crypto, CryptoKey } from "@peculiar/webcrypto"
import { KeyUsageFlags } from "@peculiar/asn1-x509"
import fs from "fs"

// Noble curves imports
import { p256 } from "@noble/curves/nist.js"
import { p384 } from "@noble/curves/nist.js"
import { p521 } from "@noble/curves/nist.js"
import { brainpoolP256r1 as bp256 } from "@noble/curves/misc.js"
import { brainpoolP384r1 as bp384 } from "@noble/curves/misc.js"
import { brainpoolP512r1 as bp512 } from "@noble/curves/misc.js"
import { ecdsa, weierstrass } from "@noble/curves/abstract/weierstrass.js"
import type { ECDSA } from "@noble/curves/abstract/weierstrass.js"
import { sha1 } from "@noble/hashes/legacy.js"
import { sha224, sha256, sha384, sha512 } from "@noble/hashes/sha2.js"
import type { CHash } from "@noble/hashes/utils.js"

const crypto = new Crypto()
cryptoProvider.set(crypto as any)

// ── Define missing curves using noble-curves abstract ──

const p192 = ecdsa(weierstrass({
  p: BigInt('0xfffffffffffffffffffffffffffffffeffffffffffffffff'),
  n: BigInt('0xffffffffffffffffffffffff99def836146bc9b1b4d22831'),
  h: BigInt(1),
  a: BigInt('0xfffffffffffffffffffffffffffffffefffffffffffffffc'),
  b: BigInt('0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1'),
  Gx: BigInt('0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012'),
  Gy: BigInt('0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811'),
}), sha1)

const p224 = ecdsa(weierstrass({
  p: BigInt('0xffffffffffffffffffffffffffffffff000000000000000000000001'),
  n: BigInt('0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d'),
  h: BigInt(1),
  a: BigInt('0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe'),
  b: BigInt('0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4'),
  Gx: BigInt('0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21'),
  Gy: BigInt('0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34'),
}), sha224)

const bp192 = ecdsa(weierstrass({
  p: BigInt('0xc302f41d932a36cda7a3463093d18db78fce476de1a86297'),
  n: BigInt('0xc302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1'),
  h: BigInt(1),
  a: BigInt('0x6a91174076b1e0e19c39c031fe8685c1cae040e5c69a28ef'),
  b: BigInt('0x469a28ef7c28cca3dc721d044f4496bcca7ef4146fbf25c9'),
  Gx: BigInt('0xc0a0647eaab6a48753b033c56cb0f0900a2f5c4853375fd6'),
  Gy: BigInt('0x14b690866abd5bb88b5f4828c1490002e6773fa2fa299b8f'),
}), sha1)

const bp224 = ecdsa(weierstrass({
  p: BigInt('0xd7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff'),
  n: BigInt('0xd7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f'),
  h: BigInt(1),
  a: BigInt('0x68a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43'),
  b: BigInt('0x2580f63ccfe44138870713b1a92369e33e2135d266dbb372386c400b'),
  Gx: BigInt('0x0d9029ad2c7e5cf4340823b2a87dc68c9e4ce3174c1e6efdee12c07d'),
  Gy: BigInt('0x58aa56f772c0726f24c6b89e4ecdac24354b9e99caa3f6d3761402cd'),
}), sha224)

// ── Curve and hash registries ──

const NOBLE_CURVES: Record<string, ECDSA> = {
  "P-192": p192,
  "P-224": p224,
  "P-256": p256,
  "P-384": p384,
  "P-521": p521,
  "brainpoolP192r1": bp192,
  "brainpoolP224r1": bp224,
  "brainpoolP256r1": bp256,
  "brainpoolP384r1": bp384,
  "brainpoolP512r1": bp512,
}

const HASH_FUNCTIONS: Record<string, CHash> = {
  "SHA-1": sha1,
  "SHA-224": sha224,
  "SHA-256": sha256,
  "SHA-384": sha384,
  "SHA-512": sha512,
}

const CURVE_OIDS: Record<string, string> = {
  "P-192": "1.2.840.10045.3.1.1",
  "P-224": "1.3.132.0.33",
  "P-256": "1.2.840.10045.3.1.7",
  "P-384": "1.3.132.0.34",
  "P-521": "1.3.132.0.35",
  "brainpoolP192r1": "1.3.36.3.3.2.8.1.1.3",
  "brainpoolP224r1": "1.3.36.3.3.2.8.1.1.5",
  "brainpoolP256r1": "1.3.36.3.3.2.8.1.1.7",
  "brainpoolP384r1": "1.3.36.3.3.2.8.1.1.11",
  "brainpoolP512r1": "1.3.36.3.3.2.8.1.1.13",
}

const ECDSA_SIGN_OIDS: Record<string, string> = {
  "SHA-1": "1.2.840.10045.4.1",
  "SHA-224": "1.2.840.10045.4.3.1",
  "SHA-256": "1.2.840.10045.4.3.2",
  "SHA-384": "1.2.840.10045.4.3.3",
  "SHA-512": "1.2.840.10045.4.3.4",
}

const EC_PUBLIC_KEY_OID = "1.2.840.10045.2.1"

// ── DER encoding helpers ──

function derLength(len: number): Uint8Array {
  if (len < 128) return new Uint8Array([len])
  if (len < 256) return new Uint8Array([0x81, len])
  return new Uint8Array([0x82, (len >> 8) & 0xff, len & 0xff])
}

function derWrap(tag: number, content: Uint8Array): Uint8Array {
  const len = derLength(content.length)
  const result = new Uint8Array(1 + len.length + content.length)
  result[0] = tag
  result.set(len, 1)
  result.set(content, 1 + len.length)
  return result
}

function derSequence(...items: Uint8Array[]): Uint8Array {
  const totalLen = items.reduce((sum, item) => sum + item.length, 0)
  const content = new Uint8Array(totalLen)
  let offset = 0
  for (const item of items) {
    content.set(item, offset)
    offset += item.length
  }
  return derWrap(0x30, content)
}

function derInteger(value: Uint8Array): Uint8Array {
  // Add leading zero if high bit is set (to keep positive)
  if (value.length > 0 && value[0] & 0x80) {
    const padded = new Uint8Array(value.length + 1)
    padded.set(value, 1)
    return derWrap(0x02, padded)
  }
  return derWrap(0x02, value)
}

function derOctetString(data: Uint8Array): Uint8Array {
  return derWrap(0x04, data)
}

function derBitString(data: Uint8Array): Uint8Array {
  // Prepend unused bits count (0)
  const content = new Uint8Array(1 + data.length)
  content[0] = 0x00
  content.set(data, 1)
  return derWrap(0x03, content)
}

function derOid(oidStr: string): Uint8Array {
  const arcs = oidStr.split(".").map(Number)
  const bytes: number[] = []
  // First two arcs combined
  bytes.push(40 * arcs[0] + arcs[1])
  // Remaining arcs in base-128
  for (let i = 2; i < arcs.length; i++) {
    let arc = arcs[i]
    if (arc < 128) {
      bytes.push(arc)
    } else {
      const encoded: number[] = []
      encoded.unshift(arc & 0x7f)
      arc >>= 7
      while (arc > 0) {
        encoded.unshift((arc & 0x7f) | 0x80)
        arc >>= 7
      }
      bytes.push(...encoded)
    }
  }
  return derWrap(0x06, new Uint8Array(bytes))
}

function derContextTag(tag: number, data: Uint8Array): Uint8Array {
  return derWrap(0xa0 | tag, data)
}

// ── EC key encoding/decoding ──

function encodeSpki(curve: EcdsaCurve, publicKeyBytes: Uint8Array): Uint8Array {
  const algId = derSequence(derOid(EC_PUBLIC_KEY_OID), derOid(CURVE_OIDS[curve]))
  const pubKeyBitString = derBitString(publicKeyBytes)
  return derSequence(algId, pubKeyBitString)
}

function encodePkcs8(curve: EcdsaCurve, rawSecretKey: Uint8Array, publicKeyBytes: Uint8Array): Uint8Array {
  const version = derInteger(new Uint8Array([0]))
  const algId = derSequence(derOid(EC_PUBLIC_KEY_OID), derOid(CURVE_OIDS[curve]))
  // ECPrivateKey inner structure
  const ecVersion = derInteger(new Uint8Array([1]))
  const privKeyOctetString = derOctetString(rawSecretKey)
  const pubKeyContext = derContextTag(1, derBitString(publicKeyBytes))
  const ecPrivateKey = derSequence(ecVersion, privKeyOctetString, pubKeyContext)
  const privKeyOuter = derOctetString(ecPrivateKey)
  return derSequence(version, algId, privKeyOuter)
}

function extractRawSecretKeyFromPkcs8(pkcs8: Uint8Array): Uint8Array {
  // Manual extraction from the PKCS8 DER
  // PKCS8: SEQUENCE { INTEGER(0), SEQUENCE { OID, OID }, OCTET STRING { ECPrivateKey } }
  // ECPrivateKey: SEQUENCE { INTEGER(1), OCTET STRING <raw-key>, ... }
  let offset = 0
  // Skip outer SEQUENCE tag+length
  offset = skipTagAndLength(pkcs8, offset)
  // Skip version INTEGER
  offset = skipTlv(pkcs8, offset)
  // Skip AlgorithmIdentifier SEQUENCE
  offset = skipTlv(pkcs8, offset)
  // Read the outer OCTET STRING (contains ECPrivateKey DER)
  const ecPrivKeyDer = readTlvValue(pkcs8, offset)
  // Parse ECPrivateKey DER
  let innerOffset = 0
  // Skip SEQUENCE tag+length
  innerOffset = skipTagAndLength(ecPrivKeyDer, innerOffset)
  // Skip version INTEGER
  innerOffset = skipTlv(ecPrivKeyDer, innerOffset)
  // Read the private key OCTET STRING
  return readTlvValue(ecPrivKeyDer, innerOffset)
}

function skipTagAndLength(data: Uint8Array, offset: number): number {
  offset++ // skip tag
  if (data[offset] < 128) {
    return offset + 1
  } else {
    const numLenBytes = data[offset] & 0x7f
    return offset + 1 + numLenBytes
  }
}

function getTlvLength(data: Uint8Array, offset: number): number {
  offset++ // skip tag
  if (data[offset] < 128) {
    return data[offset]
  } else if (data[offset] === 0x81) {
    return data[offset + 1]
  } else {
    return (data[offset + 1] << 8) | data[offset + 2]
  }
}

function skipTlv(data: Uint8Array, offset: number): number {
  const valueStart = skipTagAndLength(data, offset)
  const length = getTlvLength(data, offset)
  return valueStart + length
}

function readTlvValue(data: Uint8Array, offset: number): Uint8Array {
  const valueStart = skipTagAndLength(data, offset)
  const length = getTlvLength(data, offset)
  return data.slice(valueStart, valueStart + length)
}

// ── ECDSA signing helper ──

function ecdsaSign(
  curve: ECDSA,
  rawSecretKey: Uint8Array,
  message: Uint8Array,
  hashAlgorithm: HashAlgorithm,
  format: "compact" | "der" = "compact",
): Uint8Array {
  const hashFn = HASH_FUNCTIONS[hashAlgorithm]
  const msgHash = hashFn(message)
  return curve.sign(msgHash, rawSecretKey, { prehash: false, lowS: false, format })
}

// ── Types ──

export type EcdsaCurve =
  | "P-192"
  | "P-224"
  | "P-256"
  | "P-384"
  | "P-521"
  | "brainpoolP192r1"
  | "brainpoolP192t1"
  | "brainpoolP224r1"
  | "brainpoolP224t1"
  | "brainpoolP256r1"
  | "brainpoolP256t1"
  | "brainpoolP384r1"
  | "brainpoolP384t1"
  | "brainpoolP512r1"
  | "brainpoolP512t1"

export type HashAlgorithm = "SHA-1" | "SHA-224" | "SHA-256" | "SHA-384" | "SHA-512"

export type KeyPair = {
  publicKey: Uint8Array  // SPKI DER
  privateKey: Uint8Array // PKCS8 DER
  cryptoKey: {
    publicKey: CryptoKey
    privateKey: CryptoKey
  }
} & ({ type: "RSA"; modulusLength: number } | { type: "ECDSA"; curve: EcdsaCurve; rawSecretKey: Uint8Array })

// ── RSA key generation (unchanged, uses webcrypto) ──

export async function generateRsaKeyPair(
  keySize: number,
  hashAlgorithm: HashAlgorithm = "SHA-256",
): Promise<KeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: keySize,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: hashAlgorithm,
    },
    true,
    ["sign", "verify"],
  )

  const publicKeySpki = await crypto.subtle.exportKey("spki", keyPair.publicKey)
  const privateKeyPkcs8 = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey)

  return {
    publicKey: new Uint8Array(publicKeySpki),
    privateKey: new Uint8Array(privateKeyPkcs8),
    type: "RSA",
    modulusLength: keySize,
    cryptoKey: {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
    },
  }
}

// ── ECDSA key generation (uses noble-curves) ──

export async function generateEcdsaKeyPair(
  curve: EcdsaCurve,
  _hashAlgorithm: HashAlgorithm = "SHA-256",
): Promise<KeyPair> {
  const nobleCurve = NOBLE_CURVES[curve]
  if (!nobleCurve) throw new Error(`Unsupported ECDSA curve: ${curve}`)

  const { secretKey } = nobleCurve.keygen()
  // Get uncompressed public key (04 || x || y)
  const pubKeyRaw = nobleCurve.getPublicKey(secretKey, false)
  const spki = encodeSpki(curve, pubKeyRaw)
  const pkcs8 = encodePkcs8(curve, secretKey, pubKeyRaw)

  // Create dummy CryptoKey placeholders (not used for ECDSA operations anymore)
  const dummyCryptoKey = {} as CryptoKey

  return {
    publicKey: spki,
    privateKey: pkcs8,
    type: "ECDSA",
    curve,
    rawSecretKey: secretKey,
    cryptoKey: {
      publicKey: dummyCryptoKey,
      privateKey: dummyCryptoKey,
    },
  }
}

// ── Certificate generation ──

export async function generateSigningCertificates({
  cscSigningHashAlgorithm = "SHA-256",
  cscKeyType = "ECDSA",
  cscCurve = "P-521",
  dscSigningHashAlgorithm = "SHA-256",
  dscKeyType = "ECDSA",
  dscCurve = "P-256",
  cscKeySize = 4096,
  dscKeySize = 2048,
  dscKeypair,
  issuingCountry = "AU",
}: {
  cscSigningHashAlgorithm?: HashAlgorithm
  cscKeyType?: "RSA" | "ECDSA"
  dscSigningHashAlgorithm?: HashAlgorithm
  dscKeyType?: "RSA" | "ECDSA"
  cscCurve?: EcdsaCurve
  dscCurve?: EcdsaCurve
  cscKeySize?: number
  dscKeySize?: number
  dscKeypair?: KeyPair
  issuingCountry?: string
} = {}) {
  const cscKeys =
    cscKeyType === "RSA"
      ? await generateRsaKeyPair(cscKeySize, cscSigningHashAlgorithm)
      : await generateEcdsaKeyPair(cscCurve, cscSigningHashAlgorithm)

  const dscKeys =
    dscKeypair ||
    (dscKeyType === "RSA"
      ? await generateRsaKeyPair(dscKeySize, dscSigningHashAlgorithm)
      : await generateEcdsaKeyPair(dscCurve, dscSigningHashAlgorithm))

  const cscSubjectKeyIdentifier = sha256(cscKeys.publicKey)
  const dscSubjectKeyIdentifier = sha256(dscKeys.publicKey)

  const cscCert = await generateCertificate({
    subject: [
      { type: "2.5.4.3", value: "ZKpassport Test Root CSC" },
      { type: "2.5.4.6", value: issuingCountry },
    ],
    issuer: [
      { type: "2.5.4.3", value: "ZKpassport Test Root CSC" },
      { type: "2.5.4.6", value: issuingCountry },
    ],
    publicKey: cscKeys.publicKey,
    signingKeyPair: cscKeys,
    isCA: true,
    validityYears: 10,
    serialNumber: new Uint8Array([0x01]),
    subjectKeyIdentifier: new Uint8Array(cscSubjectKeyIdentifier),
    hashAlgorithm: cscSigningHashAlgorithm,
  })

  const dscCert = await generateCertificate({
    subject: [{ type: "2.5.4.3", value: "ZKPassport Test DSC" }],
    issuer: [
      { type: "2.5.4.3", value: "ZKpassport Test Root CSC" },
      { type: "2.5.4.6", value: issuingCountry },
    ],
    publicKey: dscKeys.publicKey,
    signingKeyPair: cscKeys,
    isCA: false,
    validityYears: 2,
    serialNumber: new Uint8Array([0x02]),
    subjectKeyIdentifier: new Uint8Array(dscSubjectKeyIdentifier),
    authorityKeyIdentifier: new Uint8Array(cscSubjectKeyIdentifier),
    hashAlgorithm: cscSigningHashAlgorithm,
  })

  const cscPem = PemConverter.encode(AsnSerializer.serialize(cscCert), "CERTIFICATE")
  const dscPem = PemConverter.encode(AsnSerializer.serialize(dscCert), "CERTIFICATE")

  return {
    csc: cscCert,
    cscPem,
    cscKeys,
    dsc: dscCert,
    dscPem,
    dscKeys,
  }
}

interface CertificateParams {
  subject: { type: string; value: string }[]
  issuer: { type: string; value: string }[]
  publicKey: Uint8Array
  signingKeyPair: KeyPair
  isCA: boolean
  validityYears: number
  serialNumber?: Uint8Array
  subjectKeyIdentifier?: Uint8Array
  authorityKeyIdentifier?: Uint8Array
  hashAlgorithm?: HashAlgorithm
}

function buildName(attrs: { type: string; value: string }[]): Name {
  const rdns: RelativeDistinguishedName[] = attrs.map((attr) => {
    // Country (2.5.4.6) uses PrintableString, others use UTF8String
    const value = attr.type === "2.5.4.6"
      ? new AttributeValue({ printableString: attr.value })
      : new AttributeValue({ utf8String: attr.value })
    const atv = new AttributeTypeAndValue({ type: attr.type, value })
    return new RelativeDistinguishedName([atv])
  })
  return new Name(rdns)
}

export async function generateCertificate(params: CertificateParams): Promise<Certificate> {
  // For RSA, keep using X509CertificateGenerator (webcrypto)
  if (params.signingKeyPair.type === "RSA") {
    return generateCertificateWithWebCrypto(params)
  }

  // For ECDSA, build certificate manually and sign with noble-curves
  const hashAlgorithm = params.hashAlgorithm || "SHA-256"
  const signingCurve = params.signingKeyPair.curve
  const signAlgOid = ECDSA_SIGN_OIDS[hashAlgorithm]

  const extensions = new Extensions([
    new X509Extension({
      extnID: "2.5.29.19",
      critical: true,
      extnValue: new OctetString(AsnSerializer.serialize(new BasicConstraints({ cA: params.isCA }))),
    }),
    new X509Extension({
      extnID: "2.5.29.15",
      critical: true,
      extnValue: new OctetString(
        AsnSerializer.serialize(
          new KeyUsage(
            params.isCA
              ? KeyUsageFlags.keyCertSign | KeyUsageFlags.digitalSignature
              : KeyUsageFlags.digitalSignature,
          ),
        ),
      ),
    }),
    ...(params.subjectKeyIdentifier
      ? [
          new X509Extension({
            extnID: "2.5.29.14",
            critical: false,
            extnValue: new OctetString(
              AsnSerializer.serialize(new SubjectKeyIdentifier(params.subjectKeyIdentifier)),
            ),
          }),
        ]
      : []),
    ...(params.authorityKeyIdentifier
      ? [
          new X509Extension({
            extnID: "2.5.29.35",
            critical: false,
            extnValue: new OctetString(
              AsnSerializer.serialize(
                new AuthorityKeyIdentifier({
                  keyIdentifier: new KeyIdentifier(params.authorityKeyIdentifier),
                }),
              ),
            ),
          }),
        ]
      : []),
  ])

  const signatureAlgId = new X509AlgorithmIdentifier({ algorithm: signAlgOid })

  const tbsCert = new TBSCertificate({
    version: Version.v3,
    serialNumber: new Uint8Array(params.serialNumber || [0x01]).buffer as ArrayBuffer,
    signature: signatureAlgId,
    issuer: buildName(params.issuer),
    validity: new Validity({
      notBefore: new Date(),
      notAfter: new Date(new Date().getTime() + params.validityYears * 365 * 24 * 60 * 60 * 1000),
    }),
    subject: buildName(params.subject),
    subjectPublicKeyInfo: AsnConvert.parse(params.publicKey, SubjectPublicKeyInfo),
    extensions,
  })

  // Serialize TBS to DER
  const tbsDer = new Uint8Array(AsnSerializer.serialize(tbsCert))

  // Sign with noble-curves
  const nobleCurve = NOBLE_CURVES[signingCurve]
  const rawSecretKey = params.signingKeyPair.rawSecretKey
  const sigDer = ecdsaSign(nobleCurve, rawSecretKey, tbsDer, hashAlgorithm, "der")

  const cert = new Certificate({
    tbsCertificate: tbsCert,
    signatureAlgorithm: signatureAlgId,
    signatureValue: sigDer.buffer.slice(sigDer.byteOffset, sigDer.byteOffset + sigDer.byteLength) as ArrayBuffer,
  })

  return cert
}

async function generateCertificateWithWebCrypto(params: CertificateParams): Promise<Certificate> {
  const extensions = [
    new Extension(
      "2.5.29.19",
      true,
      AsnSerializer.serialize(new BasicConstraints({ cA: params.isCA })),
    ),
    new Extension(
      "2.5.29.15",
      true,
      AsnSerializer.serialize(
        new KeyUsage(
          params.isCA
            ? KeyUsageFlags.keyCertSign | KeyUsageFlags.digitalSignature
            : KeyUsageFlags.digitalSignature,
        ),
      ),
    ),
    ...(params.subjectKeyIdentifier
      ? [
          new Extension(
            "2.5.29.14",
            false,
            AsnSerializer.serialize(new SubjectKeyIdentifier(params.subjectKeyIdentifier)),
          ),
        ]
      : []),
    ...(params.authorityKeyIdentifier
      ? [
          new Extension(
            "2.5.29.35",
            false,
            AsnSerializer.serialize(
              new AuthorityKeyIdentifier({
                keyIdentifier: new KeyIdentifier(params.authorityKeyIdentifier),
              }),
            ),
          ),
        ]
      : []),
  ]

  const x509Certificate = await X509CertificateGenerator.create(
    {
      serialNumber: params.serialNumber ? Buffer.from(params.serialNumber).toString("hex") : "1",
      notBefore: new Date(),
      notAfter: new Date(new Date().getTime() + params.validityYears * 365 * 24 * 60 * 60 * 1000),
      extensions: extensions,
      subject: params.subject.map((attr) => `${attr.type}=${attr.value}`).join(","),
      issuer: params.issuer.map((attr) => `${attr.type}=${attr.value}`).join(","),
      publicKey: params.publicKey,
      signingKey: params.signingKeyPair.cryptoKey.privateKey,
    },
    crypto as any,
  )

  const pemString = await x509Certificate.toString("pem")
  const rawCert = PemConverter.decode(pemString)[0]
  return AsnConvert.parse(rawCert, Certificate)
}

// ── SOD signing ──

export async function signSod(sod: SignedData, signerKeys: KeyPair, hashAlgorithm: HashAlgorithm) {
  const signedAttrs = new ASN.AttributeSet(sod.signerInfos[0]?.signedAttrs?.map((v) => v))
  const signedAttrsBytes = new Uint8Array(AsnConvert.serialize(signedAttrs))

  let signature: Uint8Array

  if (signerKeys.type === "RSA") {
    const algorithm = { name: "RSASSA-PKCS1-v1_5", hash: hashAlgorithm }
    signature = new Uint8Array(
      await crypto.subtle.sign(algorithm, signerKeys.cryptoKey.privateKey, signedAttrsBytes),
    )
  } else {
    // Use noble-curves for ECDSA signing
    const nobleCurve = NOBLE_CURVES[signerKeys.curve]
    // WebCrypto returns IEEE P1363 format (r || s), so use 'compact'
    signature = ecdsaSign(nobleCurve, signerKeys.rawSecretKey, signedAttrsBytes, hashAlgorithm, "compact")
  }

  const newSod = new SignedData({
    version: sod.version,
    digestAlgorithms: sod.digestAlgorithms,
    encapContentInfo: sod.encapContentInfo,
    certificates: sod.certificates,
    signerInfos: new SignerInfos([
      new SignerInfo({
        version: sod.signerInfos[0].version,
        sid: sod.signerInfos[0].sid,
        digestAlgorithm: sod.signerInfos[0].digestAlgorithm,
        signedAttrs: sod.signerInfos[0].signedAttrs,
        signatureAlgorithm: sod.signerInfos[0].signatureAlgorithm,
        signature: new OctetString(signature),
      }),
    ]),
  })

  return { signature, sod: newSod }
}

// ── File I/O ──

export function saveSodToFile(sod: SignedData, filePath: string, asJson = false) {
  const encoded = AsnSerializer.serialize(wrapSodInContentInfo(sod))
  if (!fs) {
    throw new Error("File system operations are only available in Node.js environment")
  }
  if (asJson) {
    fs.writeFileSync(
      filePath,
      JSON.stringify({
        encoded: Buffer.from(encoded).toString("base64"),
      }),
    )
  } else {
    fs.writeFileSync(filePath, Buffer.from(encoded))
  }
}

export function saveCertificateToFile(certificate: Certificate, filePath: string) {
  const encoded = AsnSerializer.serialize(certificate)
  if (!fs) {
    throw new Error("File system operations are only available in Node.js environment")
  }
  fs.writeFileSync(filePath, Buffer.from(encoded))
}

export function saveDG1ToFile(dg1: Binary, filePath: string) {
  if (!fs) {
    throw new Error("File system operations are only available in Node.js environment")
  }
  fs.writeFileSync(filePath, dg1.toBuffer())
}

export function saveKeypairToFile(
  keypair: KeyPair,
  filePath: string,
  hashAlgorithm: HashAlgorithm = "SHA-256",
) {
  const keypairData = {
    publicKey: Buffer.from(keypair.publicKey).toString("base64"),
    privateKey: Buffer.from(keypair.privateKey).toString("base64"),
    hashAlgorithm,
    type: keypair.type,
    ...(keypair.type === "RSA"
      ? { modulusLength: keypair.modulusLength }
      : { curve: keypair.curve }),
  }
  if (!fs) {
    throw new Error("File system operations are only available in Node.js environment")
  }
  fs.writeFileSync(filePath, JSON.stringify(keypairData, null, 2))
}

export async function loadKeypairFromFile(filePath: string): Promise<KeyPair> {
  if (!fs) {
    throw new Error("File system operations are only available in Node.js environment")
  }
  const keypairData = JSON.parse(fs.readFileSync(filePath, "utf-8"))
  const publicKey = new Uint8Array(Buffer.from(keypairData.publicKey, "base64"))
  const privateKey = new Uint8Array(Buffer.from(keypairData.privateKey, "base64"))
  const hashAlgorithm = keypairData.hashAlgorithm || "SHA-256"

  if (keypairData.type === "RSA") {
    const publicKeyCrypto = await crypto.subtle.importKey(
      "spki",
      publicKey,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: hashAlgorithm,
      },
      true,
      ["verify"],
    )

    const privateKeyCrypto = await crypto.subtle.importKey(
      "pkcs8",
      privateKey,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: hashAlgorithm,
      },
      true,
      ["sign"],
    )

    return {
      publicKey,
      privateKey,
      type: "RSA",
      modulusLength: keypairData.modulusLength,
      cryptoKey: {
        publicKey: publicKeyCrypto,
        privateKey: privateKeyCrypto,
      },
    }
  } else {
    // Extract raw secret key from PKCS8 DER
    const rawSecretKey = extractRawSecretKeyFromPkcs8(privateKey)
    const dummyCryptoKey = {} as CryptoKey

    return {
      publicKey,
      privateKey,
      type: "ECDSA",
      curve: keypairData.curve,
      rawSecretKey,
      cryptoKey: {
        publicKey: dummyCryptoKey,
        privateKey: dummyCryptoKey,
      },
    }
  }
}
