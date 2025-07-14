import { Binary } from "@zkpassport/utils"
import { SignedData, SignerInfo, SignerInfos } from "@peculiar/asn1-cms"
import { AsnConvert, AsnSerializer, OctetString } from "@peculiar/asn1-schema"
import {
  Certificate,
  BasicConstraints,
  KeyUsage,
  SubjectKeyIdentifier,
  AuthorityKeyIdentifier,
  KeyIdentifier,
} from "@peculiar/asn1-x509"
import { cryptoProvider, PemConverter, X509CertificateGenerator, Extension } from "@peculiar/x509"
import { ASN } from "./asn"
import { wrapSodInContentInfo } from "./sod-generator"
import { Crypto, CryptoKey } from "@peculiar/webcrypto"
import { KeyUsageFlags } from "@peculiar/asn1-x509"
import fs from "fs"

const crypto = new Crypto()
cryptoProvider.set(crypto as any)

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

export type HashAlgorithm = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512"

export type KeyPair = {
  publicKey: Uint8Array
  privateKey: Uint8Array
  cryptoKey: {
    publicKey: CryptoKey
    privateKey: CryptoKey
  }
} & ({ type: "RSA"; modulusLength: number } | { type: "ECDSA"; curve: EcdsaCurve })

export async function generateRsaKeyPair(
  keySize: number,
  hashAlgorithm: HashAlgorithm = "SHA-256",
): Promise<KeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: keySize,
      publicExponent: new Uint8Array([1, 0, 1]), // 65537
      hash: hashAlgorithm,
    },
    true,
    ["sign", "verify"],
  )

  // Export the keys
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

export async function generateEcdsaKeyPair(
  curve: EcdsaCurve,
  hashAlgorithm: HashAlgorithm = "SHA-256",
): Promise<KeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: curve,
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
    type: "ECDSA",
    curve,
    cryptoKey: {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
    },
  }
}

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
  // Generate or use provided key pairs
  const cscKeys =
    cscKeyType === "RSA"
      ? await generateRsaKeyPair(cscKeySize, cscSigningHashAlgorithm)
      : await generateEcdsaKeyPair(cscCurve, cscSigningHashAlgorithm)

  const dscKeys =
    dscKeypair ||
    (dscKeyType === "RSA"
      ? await generateRsaKeyPair(dscKeySize, dscSigningHashAlgorithm)
      : await generateEcdsaKeyPair(dscCurve, dscSigningHashAlgorithm))

  const cscSubjectKeyIdentifier = await crypto.subtle.digest("SHA-256", cscKeys.publicKey)
  const dscSubjectKeyIdentifier = await crypto.subtle.digest("SHA-256", dscKeys.publicKey)

  // Generate CSCA certificate
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

  // Generate DSC certificate
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
    hashAlgorithm: dscSigningHashAlgorithm,
  })

  // Convert to PEM format
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

export async function generateCertificate(params: CertificateParams): Promise<Certificate> {
  const extensions = [
    new Extension(
      "2.5.29.19", // basicConstraints
      true,
      AsnSerializer.serialize(new BasicConstraints({ cA: params.isCA })),
    ),
    new Extension(
      "2.5.29.15", // keyUsage
      true,
      AsnSerializer.serialize(
        new KeyUsage(
          // keyCertSign + digitalSignature for CSCA, digitalSignature for DSC
          params.isCA
            ? KeyUsageFlags.keyCertSign | KeyUsageFlags.digitalSignature
            : KeyUsageFlags.digitalSignature,
        ),
      ),
    ),
    ...(params.subjectKeyIdentifier
      ? [
          new Extension(
            "2.5.29.14", // subjectKeyIdentifier
            false,
            AsnSerializer.serialize(new SubjectKeyIdentifier(params.subjectKeyIdentifier)),
          ),
        ]
      : []),
    ...(params.authorityKeyIdentifier
      ? [
          new Extension(
            "2.5.29.35", // authorityKeyIdentifier
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

  // Create the certificate with explicit algorithm
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

  // Convert to ASN.1 Certificate
  const pemString = await x509Certificate.toString("pem")
  const rawCert = PemConverter.decode(pemString)[0]
  return AsnConvert.parse(rawCert, Certificate)
}

export async function signSod(sod: SignedData, signerKeys: KeyPair, hashAlgorithm: HashAlgorithm) {
  const signedAttrs = new ASN.AttributeSet(sod.signerInfos[0]?.signedAttrs?.map((v) => v))
  const signedAttrsBytes = AsnConvert.serialize(signedAttrs)

  const algorithm =
    signerKeys.type === "RSA"
      ? { name: "RSASSA-PKCS1-v1_5", hash: hashAlgorithm }
      : {
          name: "ECDSA",
          hash: hashAlgorithm,
        }

  const signature = new Uint8Array(
    await crypto.subtle.sign(algorithm, signerKeys.cryptoKey.privateKey, signedAttrsBytes),
  )

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
  const publicKey = Buffer.from(keypairData.publicKey, "base64")
  const privateKey = Buffer.from(keypairData.privateKey, "base64")
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
    const publicKeyCrypto = await crypto.subtle.importKey(
      "spki",
      publicKey,
      {
        name: "ECDSA",
        namedCurve: keypairData.curve,
      },
      true,
      ["verify"],
    )

    const privateKeyCrypto = await crypto.subtle.importKey(
      "pkcs8",
      privateKey,
      {
        name: "ECDSA",
        namedCurve: keypairData.curve,
      },
      true,
      ["sign"],
    )

    return {
      publicKey,
      privateKey,
      type: "ECDSA",
      curve: keypairData.curve,
      cryptoKey: {
        publicKey: publicKeyCrypto,
        privateKey: privateKeyCrypto,
      },
    }
  }
}
