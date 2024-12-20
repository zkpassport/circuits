import { Binary } from "@/lib/binary"
import { SignedData, SignerInfo, SignerInfos } from "@peculiar/asn1-cms"
import { AsnConvert, AsnSerializer, OctetString } from "@peculiar/asn1-schema"
import { Certificate } from "@peculiar/asn1-x509"
import * as fs from "fs"
import forge from "node-forge"
import { ASN } from "./asn"
import { wrapSodInContentInfo } from "./sod-generator"

export function generateSigningCertificates(
  {
    cscSigningHashAlgorithm,
    cscKeySize,
    dscKeySize,
    dscKeypair,
  }: {
    cscSigningHashAlgorithm:
      | "md5"
      | "sha1"
      | "sha256"
      | "sha384"
      | "sha512"
      | "sha512/224"
      | "sha512/256"
    cscKeySize: number
    dscKeySize?: number
    dscKeypair?: forge.pki.rsa.KeyPair
  } = {
    cscSigningHashAlgorithm: "sha256",
    cscKeySize: 4096,
    dscKeySize: 2048,
  },
) {
  // Create the root CSC with a 4096-bit RSA key pair
  const cscKeys = forge.pki.rsa.generateKeyPair({ bits: cscKeySize })
  const cscCert = forge.pki.createCertificate()
  cscCert.publicKey = cscKeys.publicKey
  cscCert.validity.notBefore = new Date()
  cscCert.validity.notAfter = new Date()
  cscCert.validity.notAfter.setFullYear(cscCert.validity.notBefore.getFullYear() + 10)
  cscCert.setSubject([
    { name: "commonName", value: "ZKpassport Test Root CSC" },
    { name: "countryName", value: "AUS" },
  ])
  cscCert.setIssuer([
    { name: "commonName", value: "ZKpassport Test Root CSC" },
    { name: "countryName", value: "AUS" },
  ])
  const cscSubjectKeyIdentifier = cscCert.generateSubjectKeyIdentifier().getBytes()
  cscCert.setExtensions([
    { name: "basicConstraints", cA: true },
    { name: "keyUsage", keyCertSign: true, digitalSignature: true },
    { name: "subjectKeyIdentifier", keyid: cscSubjectKeyIdentifier },
  ])
  cscCert.sign(cscKeys.privateKey, forge.md.algorithms[cscSigningHashAlgorithm].create())

  // Use existing DSC keypair if provided, otherwise generate a new one
  const dscKeys = dscKeypair || forge.pki.rsa.generateKeyPair({ bits: dscKeySize })
  const dscCert = forge.pki.createCertificate()
  dscCert.publicKey = dscKeys.publicKey
  dscCert.serialNumber = "2"
  dscCert.validity.notBefore = new Date()
  dscCert.validity.notAfter = new Date()
  dscCert.validity.notAfter.setFullYear(dscCert.validity.notBefore.getFullYear() + 2)
  dscCert.setSubject([{ name: "commonName", value: "ZKpassport Test DSC" }])
  dscCert.setIssuer(cscCert.subject.attributes)
  const dscSubjectKeyIdentifier = dscCert.generateSubjectKeyIdentifier().getBytes()
  dscCert.setExtensions([
    { name: "basicConstraints", cA: false },
    { name: "keyUsage", digitalSignature: true },
    { name: "subjectKeyIdentifier", keyid: dscSubjectKeyIdentifier },
    { name: "authorityKeyIdentifier", keyIdentifier: cscSubjectKeyIdentifier },
  ])

  // Sign the DSC's TBS with root CSC's private key
  dscCert.sign(cscKeys.privateKey, forge.md.sha256.create())

  // Convert to forge.asn1.Asn1 type
  const cscAsn1 = forge.pki.certificateToAsn1(cscCert)
  const dscAsn1 = forge.pki.certificateToAsn1(dscCert)

  // Convert to PEM format
  const cscPem = forge.pki.certificateToPem(cscCert)
  const dscPem = forge.pki.certificateToPem(dscCert)

  // Convert to @peculiar/asn1-x509 Certificate type
  const dscBuffer = new Uint8Array(Buffer.from(forge.asn1.toDer(dscAsn1).getBytes(), "binary"))
  const dsc = AsnConvert.parse(dscBuffer, Certificate)
  const cscBuffer = new Uint8Array(Buffer.from(forge.asn1.toDer(cscAsn1).getBytes(), "binary"))
  const csc = AsnConvert.parse(cscBuffer, Certificate)

  return { csc, cscPem, cscKeys, dsc, dscPem, dscKeys }
}

export function signSodWithRsaKey(sod: SignedData, rsaKey: forge.pki.rsa.KeyPair["privateKey"]) {
  // Serialise signedAttrs using an AttributeSet container to ensure bytes are correct
  const signedAttrs = new ASN.AttributeSet(sod.signerInfos[0]?.signedAttrs?.map((v) => v))
  const signedAttrsBytes = AsnConvert.serialize(signedAttrs)

  // Sign signedAttrs using private key
  const md = forge.md.sha256.create()
  md.update(Buffer.from(signedAttrsBytes).toString("binary"))
  let signature = rsaKey.sign(md)

  // Create new SOD with updated signature
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
        signature: new OctetString(Buffer.from(signature, "binary")),
      }),
    ]),
  })

  return { signature, sod: newSod }
}

export function saveSodToFile(sod: SignedData, filePath: string) {
  const encoded = AsnSerializer.serialize(wrapSodInContentInfo(sod))
  fs.writeFileSync(filePath, Buffer.from(encoded))
}

export function saveCertificateToFile(certificate: Certificate, filePath: string) {
  const encoded = AsnSerializer.serialize(certificate)
  fs.writeFileSync(filePath, Buffer.from(encoded))
}

export function saveDG1ToFile(dg1: Binary, filePath: string) {
  fs.writeFileSync(filePath, dg1.toBuffer())
}

export function saveDscKeypairToFile(keypair: forge.pki.rsa.KeyPair, filePath: string) {
  const keypairData = {
    privateKey: forge.pki.privateKeyToPem(keypair.privateKey),
    publicKey: forge.pki.publicKeyToPem(keypair.publicKey),
  }
  fs.writeFileSync(filePath, JSON.stringify(keypairData, null, 2))
}

export function loadDscKeypairFromFile(filePath: string): forge.pki.rsa.KeyPair {
  const keypairData = JSON.parse(fs.readFileSync(filePath, "utf-8"))
  return {
    privateKey: forge.pki.privateKeyFromPem(keypairData.privateKey),
    publicKey: forge.pki.publicKeyFromPem(keypairData.publicKey),
  }
}
