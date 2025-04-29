import * as path from "path"
import {
  generateRsaKeyPair,
  generateEcdsaKeyPair,
  signSod,
  generateCertificate,
  HashAlgorithm,
  EcdsaCurve,
  KeyPair,
  saveSodToFile,
  saveKeypairToFile,
  loadKeypairFromFile,
} from "../passport-generator"
import { Binary } from "@zkpassport/utils"
import { generateSod } from "@/sod-generator"
import * as fs from "fs"
import { PemConverter } from "@peculiar/x509"
import { AsnSerializer } from "@peculiar/asn1-schema"
import { Certificate } from "@peculiar/asn1-x509"

// John Miller Smith's MRZ
const johnMRZ =
  "P<ZKRSMITH<<JOHN<MILLER<<<<<<<<<<<<<<<<<<<<<ZP1111111_ZKR951112_M350101_<<<<<<<<<<<<<<<<"
const johnDG1 = Binary.fromHex("615B5F1F58").concat(Binary.from(johnMRZ))

// Jane Miller Smith's MRZ
const janeMRZ =
  "P<ZKRSMITH<<JANE<MILLER<<<<<<<<<<<<<<<<<<<<<ZP3333333_ZKR090225_F270101_<<<<<<<<<<<<<<<<"
const janeDG1 = Binary.fromHex("615B5F1F58").concat(Binary.from(janeMRZ))

// Jack Miller Smith's MRZ
const jackMRZ =
  "P<ZKRSMITH<<JACK<MILLER<<<<<<<<<<<<<<<<<<<<<ZP4444444_ZKR020414_M280101_<<<<<<<<<<<<<<<<"
const jackDG1 = Binary.fromHex("615B5F1F58").concat(Binary.from(jackMRZ))

// Mary Miller Smith's MRZ
const maryMRZ =
  "P<ZKRSMITH<<MARY<MILLER<<<<<<<<<<<<<<<<<<<<<ZP2222222_ZKR750302_F300101_<<<<<<<<<<<<<<<<"
const maryDG1 = Binary.fromHex("615B5F1F58").concat(Binary.from(maryMRZ))

// Paul Miller Smith's MRZ
const paulMRZ =
  "P<ZKRSMITH<<PAUL<MILLER<<<<<<<<<<<<<<<<<<<<<ZP6666666_ZKR500717_M310101_<<<<<<<<<<<<<<<<"
const paulDG1 = Binary.fromHex("615B5F1F58").concat(Binary.from(paulMRZ))

// Stephanie Miller Smith's MRZ
const stephanieMRZ =
  "P<ZKRSMITH<<STEPHANIE<MILLER<<<<<<<<<<<<<<<<ZP5555555_ZKR150503_F290101_<<<<<<<<<<<<<<<<"
const stephanieDG1 = Binary.fromHex("615B5F1F58").concat(Binary.from(stephanieMRZ))

async function generateCSCA({
  hashAlg,
  keyType,
  keySize,
  curve,
  filePath,
  countryCode,
  subjectName,
  serialNumber,
  years,
}: {
  hashAlg: HashAlgorithm
  keyType: "RSA" | "ECDSA"
  keySize?: number
  curve?: EcdsaCurve
  filePath?: string
  countryCode: string
  subjectName: string
  serialNumber?: Uint8Array
  years?: number
}) {
  let keyPair: KeyPair
  if (filePath) {
    // Check if the file already exists and if yes
    // loads the keypair rather than generating a new one
    const keypairPath = path.join(
      path.dirname(filePath),
      "keypairs",
      path.basename(filePath).replace(".pem", ".json"),
    )
    keyPair = await loadKeypairFromFile(keypairPath)
  } else {
    keyPair =
      keyType === "RSA"
        ? await generateRsaKeyPair(keySize!, hashAlg)
        : await generateEcdsaKeyPair(curve!, hashAlg)
  }
  const subjectKeyIdentifier = await crypto.subtle.digest("SHA-256", keyPair.publicKey)
  const authorityKeyIdentifier = subjectKeyIdentifier
  const cscaCert = await generateCertificate({
    subject: [
      { type: "2.5.4.3", value: subjectName },
      { type: "2.5.4.6", value: countryCode },
    ],
    issuer: [
      { type: "2.5.4.3", value: subjectName }, // Self-signed
      { type: "2.5.4.6", value: countryCode },
    ],
    publicKey: keyPair.publicKey,
    signingKeyPair: keyPair,
    isCA: true,
    validityYears: years ?? 10,
    serialNumber: serialNumber ?? new Uint8Array([0x01]),
    subjectKeyIdentifier: new Uint8Array(subjectKeyIdentifier),
    authorityKeyIdentifier: new Uint8Array(authorityKeyIdentifier),
    hashAlgorithm: hashAlg,
  })
  const cscaPem = PemConverter.encode(AsnSerializer.serialize(cscaCert), "CERTIFICATE")
  if (filePath) {
    fs.writeFileSync(filePath, cscaPem)
    const keypairPath = path.join(
      path.dirname(filePath),
      "keypairs",
      path.basename(filePath).replace(".pem", ".json"),
    )
    saveKeypairToFile(keyPair, keypairPath, hashAlg)
  }
  return { cert: cscaCert, pem: cscaPem, keyPair }
}

async function generateDSC({
  hashAlg,
  keyType,
  keySize,
  curve,
  filePath,
  countryCode,
  subjectName,
  issuerName,
  issuerCountryCode,
  signingKeyPair,
  serialNumber,
  years,
}: {
  hashAlg: HashAlgorithm
  keyType: "RSA" | "ECDSA"
  keySize?: number
  curve?: EcdsaCurve
  filePath?: string
  countryCode: string
  subjectName: string
  issuerName: string
  issuerCountryCode: string
  signingKeyPair: KeyPair
  serialNumber?: Uint8Array
  years?: number
}) {
  let keyPair: KeyPair
  if (filePath) {
    // Check if the file already exists and if yes
    // loads the keypair rather than generating a new one
    const keypairPath = path.join(
      path.dirname(filePath),
      "keypairs",
      path.basename(filePath).replace(".pem", ".json"),
    )
    keyPair = await loadKeypairFromFile(keypairPath)
  } else {
    keyPair =
      keyType === "RSA"
        ? await generateRsaKeyPair(keySize!, hashAlg)
        : await generateEcdsaKeyPair(curve!, hashAlg)
  }
  const subjectKeyIdentifier = await crypto.subtle.digest("SHA-256", keyPair.publicKey)
  const authorityKeyIdentifier = await crypto.subtle.digest("SHA-256", signingKeyPair.publicKey)
  const dscCert = await generateCertificate({
    subject: [
      { type: "2.5.4.3", value: subjectName },
      { type: "2.5.4.6", value: countryCode },
    ],
    issuer: [
      { type: "2.5.4.3", value: issuerName },
      { type: "2.5.4.6", value: issuerCountryCode },
    ],
    publicKey: keyPair.publicKey,
    signingKeyPair,
    isCA: false,
    validityYears: years ?? 2,
    serialNumber: serialNumber ?? new Uint8Array([0x01]),
    subjectKeyIdentifier: new Uint8Array(subjectKeyIdentifier),
    authorityKeyIdentifier: new Uint8Array(authorityKeyIdentifier),
    hashAlgorithm: hashAlg,
  })
  const dscPem = PemConverter.encode(AsnSerializer.serialize(dscCert), "CERTIFICATE")
  if (filePath) {
    fs.writeFileSync(filePath, dscPem)
    const keypairPath = path.join(
      path.dirname(filePath),
      "keypairs",
      path.basename(filePath).replace(".pem", ".json"),
    )
    saveKeypairToFile(keyPair, keypairPath, hashAlg)
  }
  return { cert: dscCert, pem: dscPem, keyPair }
}

async function generateAndSignSod({
  dg1,
  dsc,
  signingKeyPair,
  hashAlg,
  filePath,
}: {
  dg1: Binary
  dsc: Certificate
  signingKeyPair: KeyPair
  hashAlg: HashAlgorithm
  filePath: string
}) {
  // Generate SOD and sign it with DSC keypair
  const { sod } = await generateSod(dg1, [dsc], hashAlg)
  const { sod: signedSod } = await signSod(sod, signingKeyPair, hashAlg)
  saveSodToFile(signedSod, filePath, true)
}

/*
 * Zero Knowledge Republic Root CA (RSA 2048 SHA-256)
 *  - DSC (RSA 2048 SHA-256)
 *  - DSC (RSA 3072 SHA-384)
 *  - DSC (RSA 4096 SHA-512)
 *
 * Zero Knowledge Republic Root CA (ECDSA P-256 SHA-256)
 *  - DSC (ECDSA P-256 SHA-256)
 *  - DSC (ECDSA P-384 SHA-384)
 *  - DSC (ECDSA P-521 SHA-512)
 */

const fixturesDir = path.join(__dirname, "../tests/fixtures/zkr")
const cscaCountry = "ZK"
const dscCountry = "ZK"
const cscaSubject = "Zero Knowledge Republic CSCA"
const dscSubject = "Zero Knowledge Republic DSC"

const cscaRsa = await generateCSCA({
  hashAlg: "SHA-256",
  keyType: "RSA",
  keySize: 2048,
  countryCode: cscaCountry,
  subjectName: cscaSubject,
  serialNumber: new Uint8Array([0x01]),
  years: 10,
  filePath: path.join(fixturesDir, "zkr-csca-rsa-2048-sha256.pem"),
})

const dscRsa2048Sha256 = await generateDSC({
  hashAlg: "SHA-256",
  keyType: "RSA",
  keySize: 2048,
  countryCode: dscCountry,
  subjectName: dscSubject,
  issuerCountryCode: cscaCountry,
  issuerName: cscaSubject,
  signingKeyPair: cscaRsa.keyPair,
  serialNumber: new Uint8Array([0x02]),
  years: 10,
  filePath: path.join(fixturesDir, "zkr-dsc-rsa-2048-sha256.pem"),
})
const dscRsa3072Sha384 = await generateDSC({
  hashAlg: "SHA-384",
  keyType: "RSA",
  keySize: 3072,
  countryCode: dscCountry,
  subjectName: dscSubject,
  issuerCountryCode: cscaCountry,
  issuerName: cscaSubject,
  signingKeyPair: cscaRsa.keyPair,
  serialNumber: new Uint8Array([0x03]),
  years: 10,
  filePath: path.join(fixturesDir, "zkr-dsc-rsa-3072-sha384.pem"),
})
const dscRsa4096Sha512 = await generateDSC({
  hashAlg: "SHA-512",
  keyType: "RSA",
  keySize: 4096,
  countryCode: dscCountry,
  subjectName: dscSubject,
  issuerCountryCode: cscaCountry,
  issuerName: cscaSubject,
  signingKeyPair: cscaRsa.keyPair,
  serialNumber: new Uint8Array([0x04]),
  years: 10,
  filePath: path.join(fixturesDir, "zkr-dsc-rsa-4096-sha512.pem"),
})

await generateAndSignSod({
  dg1: johnDG1,
  dsc: dscRsa2048Sha256.cert,
  signingKeyPair: dscRsa2048Sha256.keyPair,
  hashAlg: "SHA-256",
  filePath: path.join(fixturesDir, "john-miller-smith-rsa-2048-sha256.json"),
})
await generateAndSignSod({
  dg1: janeDG1,
  dsc: dscRsa3072Sha384.cert,
  signingKeyPair: dscRsa3072Sha384.keyPair,
  hashAlg: "SHA-384",
  filePath: path.join(fixturesDir, "jane-miller-smith-rsa-3072-sha384.json"),
})
await generateAndSignSod({
  dg1: jackDG1,
  dsc: dscRsa4096Sha512.cert,
  signingKeyPair: dscRsa4096Sha512.keyPair,
  hashAlg: "SHA-512",
  filePath: path.join(fixturesDir, "jack-miller-smith-rsa-4096-sha512.json"),
})

const cscaEcdsa = await generateCSCA({
  hashAlg: "SHA-256",
  keyType: "ECDSA",
  curve: "P-256",
  countryCode: cscaCountry,
  subjectName: cscaSubject,
  serialNumber: new Uint8Array([0x05]),
  years: 10,
  filePath: path.join(fixturesDir, "zkr-csca-ecdsa-p256-sha256.pem"),
})
const dscEcdsaP256Sha256 = await generateDSC({
  hashAlg: "SHA-256",
  keyType: "ECDSA",
  curve: "P-256",
  countryCode: dscCountry,
  subjectName: dscSubject,
  issuerCountryCode: cscaCountry,
  issuerName: cscaSubject,
  signingKeyPair: cscaEcdsa.keyPair,
  serialNumber: new Uint8Array([0x06]),
  years: 10,
  filePath: path.join(fixturesDir, "zkr-dsc-ecdsa-p256-sha256.pem"),
})
const dscEcdsaP384Sha384 = await generateDSC({
  hashAlg: "SHA-384",
  keyType: "ECDSA",
  curve: "P-384",
  countryCode: dscCountry,
  subjectName: dscSubject,
  issuerCountryCode: cscaCountry,
  issuerName: cscaSubject,
  signingKeyPair: cscaEcdsa.keyPair,
  serialNumber: new Uint8Array([0x07]),
  years: 10,
  filePath: path.join(fixturesDir, "zkr-dsc-ecdsa-p384-sha384.pem"),
})
const dscEcdsaP521Sha512 = await generateDSC({
  hashAlg: "SHA-512",
  keyType: "ECDSA",
  curve: "P-521",
  countryCode: dscCountry,
  subjectName: dscSubject,
  issuerCountryCode: cscaCountry,
  issuerName: cscaSubject,
  signingKeyPair: cscaEcdsa.keyPair,
  serialNumber: new Uint8Array([0x08]),
  years: 10,
  filePath: path.join(fixturesDir, "zkr-dsc-ecdsa-p521-sha512.pem"),
})
await generateAndSignSod({
  dg1: maryDG1,
  dsc: dscEcdsaP256Sha256.cert,
  signingKeyPair: dscEcdsaP256Sha256.keyPair,
  hashAlg: "SHA-256",
  filePath: path.join(fixturesDir, "mary-miller-smith-ecdsa-p256-sha256.json"),
})
await generateAndSignSod({
  dg1: paulDG1,
  dsc: dscEcdsaP384Sha384.cert,
  signingKeyPair: dscEcdsaP384Sha384.keyPair,
  hashAlg: "SHA-384",
  filePath: path.join(fixturesDir, "paul-miller-smith-ecdsa-p384-sha384.json"),
})
await generateAndSignSod({
  dg1: stephanieDG1,
  dsc: dscEcdsaP521Sha512.cert,
  signingKeyPair: dscEcdsaP521Sha512.keyPair,
  hashAlg: "SHA-512",
  filePath: path.join(fixturesDir, "stephanie-miller-smith-ecdsa-p521-sha512.json"),
})

/*
To verify:
openssl verify -check_ss_sig -partial_chain -CAfile zkr-csca-rsa-2048-sha256.pem zkr-dsc-rsa-2048-sha256.pem
openssl verify -check_ss_sig -partial_chain -CAfile zkr-csca-rsa-2048-sha256.pem zkr-dsc-rsa-3072-sha384.pem
openssl verify -check_ss_sig -partial_chain -CAfile zkr-csca-rsa-2048-sha256.pem zkr-dsc-rsa-4096-sha512.pem
openssl verify -check_ss_sig -partial_chain -CAfile zkr-csca-ecdsa-p256-sha256.pem zkr-dsc-ecdsa-p256-sha256.pem
openssl verify -check_ss_sig -partial_chain -CAfile zkr-csca-ecdsa-p256-sha256.pem zkr-dsc-ecdsa-p384-sha384.pem
openssl verify -check_ss_sig -partial_chain -CAfile zkr-csca-ecdsa-p256-sha256.pem zkr-dsc-ecdsa-p521-sha512.pem
*/
