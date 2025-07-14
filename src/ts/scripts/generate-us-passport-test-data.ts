import * as path from "path"
import * as fs from "fs"
import {
  generateEcdsaKeyPair,
  generateCertificate,
  signSod,
  saveSodToFile,
  saveKeypairToFile,
  EcdsaCurve,
  HashAlgorithm,
  KeyPair,
} from "../passport-generator"
import { Binary } from "@zkpassport/utils"
import { generateSod } from "../sod-generator"
import { PemConverter } from "@peculiar/x509"
import { AsnSerializer } from "@peculiar/asn1-schema"
import { Certificate } from "@peculiar/asn1-x509"

// US Passport test data for benchmarking
// Fictional citizen: John Doe
const johnDoeMRZ = 
  "P<USADOE<<JOHN<PAUL<<<<<<<<<<<<<<<<<<<<<<<<<<123456789<USA8506151M3012315<<<<<<<<<<<<<<<<"
const johnDoeDG1 = Binary.fromHex("615B5F1F58").concat(Binary.from(johnDoeMRZ))

// Configuration for ECDSA P-256 with SHA-256
const CURVE: EcdsaCurve = "P-256"
const HASH_ALG: HashAlgorithm = "SHA-256"
const COUNTRY_CODE = "USA"
const OUTPUT_DIR = path.join(__dirname, "..", "tests", "fixtures", "us-passport")

async function generateUSPassportData() {
  console.log("Generating US passport test data with ECDSA P-256 + SHA-256...")
  
  // Ensure output directory exists
  if (!fs.existsSync(OUTPUT_DIR)) {
    fs.mkdirSync(OUTPUT_DIR, { recursive: true })
  }

  // Step 1: Generate US CSCA (Country Signing CA) with ECDSA P-256
  console.log("1. Generating US CSCA certificate...")
  const cscaKeyPair = await generateEcdsaKeyPair(CURVE, HASH_ALG)
  
  const subjectKeyIdentifier = await crypto.subtle.digest("SHA-256", cscaKeyPair.publicKey)
  const cscaCert = await generateCertificate({
    subject: [
      { type: "2.5.4.3", value: "US Country Signing CA" },
      { type: "2.5.4.6", value: COUNTRY_CODE },
      { type: "2.5.4.10", value: "Department of State" },
      { type: "2.5.4.11", value: "Bureau of Consular Affairs" },
    ],
    issuer: [
      { type: "2.5.4.3", value: "US Country Signing CA" },
      { type: "2.5.4.6", value: COUNTRY_CODE },
      { type: "2.5.4.10", value: "Department of State" },
      { type: "2.5.4.11", value: "Bureau of Consular Affairs" },
    ],
    publicKey: cscaKeyPair.publicKey,
    signingKeyPair: cscaKeyPair,
    isCA: true,
    validityYears: 15,
    serialNumber: new Uint8Array([0x01, 0x00, 0x00, 0x01]),
    subjectKeyIdentifier: new Uint8Array(subjectKeyIdentifier),
    authorityKeyIdentifier: new Uint8Array(subjectKeyIdentifier),
    hashAlgorithm: HASH_ALG,
  })

  const cscaPem = PemConverter.encode(AsnSerializer.serialize(cscaCert), "CERTIFICATE")
  const cscaPath = path.join(OUTPUT_DIR, "us-csca-ecdsa-p256-sha256.pem")
  fs.writeFileSync(cscaPath, cscaPem)
  
  const cscaKeypairPath = path.join(OUTPUT_DIR, "us-csca-ecdsa-p256-sha256-keypair.json")
  saveKeypairToFile(cscaKeyPair, cscaKeypairPath, HASH_ALG)
  console.log(`  ✓ CSCA certificate saved to: ${cscaPath}`)

  // Step 2: Generate US DSC (Document Signing Certificate) signed by CSCA
  console.log("2. Generating US DSC certificate...")
  const dscKeyPair = await generateEcdsaKeyPair(CURVE, HASH_ALG)
  
  const dscSubjectKeyIdentifier = await crypto.subtle.digest("SHA-256", dscKeyPair.publicKey)
  const dscCert = await generateCertificate({
    subject: [
      { type: "2.5.4.3", value: "US Document Signing Certificate" },
      { type: "2.5.4.6", value: COUNTRY_CODE },
      { type: "2.5.4.10", value: "Department of State" },
      { type: "2.5.4.11", value: "Passport Services" },
    ],
    issuer: [
      { type: "2.5.4.3", value: "US Country Signing CA" },
      { type: "2.5.4.6", value: COUNTRY_CODE },
      { type: "2.5.4.10", value: "Department of State" },
      { type: "2.5.4.11", value: "Bureau of Consular Affairs" },
    ],
    publicKey: dscKeyPair.publicKey,
    signingKeyPair: cscaKeyPair,
    isCA: false,
    validityYears: 5,
    serialNumber: new Uint8Array([0x02, 0x00, 0x00, 0x01]),
    subjectKeyIdentifier: new Uint8Array(dscSubjectKeyIdentifier),
    authorityKeyIdentifier: new Uint8Array(subjectKeyIdentifier),
    hashAlgorithm: HASH_ALG,
  })

  const dscPem = PemConverter.encode(AsnSerializer.serialize(dscCert), "CERTIFICATE")
  const dscPath = path.join(OUTPUT_DIR, "us-dsc-ecdsa-p256-sha256.pem")
  fs.writeFileSync(dscPath, dscPem)
  
  const dscKeypairPath = path.join(OUTPUT_DIR, "us-dsc-ecdsa-p256-sha256-keypair.json")
  saveKeypairToFile(dscKeyPair, dscKeypairPath, HASH_ALG)
  console.log(`  ✓ DSC certificate saved to: ${dscPath}`)

  // Step 3: Generate SOD (Security Object Document) for John Doe's passport
  console.log("3. Generating passport SOD for John Doe...")
  const { sod } = generateSod(johnDoeDG1, [dscCert], HASH_ALG)

  const { sod: signedSod } = await signSod(
    sod,
    dscKeyPair,
    HASH_ALG,
  )

  const sodPath = path.join(OUTPUT_DIR, "john-doe-us-passport-ecdsa-p256-sha256.sod")
  await saveSodToFile(signedSod, sodPath)
  console.log(`  ✓ SOD saved to: ${sodPath}`)

  // Step 4: Save DG1 data separately for easy access
  const dg1Path = path.join(OUTPUT_DIR, "john-doe-dg1.bin")
  fs.writeFileSync(dg1Path, johnDoeDG1.toBuffer())
  console.log(`  ✓ DG1 saved to: ${dg1Path}`)

  // Step 5: Create a summary JSON file with all the test data info
  const summary = {
    description: "US Passport test data for ECDSA P-256 + SHA-256 benchmarking",
    signatureAlgorithm: "ECDSA",
    curve: CURVE,
    hashAlgorithm: HASH_ALG,
    countryCode: COUNTRY_CODE,
    holder: {
      name: "John Paul Doe",
      passportNumber: "123456789",
      nationality: "USA",
      dateOfBirth: "1985-06-15",
      gender: "M",
      expiryDate: "2030-12-31",
    },
    files: {
      csca: "us-csca-ecdsa-p256-sha256.pem",
      dsc: "us-dsc-ecdsa-p256-sha256.pem",
      sod: "john-doe-us-passport-ecdsa-p256-sha256.sod",
      dg1: "john-doe-dg1.bin",
    },
    mrz: johnDoeMRZ,
  }

  const summaryPath = path.join(OUTPUT_DIR, "test-data-summary.json")
  fs.writeFileSync(summaryPath, JSON.stringify(summary, null, 2))
  console.log(`  ✓ Summary saved to: ${summaryPath}`)

  console.log("\n✅ US passport test data generation complete!")
  console.log(`   All files saved to: ${OUTPUT_DIR}`)
}

// Run the generator
generateUSPassportData().catch((error) => {
  console.error("Error generating US passport test data:", error)
  process.exit(1)
})