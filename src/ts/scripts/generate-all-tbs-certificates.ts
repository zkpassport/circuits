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

// Configuration
const CURVE: EcdsaCurve = "P-256"
const HASH_ALG: HashAlgorithm = "SHA-256"
const COUNTRY_CODE = "USA"
const TBS_SIZES = [700, 1000, 1200, 1500, 1600]

// John Doe's MRZ - same for all certificates
const johnDoeMRZ = 
  "P<USADOE<<JOHN<PAUL<<<<<<<<<<<<<<<<<<<<<<<<<<123456789<USA8506151M3012315<<<<<<<<<<<<<<<<"
const johnDoeDG1 = Binary.fromHex("615B5F1F58").concat(Binary.from(johnDoeMRZ))

// Extensions to add padding to reach target TBS size
function generatePaddingExtension(targetSize: number, currentSize: number): { type: string, value: string } | null {
  const paddingNeeded = targetSize - currentSize
  
  if (paddingNeeded <= 0) return null
  
  // Use a custom extension OID and pad with a string
  // Extension format adds overhead, so we need to account for that
  const extensionOverhead = 50 // Approximate overhead for extension structure
  const contentSize = paddingNeeded - extensionOverhead
  
  if (contentSize <= 0) return null
  
  // Create padding content
  const paddingContent = "X".repeat(Math.max(1, contentSize))
  
  return {
    type: "1.2.3.4.5.6.7.8.9.10." + targetSize, // Custom OID including target size
    value: paddingContent
  }
}

async function generateCertificateForTBS(
  targetTbsSize: number,
  cscaKeyPair: KeyPair,
  subjectKeyIdentifier: Uint8Array
): Promise<{ cert: Certificate, keyPair: KeyPair }> {
  console.log(`\nGenerating certificate for TBS size ${targetTbsSize}...`)
  
  // Generate DSC key pair
  const dscKeyPair = await generateEcdsaKeyPair(CURVE, HASH_ALG)
  const dscSubjectKeyIdentifier = await crypto.subtle.digest("SHA-256", dscKeyPair.publicKey)
  
  // Start with base certificate
  let attempts = 0
  let cert: Certificate | null = null
  let currentSize = 0
  
  // Binary search for the right padding
  let minPadding = 0
  let maxPadding = targetTbsSize
  
  while (attempts < 50) {
    attempts++
    
    // Calculate padding to try
    const paddingSize = Math.floor((minPadding + maxPadding) / 2)
    
    // Build subject with padding if needed
    const subject = [
      { type: "2.5.4.3", value: "US Document Signing Certificate" },
      { type: "2.5.4.6", value: COUNTRY_CODE },
      { type: "2.5.4.10", value: "Department of State" },
      { type: "2.5.4.11", value: "Passport Services" },
    ]
    
    // Add organization unit with padding to reach target size
    if (paddingSize > 100) {
      const ouPadding = "Bureau-" + "X".repeat(Math.max(1, paddingSize - 100))
      subject.push({ type: "2.5.4.11", value: ouPadding })
    }
    
    // Generate certificate
    const testCert = await generateCertificate({
      subject,
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
      serialNumber: new Uint8Array([0x02, targetTbsSize >> 8, targetTbsSize & 0xFF, attempts]),
      subjectKeyIdentifier: new Uint8Array(dscSubjectKeyIdentifier),
      authorityKeyIdentifier: new Uint8Array(subjectKeyIdentifier),
      hashAlgorithm: HASH_ALG,
    })
    
    // Check TBS size
    currentSize = testCert.tbsCertificate ? 
      AsnSerializer.serialize(testCert.tbsCertificate).byteLength : 0
    
    console.log(`  Attempt ${attempts}: TBS size = ${currentSize} (target: ${targetTbsSize})`)
    
    if (currentSize === targetTbsSize) {
      cert = testCert
      break
    } else if (currentSize < targetTbsSize) {
      minPadding = paddingSize + 1
    } else {
      maxPadding = paddingSize - 1
    }
    
    // If we're very close, try fine-tuning
    if (Math.abs(currentSize - targetTbsSize) < 50) {
      const delta = targetTbsSize - currentSize
      if (delta > 0) {
        minPadding = paddingSize + delta - 10
        maxPadding = paddingSize + delta + 10
      } else {
        minPadding = paddingSize + delta - 10
        maxPadding = paddingSize + delta + 10
      }
    }
  }
  
  if (!cert) {
    console.log(`  ⚠️  Could not generate exact TBS size ${targetTbsSize}, closest was ${currentSize}`)
    // Use the last attempt even if not exact
    cert = await generateCertificate({
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
      serialNumber: new Uint8Array([0x02, targetTbsSize >> 8, targetTbsSize & 0xFF, 0xFF]),
      subjectKeyIdentifier: new Uint8Array(dscSubjectKeyIdentifier),
      authorityKeyIdentifier: new Uint8Array(subjectKeyIdentifier),
      hashAlgorithm: HASH_ALG,
    })
  } else {
    console.log(`  ✓ Generated certificate with exact TBS size ${targetTbsSize}`)
  }
  
  return { cert, keyPair: dscKeyPair }
}

async function generateAllTBSCertificates() {
  console.log("🚀 Generating US passport test data for all TBS sizes...")
  console.log("=" .repeat(50))
  
  // Create output directory structure
  const baseDir = path.join(__dirname, "..", "tests", "fixtures", "us-passport-all-tbs")
  if (!fs.existsSync(baseDir)) {
    fs.mkdirSync(baseDir, { recursive: true })
  }
  
  // Step 1: Generate CSCA (same for all)
  console.log("\n1. Generating US CSCA certificate...")
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
  const cscaPath = path.join(baseDir, "us-csca-ecdsa-p256-sha256.pem")
  fs.writeFileSync(cscaPath, cscaPem)
  const cscaKeypairPath = path.join(baseDir, "us-csca-ecdsa-p256-sha256-keypair.json")
  saveKeypairToFile(cscaKeyPair, cscaKeypairPath, HASH_ALG)
  console.log(`  ✓ CSCA certificate saved`)
  
  // Step 2: Generate DSC and passport data for each TBS size
  const results: any[] = []
  
  for (const tbsSize of TBS_SIZES) {
    const tbsDir = path.join(baseDir, `tbs-${tbsSize}`)
    if (!fs.existsSync(tbsDir)) {
      fs.mkdirSync(tbsDir, { recursive: true })
    }
    
    try {
      // Generate DSC with specific TBS size
      const { cert: dscCert, keyPair: dscKeyPair } = await generateCertificateForTBS(
        tbsSize,
        cscaKeyPair,
        new Uint8Array(subjectKeyIdentifier)
      )
      
      // Save DSC
      const dscPem = PemConverter.encode(AsnSerializer.serialize(dscCert), "CERTIFICATE")
      const dscPath = path.join(tbsDir, `us-dsc-tbs-${tbsSize}-ecdsa-p256-sha256.pem`)
      fs.writeFileSync(dscPath, dscPem)
      
      const dscKeypairPath = path.join(tbsDir, `us-dsc-tbs-${tbsSize}-keypair.json`)
      saveKeypairToFile(dscKeyPair, dscKeypairPath, HASH_ALG)
      
      // Verify actual TBS size
      const actualTbsSize = dscCert.tbsCertificate ? 
        AsnSerializer.serialize(dscCert.tbsCertificate).byteLength : 0
      
      console.log(`  ✓ DSC certificate saved (actual TBS: ${actualTbsSize} bytes)`)
      
      // Generate SOD
      console.log(`  Generating passport SOD...`)
      const { sod } = generateSod(johnDoeDG1, [dscCert], HASH_ALG)
      const { sod: signedSod } = await signSod(sod, dscKeyPair, HASH_ALG)
      
      const sodPath = path.join(tbsDir, `john-doe-us-passport-tbs-${tbsSize}.sod`)
      await saveSodToFile(signedSod, sodPath)
      console.log(`  ✓ SOD saved`)
      
      // Save DG1
      const dg1Path = path.join(tbsDir, "john-doe-dg1.bin")
      fs.writeFileSync(dg1Path, johnDoeDG1.toBuffer())
      
      // Create summary
      const summary = {
        description: `US Passport test data for TBS ${tbsSize}`,
        targetTbsSize: tbsSize,
        actualTbsSize: actualTbsSize,
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
          csca: "../us-csca-ecdsa-p256-sha256.pem",
          dsc: `us-dsc-tbs-${tbsSize}-ecdsa-p256-sha256.pem`,
          sod: `john-doe-us-passport-tbs-${tbsSize}.sod`,
          dg1: "john-doe-dg1.bin",
        },
      }
      
      const summaryPath = path.join(tbsDir, "summary.json")
      fs.writeFileSync(summaryPath, JSON.stringify(summary, null, 2))
      
      results.push({
        tbsSize,
        actualTbsSize,
        exactMatch: tbsSize === actualTbsSize,
        directory: `tbs-${tbsSize}`,
      })
      
    } catch (error) {
      console.error(`  ❌ Failed to generate TBS ${tbsSize}:`, error)
      results.push({
        tbsSize,
        error: error.message,
      })
    }
  }
  
  // Create overall summary
  const overallSummary = {
    generated: new Date().toISOString(),
    description: "US Passport test data for all TBS sizes",
    signatureAlgorithm: "ECDSA P-256",
    hashAlgorithm: "SHA-256",
    results,
  }
  
  const summaryPath = path.join(baseDir, "generation-summary.json")
  fs.writeFileSync(summaryPath, JSON.stringify(overallSummary, null, 2))
  
  console.log("\n" + "=" .repeat(50))
  console.log("✅ Certificate generation complete!")
  console.log(`   Files saved to: ${baseDir}`)
  console.log("\nGeneration Summary:")
  results.forEach(r => {
    if (r.error) {
      console.log(`  TBS ${r.tbsSize}: ❌ Failed - ${r.error}`)
    } else {
      const status = r.exactMatch ? "✓ Exact match" : `⚠️  Actual: ${r.actualTbsSize}`
      console.log(`  TBS ${r.tbsSize}: ${status}`)
    }
  })
}

// Run the generator
generateAllTBSCertificates().catch((error) => {
  console.error("Error generating certificates:", error)
  process.exit(1)
})