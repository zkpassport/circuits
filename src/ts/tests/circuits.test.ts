import {
  Binary,
  parseCertificate,
  getDiscloseFlagsCircuitInputs,
  getCountryInclusionCircuitInputs,
  getCountryExclusionCircuitInputs,
  getAgeCircuitInputs,
  getBirthdateCircuitInputs,
  calculateAge,
  DisclosedData,
  getCountryListFromInclusionProof,
  getCountryListFromExclusionProof,
  getMinAgeFromProof,
  getMaxAgeFromProof,
  getNullifierFromDisclosureProof,
  getExpiryDateCircuitInputs,
  getMinDateFromProof,
  getMaxDateFromProof,
  getMerkleRootFromDSCProof,
  getCommitmentFromDSCProof,
  getCommitmentInFromIDDataProof,
  getCommitmentOutFromIDDataProof,
  getCommitmentInFromIntegrityProof,
  getCommitmentOutFromIntegrityProof,
  getCommitmentInFromDisclosureProof,
  getCurrentDateFromIntegrityProof,
  getCurrentDateFromAgeProof,
  getCurrentDateFromDateProof,
  getDiscloseCircuitInputs,
  getHostedPackagedCircuitByName,
} from "@zkpassport/utils"
import type { CSCMasterlist, Query } from "@zkpassport/utils"
import { beforeAll, describe, expect, test } from "@jest/globals"
import * as path from "path"
import { TestHelper } from "../test-helper"
import { generateSigningCertificates, signSod } from "../passport-generator"
import { loadKeypairFromFile } from "../passport-generator"
import { wrapSodInContentInfo } from "../sod-generator"
import { generateSod } from "../sod-generator"
import { serializeAsn } from "../utils"
import { Circuit } from "../circuits"
import { BarretenbergVerifier } from "@aztec/bb.js"

describe("test recursive proof verification", () => {
  const helper = new TestHelper()
  const masterlist: CSCMasterlist = { certificates: [] }
  const FIXTURES_PATH = path.join(__dirname, "fixtures")
  const DSC_KEYPAIR_PATH = path.join(FIXTURES_PATH, "dsc-keypair-rsa.json")

  beforeAll(async () => {
    // Johnny Silverhand's MRZ
    const mrz =
      "P<AUSSILVERHAND<<JOHNNY<<<<<<<<<<<<<<<<<<<<<PA1234567_AUS881112_M300101_<CYBERCITY<<<<\0\0"
    const dg1 = Binary.fromHex("615B5F1F58").concat(Binary.from(mrz))
    // Load DSC keypair
    const dscKeypair = await loadKeypairFromFile(DSC_KEYPAIR_PATH)
    // Generate CSC and DSC signing certificates
    const { cscPem, dsc, dscKeys } = await generateSigningCertificates({
      cscSigningHashAlgorithm: "SHA-256",
      cscKeyType: "RSA",
      cscKeySize: 4096,
      dscSigningHashAlgorithm: "SHA-256",
      dscKeyType: "RSA",
      dscKeySize: 2048,
      dscKeypair,
    })
    // Generate SOD and sign it with DSC keypair
    const { sod } = await generateSod(dg1, [dsc])
    const { sod: signedSod } = await signSod(sod, dscKeys, "SHA-256")
    // Add newly generated CSC to masterlist
    masterlist.certificates.push(parseCertificate(cscPem))
    // Load passport data into helper
    const contentInfoWrappedSod = serializeAsn(wrapSodInContentInfo(signedSod))
    await helper.loadPassport(dg1, Binary.from(contentInfoWrappedSod))
    helper.setMasterlist(masterlist)
  })

  test("compare-age", async () => {
    const circuitName = "compare_age"
    const packagedCircuit = await getHostedPackagedCircuitByName("0.0.5", circuitName)
    const circuit = Circuit.from(circuitName, { recursive: true })

    const query: Query = {
      age: { gte: 18 },
    }
    const inputs = {
      dg1: [
        97, 91, 95, 31, 88, 80, 60, 65, 85, 83, 83, 73, 76, 86, 69, 82, 72, 65, 78, 68, 60, 60, 74,
        79, 72, 78, 78, 89, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
        60, 60, 60, 80, 65, 49, 50, 51, 52, 53, 54, 55, 95, 65, 85, 83, 56, 56, 49, 49, 49, 50, 95,
        77, 51, 48, 48, 49, 48, 49, 95, 60, 67, 89, 66, 69, 82, 67, 73, 84, 89, 60, 60, 60, 60, 0,
        0, 0, 0,
      ],
      current_date: "20250123",
      comm_in: "7694185967331967122598937599962011399995403044685988790544195459575107688011",
      private_nullifier:
        "5022805498473834598648760017381154431346061686926175510073091446144535733586",
      service_scope: "0",
      service_subscope: "0",
      salt: "0",
      min_age_required: "18",
      max_age_required: "0",
    }
    const proof = await circuit.prove(inputs)
    expect(proof).toBeDefined()
    const minAge = getMinAgeFromProof(proof)
    const maxAge = getMaxAgeFromProof(proof)
    const nullifier = getNullifierFromDisclosureProof(proof)
    const currentDate = getCurrentDateFromAgeProof(proof)
    expect(minAge).toBe(18)
    expect(maxAge).toBe(0)

    console.log("proof:", Buffer.from(proof.proof).toString("base64"))
    console.log("vkey:", packagedCircuit.vkey)

    const verifier = new BarretenbergVerifier()
    const verified = await verifier.verifyUltraHonkProof(
      proof,
      Buffer.from(packagedCircuit.vkey, "base64"),
    )
    console.log("verified?", verified)

    await circuit.destroy()
  }, 30000)
})
