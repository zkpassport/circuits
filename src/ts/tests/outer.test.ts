import { describe, expect, test } from "@jest/globals"
import { poseidon2HashAsync } from "@zkpassport/poseidon2"
import type { PackagedCertificate, Query } from "@zkpassport/utils"
import {
  Binary,
  DisclosedData,
  convertPemToPackagedCertificate,
  getAgeCircuitInputs,
  getBindCircuitInputs,
  getBirthdateCircuitInputs,
  getCertificateRegistryRootFromOuterProof,
  getCircuitMerkleProof,
  getCommitmentFromDSCProof,
  getCommitmentInFromDisclosureProof,
  getCommitmentInFromIDDataProof,
  getCommitmentInFromIntegrityProof,
  getCommitmentOutFromIDDataProof,
  getCommitmentOutFromIntegrityProof,
  getCurrentDateFromIntegrityProof,
  getCurrentDateFromOuterProof,
  getDiscloseCircuitInputs,
  getDiscloseEVMParameterCommitment,
  getDiscloseParameterCommitment,
  getDisclosedBytesFromMrzAndMask,
  getExpiryDateCircuitInputs,
  getIssuingCountryExclusionCircuitInputs,
  getIssuingCountryInclusionCircuitInputs,
  getMerkleRootFromDSCProof,
  getNationalityExclusionCircuitInputs,
  getNationalityInclusionCircuitInputs,
  getNowTimestamp,
  getNullifierFromDisclosureProof,
  getNullifierFromOuterProof,
  getSanctionsExclusionCheckCircuitInputs,
  getOuterCircuitInputs,
  getParamCommitmentsFromOuterProof,
  getParameterCommitmentFromDisclosureProof,
  getServiceScopeHash,
  getServiceSubscopeHash,
  ProofType,
} from "@zkpassport/utils"
import * as path from "path"
import * as fs from "fs"
import { Circuit } from "../circuits"
import { generateSigningCertificates, loadKeypairFromFile, signSod } from "../passport-generator"
import { generateSod, wrapSodInContentInfo } from "../sod-generator"
import { TestHelper } from "../test-helper"
import { createUTCDate, serializeAsn } from "../utils"
import circuitManifest from "./fixtures/circuit-manifest.json"

const DEBUG_OUTPUT = process.env.DEBUG_OUTPUT === 'true'
const fixturesOutputDir = path.join(__dirname, '../../../output-fixtures');

if (DEBUG_OUTPUT) {
  // Write fixtures to output directory
  if (!fs.existsSync(fixturesOutputDir)) {
    fs.mkdirSync(fixturesOutputDir, { recursive: true });
  }
}
const nowTimestamp = getNowTimestamp()

describe("outer proof", () => {
  const helper = new TestHelper()
  const cscaCerts: PackagedCertificate[] = []
  const FIXTURES_PATH = path.join(__dirname, "fixtures")
  const DSC_KEYPAIR_PATH = path.join(FIXTURES_PATH, "dsc-keypair-rsa.json")
  const MAX_TBS_LENGTH = 700
  let subproofs: Map<
    number,
    {
      proof: string[]
      publicInputs: string[]
      vkey: string[]
      vkeyHash: string
      paramCommitment?: bigint
    }
  > = new Map()
  let certificateRegistryRoot: bigint

  beforeEach(async () => {
    // Johnny Silverhand's MRZ
    const mrz =
      "P<AUSSILVERHAND<<JOHNNY<<<<<<<<<<<<<<<<<<<<<PA1234567_AUS881112_M300101_<CYBERCITY<<<<\0\0"
    const dg1 = Binary.fromHex("615B5F1F58").concat(Binary.from(mrz))
    // Load DSC keypair
    const dscKeypair = await loadKeypairFromFile(DSC_KEYPAIR_PATH)

    // Generate CSC and DSC signing certificates
    const { cscPem, dsc, dscKeys } = await generateSigningCertificates({
      cscSigningHashAlgorithm: "SHA-512",
      cscKeyType: "RSA",
      cscKeySize: 4096,
      dscSigningHashAlgorithm: "SHA-256",
      dscKeyType: "RSA",
      dscKeySize: 2048,
      dscKeypair,
    })
    // Generate SOD and sign it with DSC keypair
    const { sod } = await generateSod(dg1, [dsc], "SHA-256")
    const { sod: signedSod } = await signSod(sod, dscKeys, "SHA-256")
    // Add newly generated CSC to masterlist
    cscaCerts.push(convertPemToPackagedCertificate(cscPem))
    // Load passport data into helper
    const contentInfoWrappedSod = serializeAsn(wrapSodInContentInfo(signedSod))
    await helper.loadPassport(dg1, Binary.from(contentInfoWrappedSod))
    helper.setCertificates(cscaCerts)

    subproofs = new Map()
    const cscToDscCircuit = Circuit.from(`sig_check_dsc_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_4096_sha512`)
    const cscToDscInputs = await helper.generateCircuitInputs("dsc")
    const cscToDscProof = await cscToDscCircuit.prove(cscToDscInputs, {
      recursive: true,
      useCli: true,
      circuitName: `sig_check_dsc_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_4096_sha512`,
    })
    expect(cscToDscProof).toBeDefined()
    expect(cscToDscProof.publicInputs.length).toEqual(2)
    certificateRegistryRoot = getMerkleRootFromDSCProof(cscToDscProof)
    expect(certificateRegistryRoot).toBeDefined()
    const cscToDscCommitment = getCommitmentFromDSCProof(cscToDscProof)
    const cscToDscVkey = (await cscToDscCircuit.getVerificationKey({ evm: false })).vkeyFields
    const cscToDscVkeyHash = `0x${(
      await poseidon2HashAsync(cscToDscVkey.map((x) => BigInt(x)))
    ).toString(16)}`
    subproofs.set(0, {
      proof: cscToDscProof.proof,
      publicInputs: cscToDscProof.publicInputs,
      vkey: cscToDscVkey,
      vkeyHash: cscToDscVkeyHash,
    })
    await cscToDscCircuit.destroy()

    const idDataToIntegrityCircuit = Circuit.from(
      `sig_check_id_data_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_2048_sha256`,
    )
    const idDataToIntegrityInputs = await helper.generateCircuitInputs("id")
    const idDataToIntegrityProof = await idDataToIntegrityCircuit.prove(idDataToIntegrityInputs, {
      recursive: true,
      useCli: true,
      circuitName: `sig_check_id_data_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_2048_sha256`,
    })
    expect(idDataToIntegrityProof).toBeDefined()
    const idDataCommitmentIn = getCommitmentInFromIDDataProof(idDataToIntegrityProof)
    const dscToIdDataCommitment = getCommitmentOutFromIDDataProof(idDataToIntegrityProof)
    expect(idDataCommitmentIn).toEqual(cscToDscCommitment)
    const idDataToIntegrityVkey = (
      await idDataToIntegrityCircuit.getVerificationKey({ evm: false })
    ).vkeyFields
    const idDataToIntegrityVkeyHash = `0x${(
      await poseidon2HashAsync(idDataToIntegrityVkey.map((x) => BigInt(x)))
    ).toString(16)}`
    subproofs.set(1, {
      proof: idDataToIntegrityProof.proof,
      publicInputs: idDataToIntegrityProof.publicInputs,
      vkey: idDataToIntegrityVkey,
      vkeyHash: idDataToIntegrityVkeyHash,
    })
    await idDataToIntegrityCircuit.destroy()

    const integrityCircuit = Circuit.from("data_check_integrity_sa_sha256_dg_sha256")
    const integrityInputs = await helper.generateCircuitInputs("integrity", nowTimestamp)
    const integrityProof = await integrityCircuit.prove(integrityInputs, {
      recursive: true,
      useCli: true,
      circuitName: `data_check_integrity_sa_sha256_dg_sha256`,
    })
    expect(integrityProof).toBeDefined()
    const integrityCheckCommitmentIn = getCommitmentInFromIntegrityProof(integrityProof)
    const integrityCheckToDisclosureCommitment = getCommitmentOutFromIntegrityProof(integrityProof)
    const currentDate = getCurrentDateFromIntegrityProof(integrityProof)
    expect(integrityCheckCommitmentIn).toEqual(dscToIdDataCommitment)
    expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
    const integrityVkey = (await integrityCircuit.getVerificationKey({ evm: false })).vkeyFields
    const integrityVkeyHash = `0x${(
      await poseidon2HashAsync(integrityVkey.map((x) => BigInt(x)))
    ).toString(16)}`
    subproofs.set(2, {
      proof: integrityProof.proof,
      publicInputs: integrityProof.publicInputs,
      vkey: integrityVkey,
      vkeyHash: integrityVkeyHash,
    })
    await integrityCircuit.destroy()

    const discloseCircuit = Circuit.from("disclose_bytes")
    const query: Query = {
      issuing_country: { disclose: true },
      nationality: { disclose: true },
      document_type: { disclose: true },
      document_number: { disclose: true },
      fullname: { disclose: true },
      birthdate: { disclose: true },
      expiry_date: { disclose: true },
      gender: { disclose: true },
    }
    let inputs = await getDiscloseCircuitInputs(helper.passport as any, query, 3n)
    if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
    const proof = await discloseCircuit.prove(inputs, {
      recursive: true,
      useCli: true,
      circuitName: `disclose_bytes`,
    })
    expect(proof).toBeDefined()
    const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
    const disclosedBytes = getDisclosedBytesFromMrzAndMask(
      helper.passport.mrz,
      inputs.disclose_mask,
    )
    const calculatedParamCommitment = await getDiscloseParameterCommitment(
      inputs.disclose_mask,
      disclosedBytes,
    )
    expect(paramCommitment).toEqual(calculatedParamCommitment)
    // Verify the disclosed data
    const disclosedData = DisclosedData.fromDisclosedBytes(disclosedBytes, "passport")
    const nullifier = getNullifierFromDisclosureProof(proof)
    expect(disclosedData.issuingCountry).toBe("AUS")
    expect(disclosedData.nationality).toBe("AUS")
    expect(disclosedData.documentType).toBe("passport")
    expect(disclosedData.documentNumber).toBe("PA1234567")
    expect(disclosedData.name).toBe("JOHNNY SILVERHAND")
    expect(disclosedData.firstName).toBe("JOHNNY")
    expect(disclosedData.lastName).toBe("SILVERHAND")
    expect(disclosedData.dateOfBirth).toEqual(createUTCDate(1988, 10, 12))
    expect(disclosedData.dateOfExpiry).toEqual(createUTCDate(2030, 0, 1))
    expect(disclosedData.gender).toBe("M")
    expect(nullifier).toEqual(
      779855614087059216963642638396438072807460693353731593953501664068287689340n,
    )
    const discloseCommitmentIn = getCommitmentInFromDisclosureProof(proof)
    expect(discloseCommitmentIn).toEqual(integrityCheckToDisclosureCommitment)
    const discloseVkey = (await discloseCircuit.getVerificationKey({ evm: false })).vkeyFields
    const discloseVkeyHash = `0x${(
      await poseidon2HashAsync(discloseVkey.map((x) => BigInt(x)))
    ).toString(16)}`
    subproofs.set(3, {
      proof: proof.proof,
      publicInputs: proof.publicInputs,
      vkey: discloseVkey,
      vkeyHash: discloseVkeyHash,
      paramCommitment: paramCommitment,
    })
    await discloseCircuit.destroy()
  }, 60000 * 3)

  test(
    "4 subproofs",
    async () => {
      const circuit = Circuit.from("outer_count_4")
      const { path: cscToDscTreeHashPath, index: cscToDscTreeIndex } = await getCircuitMerkleProof(
        subproofs.get(0)?.vkeyHash as string,
        circuitManifest,
      )
      const { path: idDataToIntegrityTreeHashPath, index: idDataToIntegrityTreeIndex } =
        await getCircuitMerkleProof(subproofs.get(1)?.vkeyHash as string, circuitManifest)
      const { path: integrityCheckTreeHashPath, index: integrityCheckTreeIndex } =
        await getCircuitMerkleProof(subproofs.get(2)?.vkeyHash as string, circuitManifest)
      const { path: discloseTreeHashPath, index: discloseTreeIndex } = await getCircuitMerkleProof(
        subproofs.get(3)?.vkeyHash as string,
        circuitManifest,
      )
      const inputs = await getOuterCircuitInputs(
        {
          proof: subproofs.get(0)?.proof as string[],
          publicInputs: subproofs.get(0)?.publicInputs as string[],
          vkey: subproofs.get(0)?.vkey as string[],
          keyHash: subproofs.get(0)?.vkeyHash as string,
          treeHashPath: cscToDscTreeHashPath,
          treeIndex: cscToDscTreeIndex.toString(),
        },
        {
          proof: subproofs.get(1)?.proof as string[],
          publicInputs: subproofs.get(1)?.publicInputs as string[],
          vkey: subproofs.get(1)?.vkey as string[],
          keyHash: subproofs.get(1)?.vkeyHash as string,
          treeHashPath: idDataToIntegrityTreeHashPath,
          treeIndex: idDataToIntegrityTreeIndex.toString(),
        },
        {
          proof: subproofs.get(2)?.proof as string[],
          publicInputs: subproofs.get(2)?.publicInputs as string[],
          vkey: subproofs.get(2)?.vkey as string[],
          keyHash: subproofs.get(2)?.vkeyHash as string,
          treeHashPath: integrityCheckTreeHashPath,
          treeIndex: integrityCheckTreeIndex.toString(),
        },
        [
          {
            proof: subproofs.get(3)?.proof as string[],
            publicInputs: subproofs.get(3)?.publicInputs as string[],
            vkey: subproofs.get(3)?.vkey as string[],
            keyHash: subproofs.get(3)?.vkeyHash as string,
            treeHashPath: discloseTreeHashPath,
            treeIndex: discloseTreeIndex.toString(),
          },
        ],
        circuitManifest.root,
      )
      const proof = await circuit.prove(inputs, {
        useCli: true,
        circuitName: "outer_count_4",
        recursive: true,
      })
      expect(proof).toBeDefined()
      const currentDate = getCurrentDateFromOuterProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
      const nullifier = getNullifierFromOuterProof(proof)
      expect(nullifier).toEqual(
        779855614087059216963642638396438072807460693353731593953501664068287689340n,
      )
      const certificateRegistryRootFromProof = getCertificateRegistryRootFromOuterProof(proof)
      expect(certificateRegistryRoot).toEqual(certificateRegistryRootFromProof)
      const paramCommitmentsFromProof = getParamCommitmentsFromOuterProof(proof)
      expect(subproofs.get(3)?.paramCommitment).toEqual(paramCommitmentsFromProof[0])
      await circuit.destroy()
    },
    60000 * 3,
  )

  test(
    "6 subproofs",
    async () => {
      // 2nd disclosure proof
      const nationalityCircuit = Circuit.from("inclusion_check_nationality")
      const nationalityQuery: Query = {
        nationality: { in: ["AUS", "FRA", "USA", "GBR"] },
      }
      const nationalityInputs = await getNationalityInclusionCircuitInputs(
        helper.passport as any,
        nationalityQuery,
        3n,
      )
      if (!nationalityInputs) throw new Error("Unable to generate inclusion check circuit inputs")
      const nationalityProof = await nationalityCircuit.prove(nationalityInputs, {
        recursive: true,
        useCli: true,
        circuitName: `inclusion_check_nationality`,
      })
      expect(nationalityProof).toBeDefined()
      const nationalityParamCommitment = getParameterCommitmentFromDisclosureProof(nationalityProof)
      const nationalityVkey = (await nationalityCircuit.getVerificationKey({ evm: false }))
        .vkeyFields
      const nationalityVkeyHash = `0x${(
        await poseidon2HashAsync(nationalityVkey.map((x) => BigInt(x)))
      ).toString(16)}`
      await nationalityCircuit.destroy()

      // 3rd disclosure proof
      const query: Query = {
        age: { gte: 18 },
      }
      const ageCircuit = Circuit.from("compare_age")
      const ageInputs = await getAgeCircuitInputs(
        helper.passport as any,
        query,
        3n,
        0n,
        0n,
        nowTimestamp,
      )
      if (!ageInputs) throw new Error("Unable to generate compare-age greater than circuit inputs")
      const ageProof = await ageCircuit.prove(ageInputs, {
        recursive: true,
        useCli: true,
        circuitName: `compare_age`,
      })
      expect(ageProof).toBeDefined()
      const ageParamCommitment = getParameterCommitmentFromDisclosureProof(ageProof)
      const ageVkey = (await ageCircuit.getVerificationKey({ evm: false })).vkeyFields
      const ageVkeyHash = `0x${(await poseidon2HashAsync(ageVkey.map((x) => BigInt(x)))).toString(
        16,
      )}`
      await ageCircuit.destroy()

      // Outer proof
      const outerProofCircuit = Circuit.from("outer_count_6")
      const { path: cscToDscTreeHashPath, index: cscToDscTreeIndex } = await getCircuitMerkleProof(
        subproofs.get(0)?.vkeyHash as string,
        circuitManifest,
      )
      const { path: idDataToIntegrityTreeHashPath, index: idDataToIntegrityTreeIndex } =
        await getCircuitMerkleProof(subproofs.get(1)?.vkeyHash as string, circuitManifest)
      const { path: integrityCheckTreeHashPath, index: integrityCheckTreeIndex } =
        await getCircuitMerkleProof(subproofs.get(2)?.vkeyHash as string, circuitManifest)
      const { path: discloseTreeHashPath, index: discloseTreeIndex } = await getCircuitMerkleProof(
        subproofs.get(3)?.vkeyHash as string,
        circuitManifest,
      )
      const { path: nationalityTreeHashPath, index: nationalityTreeIndex } =
        await getCircuitMerkleProof(nationalityVkeyHash as string, circuitManifest)
      const { path: ageTreeHashPath, index: ageTreeIndex } = await getCircuitMerkleProof(
        ageVkeyHash as string,
        circuitManifest,
      )
      const inputs = await getOuterCircuitInputs(
        {
          proof: subproofs.get(0)?.proof as string[],
          publicInputs: subproofs.get(0)?.publicInputs as string[],
          vkey: subproofs.get(0)?.vkey as string[],
          keyHash: subproofs.get(0)?.vkeyHash as string,
          treeHashPath: cscToDscTreeHashPath,
          treeIndex: cscToDscTreeIndex.toString(),
        },
        {
          proof: subproofs.get(1)?.proof as string[],
          publicInputs: subproofs.get(1)?.publicInputs as string[],
          vkey: subproofs.get(1)?.vkey as string[],
          keyHash: subproofs.get(1)?.vkeyHash as string,
          treeHashPath: idDataToIntegrityTreeHashPath,
          treeIndex: idDataToIntegrityTreeIndex.toString(),
        },
        {
          proof: subproofs.get(2)?.proof as string[],
          publicInputs: subproofs.get(2)?.publicInputs as string[],
          vkey: subproofs.get(2)?.vkey as string[],
          keyHash: subproofs.get(2)?.vkeyHash as string,
          treeHashPath: integrityCheckTreeHashPath,
          treeIndex: integrityCheckTreeIndex.toString(),
        },
        [
          {
            proof: subproofs.get(3)?.proof as string[],
            publicInputs: subproofs.get(3)?.publicInputs as string[],
            vkey: subproofs.get(3)?.vkey as string[],
            keyHash: subproofs.get(3)?.vkeyHash as string,
            treeHashPath: discloseTreeHashPath,
            treeIndex: discloseTreeIndex.toString(),
          },
          {
            proof: nationalityProof.proof as string[],
            publicInputs: nationalityProof.publicInputs as string[],
            vkey: nationalityVkey,
            keyHash: nationalityVkeyHash,
            treeHashPath: nationalityTreeHashPath,
            treeIndex: nationalityTreeIndex.toString(),
          },
          {
            proof: ageProof.proof as string[],
            publicInputs: ageProof.publicInputs as string[],
            vkey: ageVkey,
            keyHash: ageVkeyHash,
            treeHashPath: ageTreeHashPath,
            treeIndex: ageTreeIndex.toString(),
          },
        ],
        circuitManifest.root,
      )

      const proof = await outerProofCircuit.prove(inputs, {
        useCli: true,
        circuitName: "outer_count_6",
        recursive: true,
      })
      expect(proof).toBeDefined()
      const currentDate = getCurrentDateFromOuterProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
      const nullifier = getNullifierFromOuterProof(proof)
      expect(nullifier).toEqual(
        779855614087059216963642638396438072807460693353731593953501664068287689340n,
      )
      const certificateRegistryRootFromProof = getCertificateRegistryRootFromOuterProof(proof)
      expect(certificateRegistryRoot).toEqual(certificateRegistryRootFromProof)
      const paramCommitmentsFromProof = getParamCommitmentsFromOuterProof(proof)
      expect(subproofs.get(3)?.paramCommitment).toEqual(paramCommitmentsFromProof[0])
      expect(nationalityParamCommitment).toEqual(paramCommitmentsFromProof[1])
      expect(ageParamCommitment).toEqual(paramCommitmentsFromProof[2])
      await outerProofCircuit.destroy()
    },
    60000 * 3,
  )
})

describe("outer proof - evm optimised", () => {
  const helper = new TestHelper()
  const cscaCerts: PackagedCertificate[] = []
  const FIXTURES_PATH = path.join(__dirname, "fixtures")
  const DSC_KEYPAIR_PATH = path.join(FIXTURES_PATH, "dsc-keypair-rsa.json")
  const MAX_TBS_LENGTH = 700
  let subproofs: Map<
    number,
    {
      proof: string[]
      publicInputs: string[]
      vkey: string[]
      vkeyHash: string
      paramCommitment?: bigint
    }
  > = new Map()
  let certificateRegistryRoot: bigint

  beforeEach(async () => {
    // Johnny Silverhand's MRZ
    const mrz =
      "P<AUSSILVERHAND<<JOHNNY<<<<<<<<<<<<<<<<<<<<<PA1234567_AUS881112_M300101_<CYBERCITY<<<<\0\0"
    const dg1 = Binary.fromHex("615B5F1F58").concat(Binary.from(mrz))
    // Load DSC keypair
    const dscKeypair = await loadKeypairFromFile(DSC_KEYPAIR_PATH)

    // Generate CSC and DSC signing certificates
    const { cscPem, dsc, dscKeys } = await generateSigningCertificates({
      cscSigningHashAlgorithm: "SHA-512",
      cscKeyType: "RSA",
      cscKeySize: 4096,
      dscSigningHashAlgorithm: "SHA-256",
      dscKeyType: "RSA",
      dscKeySize: 2048,
      dscKeypair,
    })
    // Generate SOD and sign it with DSC keypair
    const { sod } = await generateSod(dg1, [dsc], "SHA-256")
    const { sod: signedSod } = await signSod(sod, dscKeys, "SHA-256")
    // Add newly generated CSC to masterlist
    cscaCerts.push(convertPemToPackagedCertificate(cscPem))
    // Load passport data into helper
    const contentInfoWrappedSod = serializeAsn(wrapSodInContentInfo(signedSod))
    await helper.loadPassport(dg1, Binary.from(contentInfoWrappedSod))
    helper.setCertificates(cscaCerts)

    subproofs = new Map()
    const cscToDscCircuit = Circuit.from(`sig_check_dsc_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_4096_sha512`)
    const cscToDscInputs = await helper.generateCircuitInputs("dsc")
    const cscToDscProof = await cscToDscCircuit.prove(cscToDscInputs, {
      recursive: true,
      useCli: true,
      circuitName: `sig_check_dsc_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_4096_sha512`,
    })
    expect(cscToDscProof).toBeDefined()
    expect(cscToDscProof.publicInputs.length).toEqual(2)
    certificateRegistryRoot = getMerkleRootFromDSCProof(cscToDscProof)
    expect(certificateRegistryRoot).toBeDefined()
    const cscToDscCommitment = getCommitmentFromDSCProof(cscToDscProof)
    const cscToDscVkey = (await cscToDscCircuit.getVerificationKey({ evm: false })).vkeyFields
    const cscToDscVkeyHash = `0x${(
      await poseidon2HashAsync(cscToDscVkey.map((x) => BigInt(x)))
    ).toString(16)}`
    subproofs.set(0, {
      proof: cscToDscProof.proof,
      publicInputs: cscToDscProof.publicInputs,
      vkey: cscToDscVkey,
      vkeyHash: cscToDscVkeyHash,
    })
    await cscToDscCircuit.destroy()

    const idDataToIntegrityCircuit = Circuit.from(
      `sig_check_id_data_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_2048_sha256`,
    )
    const idDataToIntegrityInputs = await helper.generateCircuitInputs("id")
    const idDataToIntegrityProof = await idDataToIntegrityCircuit.prove(idDataToIntegrityInputs, {
      recursive: true,
      useCli: true,
      circuitName: `sig_check_id_data_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_2048_sha256`,
    })
    expect(idDataToIntegrityProof).toBeDefined()
    const idDataCommitmentIn = getCommitmentInFromIDDataProof(idDataToIntegrityProof)
    const dscToIdDataCommitment = getCommitmentOutFromIDDataProof(idDataToIntegrityProof)
    expect(idDataCommitmentIn).toEqual(cscToDscCommitment)
    const idDataToIntegrityVkey = (
      await idDataToIntegrityCircuit.getVerificationKey({ evm: false })
    ).vkeyFields
    const idDataToIntegrityVkeyHash = `0x${(
      await poseidon2HashAsync(idDataToIntegrityVkey.map((x) => BigInt(x)))
    ).toString(16)}`
    subproofs.set(1, {
      proof: idDataToIntegrityProof.proof,
      publicInputs: idDataToIntegrityProof.publicInputs,
      vkey: idDataToIntegrityVkey,
      vkeyHash: idDataToIntegrityVkeyHash,
    })
    await idDataToIntegrityCircuit.destroy()

    const integrityCircuit = Circuit.from("data_check_integrity_sa_sha256_dg_sha256")
    const integrityInputs = await helper.generateCircuitInputs("integrity", nowTimestamp)
    const integrityProof = await integrityCircuit.prove(integrityInputs, {
      recursive: true,
      useCli: true,
      circuitName: `data_check_integrity_sa_sha256_dg_sha256`,
    })
    expect(integrityProof).toBeDefined()
    const integrityCheckCommitmentIn = getCommitmentInFromIntegrityProof(integrityProof)
    const integrityCheckToDisclosureCommitment = getCommitmentOutFromIntegrityProof(integrityProof)
    const currentDate = getCurrentDateFromIntegrityProof(integrityProof)
    expect(integrityCheckCommitmentIn).toEqual(dscToIdDataCommitment)
    expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
    const integrityVkey = (await integrityCircuit.getVerificationKey({ evm: false })).vkeyFields
    const integrityVkeyHash = `0x${(
      await poseidon2HashAsync(integrityVkey.map((x) => BigInt(x)))
    ).toString(16)}`
    subproofs.set(2, {
      proof: integrityProof.proof,
      publicInputs: integrityProof.publicInputs,
      vkey: integrityVkey,
      vkeyHash: integrityVkeyHash,
    })
    await integrityCircuit.destroy()

    const discloseCircuit = Circuit.from("disclose_bytes_evm")
    const query: Query = {
      nationality: { disclose: true },
      document_type: { disclose: true },
      document_number: { disclose: true },
      fullname: { disclose: true },
      birthdate: { disclose: true },
      gender: { disclose: true },
    }
    let inputs = await getDiscloseCircuitInputs(
      helper.passport as any,
      query,
      3n,
      getServiceScopeHash("zkpassport.id"),
      getServiceSubscopeHash("bigproof"),
    )
    if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
    const proof = await discloseCircuit.prove(inputs, {
      recursive: true,
      useCli: true,
      circuitName: `disclose_bytes_evm`,
    })
    expect(proof).toBeDefined()
    const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
    const disclosedBytes = getDisclosedBytesFromMrzAndMask(
      helper.passport.mrz,
      inputs.disclose_mask,
    )
    const calculatedParamCommitment = await getDiscloseEVMParameterCommitment(
      inputs.disclose_mask,
      disclosedBytes,
    )
    if (DEBUG_OUTPUT) {
      console.log("Disclose compressedCommittedInputs")

      const committedInputs = ProofType.DISCLOSE.toString(16).padStart(2, "0") +
          inputs.disclose_mask.map((x: number) => x.toString(16).padStart(2, "0")).join("") +
          disclosedBytes.map((x: number) => x.toString(16).padStart(2, "0")).join("")

      console.log(committedInputs)

      fs.writeFileSync(
        path.join(fixturesOutputDir, 'disclose_committed_inputs.hex'),
        committedInputs
      );
    }
    expect(paramCommitment).toEqual(calculatedParamCommitment)
    // Verify the disclosed data
    const disclosedData = DisclosedData.fromDisclosedBytes(disclosedBytes, "passport")
    const nullifier = getNullifierFromDisclosureProof(proof)
    expect(disclosedData.nationality).toBe("AUS")
    expect(disclosedData.documentType).toBe("passport")
    expect(disclosedData.documentNumber).toBe("PA1234567")
    expect(disclosedData.name).toBe("JOHNNY SILVERHAND")
    expect(disclosedData.firstName).toBe("JOHNNY")
    expect(disclosedData.lastName).toBe("SILVERHAND")
    expect(disclosedData.dateOfBirth).toEqual(createUTCDate(1988, 10, 12))
    expect(disclosedData.gender).toBe("M")
    expect(nullifier).toEqual(
      4721170378885156317428488923010239726308591232293531695919010613758228710886n,
    )
    const discloseCommitmentIn = getCommitmentInFromDisclosureProof(proof)
    expect(discloseCommitmentIn).toEqual(integrityCheckToDisclosureCommitment)
    const discloseVkey = (await discloseCircuit.getVerificationKey({ evm: false })).vkeyFields
    const discloseVkeyHash = `0x${(
      await poseidon2HashAsync(discloseVkey.map((x) => BigInt(x)))
    ).toString(16)}`
    subproofs.set(3, {
      proof: proof.proof,
      publicInputs: proof.publicInputs,
      vkey: discloseVkey,
      vkeyHash: discloseVkeyHash,
      paramCommitment: paramCommitment,
    })
    await discloseCircuit.destroy()
  }, 60000 * 3)

  test(
    "5 subproofs",
    async () => {
      const bindQuery: Query = {
        bind: {
          user_address: "0x04Fb06E8BF44eC60b6A99D2F98551172b2F2dED8",
          chain: "local_anvil",
          custom_data: "email:test@test.com,customer_id:1234567890",
        },
      }
      const bindCircuitInputs = await getBindCircuitInputs(
        helper.passport as any,
        bindQuery,
        3n,
        getServiceScopeHash("zkpassport.id"),
        getServiceSubscopeHash("bigproof"),
      )
      if (!bindCircuitInputs) throw new Error("Unable to generate bind circuit inputs")
      const bindCircuit = Circuit.from("bind_evm")
      const bindProof = await bindCircuit.prove(bindCircuitInputs, {
        recursive: true,
        useCli: true,
        circuitName: `bind_evm`,
      })
      expect(bindProof).toBeDefined()
      const bindParamCommitment = getParameterCommitmentFromDisclosureProof(bindProof)
      const bindVkey = (await bindCircuit.getVerificationKey({ evm: false })).vkeyFields
      const bindVkeyHash = `0x${(await poseidon2HashAsync(bindVkey.map((x) => BigInt(x)))).toString(
        16,
      )}`
      await bindCircuit.destroy()

      const circuit = Circuit.from("outer_count_5")
      const { path: cscToDscTreeHashPath, index: cscToDscTreeIndex } = await getCircuitMerkleProof(
        subproofs.get(0)?.vkeyHash as string,
        circuitManifest,
      )
      const { path: idDataToIntegrityTreeHashPath, index: idDataToIntegrityTreeIndex } =
        await getCircuitMerkleProof(subproofs.get(1)?.vkeyHash as string, circuitManifest)
      const { path: integrityCheckTreeHashPath, index: integrityCheckTreeIndex } =
        await getCircuitMerkleProof(subproofs.get(2)?.vkeyHash as string, circuitManifest)
      const { path: discloseTreeHashPath, index: discloseTreeIndex } = await getCircuitMerkleProof(
        subproofs.get(3)?.vkeyHash as string,
        circuitManifest,
      )
      const { path: bindTreeHashPath, index: bindTreeIndex } = await getCircuitMerkleProof(
        bindVkeyHash as string,
        circuitManifest,
      )
      const inputs = await getOuterCircuitInputs(
        {
          proof: subproofs.get(0)?.proof as string[],
          publicInputs: subproofs.get(0)?.publicInputs as string[],
          vkey: subproofs.get(0)?.vkey as string[],
          keyHash: subproofs.get(0)?.vkeyHash as string,
          treeHashPath: cscToDscTreeHashPath,
          treeIndex: cscToDscTreeIndex.toString(),
        },
        {
          proof: subproofs.get(1)?.proof as string[],
          publicInputs: subproofs.get(1)?.publicInputs as string[],
          vkey: subproofs.get(1)?.vkey as string[],
          keyHash: subproofs.get(1)?.vkeyHash as string,
          treeHashPath: idDataToIntegrityTreeHashPath,
          treeIndex: idDataToIntegrityTreeIndex.toString(),
        },
        {
          proof: subproofs.get(2)?.proof as string[],
          publicInputs: subproofs.get(2)?.publicInputs as string[],
          vkey: subproofs.get(2)?.vkey as string[],
          keyHash: subproofs.get(2)?.vkeyHash as string,
          treeHashPath: integrityCheckTreeHashPath,
          treeIndex: integrityCheckTreeIndex.toString(),
        },
        [
          {
            proof: subproofs.get(3)?.proof as string[],
            publicInputs: subproofs.get(3)?.publicInputs as string[],
            vkey: subproofs.get(3)?.vkey as string[],
            keyHash: subproofs.get(3)?.vkeyHash as string,
            treeHashPath: discloseTreeHashPath,
            treeIndex: discloseTreeIndex.toString(),
          },
          {
            proof: bindProof.proof as string[],
            publicInputs: bindProof.publicInputs as string[],
            vkey: bindVkey,
            keyHash: bindVkeyHash,
            treeHashPath: bindTreeHashPath,
            treeIndex: bindTreeIndex.toString(),
          },
        ],
        circuitManifest.root,
      )
      const proof = await circuit.prove(inputs, {
        useCli: true,
        circuitName: "outer_count_5",
        recursive: false,
        evm: true,
        // Disable the fully ZK property for outer proofs meant to be verified onchain
        // The subproofs are already ZK and it's cheaper to verify a non ZK proof onchain
        disableZK: true,
      })
      expect(proof).toBeDefined()
      const currentDate = getCurrentDateFromOuterProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
      const nullifier = getNullifierFromOuterProof(proof)
      expect(nullifier).toEqual(
        4721170378885156317428488923010239726308591232293531695919010613758228710886n,
      )
      const certificateRegistryRootFromProof = getCertificateRegistryRootFromOuterProof(proof)
      expect(certificateRegistryRoot).toEqual(certificateRegistryRootFromProof)
      const paramCommitmentsFromProof = getParamCommitmentsFromOuterProof(proof)
      expect(subproofs.get(3)?.paramCommitment).toEqual(paramCommitmentsFromProof[0])
      expect(bindParamCommitment).toEqual(paramCommitmentsFromProof[1])
      await circuit.destroy()
    },
    60000 * 3,
  )

  test.only(
    "12 subproofs",
    async () => {
      // 2nd disclosure proof
      const nationalityInclusionCircuit = Circuit.from("inclusion_check_nationality_evm")
      const nationalityInclusionQuery: Query = {
        nationality: { in: ["AUS", "FRA", "USA", "GBR"] },
      }
      const nationalityInclusionInputs = await getNationalityInclusionCircuitInputs(
        helper.passport as any,
        nationalityInclusionQuery,
        3n,
        getServiceScopeHash("zkpassport.id"),
        getServiceSubscopeHash("bigproof"),
      )
      if (!nationalityInclusionInputs)
        throw new Error("Unable to generate inclusion check circuit inputs")
      const nationalityInclusionProof = await nationalityInclusionCircuit.prove(
        nationalityInclusionInputs,
        {
          recursive: true,
          useCli: true,
          circuitName: `inclusion_check_nationality_evm`,
        },
      )
      expect(nationalityInclusionProof).toBeDefined()
      const nationalityInclusionParamCommitment =
        getParameterCommitmentFromDisclosureProof(nationalityInclusionProof)
      const nationalityInclusionVkey = (
        await nationalityInclusionCircuit.getVerificationKey({ evm: false })
      ).vkeyFields
      const nationalityInclusionVkeyHash = `0x${(
        await poseidon2HashAsync(nationalityInclusionVkey.map((x) => BigInt(x)))
      ).toString(16)}`
      await nationalityInclusionCircuit.destroy()

      // 3rd disclosure proof
      const nationalityExclusionCircuit = Circuit.from("exclusion_check_nationality_evm")
      const nationalityExclusionQuery: Query = {
        nationality: { out: ["ESP", "PRT", "ITA"] },
      }
      const nationalityExclusionInputs = await getNationalityExclusionCircuitInputs(
        helper.passport as any,
        nationalityExclusionQuery,
        3n,
        getServiceScopeHash("zkpassport.id"),
        getServiceSubscopeHash("bigproof"),
      )
      if (!nationalityExclusionInputs)
        throw new Error("Unable to generate inclusion check circuit inputs")
      const nationalityExclusionProof = await nationalityExclusionCircuit.prove(
        nationalityExclusionInputs,
        {
          recursive: true,
          useCli: true,
          circuitName: `exclusion_check_nationality_evm`,
        },
      )
      expect(nationalityExclusionProof).toBeDefined()
      const nationalityExclusionParamCommitment =
        getParameterCommitmentFromDisclosureProof(nationalityExclusionProof)
      const nationalityExclusionVkey = (
        await nationalityExclusionCircuit.getVerificationKey({ evm: false })
      ).vkeyFields
      const nationalityExclusionVkeyHash = `0x${(
        await poseidon2HashAsync(nationalityExclusionVkey.map((x) => BigInt(x)))
      ).toString(16)}`
      await nationalityExclusionCircuit.destroy()

      // 4th disclosure proof
      const issuingCountryInclusionCircuit = Circuit.from("inclusion_check_issuing_country_evm")
      const issuingCountryInclusionQuery: Query = {
        issuing_country: { in: ["AUS", "FRA", "USA", "GBR"] },
      }
      const issuingCountryInclusionInputs = await getIssuingCountryInclusionCircuitInputs(
        helper.passport as any,
        issuingCountryInclusionQuery,
        3n,
        getServiceScopeHash("zkpassport.id"),
        getServiceSubscopeHash("bigproof"),
      )
      if (!issuingCountryInclusionInputs)
        throw new Error("Unable to generate inclusion check circuit inputs")
      const issuingCountryInclusionProof = await issuingCountryInclusionCircuit.prove(
        issuingCountryInclusionInputs,
        {
          recursive: true,
          useCli: true,
          circuitName: `inclusion_check_issuing_country_evm`,
        },
      )
      expect(issuingCountryInclusionProof).toBeDefined()
      const issuingCountryInclusionParamCommitment = getParameterCommitmentFromDisclosureProof(
        issuingCountryInclusionProof,
      )
      const issuingCountryInclusionVkey = (
        await issuingCountryInclusionCircuit.getVerificationKey({ evm: false })
      ).vkeyFields
      const issuingCountryInclusionVkeyHash = `0x${(
        await poseidon2HashAsync(issuingCountryInclusionVkey.map((x) => BigInt(x)))
      ).toString(16)}`
      await issuingCountryInclusionCircuit.destroy()

      // 5th disclosure proof
      const issuingCountryExclusionCircuit = Circuit.from("exclusion_check_issuing_country_evm")
      const issuingCountryExclusionQuery: Query = {
        issuing_country: { out: ["ESP", "PRT", "ITA"] },
      }
      const issuingCountryExclusionInputs = await getIssuingCountryExclusionCircuitInputs(
        helper.passport as any,
        issuingCountryExclusionQuery,
        3n,
        getServiceScopeHash("zkpassport.id"),
        getServiceSubscopeHash("bigproof"),
      )
      if (!issuingCountryExclusionInputs)
        throw new Error("Unable to generate inclusion check circuit inputs")
      const issuingCountryExclusionProof = await issuingCountryExclusionCircuit.prove(
        issuingCountryExclusionInputs,
        {
          recursive: true,
          useCli: true,
          circuitName: `exclusion_check_issuing_country_evm`,
        },
      )
      expect(issuingCountryExclusionProof).toBeDefined()
      const issuingCountryExclusionParamCommitment = getParameterCommitmentFromDisclosureProof(
        issuingCountryExclusionProof,
      )
      const issuingCountryExclusionVkey = (
        await issuingCountryExclusionCircuit.getVerificationKey({ evm: false })
      ).vkeyFields
      const issuingCountryExclusionVkeyHash = `0x${(
        await poseidon2HashAsync(issuingCountryExclusionVkey.map((x) => BigInt(x)))
      ).toString(16)}`
      await issuingCountryExclusionCircuit.destroy()

      // 6th disclosure proof
      const ageQuery: Query = {
        age: { gte: 18 },
      }
      const ageCircuit = Circuit.from("compare_age_evm")
      const ageInputs = await getAgeCircuitInputs(
        helper.passport as any,
        ageQuery,
        3n,
        0n,
        0n,
        nowTimestamp,
      )
      if (!ageInputs) throw new Error("Unable to generate compare-age greater than circuit inputs")
      const ageProof = await ageCircuit.prove(ageInputs, {
        recursive: true,
        useCli: true,
        circuitName: `compare_age_evm`,
      })
      expect(ageProof).toBeDefined()
      const ageParamCommitment = getParameterCommitmentFromDisclosureProof(ageProof)
      const ageVkey = (await ageCircuit.getVerificationKey({ evm: false })).vkeyFields
      const ageVkeyHash = `0x${(await poseidon2HashAsync(ageVkey.map((x) => BigInt(x)))).toString(
        16,
      )}`
      await ageCircuit.destroy()

      // 7th disclosure proof
      const expiryDateCircuit = Circuit.from("compare_expiry_evm")
      const expiryDateQuery: Query = {
        expiry_date: { gte: new Date() },
      }
      const expiryDateInputs = await getExpiryDateCircuitInputs(
        helper.passport as any,
        expiryDateQuery,
        3n,
        getServiceScopeHash("zkpassport.id"),
        getServiceSubscopeHash("bigproof"),
        nowTimestamp,
      )
      if (!expiryDateInputs)
        throw new Error("Unable to generate compare-expiry-date greater than circuit inputs")
      const expiryDateProof = await expiryDateCircuit.prove(expiryDateInputs, {
        recursive: true,
        useCli: true,
        circuitName: `compare_expiry_evm`,
      })
      expect(expiryDateProof).toBeDefined()
      const expiryDateParamCommitment = getParameterCommitmentFromDisclosureProof(expiryDateProof)
      const expiryDateVkey = (await expiryDateCircuit.getVerificationKey({ evm: false })).vkeyFields
      const expiryDateVkeyHash = `0x${(
        await poseidon2HashAsync(expiryDateVkey.map((x) => BigInt(x)))
      ).toString(16)}`
      await expiryDateCircuit.destroy()
      if (DEBUG_OUTPUT) {
        compressedCommittedInputs +=
          ProofType.EXPIRY_DATE.toString(16).padStart(2, "0") +
          Array.from(new TextEncoder().encode(expiryDateInputs.current_date))
            .map((x: number) => x.toString(16).padStart(2, "0"))
            .join("") +
          Array.from(new TextEncoder().encode(expiryDateInputs.min_date))
            .map((x: number) => x.toString(16).padStart(2, "0"))
            .join("") +
          Array.from(new TextEncoder().encode(expiryDateInputs.max_date))
            .map((x: number) => x.toString(16).padStart(2, "0"))
            .join("")
          
      }

      // 8th disclosure proof
      const birthDateCircuit = Circuit.from("compare_birthdate_evm")
      const birthDateQuery: Query = {
        birthdate: { lte: new Date() },
      }
      const birthDateInputs = await getBirthdateCircuitInputs(
        helper.passport as any,
        birthDateQuery,
        3n,
        getServiceScopeHash("zkpassport.id"),
        getServiceSubscopeHash("bigproof"),
        nowTimestamp,
      )
      if (!birthDateInputs)
        throw new Error("Unable to generate compare-birthdate-date less than circuit inputs")
      const birthDateProof = await birthDateCircuit.prove(birthDateInputs, {
        recursive: true,
        useCli: true,
        circuitName: `compare_birthdate_evm`,
      })
      expect(birthDateProof).toBeDefined()
      const birthDateParamCommitment = getParameterCommitmentFromDisclosureProof(birthDateProof)
      const birthDateVkey = (await birthDateCircuit.getVerificationKey({ evm: false })).vkeyFields
      const birthDateVkeyHash = `0x${(
        await poseidon2HashAsync(birthDateVkey.map((x) => BigInt(x)))
      ).toString(16)}`
      await birthDateCircuit.destroy()

      // 9 th disclosure proof
      const sanctionsExclusionCircuit = Circuit.from("exclusion_check_sanctions_evm")
      const sanctionsExclusionInputs = await getSanctionsExclusionCheckCircuitInputs(
        helper.passport as any,
        3n,
        getServiceScopeHash("zkpassport.id", 31337),
        getServiceSubscopeHash("bigproof"),
      )
      if (!sanctionsExclusionInputs) throw new Error("Unable to generate sanctions exclusion check circuit inputs")
      if (!sanctionsExclusionInputs)
        throw new Error("Unable to generate sanctions exclusion check circuit inputs")
      const sanctionsExclusionProof = await sanctionsExclusionCircuit.prove(sanctionsExclusionInputs, {
        recursive: true,
        useCli: true,
        circuitName: `exclusion_check_sanctions_evm`,
      })
      expect(sanctionsExclusionProof).toBeDefined()
      const sanctionsExclusionParamCommitment = getParameterCommitmentFromDisclosureProof(sanctionsExclusionProof)
      const sanctionsExclusionVkey = ultraVkToFields(
        await sanctionsExclusionCircuit.getVerificationKey({
          recursive: true,
          evm: false,
          useCli: true,
        }),
      )
      const sanctionsExclusionVkeyHash = `0x${(
        await poseidon2HashAsync(sanctionsExclusionVkey.map((x) => BigInt(x)))
      ).toString(16)}`
      await sanctionsExclusionCircuit.destroy()

      if (DEBUG_OUTPUT) {
        compressedCommittedInputs +=
          ProofType.Sanctions_EXCLUSION.toString(16).padStart(2, "0") +
          sanctionsExclusionInputs.root_hash.slice(2).padStart(64, "0")
      }


      // Outer proof
      // We can use the regular outer_count_12 rather than outer_evm_count_12
      // since only the vkey changes and we don't use it here
      const outerProofCircuit = Circuit.from("outer_count_12")
      const { path: cscToDscTreeHashPath, index: cscToDscTreeIndex } = await getCircuitMerkleProof(
        subproofs.get(0)?.vkeyHash as string,
        circuitManifest,
      )
      const { path: idDataToIntegrityTreeHashPath, index: idDataToIntegrityTreeIndex } =
        await getCircuitMerkleProof(subproofs.get(1)?.vkeyHash as string, circuitManifest)
      const { path: integrityCheckTreeHashPath, index: integrityCheckTreeIndex } =
        await getCircuitMerkleProof(subproofs.get(2)?.vkeyHash as string, circuitManifest)
      const { path: discloseTreeHashPath, index: discloseTreeIndex } = await getCircuitMerkleProof(
        subproofs.get(3)?.vkeyHash as string,
        circuitManifest,
      )
      const { path: nationalityExclusionTreeHashPath, index: nationalityExclusionTreeIndex } =
        await getCircuitMerkleProof(nationalityExclusionVkeyHash as string, circuitManifest)
      const { path: nationalityInclusionTreeHashPath, index: nationalityInclusionTreeIndex } =
        await getCircuitMerkleProof(nationalityInclusionVkeyHash as string, circuitManifest)
      const { path: issuingCountryExclusionTreeHashPath, index: issuingCountryExclusionTreeIndex } =
        await getCircuitMerkleProof(issuingCountryExclusionVkeyHash as string, circuitManifest)
      const { path: issuingCountryInclusionTreeHashPath, index: issuingCountryInclusionTreeIndex } =
        await getCircuitMerkleProof(issuingCountryInclusionVkeyHash as string, circuitManifest)
      const { path: ageTreeHashPath, index: ageTreeIndex } = await getCircuitMerkleProof(
        ageVkeyHash as string,
        circuitManifest,
      )
      const { path: expiryDateTreeHashPath, index: expiryDateTreeIndex } =
        await getCircuitMerkleProof(expiryDateVkeyHash as string, circuitManifest)
      const { path: birthDateTreeHashPath, index: birthDateTreeIndex } =
        await getCircuitMerkleProof(birthDateVkeyHash as string, circuitManifest)
      const { path: sanctionsExclusionTreeHashPath, index: sanctionsExclusionTreeIndex } =
        await getCircuitMerkleProof(sanctionsExclusionVkeyHash as string, circuitManifest)

      const inputs = await getOuterCircuitInputs(
        {
          proof: subproofs.get(0)?.proof as string[],
          publicInputs: subproofs.get(0)?.publicInputs as string[],
          vkey: subproofs.get(0)?.vkey as string[],
          keyHash: subproofs.get(0)?.vkeyHash as string,
          treeHashPath: cscToDscTreeHashPath,
          treeIndex: cscToDscTreeIndex.toString(),
        },
        {
          proof: subproofs.get(1)?.proof as string[],
          publicInputs: subproofs.get(1)?.publicInputs as string[],
          vkey: subproofs.get(1)?.vkey as string[],
          keyHash: subproofs.get(1)?.vkeyHash as string,
          treeHashPath: idDataToIntegrityTreeHashPath,
          treeIndex: idDataToIntegrityTreeIndex.toString(),
        },
        {
          proof: subproofs.get(2)?.proof as string[],
          publicInputs: subproofs.get(2)?.publicInputs as string[],
          vkey: subproofs.get(2)?.vkey as string[],
          keyHash: subproofs.get(2)?.vkeyHash as string,
          treeHashPath: integrityCheckTreeHashPath,
          treeIndex: integrityCheckTreeIndex.toString(),
        },
        [
          {
            proof: subproofs.get(3)?.proof as string[],
            publicInputs: subproofs.get(3)?.publicInputs as string[],
            vkey: subproofs.get(3)?.vkey as string[],
            keyHash: subproofs.get(3)?.vkeyHash as string,
            treeHashPath: discloseTreeHashPath,
            treeIndex: discloseTreeIndex.toString(),
          },
          {
            proof: nationalityInclusionProof.proof as string[],
            publicInputs: nationalityInclusionProof.publicInputs as string[],
            vkey: nationalityInclusionVkey,
            keyHash: nationalityInclusionVkeyHash,
            treeHashPath: nationalityInclusionTreeHashPath,
            treeIndex: nationalityInclusionTreeIndex.toString(),
          },
          {
            proof: nationalityExclusionProof.proof as string[],
            publicInputs: nationalityExclusionProof.publicInputs as string[],
            vkey: nationalityExclusionVkey,
            keyHash: nationalityExclusionVkeyHash,
            treeHashPath: nationalityExclusionTreeHashPath,
            treeIndex: nationalityExclusionTreeIndex.toString(),
          },
          {
            proof: issuingCountryInclusionProof.proof as string[],
            publicInputs: issuingCountryInclusionProof.publicInputs as string[],
            vkey: issuingCountryInclusionVkey,
            keyHash: issuingCountryInclusionVkeyHash,
            treeHashPath: issuingCountryInclusionTreeHashPath,
            treeIndex: issuingCountryInclusionTreeIndex.toString(),
          },
          {
            proof: issuingCountryExclusionProof.proof as string[],
            publicInputs: issuingCountryExclusionProof.publicInputs as string[],
            vkey: issuingCountryExclusionVkey,
            keyHash: issuingCountryExclusionVkeyHash,
            treeHashPath: issuingCountryExclusionTreeHashPath,
            treeIndex: issuingCountryExclusionTreeIndex.toString(),
          },
          {
            proof: ageProof.proof as string[],
            publicInputs: ageProof.publicInputs as string[],
            vkey: ageVkey,
            keyHash: ageVkeyHash,
            treeHashPath: ageTreeHashPath,
            treeIndex: ageTreeIndex.toString(),
          },
          {
            proof: expiryDateProof.proof as string[],
            publicInputs: expiryDateProof.publicInputs as string[],
            vkey: expiryDateVkey,
            keyHash: expiryDateVkeyHash,
            treeHashPath: expiryDateTreeHashPath,
            treeIndex: expiryDateTreeIndex.toString(),
          },
          {
            proof: birthDateProof.proof as string[],
            publicInputs: birthDateProof.publicInputs as string[],
            vkey: birthDateVkey,
            keyHash: birthDateVkeyHash,
            treeHashPath: birthDateTreeHashPath,
            treeIndex: birthDateTreeIndex.toString(),
          },
          {
            proof: sanctionsExclusionProof.proof.map((f) => `0x${f}`) as string[],
            publicInputs: sanctionsExclusionProof.publicInputs as string[],
            vkey: sanctionsExclusionVkey,
            keyHash: sanctionsExclusionVkeyHash,
            treeHashPath: sanctionsExclusionTreeHashPath,
            treeIndex: sanctionsExclusionTreeIndex.toString(),
          },
        ],
        circuitManifest.root,
      )

      const proof = await outerProofCircuit.prove(inputs, {
        useCli: true,
        circuitName: "outer_evm_count_12",
        recursive: false,
        evm: true,
        // Disable the fully ZK property for outer proofs meant to be verified onchain
        // The subproofs are already ZK and it's cheaper to verify a non ZK proof onchain
        disableZK: true,
      })
      expect(proof).toBeDefined()
      if (DEBUG_OUTPUT) {
        console.log("Outer 12 subproofs")
        console.log(
          JSON.stringify({
            proof: proof.proof.slice(16).join(""),
            publicInputs: proof.publicInputs.concat(proof.proof.slice(0, 16).map((f) => `0x${f}`)),
          }),
        )
        console.log("committed inputs")
        console.log(compressedCommittedInputs)

        // Write fixtures to output directory
        // Read committed inputs
        const committedInputs = fs.readFileSync(
          path.join(fixturesOutputDir, 'disclose_committed_inputs.hex'),
          'utf8'
        )
        
        // Write committed inputs
        fs.writeFileSync(
          path.join(fixturesOutputDir, 'all_subproofs_committed_inputs.hex'),
          committedInputs + compressedCommittedInputs
        );
        
        // Write public inputs
        fs.writeFileSync(
          path.join(fixturesOutputDir, 'all_subproofs_public_inputs.json'),
          JSON.stringify({
            inputs: proof.publicInputs.concat(proof.proof.slice(0, 16).map((f) => `0x${f}`))
          }, null, 2)
        );
        
        // Write proof
        fs.writeFileSync(
          path.join(fixturesOutputDir, 'all_subproofs_proof.hex'),
          proof.proof.slice(16).join("")
        );
        
        console.log(`Fixtures written to: ${fixturesOutputDir}`);
      }
      const currentDate = getCurrentDateFromOuterProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
      const nullifier = getNullifierFromOuterProof(proof)
      expect(nullifier).toEqual(
        4721170378885156317428488923010239726308591232293531695919010613758228710886n,
      )
      const certificateRegistryRootFromProof = getCertificateRegistryRootFromOuterProof(proof)
      expect(certificateRegistryRoot).toEqual(certificateRegistryRootFromProof)
      const paramCommitmentsFromProof = getParamCommitmentsFromOuterProof(proof)
      expect(subproofs.get(3)?.paramCommitment).toEqual(paramCommitmentsFromProof[0])
      expect(nationalityInclusionParamCommitment).toEqual(paramCommitmentsFromProof[1])
      expect(nationalityExclusionParamCommitment).toEqual(paramCommitmentsFromProof[2])
      expect(issuingCountryInclusionParamCommitment).toEqual(paramCommitmentsFromProof[3])
      expect(issuingCountryExclusionParamCommitment).toEqual(paramCommitmentsFromProof[4])
      expect(ageParamCommitment).toEqual(paramCommitmentsFromProof[5])
      expect(expiryDateParamCommitment).toEqual(paramCommitmentsFromProof[6])
      expect(birthDateParamCommitment).toEqual(paramCommitmentsFromProof[7])
      expect(sanctionsExclusionParamCommitment).toEqual(paramCommitmentsFromProof[8])
      await outerProofCircuit.destroy()
    },
    60000 * 4,
  )
})
