import {
  Binary,
  parseCertificate,
  getNationalityInclusionCircuitInputs,
  getAgeCircuitInputs,
  DisclosedData,
  getNullifierFromDisclosureProof,
  getMerkleRootFromDSCProof,
  getCommitmentFromDSCProof,
  getCommitmentInFromIDDataProof,
  getCommitmentOutFromIDDataProof,
  getCommitmentInFromIntegrityProof,
  getCommitmentOutFromIntegrityProof,
  getCommitmentInFromDisclosureProof,
  getCurrentDateFromIntegrityProof,
  getDiscloseCircuitInputs,
  getParameterCommitmentFromDisclosureProof,
  getDiscloseParameterCommitment,
  getDisclosedBytesFromMrzAndMask,
  getOuterCircuitInputs,
  ultraVkToFields,
  getCurrentDateFromOuterProof,
  getNullifierFromOuterProof,
  getCertificateRegistryRootFromOuterProof,
  getParamCommitmentsFromOuterProof,
  getDiscloseEVMParameterCommitment,
} from "@zkpassport/utils"
import type { CSCMasterlist, Query } from "@zkpassport/utils"
import { beforeAll, describe, expect, test } from "@jest/globals"
import * as path from "path"
import { TestHelper } from "../test-helper"
import { generateSigningCertificates, signSod } from "../passport-generator"
import { loadKeypairFromFile } from "../passport-generator"
import { wrapSodInContentInfo } from "../sod-generator"
import { generateSod } from "../sod-generator"
import { serializeAsn, createUTCDate } from "../utils"
import { Circuit } from "../circuits"
import { poseidon2HashAsync } from "@zkpassport/poseidon2"

describe("outer proof", () => {
  const helper = new TestHelper()
  const masterlist: CSCMasterlist = { certificates: [] }
  const FIXTURES_PATH = path.join(__dirname, "fixtures")
  const DSC_KEYPAIR_PATH = path.join(FIXTURES_PATH, "dsc-keypair-rsa.json")
  const MAX_TBS_LENGTH = 700
  const globalCurrentDate = new Date(
    new Date().getFullYear(),
    new Date().getMonth(),
    new Date().getDate(),
    0,
    0,
    0,
    0,
  )
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
    masterlist.certificates.push(parseCertificate(cscPem))
    // Load passport data into helper
    const contentInfoWrappedSod = serializeAsn(wrapSodInContentInfo(signedSod))
    await helper.loadPassport(dg1, Binary.from(contentInfoWrappedSod))
    helper.setMasterlist(masterlist)

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
    const cscToDscVkey = ultraVkToFields(await cscToDscCircuit.getVerificationKey(true))
    const cscToDscVkeyHash = `0x${(
      await poseidon2HashAsync(cscToDscVkey.map((x) => BigInt(x)))
    ).toString(16)}`
    subproofs.set(0, {
      proof: cscToDscProof.proof.map((f) => `0x${f}`),
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
    const idDataToIntegrityVkey = ultraVkToFields(
      await idDataToIntegrityCircuit.getVerificationKey(true),
    )
    const idDataToIntegrityVkeyHash = `0x${(
      await poseidon2HashAsync(idDataToIntegrityVkey.map((x) => BigInt(x)))
    ).toString(16)}`
    subproofs.set(1, {
      proof: idDataToIntegrityProof.proof.map((f) => `0x${f}`),
      publicInputs: idDataToIntegrityProof.publicInputs,
      vkey: idDataToIntegrityVkey,
      vkeyHash: idDataToIntegrityVkeyHash,
    })
    await idDataToIntegrityCircuit.destroy()

    const integrityCircuit = Circuit.from("data_check_integrity_sha256")
    const integrityInputs = await helper.generateCircuitInputs("integrity")
    const integrityProof = await integrityCircuit.prove(integrityInputs, {
      recursive: true,
      useCli: true,
      circuitName: `data_check_integrity_sha256`,
    })
    expect(integrityProof).toBeDefined()
    const integrityCheckCommitmentIn = getCommitmentInFromIntegrityProof(integrityProof)
    const integrityCheckToDisclosureCommitment = getCommitmentOutFromIntegrityProof(integrityProof)
    const currentDate = getCurrentDateFromIntegrityProof(integrityProof)
    expect(integrityCheckCommitmentIn).toEqual(dscToIdDataCommitment)
    expect(currentDate).toEqual(globalCurrentDate)
    const integrityVkey = ultraVkToFields(await integrityCircuit.getVerificationKey(true))
    const integrityVkeyHash = `0x${(
      await poseidon2HashAsync(integrityVkey.map((x) => BigInt(x)))
    ).toString(16)}`
    subproofs.set(2, {
      proof: integrityProof.proof.map((f) => `0x${f}`),
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
      10145717760157071414871097616712373356688301026314602642662418913725691010870n,
    )
    const discloseCommitmentIn = getCommitmentInFromDisclosureProof(proof)
    expect(discloseCommitmentIn).toEqual(integrityCheckToDisclosureCommitment)
    const discloseVkey = ultraVkToFields(await discloseCircuit.getVerificationKey(true))
    const discloseVkeyHash = `0x${(
      await poseidon2HashAsync(discloseVkey.map((x) => BigInt(x)))
    ).toString(16)}`
    subproofs.set(3, {
      proof: proof.proof.map((f) => `0x${f}`),
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
      const inputs = await getOuterCircuitInputs(
        {
          proof: subproofs.get(0)?.proof as string[],
          publicInputs: subproofs.get(0)?.publicInputs as string[],
          vkey: subproofs.get(0)?.vkey as string[],
          keyHash: subproofs.get(0)?.vkeyHash as string,
        },
        {
          proof: subproofs.get(1)?.proof as string[],
          publicInputs: subproofs.get(1)?.publicInputs as string[],
          vkey: subproofs.get(1)?.vkey as string[],
          keyHash: subproofs.get(1)?.vkeyHash as string,
        },
        {
          proof: subproofs.get(2)?.proof as string[],
          publicInputs: subproofs.get(2)?.publicInputs as string[],
          vkey: subproofs.get(2)?.vkey as string[],
          keyHash: subproofs.get(2)?.vkeyHash as string,
        },
        [
          {
            proof: subproofs.get(3)?.proof as string[],
            publicInputs: subproofs.get(3)?.publicInputs as string[],
            vkey: subproofs.get(3)?.vkey as string[],
            keyHash: subproofs.get(3)?.vkeyHash as string,
          },
        ],
      )
      const proof = await circuit.prove(inputs, {
        useCli: true,
        circuitName: "outer_count_4",
        recursive: true,
      })
      expect(proof).toBeDefined()
      const currentDate = getCurrentDateFromOuterProof(proof)
      expect(currentDate).toEqual(globalCurrentDate)
      const nullifier = getNullifierFromOuterProof(proof)
      expect(nullifier).toEqual(
        10145717760157071414871097616712373356688301026314602642662418913725691010870n,
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
      const nationalityVkey = ultraVkToFields(await nationalityCircuit.getVerificationKey(true))
      const nationalityVkeyHash = `0x${(
        await poseidon2HashAsync(nationalityVkey.map((x) => BigInt(x)))
      ).toString(16)}`
      await nationalityCircuit.destroy()

      // 3rd disclosure proof
      const query: Query = {
        age: { gte: 18 },
      }
      const ageCircuit = Circuit.from("compare_age")
      const ageInputs = await getAgeCircuitInputs(helper.passport as any, query, 3n)
      if (!ageInputs) throw new Error("Unable to generate compare-age greater than circuit inputs")
      const ageProof = await ageCircuit.prove(ageInputs, {
        recursive: true,
        useCli: true,
        circuitName: `compare_age`,
      })
      expect(ageProof).toBeDefined()
      const ageParamCommitment = getParameterCommitmentFromDisclosureProof(ageProof)
      const ageVkey = ultraVkToFields(await ageCircuit.getVerificationKey(true))
      const ageVkeyHash = `0x${(await poseidon2HashAsync(ageVkey.map((x) => BigInt(x)))).toString(
        16,
      )}`
      await ageCircuit.destroy()

      // Outer proof
      const outerProofCircuit = Circuit.from("outer_count_6")
      const inputs = await getOuterCircuitInputs(
        {
          proof: subproofs.get(0)?.proof as string[],
          publicInputs: subproofs.get(0)?.publicInputs as string[],
          vkey: subproofs.get(0)?.vkey as string[],
          keyHash: subproofs.get(0)?.vkeyHash as string,
        },
        {
          proof: subproofs.get(1)?.proof as string[],
          publicInputs: subproofs.get(1)?.publicInputs as string[],
          vkey: subproofs.get(1)?.vkey as string[],
          keyHash: subproofs.get(1)?.vkeyHash as string,
        },
        {
          proof: subproofs.get(2)?.proof as string[],
          publicInputs: subproofs.get(2)?.publicInputs as string[],
          vkey: subproofs.get(2)?.vkey as string[],
          keyHash: subproofs.get(2)?.vkeyHash as string,
        },
        [
          {
            proof: subproofs.get(3)?.proof as string[],
            publicInputs: subproofs.get(3)?.publicInputs as string[],
            vkey: subproofs.get(3)?.vkey as string[],
            keyHash: subproofs.get(3)?.vkeyHash as string,
          },
          {
            proof: nationalityProof.proof.map((f) => `0x${f}`) as string[],
            publicInputs: nationalityProof.publicInputs as string[],
            vkey: nationalityVkey,
            keyHash: nationalityVkeyHash,
          },
          {
            proof: ageProof.proof.map((f) => `0x${f}`) as string[],
            publicInputs: ageProof.publicInputs as string[],
            vkey: ageVkey,
            keyHash: ageVkeyHash,
          },
        ],
      )

      const proof = await outerProofCircuit.prove(inputs, {
        useCli: true,
        circuitName: "outer_count_6",
        recursive: true,
      })
      expect(proof).toBeDefined()
      const currentDate = getCurrentDateFromOuterProof(proof)
      expect(currentDate).toEqual(globalCurrentDate)
      const nullifier = getNullifierFromOuterProof(proof)
      expect(nullifier).toEqual(
        10145717760157071414871097616712373356688301026314602642662418913725691010870n,
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
  const masterlist: CSCMasterlist = { certificates: [] }
  const FIXTURES_PATH = path.join(__dirname, "fixtures")
  const DSC_KEYPAIR_PATH = path.join(FIXTURES_PATH, "dsc-keypair-rsa.json")
  const MAX_TBS_LENGTH = 700
  const globalCurrentDate = new Date(
    new Date().getFullYear(),
    new Date().getMonth(),
    new Date().getDate(),
    0,
    0,
    0,
    0,
  )
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
    masterlist.certificates.push(parseCertificate(cscPem))
    // Load passport data into helper
    const contentInfoWrappedSod = serializeAsn(wrapSodInContentInfo(signedSod))
    await helper.loadPassport(dg1, Binary.from(contentInfoWrappedSod))
    helper.setMasterlist(masterlist)

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
    const cscToDscVkey = ultraVkToFields(await cscToDscCircuit.getVerificationKey(true))
    const cscToDscVkeyHash = `0x${(
      await poseidon2HashAsync(cscToDscVkey.map((x) => BigInt(x)))
    ).toString(16)}`
    subproofs.set(0, {
      proof: cscToDscProof.proof.map((f) => `0x${f}`),
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
    const idDataToIntegrityVkey = ultraVkToFields(
      await idDataToIntegrityCircuit.getVerificationKey(true),
    )
    const idDataToIntegrityVkeyHash = `0x${(
      await poseidon2HashAsync(idDataToIntegrityVkey.map((x) => BigInt(x)))
    ).toString(16)}`
    subproofs.set(1, {
      proof: idDataToIntegrityProof.proof.map((f) => `0x${f}`),
      publicInputs: idDataToIntegrityProof.publicInputs,
      vkey: idDataToIntegrityVkey,
      vkeyHash: idDataToIntegrityVkeyHash,
    })
    await idDataToIntegrityCircuit.destroy()

    const integrityCircuit = Circuit.from("data_check_integrity_sha256")
    const integrityInputs = await helper.generateCircuitInputs("integrity")
    const integrityProof = await integrityCircuit.prove(integrityInputs, {
      recursive: true,
      useCli: true,
      circuitName: `data_check_integrity_sha256`,
    })
    expect(integrityProof).toBeDefined()
    const integrityCheckCommitmentIn = getCommitmentInFromIntegrityProof(integrityProof)
    const integrityCheckToDisclosureCommitment = getCommitmentOutFromIntegrityProof(integrityProof)
    const currentDate = getCurrentDateFromIntegrityProof(integrityProof)
    expect(integrityCheckCommitmentIn).toEqual(dscToIdDataCommitment)
    expect(currentDate).toEqual(globalCurrentDate)
    const integrityVkey = ultraVkToFields(await integrityCircuit.getVerificationKey(true))
    const integrityVkeyHash = `0x${(
      await poseidon2HashAsync(integrityVkey.map((x) => BigInt(x)))
    ).toString(16)}`
    subproofs.set(2, {
      proof: integrityProof.proof.map((f) => `0x${f}`),
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
    let inputs = await getDiscloseCircuitInputs(helper.passport as any, query, 3n)
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
    console.log("compressedCommittedInputs")
    console.log(
      inputs.disclose_mask.map((x: number) => x.toString(16).padStart(2, "0")).join("") +
        disclosedBytes.map((x: number) => x.toString(16).padStart(2, "0")).join(""),
    )
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
      10145717760157071414871097616712373356688301026314602642662418913725691010870n,
    )
    const discloseCommitmentIn = getCommitmentInFromDisclosureProof(proof)
    expect(discloseCommitmentIn).toEqual(integrityCheckToDisclosureCommitment)
    const discloseVkey = ultraVkToFields(await discloseCircuit.getVerificationKey(true))
    const discloseVkeyHash = `0x${(
      await poseidon2HashAsync(discloseVkey.map((x) => BigInt(x)))
    ).toString(16)}`
    subproofs.set(3, {
      proof: proof.proof.map((f) => `0x${f}`),
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
      // We can use the regular outer_count_4 rather than outer_evm_count_4
      // since only the vkey changes and we don't use it here
      const circuit = Circuit.from("outer_count_4")
      const inputs = await getOuterCircuitInputs(
        {
          proof: subproofs.get(0)?.proof as string[],
          publicInputs: subproofs.get(0)?.publicInputs as string[],
          vkey: subproofs.get(0)?.vkey as string[],
          keyHash: subproofs.get(0)?.vkeyHash as string,
        },
        {
          proof: subproofs.get(1)?.proof as string[],
          publicInputs: subproofs.get(1)?.publicInputs as string[],
          vkey: subproofs.get(1)?.vkey as string[],
          keyHash: subproofs.get(1)?.vkeyHash as string,
        },
        {
          proof: subproofs.get(2)?.proof as string[],
          publicInputs: subproofs.get(2)?.publicInputs as string[],
          vkey: subproofs.get(2)?.vkey as string[],
          keyHash: subproofs.get(2)?.vkeyHash as string,
        },
        [
          {
            proof: subproofs.get(3)?.proof as string[],
            publicInputs: subproofs.get(3)?.publicInputs as string[],
            vkey: subproofs.get(3)?.vkey as string[],
            keyHash: subproofs.get(3)?.vkeyHash as string,
          },
        ],
      )
      const proof = await circuit.prove(inputs, {
        useCli: true,
        circuitName: "outer_evm_count_4",
        recursive: false,
        evm: true,
      })
      expect(proof).toBeDefined()
      console.log("Outer 4 subproofs")
      console.log(
        JSON.stringify({
          proof: proof.proof.slice(16).join(""),
          publicInputs: proof.publicInputs.concat(proof.proof.slice(0, 16).map((f) => `0x${f}`)),
        }),
      )
      const currentDate = getCurrentDateFromOuterProof(proof)
      expect(currentDate).toEqual(globalCurrentDate)
      const nullifier = getNullifierFromOuterProof(proof)
      expect(nullifier).toEqual(
        10145717760157071414871097616712373356688301026314602642662418913725691010870n,
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
      const nationalityCircuit = Circuit.from("inclusion_check_nationality_evm")
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
        circuitName: `inclusion_check_nationality_evm`,
      })
      expect(nationalityProof).toBeDefined()
      const nationalityParamCommitment = getParameterCommitmentFromDisclosureProof(nationalityProof)
      const nationalityVkey = ultraVkToFields(await nationalityCircuit.getVerificationKey(true))
      const nationalityVkeyHash = `0x${(
        await poseidon2HashAsync(nationalityVkey.map((x) => BigInt(x)))
      ).toString(16)}`
      await nationalityCircuit.destroy()

      // 3rd disclosure proof
      const query: Query = {
        age: { gte: 18 },
      }
      const ageCircuit = Circuit.from("compare_age_evm")
      const ageInputs = await getAgeCircuitInputs(helper.passport as any, query, 3n)
      if (!ageInputs) throw new Error("Unable to generate compare-age greater than circuit inputs")
      const ageProof = await ageCircuit.prove(ageInputs, {
        recursive: true,
        useCli: true,
        circuitName: `compare_age_evm`,
      })
      expect(ageProof).toBeDefined()
      const ageParamCommitment = getParameterCommitmentFromDisclosureProof(ageProof)
      const ageVkey = ultraVkToFields(await ageCircuit.getVerificationKey(true))
      const ageVkeyHash = `0x${(await poseidon2HashAsync(ageVkey.map((x) => BigInt(x)))).toString(
        16,
      )}`
      await ageCircuit.destroy()

      // Outer proof
      // We can use the regular outer_count_6 rather than outer_evm_count_6
      // since only the vkey changes and we don't use it here
      const outerProofCircuit = Circuit.from("outer_count_6")
      const inputs = await getOuterCircuitInputs(
        {
          proof: subproofs.get(0)?.proof as string[],
          publicInputs: subproofs.get(0)?.publicInputs as string[],
          vkey: subproofs.get(0)?.vkey as string[],
          keyHash: subproofs.get(0)?.vkeyHash as string,
        },
        {
          proof: subproofs.get(1)?.proof as string[],
          publicInputs: subproofs.get(1)?.publicInputs as string[],
          vkey: subproofs.get(1)?.vkey as string[],
          keyHash: subproofs.get(1)?.vkeyHash as string,
        },
        {
          proof: subproofs.get(2)?.proof as string[],
          publicInputs: subproofs.get(2)?.publicInputs as string[],
          vkey: subproofs.get(2)?.vkey as string[],
          keyHash: subproofs.get(2)?.vkeyHash as string,
        },
        [
          {
            proof: subproofs.get(3)?.proof as string[],
            publicInputs: subproofs.get(3)?.publicInputs as string[],
            vkey: subproofs.get(3)?.vkey as string[],
            keyHash: subproofs.get(3)?.vkeyHash as string,
          },
          {
            proof: nationalityProof.proof.map((f) => `0x${f}`) as string[],
            publicInputs: nationalityProof.publicInputs as string[],
            vkey: nationalityVkey,
            keyHash: nationalityVkeyHash,
          },
          {
            proof: ageProof.proof.map((f) => `0x${f}`) as string[],
            publicInputs: ageProof.publicInputs as string[],
            vkey: ageVkey,
            keyHash: ageVkeyHash,
          },
        ],
      )

      const proof = await outerProofCircuit.prove(inputs, {
        useCli: true,
        circuitName: "outer_evm_count_6",
        recursive: false,
        evm: true,
      })
      expect(proof).toBeDefined()
      console.log("Outer 6 subproofs")
      console.log(
        JSON.stringify({
          proof: proof.proof.slice(16).join(""),
          publicInputs: proof.publicInputs.concat(proof.proof.slice(0, 16).map((f) => `0x${f}`)),
        }),
      )
      const currentDate = getCurrentDateFromOuterProof(proof)
      expect(currentDate).toEqual(globalCurrentDate)
      const nullifier = getNullifierFromOuterProof(proof)
      expect(nullifier).toEqual(
        10145717760157071414871097616712373356688301026314602642662418913725691010870n,
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
