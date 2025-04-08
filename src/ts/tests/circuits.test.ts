import {
  Binary,
  parseCertificate,
  getNationalityInclusionCircuitInputs,
  getNationalityExclusionCircuitInputs,
  getAgeCircuitInputs,
  getBirthdateCircuitInputs,
  calculateAge,
  DisclosedData,
  getNullifierFromDisclosureProof,
  getExpiryDateCircuitInputs,
  getMerkleRootFromDSCProof,
  getCommitmentFromDSCProof,
  getCommitmentInFromIDDataProof,
  getCommitmentOutFromIDDataProof,
  getCommitmentInFromIntegrityProof,
  getCommitmentOutFromIntegrityProof,
  getCommitmentInFromDisclosureProof,
  getCurrentDateFromIntegrityProof,
  getDiscloseCircuitInputs,
  getIssuingCountryExclusionCircuitInputs,
  getIssuingCountryInclusionCircuitInputs,
  getParameterCommitmentFromDisclosureProof,
  getCountryParameterCommitment,
  getAgeParameterCommitment,
  getFormattedDate,
  getDateParameterCommitment,
  getDiscloseParameterCommitment,
  getDisclosedBytesFromMrzAndMask,
  getOuterCircuitInputs,
  proofToFields,
  ultraVkToFields,
} from "@zkpassport/utils"
import type { CSCMasterlist, Query } from "@zkpassport/utils"
import { beforeAll, describe, expect, test } from "@jest/globals"
import * as path from "path"
import { TestHelper } from "../test-helper"
import { generateSigningCertificates, signSod } from "../passport-generator"
import { loadKeypairFromFile } from "../passport-generator"
import { wrapSodInContentInfo } from "../sod-generator"
import { generateSod } from "../sod-generator"
import { serializeAsn, createUTCDate, loadPackagedCircuit } from "../utils"
import { Circuit } from "../circuits"

describe("subcircuits - RSA PKCS", () => {
  const helper = new TestHelper()
  const masterlist: CSCMasterlist = { certificates: [] }
  const FIXTURES_PATH = path.join(__dirname, "fixtures")
  const DSC_KEYPAIR_PATH = path.join(FIXTURES_PATH, "dsc-keypair-rsa.json")
  const MAX_TBS_LENGTH = 700
  let dscCommitment: bigint
  let idDataCommitment: bigint
  let integrityCheckCommitment: bigint
  const globalCurrentDate = new Date(
    new Date().getFullYear(),
    new Date().getMonth(),
    new Date().getDate(),
    0,
    0,
    0,
    0,
  )
  let subproofs: Map<number, { proof: string[]; publicInputs: string[] }> = new Map()

  beforeAll(async () => {
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
  })

  describe("dsc", () => {
    test("rsa pkcs 4096", async () => {
      const circuit = Circuit.from(`sig_check_dsc_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_4096_sha512`)
      const inputs = await helper.generateCircuitInputs("dsc")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      expect(proof.publicInputs.length).toEqual(2)
      const merkleRoot = getMerkleRootFromDSCProof(proof)
      expect(merkleRoot).toBeDefined()
      dscCommitment = getCommitmentFromDSCProof(proof)
      subproofs.set(0, {
        proof: proofToFields(Buffer.from(proof.proof), 0).map((f) => `0x${f}`),
        publicInputs: proof.publicInputs,
      })
      await circuit.destroy()
    }, 30000)
  })

  describe("id", () => {
    test("rsa pkcs 2048", async () => {
      const circuit = Circuit.from(`sig_check_id_data_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_2048_sha256`)
      const inputs = await helper.generateCircuitInputs("id")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIDDataProof(proof)
      idDataCommitment = getCommitmentOutFromIDDataProof(proof)
      expect(commitmentIn).toEqual(dscCommitment)
      subproofs.set(1, {
        proof: proofToFields(Buffer.from(proof.proof), 0).map((f) => `0x${f}`),
        publicInputs: proof.publicInputs,
      })
      await circuit.destroy()
    }, 30000)
  })

  describe("integrity", () => {
    test("data integrity check", async () => {
      const circuit = Circuit.from("data_check_integrity_sha256")
      const inputs = await helper.generateCircuitInputs("integrity")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIntegrityProof(proof)
      integrityCheckCommitment = getCommitmentOutFromIntegrityProof(proof)
      const currentDate = getCurrentDateFromIntegrityProof(proof)
      expect(commitmentIn).toEqual(idDataCommitment)
      expect(currentDate).toEqual(globalCurrentDate)
      subproofs.set(2, {
        proof: proofToFields(Buffer.from(proof.proof), 0).map((f) => `0x${f}`),
        publicInputs: proof.publicInputs,
      })
      await circuit.destroy()
    }, 30000)
  })

  describe("disclose", () => {
    let circuit: Circuit
    beforeAll(async () => {
      circuit = Circuit.from("disclose_bytes")
    })
    afterAll(async () => {
      await circuit.destroy()
    })

    test("disclose all bytes", async () => {
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
      const proof = await circuit.prove(inputs, { witness: await circuit.solve(inputs) })
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
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("disclose some bytes", async () => {
      const query: Query = {
        nationality: { disclose: true },
      }
      let inputs = await getDiscloseCircuitInputs(helper.passport as any, query, 3n)
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      const proof = await circuit.prove(inputs, { witness: await circuit.solve(inputs) })
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
      expect(disclosedData.issuingCountry).toBe("")
      expect(disclosedData.nationality).toBe("AUS")
      expect(disclosedData.documentType).toBe("other")
      expect(disclosedData.documentNumber).toBe("")
      expect(disclosedData.name).toBe("")
      expect(disclosedData.firstName).toBe("")
      expect(disclosedData.lastName).toBe("")
      expect(isNaN(disclosedData.dateOfBirth.getTime())).toBe(true)
      expect(isNaN(disclosedData.dateOfExpiry.getTime())).toBe(true)
      expect(disclosedData.gender).toBe("")
      expect(nullifier).toEqual(
        10145717760157071414871097616712373356688301026314602642662418913725691010870n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      subproofs.set(3, {
        proof: proofToFields(Buffer.from(proof.proof), 0).map((f) => `0x${f}`),
        publicInputs: proof.publicInputs,
      })
    })
  })

  describe("inclusion-check", () => {
    test("nationality", async () => {
      const circuit = Circuit.from("inclusion_check_nationality")
      const query: Query = {
        nationality: { in: ["AUS", "FRA", "USA", "GBR"] },
      }
      const inputs = await getNationalityInclusionCircuitInputs(helper.passport as any, query, 3n)
      if (!inputs) throw new Error("Unable to generate inclusion check circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getCountryParameterCommitment([
        "AUS",
        "FRA",
        "USA",
        "GBR",
      ])
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(
        10145717760157071414871097616712373356688301026314602642662418913725691010870n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      await circuit.destroy()
    })

    test("issuing country", async () => {
      const circuit = Circuit.from("inclusion_check_issuing_country")
      const query: Query = {
        issuing_country: { in: ["AUS", "FRA", "USA", "GBR"] },
      }
      const inputs = await getIssuingCountryInclusionCircuitInputs(
        helper.passport as any,
        query,
        3n,
      )
      if (!inputs) throw new Error("Unable to generate inclusion check circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getCountryParameterCommitment([
        "AUS",
        "FRA",
        "USA",
        "GBR",
      ])
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(
        10145717760157071414871097616712373356688301026314602642662418913725691010870n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      await circuit.destroy()
    })
  })

  describe("exclusion-check", () => {
    test("nationality", async () => {
      const circuit = Circuit.from("exclusion_check_nationality")
      const query: Query = {
        nationality: { out: ["FRA", "USA", "GBR"] },
      }
      const inputs = await getNationalityExclusionCircuitInputs(helper.passport as any, query, 3n)
      if (!inputs) throw new Error("Unable to generate exclusion check circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      // Note that the order is in ascending order
      // while the original query was not
      // Before being passed to the circuit, the list is sorted in ascending order
      const calculatedParamCommitment = await getCountryParameterCommitment(
        ["FRA", "GBR", "USA"],
        true,
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(
        10145717760157071414871097616712373356688301026314602642662418913725691010870n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      await circuit.destroy()
    })

    test("issuing country", async () => {
      const circuit = Circuit.from("exclusion_check_issuing_country")
      const query: Query = {
        issuing_country: { out: ["FRA", "USA", "GBR"] },
      }
      const inputs = await getIssuingCountryExclusionCircuitInputs(
        helper.passport as any,
        query,
        3n,
      )
      if (!inputs) throw new Error("Unable to generate exclusion check circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      // Note that the order is in ascending order
      // while the original query was not
      // Before being passed to the circuit, the list is sorted in ascending order
      const calculatedParamCommitment = await getCountryParameterCommitment(
        ["FRA", "GBR", "USA"],
        true,
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(
        10145717760157071414871097616712373356688301026314602642662418913725691010870n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      await circuit.destroy()
    })
  })

  describe("compare-age", () => {
    let circuit: Circuit
    beforeAll(async () => {
      circuit = Circuit.from("compare_age")
    })
    afterAll(async () => {
      await circuit.destroy()
    })

    test("greater than", async () => {
      const query: Query = {
        age: { gte: 18 },
      }
      const inputs = await getAgeCircuitInputs(helper.passport as any, query, 3n)
      if (!inputs) throw new Error("Unable to generate compare-age greater than circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getAgeParameterCommitment(
        getFormattedDate(globalCurrentDate),
        18,
        0,
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(
        10145717760157071414871097616712373356688301026314602642662418913725691010870n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("less than", async () => {
      const age = calculateAge(helper.passport)
      const query: Query = {
        age: { lt: age + 1 },
      }
      const inputs = await getAgeCircuitInputs(helper.passport as any, query, 3n)
      if (!inputs) throw new Error("Unable to generate compare-age less than circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getAgeParameterCommitment(
        getFormattedDate(globalCurrentDate),
        0,
        age + 1,
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(
        10145717760157071414871097616712373356688301026314602642662418913725691010870n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("between", async () => {
      const age = calculateAge(helper.passport)
      const query: Query = {
        age: { gte: age, lt: age + 2 },
      }
      const inputs = await getAgeCircuitInputs(helper.passport as any, query, 3n)
      if (!inputs) throw new Error("Unable to generate compare-age between circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getAgeParameterCommitment(
        getFormattedDate(globalCurrentDate),
        age,
        age + 2,
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(
        10145717760157071414871097616712373356688301026314602642662418913725691010870n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("equal", async () => {
      const age = calculateAge(helper.passport)
      const query: Query = {
        age: { eq: age },
      }
      const inputs = await getAgeCircuitInputs(helper.passport as any, query, 3n)
      if (!inputs) throw new Error("Unable to generate compare-age equal circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getAgeParameterCommitment(
        getFormattedDate(globalCurrentDate),
        age,
        age,
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(
        10145717760157071414871097616712373356688301026314602642662418913725691010870n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("disclose", async () => {
      const query: Query = {
        age: { disclose: true },
      }
      const inputs = await getAgeCircuitInputs(helper.passport as any, query, 3n)
      if (!inputs) throw new Error("Unable to generate compare-age equal circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const age = calculateAge(helper.passport)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getAgeParameterCommitment(
        getFormattedDate(globalCurrentDate),
        age,
        age,
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        10145717760157071414871097616712373356688301026314602642662418913725691010870n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("range", async () => {
      const age = calculateAge(helper.passport)
      const query: Query = {
        age: { range: [age - 5, age + 5] },
      }
      const inputs = await getAgeCircuitInputs(helper.passport as any, query, 3n)
      if (!inputs) throw new Error("Unable to generate compare-age range circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getAgeParameterCommitment(
        getFormattedDate(globalCurrentDate),
        age - 5,
        age + 5,
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        10145717760157071414871097616712373356688301026314602642662418913725691010870n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })
  })

  describe("compare-birthdate", () => {
    let circuit: Circuit
    beforeAll(async () => {
      circuit = Circuit.from("compare_birthdate")
    })
    afterAll(async () => {
      await circuit.destroy()
    })

    test("equal", async () => {
      const query: Query = {
        // Remember months start at 0 so 10 is November
        birthdate: { eq: new Date(1988, 10, 12) },
      }
      const inputs = await getBirthdateCircuitInputs(helper.passport as any, query, 3n)
      if (!inputs) throw new Error("Unable to generate compare-birthdate equal circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateParameterCommitment(
        getFormattedDate(globalCurrentDate),
        "19881112",
        "19881112",
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        10145717760157071414871097616712373356688301026314602642662418913725691010870n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("range", async () => {
      const query: Query = {
        birthdate: { range: [new Date(1988, 10, 11), new Date(1988, 10, 13)] },
      }
      const inputs = await getBirthdateCircuitInputs(helper.passport as any, query, 3n)
      if (!inputs) throw new Error("Unable to generate compare-birthdate range circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateParameterCommitment(
        getFormattedDate(globalCurrentDate),
        "19881111",
        "19881113",
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        10145717760157071414871097616712373356688301026314602642662418913725691010870n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("disclose", async () => {
      const query: Query = {
        birthdate: { disclose: true },
      }
      const inputs = await getBirthdateCircuitInputs(helper.passport as any, query, 3n)
      if (!inputs) throw new Error("Unable to generate compare-birthdate disclose circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateParameterCommitment(
        getFormattedDate(globalCurrentDate),
        "19881112",
        "19881112",
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        10145717760157071414871097616712373356688301026314602642662418913725691010870n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("greater than", async () => {
      const query: Query = {
        birthdate: { gte: new Date(1988, 10, 11) },
      }
      const inputs = await getBirthdateCircuitInputs(helper.passport as any, query, 3n)
      if (!inputs)
        throw new Error("Unable to generate compare-birthdate greater than circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateParameterCommitment(
        getFormattedDate(globalCurrentDate),
        "19881111",
        "11111111",
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        10145717760157071414871097616712373356688301026314602642662418913725691010870n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("less than", async () => {
      const query: Query = {
        birthdate: { lte: new Date(1988, 10, 15) },
      }
      const inputs = await getBirthdateCircuitInputs(helper.passport as any, query, 3n)
      if (!inputs) throw new Error("Unable to generate compare-birthdate less than circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateParameterCommitment(
        getFormattedDate(globalCurrentDate),
        "11111111",
        "19881115",
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        10145717760157071414871097616712373356688301026314602642662418913725691010870n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("between", async () => {
      const query: Query = {
        birthdate: { gte: new Date(1988, 10, 11), lte: new Date(1988, 10, 15) },
      }
      const inputs = await getBirthdateCircuitInputs(helper.passport as any, query, 3n)
      if (!inputs) throw new Error("Unable to generate compare-birthdate between circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateParameterCommitment(
        getFormattedDate(globalCurrentDate),
        "19881111",
        "19881115",
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        10145717760157071414871097616712373356688301026314602642662418913725691010870n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })
  })

  describe("compare-expiry", () => {
    let circuit: Circuit
    beforeAll(async () => {
      circuit = Circuit.from("compare_expiry")
    })
    afterAll(async () => {
      await circuit.destroy()
    })

    test("equal", async () => {
      const query: Query = {
        expiry_date: { eq: new Date(2030, 0, 1) },
      }
      const inputs = await getExpiryDateCircuitInputs(helper.passport as any, query, 3n)
      if (!inputs) throw new Error("Unable to generate compare-expirydate equal circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateParameterCommitment(
        getFormattedDate(globalCurrentDate),
        "20300101",
        "20300101",
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        10145717760157071414871097616712373356688301026314602642662418913725691010870n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("range", async () => {
      const query: Query = {
        expiry_date: { range: [new Date(2025, 0, 1), new Date(2035, 0, 1)] },
      }
      const inputs = await getExpiryDateCircuitInputs(helper.passport as any, query, 3n)
      if (!inputs) throw new Error("Unable to generate compare-expirydate range circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateParameterCommitment(
        getFormattedDate(globalCurrentDate),
        "20250101",
        "20350101",
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        10145717760157071414871097616712373356688301026314602642662418913725691010870n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("disclose", async () => {
      const query: Query = {
        expiry_date: { disclose: true },
      }
      const inputs = await getExpiryDateCircuitInputs(helper.passport as any, query, 3n)
      if (!inputs) throw new Error("Unable to generate compare-expirydate disclose circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateParameterCommitment(
        getFormattedDate(globalCurrentDate),
        "20300101",
        "20300101",
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        10145717760157071414871097616712373356688301026314602642662418913725691010870n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("greater than", async () => {
      const query: Query = {
        expiry_date: { gte: new Date(2025, 0, 1) },
      }
      const inputs = await getExpiryDateCircuitInputs(helper.passport as any, query, 3n)
      if (!inputs)
        throw new Error("Unable to generate compare-expirydate greater than circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateParameterCommitment(
        getFormattedDate(globalCurrentDate),
        "20250101",
        "11111111",
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        10145717760157071414871097616712373356688301026314602642662418913725691010870n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("less than", async () => {
      const query: Query = {
        expiry_date: { lte: new Date(2035, 0, 1) },
      }
      const inputs = await getExpiryDateCircuitInputs(helper.passport as any, query, 3n)
      if (!inputs) throw new Error("Unable to generate compare-expirydate less than circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateParameterCommitment(
        getFormattedDate(globalCurrentDate),
        "11111111",
        "20350101",
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        10145717760157071414871097616712373356688301026314602642662418913725691010870n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("between", async () => {
      const query: Query = {
        expiry_date: { gte: new Date(2025, 0, 1), lte: new Date(2035, 0, 1) },
      }
      const inputs = await getExpiryDateCircuitInputs(helper.passport as any, query, 3n)
      if (!inputs) throw new Error("Unable to generate compare-expirydate between circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateParameterCommitment(
        getFormattedDate(globalCurrentDate),
        "20250101",
        "20350101",
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        10145717760157071414871097616712373356688301026314602642662418913725691010870n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })
  })

  describe("outer", () => {
    test("4-subproofs", async () => {
      const circuit = Circuit.from("outer_count_4")
      const cscToDscCircuit = await loadPackagedCircuit(
        `sig_check_dsc_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_4096_sha512`,
      )
      const dscToIdDataCircuit = await loadPackagedCircuit(
        `sig_check_id_data_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_2048_sha256`,
      )
      const integrityCheckCircuit = await loadPackagedCircuit("data_check_integrity_sha256")
      const disclosureCircuit = await loadPackagedCircuit("disclose_bytes")
      const inputs = await getOuterCircuitInputs(
        {
          proof: subproofs.get(0)?.proof as string[],
          publicInputs: subproofs.get(0)?.publicInputs as string[],
          vkey: ultraVkToFields(Binary.fromBase64(cscToDscCircuit.vkey).toUInt8Array()),
          keyHash: cscToDscCircuit.vkey_hash,
        },
        {
          proof: subproofs.get(1)?.proof as string[],
          publicInputs: subproofs.get(1)?.publicInputs as string[],
          vkey: ultraVkToFields(Binary.fromBase64(dscToIdDataCircuit.vkey).toUInt8Array()),
          keyHash: dscToIdDataCircuit.vkey_hash,
        },
        {
          proof: subproofs.get(2)?.proof as string[],
          publicInputs: subproofs.get(2)?.publicInputs as string[],
          vkey: ultraVkToFields(Binary.fromBase64(integrityCheckCircuit.vkey).toUInt8Array()),
          keyHash: integrityCheckCircuit.vkey_hash,
        },
        [
          {
            proof: subproofs.get(3)?.proof as string[],
            publicInputs: subproofs.get(3)?.publicInputs as string[],
            vkey: ultraVkToFields(Binary.fromBase64(disclosureCircuit.vkey).toUInt8Array()),
            keyHash: disclosureCircuit.vkey_hash,
          },
        ],
      )
      console.log("outer inputs", inputs)
      const proof = await circuit.prove(inputs, { useCli: true, circuitName: "outer_count_4" })
      expect(proof).toBeDefined()
      console.log("outer proof", proof)
      await circuit.destroy()
    }, 30000)
  })
})

describe("subcircuits - ECDSA NIST P-384 and P-256", () => {
  const helper = new TestHelper()
  const masterlist: CSCMasterlist = { certificates: [] }
  const FIXTURES_PATH = path.join(__dirname, "fixtures")
  const DSC_KEYPAIR_PATH = path.join(FIXTURES_PATH, "dsc-keypair-ecdsa.json")
  const MAX_TBS_LENGTH = 700
  let dscCommitment: bigint
  let idDataCommitment: bigint
  let integrityCheckCommitment: bigint
  const globalCurrentDate = new Date(
    new Date().getFullYear(),
    new Date().getMonth(),
    new Date().getDate(),
    0,
    0,
    0,
    0,
  )
  // We need to store the nullifier
  // as we cannot compare to a constant value
  // since ECDSA signatures are not deterministic
  let globalNullifier: bigint

  beforeAll(async () => {
    // Johnny Silverhand's MRZ
    const mrz =
      "P<AUSSILVERHAND<<JOHNNY<MATTHEW<<<<<<<<<<<<<PA1234567_AUS881112_M300101_<CYBERCITY<<<<\0\0"
    const dg1 = Binary.fromHex("615B5F1F58").concat(Binary.from(mrz))
    // Load DSC keypair
    const dscKeypair = await loadKeypairFromFile(DSC_KEYPAIR_PATH)

    // Generate CSC and DSC signing certificates
    const { cscPem, dsc, dscKeys } = await generateSigningCertificates({
      cscSigningHashAlgorithm: "SHA-384",
      cscKeyType: "ECDSA",
      cscCurve: "P-384",
      dscSigningHashAlgorithm: "SHA-256",
      dscKeyType: "ECDSA",
      dscCurve: "P-256",
      dscKeypair: dscKeypair,
    })
    // Generate SOD and sign it with DSC keypair
    const { sod } = await generateSod(dg1, [dsc], "SHA-384")
    const { sod: signedSod } = await signSod(sod, dscKeys, "SHA-256")
    // Add newly generated CSC to masterlist
    masterlist.certificates.push(parseCertificate(cscPem))
    // Load passport data into helper
    const contentInfoWrappedSod = serializeAsn(wrapSodInContentInfo(signedSod))
    await helper.loadPassport(dg1, Binary.from(contentInfoWrappedSod))
    helper.setMasterlist(masterlist)
  })

  describe("dsc", () => {
    test("ecdsa nist p-384", async () => {
      const circuit = Circuit.from(`sig_check_dsc_tbs_${MAX_TBS_LENGTH}_ecdsa_nist_p384_sha384`)
      const inputs = await helper.generateCircuitInputs("dsc")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      expect(proof.publicInputs.length).toEqual(2)
      const merkleRoot = getMerkleRootFromDSCProof(proof)
      expect(merkleRoot).toBeDefined()
      dscCommitment = getCommitmentFromDSCProof(proof)
      await circuit.destroy()
    }, 60000)
  })

  describe("id", () => {
    test("ecdsa nist p-256", async () => {
      const circuit = Circuit.from(`sig_check_id_data_tbs_${MAX_TBS_LENGTH}_ecdsa_nist_p256_sha256`)
      const inputs = await helper.generateCircuitInputs("id")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIDDataProof(proof)
      idDataCommitment = getCommitmentOutFromIDDataProof(proof)
      expect(commitmentIn).toEqual(dscCommitment)
      await circuit.destroy()
    }, 30000)
  })

  describe("integrity", () => {
    test("data integrity check", async () => {
      const circuit = Circuit.from("data_check_integrity_sha384")
      const inputs = await helper.generateCircuitInputs("integrity")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIntegrityProof(proof)
      integrityCheckCommitment = getCommitmentOutFromIntegrityProof(proof)
      const currentDate = getCurrentDateFromIntegrityProof(proof)
      expect(commitmentIn).toEqual(idDataCommitment)
      expect(currentDate).toEqual(globalCurrentDate)
      await circuit.destroy()
    }, 30000)
  })

  describe("disclose", () => {
    let circuit: Circuit
    beforeAll(async () => {
      circuit = Circuit.from("disclose_bytes")
    })
    afterAll(async () => {
      await circuit.destroy()
    })

    test("disclose all bytes", async () => {
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
      const proof = await circuit.prove(inputs, { witness: await circuit.solve(inputs) })
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
      globalNullifier = getNullifierFromDisclosureProof(proof)
      expect(disclosedData.issuingCountry).toBe("AUS")
      expect(disclosedData.nationality).toBe("AUS")
      expect(disclosedData.documentType).toBe("passport")
      expect(disclosedData.documentNumber).toBe("PA1234567")
      expect(disclosedData.name).toBe("JOHNNY MATTHEW SILVERHAND")
      expect(disclosedData.firstName).toBe("JOHNNY MATTHEW")
      expect(disclosedData.lastName).toBe("SILVERHAND")
      expect(disclosedData.dateOfBirth).toEqual(createUTCDate(1988, 10, 12))
      expect(disclosedData.dateOfExpiry).toEqual(createUTCDate(2030, 0, 1))
      expect(disclosedData.gender).toBe("M")
      expect(globalNullifier).toBeDefined()
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("disclose some bytes", async () => {
      const query: Query = {
        nationality: { disclose: true },
        firstname: { disclose: true },
        lastname: { disclose: true },
      }
      let inputs = await getDiscloseCircuitInputs(helper.passport as any, query, 3n)
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      const proof = await circuit.prove(inputs, { witness: await circuit.solve(inputs) })
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
      expect(disclosedData.issuingCountry).toBe("")
      expect(disclosedData.nationality).toBe("AUS")
      expect(disclosedData.documentType).toBe("other")
      expect(disclosedData.documentNumber).toBe("")
      expect(disclosedData.name).toBe("JOHNNY SILVERHAND")
      expect(disclosedData.firstName).toBe("JOHNNY")
      expect(disclosedData.lastName).toBe("SILVERHAND")
      expect(isNaN(disclosedData.dateOfBirth.getTime())).toBe(true)
      expect(isNaN(disclosedData.dateOfExpiry.getTime())).toBe(true)
      expect(disclosedData.gender).toBe("")
      expect(nullifier).toEqual(globalNullifier)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })
  })
})

describe("subcircuits - ECDSA NIST P-521 and P-384", () => {
  const helper = new TestHelper()
  const masterlist: CSCMasterlist = { certificates: [] }
  const FIXTURES_PATH = path.join(__dirname, "fixtures")
  const DSC_KEYPAIR_PATH = path.join(FIXTURES_PATH, "dsc-keypair-ecdsa.json")
  const MAX_TBS_LENGTH = 700
  let dscCommitment: bigint
  let idDataCommitment: bigint
  let integrityCheckCommitment: bigint
  const globalCurrentDate = new Date(
    new Date().getFullYear(),
    new Date().getMonth(),
    new Date().getDate(),
    0,
    0,
    0,
    0,
  )
  // We need to store the nullifier
  // as we cannot compare to a constant value
  // since ECDSA signatures are not deterministic
  let globalNullifier: bigint

  beforeAll(async () => {
    // Johnny Silverhand's MRZ
    const mrz =
      "P<AUSSILVERHAND<<JOHNNY<<<<<<<<<<<<<<<<<<<<<PA1234567_AUS881112_M300101_<CYBERCITY<<<<\0\0"
    const dg1 = Binary.fromHex("615B5F1F58").concat(Binary.from(mrz))

    // Generate CSC and DSC signing certificates
    const { cscPem, dsc, dscKeys } = await generateSigningCertificates({
      cscSigningHashAlgorithm: "SHA-512",
      cscKeyType: "ECDSA",
      cscCurve: "P-521",
      dscSigningHashAlgorithm: "SHA-384",
      dscKeyType: "ECDSA",
      dscCurve: "P-384",
    })
    // Generate SOD and sign it with DSC keypair
    const { sod } = await generateSod(dg1, [dsc], "SHA-512")
    const { sod: signedSod } = await signSod(sod, dscKeys, "SHA-384")
    // Add newly generated CSC to masterlist
    masterlist.certificates.push(parseCertificate(cscPem))
    // Load passport data into helper
    const contentInfoWrappedSod = serializeAsn(wrapSodInContentInfo(signedSod))
    await helper.loadPassport(dg1, Binary.from(contentInfoWrappedSod))
    helper.setMasterlist(masterlist)
  })

  describe("dsc", () => {
    test("ecdsa nist p-521", async () => {
      const circuit = Circuit.from(`sig_check_dsc_tbs_${MAX_TBS_LENGTH}_ecdsa_nist_p521_sha512`)
      const inputs = await helper.generateCircuitInputs("dsc")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      expect(proof.publicInputs.length).toEqual(2)
      const merkleRoot = getMerkleRootFromDSCProof(proof)
      expect(merkleRoot).toBeDefined()
      dscCommitment = getCommitmentFromDSCProof(proof)
      await circuit.destroy()
    }, 60000)
  })

  describe("id", () => {
    test("ecdsa nist p-384", async () => {
      const circuit = Circuit.from(`sig_check_id_data_tbs_${MAX_TBS_LENGTH}_ecdsa_nist_p384_sha384`)
      const inputs = await helper.generateCircuitInputs("id")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIDDataProof(proof)
      idDataCommitment = getCommitmentOutFromIDDataProof(proof)
      expect(commitmentIn).toEqual(dscCommitment)
      await circuit.destroy()
    }, 30000)
  })

  describe("integrity", () => {
    test("data integrity check", async () => {
      const circuit = Circuit.from("data_check_integrity_sha512")
      const inputs = await helper.generateCircuitInputs("integrity")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIntegrityProof(proof)
      integrityCheckCommitment = getCommitmentOutFromIntegrityProof(proof)
      const currentDate = getCurrentDateFromIntegrityProof(proof)
      expect(commitmentIn).toEqual(idDataCommitment)
      expect(currentDate).toEqual(globalCurrentDate)
      await circuit.destroy()
    }, 30000)
  })

  describe("disclose", () => {
    let circuit: Circuit
    beforeAll(async () => {
      circuit = Circuit.from("disclose_bytes")
    })
    afterAll(async () => {
      await circuit.destroy()
    })

    test("disclose all bytes", async () => {
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
      const proof = await circuit.prove(inputs, { witness: await circuit.solve(inputs) })
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
      globalNullifier = getNullifierFromDisclosureProof(proof)
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
      expect(globalNullifier).toBeDefined()
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("disclose some bytes", async () => {
      const query: Query = {
        nationality: { disclose: true },
      }
      let inputs = await getDiscloseCircuitInputs(helper.passport as any, query, 3n)
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      const proof = await circuit.prove(inputs, { witness: await circuit.solve(inputs) })
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
      expect(disclosedData.issuingCountry).toBe("")
      expect(disclosedData.nationality).toBe("AUS")
      expect(disclosedData.documentType).toBe("other")
      expect(disclosedData.documentNumber).toBe("")
      expect(disclosedData.name).toBe("")
      expect(disclosedData.firstName).toBe("")
      expect(disclosedData.lastName).toBe("")
      expect(isNaN(disclosedData.dateOfBirth.getTime())).toBe(true)
      expect(isNaN(disclosedData.dateOfExpiry.getTime())).toBe(true)
      expect(disclosedData.gender).toBe("")
      expect(nullifier).toEqual(globalNullifier)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })
  })
})
