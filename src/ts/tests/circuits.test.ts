import {
  Binary,
  convertPemToPackagedCertificate,
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
  getDiscloseCircuitInputs,
  SanctionsBuilder,
  getIssuingCountryExclusionCircuitInputs,
  getIssuingCountryInclusionCircuitInputs,
  getParameterCommitmentFromDisclosureProof,
  getCountryParameterCommitment,
  getAgeParameterCommitment,
  getDateParameterCommitment,
  getDiscloseParameterCommitment,
  getDisclosedBytesFromMrzAndMask,
  getDiscloseEVMParameterCommitment,
  getCountryEVMParameterCommitment,
  getAgeEVMParameterCommitment,
  getDateEVMParameterCommitment,
  ProofType,
  getBindCircuitInputs,
  getBindParameterCommitment,
  formatBoundData,
  getBindEVMParameterCommitment,
  getSanctionsExclusionCheckCircuitInputs,
  getUnixTimestamp,
  getNowTimestamp,
  getCurrentDateFromIntegrityProof,
} from "@zkpassport/utils"
import type { PackagedCertificate, Query } from "@zkpassport/utils"
import { beforeAll, describe, expect, test } from "@jest/globals"
import * as path from "path"
import { TestHelper } from "../test-helper"
import { generateSigningCertificates, signSod } from "../passport-generator"
import { loadKeypairFromFile } from "../passport-generator"
import { wrapSodInContentInfo } from "../sod-generator"
import { generateSod } from "../sod-generator"
import { serializeAsn, createUTCDate } from "../utils"
import { Circuit } from "../circuits"
import fs from "fs"

// Test constants
const SALT = 3n;
const EXPECTED_NULLIFIER = 4853682424986581472334861422312401004117384679706333968331573984300501658337n;
const nowTimestamp = getNowTimestamp()

describe("subcircuits - RSA PKCS", () => {
  const helper = new TestHelper()
  const cscaCerts: PackagedCertificate[] = []
  const FIXTURES_PATH = path.join(__dirname, "fixtures")
  const DSC_KEYPAIR_PATH = path.join(FIXTURES_PATH, "dsc-keypair-rsa.json")
  const MAX_TBS_LENGTH = 700
  let dscCommitment: bigint
  let idDataCommitment: bigint
  let integrityCheckCommitment: bigint

  beforeAll(async () => {
    // Add CSCA certificate test fixtures
    const fixtureCSCACerts = JSON.parse(
      fs.readFileSync(path.join(FIXTURES_PATH, "csca-packaged-certs.json"), "utf8"),
    ).certificates
    cscaCerts.push(...fixtureCSCACerts)

    // Johnny Silverhand's MRZ
    const mrz =
      "P<AUSSILVERHAND<<JOHNNY<<<<<<<<<<<<<<<<<<<<<PA1234567_AUS881112_M300101_<CYBERCITY<<<<<<"
    const dg1 = Binary.fromHex("615B5F1F58").concat(Binary.from(mrz))
    // Load DSC keypair
    const dscKeypair = await loadKeypairFromFile(DSC_KEYPAIR_PATH)

    // Generate CSCA and DSC signing certificates
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

    // Add newly generated CSCA certificate to the list
    cscaCerts.push(convertPemToPackagedCertificate(cscPem))

    // Load passport data into helper
    const contentInfoWrappedSod = serializeAsn(wrapSodInContentInfo(signedSod))
    await helper.loadPassport(dg1, Binary.from(contentInfoWrappedSod))
    helper.setCertificates(cscaCerts)
  })

  describe("dsc", () => {
    test("rsa pkcs 4096", async () => {
      const circuit = Circuit.from(`sig_check_dsc_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_4096_sha512`)
      const inputs = await helper.generateCircuitInputs("dsc")
      const proof = await circuit.prove(inputs, {
        circuitName: `sig_check_dsc_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_4096_sha512`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      expect(proof.publicInputs.length).toEqual(2)
      const merkleRoot = getMerkleRootFromDSCProof(proof)
      expect(merkleRoot).toBeDefined()
      dscCommitment = getCommitmentFromDSCProof(proof)
      await circuit.destroy()
    }, 30000)
  })

  describe("id", () => {
    test("rsa pkcs 2048", async () => {
      const circuit = Circuit.from(`sig_check_id_data_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_2048_sha256`)
      const inputs = await helper.generateCircuitInputs("id")
      const proof = await circuit.prove(inputs, {
        circuitName: `sig_check_id_data_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_2048_sha256`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIDDataProof(proof)
      idDataCommitment = getCommitmentOutFromIDDataProof(proof)
      expect(commitmentIn).toEqual(dscCommitment)
      await circuit.destroy()
    }, 30000)
  })

  describe("integrity", () => {
    test("data integrity check", async () => {
      const circuit = Circuit.from("data_check_integrity_sa_sha256_dg_sha256")
      const inputs = await helper.generateCircuitInputs("integrity", nowTimestamp)
      const proof = await circuit.prove(inputs, {
        circuitName: `data_check_integrity_sa_sha256_dg_sha256`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIntegrityProof(proof)
      expect(commitmentIn).toEqual(idDataCommitment)
      integrityCheckCommitment = getCommitmentOutFromIntegrityProof(proof)
      const currentDate = getCurrentDateFromIntegrityProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
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
      let inputs = await getDiscloseCircuitInputs(helper.passport as any, query, SALT)
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      const proof = await circuit.prove(inputs, {
        witness: await circuit.solve(inputs),
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
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("disclose some bytes", async () => {
      const query: Query = {
        nationality: { disclose: true },
      }
      let inputs = await getDiscloseCircuitInputs(helper.passport as any, query, SALT)
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      const proof = await circuit.prove(inputs, {
        witness: await circuit.solve(inputs),
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
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })
  })

  describe("disclose evm", () => {
    let circuit: Circuit
    beforeAll(async () => {
      circuit = Circuit.from("disclose_bytes_evm")
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
      let inputs = await getDiscloseCircuitInputs(helper.passport as any, query, SALT)
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      const proof = await circuit.prove(inputs, {
        witness: await circuit.solve(inputs),
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
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("disclose some bytes", async () => {
      const query: Query = {
        nationality: { disclose: true },
      }
      let inputs = await getDiscloseCircuitInputs(helper.passport as any, query, SALT)
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      const proof = await circuit.prove(inputs, {
        witness: await circuit.solve(inputs),
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
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })
  })

  describe("inclusion-check", () => {
    test("nationality", async () => {
      const circuit = Circuit.from("inclusion_check_nationality")
      const query: Query = {
        nationality: { in: ["AUS", "FRA", "USA", "GBR"] },
      }
      const inputs = await getNationalityInclusionCircuitInputs(helper.passport as any, query, SALT)
      if (!inputs) throw new Error("Unable to generate inclusion check circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `inclusion_check_nationality`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getCountryParameterCommitment(
        ProofType.NATIONALITY_INCLUSION,
        ["AUS", "FRA", "USA", "GBR"],
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
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
        SALT,
      )
      if (!inputs) throw new Error("Unable to generate inclusion check circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `inclusion_check_issuing_country`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getCountryParameterCommitment(
        ProofType.ISSUING_COUNTRY_INCLUSION,
        ["AUS", "FRA", "USA", "GBR"],
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      await circuit.destroy()
    })
  })

  describe("inclusion-check evm", () => {
    test("nationality", async () => {
      const circuit = Circuit.from("inclusion_check_nationality_evm")
      const query: Query = {
        nationality: { in: ["AUS", "FRA", "USA", "GBR"] },
      }
      const inputs = await getNationalityInclusionCircuitInputs(helper.passport as any, query, SALT)
      if (!inputs) throw new Error("Unable to generate inclusion check circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `inclusion_check_nationality_evm`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getCountryEVMParameterCommitment(
        ProofType.NATIONALITY_INCLUSION,
        ["AUS", "FRA", "USA", "GBR"],
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      await circuit.destroy()
    }, 30000)

    test("issuing country", async () => {
      const circuit = Circuit.from("inclusion_check_issuing_country_evm")
      const query: Query = {
        issuing_country: { in: ["AUS", "FRA", "USA", "GBR"] },
      }
      const inputs = await getIssuingCountryInclusionCircuitInputs(
        helper.passport as any,
        query,
        SALT,
      )
      if (!inputs) throw new Error("Unable to generate inclusion check circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `inclusion_check_issuing_country_evm`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getCountryEVMParameterCommitment(
        ProofType.ISSUING_COUNTRY_INCLUSION,
        ["AUS", "FRA", "USA", "GBR"],
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      await circuit.destroy()
    }, 30000)
  })

  describe("exclusion-check", () => {
    test("nationality", async () => {
      const circuit = Circuit.from("exclusion_check_nationality")
      const query: Query = {
        nationality: { out: ["FRA", "USA", "GBR"] },
      }
      const inputs = await getNationalityExclusionCircuitInputs(helper.passport as any, query, SALT)
      if (!inputs) throw new Error("Unable to generate exclusion check circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `exclusion_check_nationality`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      // Note that the order is in ascending order
      // while the original query was not
      // Before being passed to the circuit, the list is sorted in ascending order
      const calculatedParamCommitment = await getCountryParameterCommitment(
        ProofType.NATIONALITY_EXCLUSION,
        ["FRA", "GBR", "USA"],
        true,
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      await circuit.destroy()
    })

    test.only("issuing country", async () => {
      const circuit = Circuit.from("exclusion_check_issuing_country")
      const query: Query = {
        issuing_country: { out: ["FRA", "USA", "GBR"] },
      }
      const inputs = await getIssuingCountryExclusionCircuitInputs(
        helper.passport as any,
        query,
        SALT,
      )
      if (!inputs) throw new Error("Unable to generate exclusion check circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `exclusion_check_issuing_country`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      // Note that the order is in ascending order
      // while the original query was not
      // Before being passed to the circuit, the list is sorted in ascending order
      const calculatedParamCommitment = await getCountryParameterCommitment(
        ProofType.ISSUING_COUNTRY_EXCLUSION,
        ["FRA", "GBR", "USA"],
        true,
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      await circuit.destroy()
    })

    test("sanctions exclusion check", async () => {
      const circuit = Circuit.from("exclusion_check_sanctions")
      const sanctions = await SanctionsBuilder.create();
      const inputs = await getSanctionsExclusionCheckCircuitInputs(helper.passport as any, SALT, undefined, undefined, sanctions)

      console.log("inputs", inputs)
      console.log("passport_no_and_nationality_proof - left", inputs.proofs.passport_no_and_nationality_proof.left)
      console.log("passport_no_and_nationality_proof - right", inputs.proofs.passport_no_and_nationality_proof.right)
      console.log("name_and_dob_proof - left", inputs.proofs.name_and_dob_proof.left)
      console.log("name_and_dob_proof - right", inputs.proofs.name_and_dob_proof.right)
      console.log("name_and_yob_proof - left", inputs.proofs.name_and_yob_proof.left)
      console.log("name_and_yob_proof - right", inputs.proofs.name_and_yob_proof.right)

      if (!inputs) throw new Error("Unable to generate sanctions circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `exclusion_check_sanctions`,
      });
      expect(proof).toBeDefined()
      const calculatedParamCommitment = await sanctions.getSanctionsParameterCommitment()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      await circuit.destroy()
    }, 10000)

  })

  describe("exclusion-check evm", () => {
    test("nationality", async () => {
      const circuit = Circuit.from("exclusion_check_nationality_evm")
      const query: Query = {
        nationality: { out: ["FRA", "USA", "GBR"] },
      }
      const inputs = await getNationalityExclusionCircuitInputs(helper.passport as any, query, SALT)
      if (!inputs) throw new Error("Unable to generate exclusion check circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `exclusion_check_nationality_evm`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      // Note that the order is in ascending order
      // while the original query was not
      // Before being passed to the circuit, the list is sorted in ascending order
      const calculatedParamCommitment = await getCountryEVMParameterCommitment(
        ProofType.NATIONALITY_EXCLUSION,
        ["FRA", "GBR", "USA"],
        true,
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      await circuit.destroy()
    }, 30000)

    test("issuing country", async () => {
      const circuit = Circuit.from("exclusion_check_issuing_country_evm")
      const query: Query = {
        issuing_country: { out: ["FRA", "USA", "GBR"] },
      }
      const inputs = await getIssuingCountryExclusionCircuitInputs(
        helper.passport as any,
        query,
        SALT,
      )
      if (!inputs) throw new Error("Unable to generate exclusion check circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `exclusion_check_issuing_country_evm`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      // Note that the order is in ascending order
      // while the original query was not
      // Before being passed to the circuit, the list is sorted in ascending order
      const calculatedParamCommitment = await getCountryEVMParameterCommitment(
        ProofType.ISSUING_COUNTRY_EXCLUSION,
        ["FRA", "GBR", "USA"],
        true,
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      await circuit.destroy()
    }, 30000)

    test("sanctions exclusion check", async () => {
      const sanctions = await SanctionsBuilder.create();
      const circuit = Circuit.from("exclusion_check_sanctions_evm")

      const inputs = await getSanctionsExclusionCheckCircuitInputs(helper.passport as any, SALT, undefined, undefined, sanctions)
      if (!inputs) throw new Error("Unable to generate sanctions circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `exclusion_check_sanctions_evm`,
      });
      expect(proof).toBeDefined()

      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await sanctions.getSanctionsEvmParameterCommitment()
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      await circuit.destroy()
    }, 10000)
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
      // const inputs = await getAgeCircuitInputs(helper.passport as any, query, SALT)
      const inputs = await getAgeCircuitInputs(
        helper.passport as any,
        query,
        3n,
        0n,
        0n,
        nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate compare-age greater than circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `compare_age`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getAgeParameterCommitment(nowTimestamp, 18, 0)
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("less than", async () => {
      const age = calculateAge(helper.passport)
      const query: Query = {
        age: { lt: age + 1 },
      }
      // const inputs = await getAgeCircuitInputs(helper.passport as any, query, SALT)
      const inputs = await getAgeCircuitInputs(
        helper.passport as any,
        query,
        3n,
        0n,
        0n,
        nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate compare-age less than circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `compare_age`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getAgeParameterCommitment(nowTimestamp, 0, age + 1)
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("between", async () => {
      const age = calculateAge(helper.passport)
      const query: Query = {
        age: { gte: age, lt: age + 2 },
      }
      // const inputs = await getAgeCircuitInputs(helper.passport as any, query, SALT)
      const inputs = await getAgeCircuitInputs(
        helper.passport as any,
        query,
        3n,
        0n,
        0n,
        nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate compare-age between circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `compare_age`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getAgeParameterCommitment(nowTimestamp, age, age + 2)
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("equal", async () => {
      const age = calculateAge(helper.passport)
      const query: Query = {
        age: { eq: age },
      }
      // const inputs = await getAgeCircuitInputs(helper.passport as any, query, SALT)
      const inputs = await getAgeCircuitInputs(
        helper.passport as any,
        query,
        3n,
        0n,
        0n,
        nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate compare-age equal circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `compare_age`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getAgeParameterCommitment(nowTimestamp, age, age)
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("disclose", async () => {
      const query: Query = {
        age: { disclose: true },
      }
      // const inputs = await getAgeCircuitInputs(helper.passport as any, query, SALT)
      const inputs = await getAgeCircuitInputs(
        helper.passport as any,
        query,
        3n,
        0n,
        0n,
        nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate compare-age equal circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `compare_age`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const age = calculateAge(helper.passport)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getAgeParameterCommitment(nowTimestamp, age, age)
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("range", async () => {
      const age = calculateAge(helper.passport)
      const query: Query = {
        age: { range: [age - 5, age + 5] },
      }
      // const inputs = await getAgeCircuitInputs(helper.passport as any, query, SALT)
      const inputs = await getAgeCircuitInputs(
        helper.passport as any,
        query,
        3n,
        0n,
        0n,
        nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate compare-age range circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `compare_age`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getAgeParameterCommitment(
        nowTimestamp,
        age - 5,
        age + 5,
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })
  })

  describe("compare-age evm", () => {
    let circuit: Circuit
    beforeAll(async () => {
      circuit = Circuit.from("compare_age_evm")
    })
    afterAll(async () => {
      await circuit.destroy()
    })

    test("greater than", async () => {
      const query: Query = {
        age: { gte: 18 },
      }
      // const inputs = await getAgeCircuitInputs(helper.passport as any, query, SALT)
      const inputs = await getAgeCircuitInputs(
        helper.passport as any,
        query,
        3n,
        0n,
        0n,
        nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate compare-age greater than circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `compare_age_evm`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getAgeEVMParameterCommitment(nowTimestamp, 18, 0)
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
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
      // const inputs = await getBirthdateCircuitInputs(helper.passport as any, query, SALT)
      const inputs = await getBirthdateCircuitInputs(
        helper.passport as any,
        query,
        3n,
        0n,
        0n,
        nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate compare-birthdate equal circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `compare_birthdate`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateParameterCommitment(
        ProofType.BIRTHDATE,
        nowTimestamp,
        getUnixTimestamp(new Date(1988, 10, 12)),
        getUnixTimestamp(new Date(1988, 10, 12)),
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("range", async () => {
      const query: Query = {
        birthdate: { range: [new Date(1988, 10, 11), new Date(1988, 10, 13)] },
      }
      // const inputs = await getBirthdateCircuitInputs(helper.passport as any, query, SALT)
      const inputs = await getBirthdateCircuitInputs(
        helper.passport as any,
        query,
        3n,
        0n,
        0n,
        nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate compare-birthdate range circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `compare_birthdate`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateParameterCommitment(
        ProofType.BIRTHDATE,
        nowTimestamp,
        getUnixTimestamp(new Date(1988, 10, 11)),
        getUnixTimestamp(new Date(1988, 10, 13)),
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("disclose", async () => {
      const query: Query = {
        birthdate: { disclose: true },
      }
      // const inputs = await getBirthdateCircuitInputs(helper.passport as any, query, SALT)
      const inputs = await getBirthdateCircuitInputs(
        helper.passport as any,
        query,
        3n,
        0n,
        0n,
        nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate compare-birthdate disclose circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `compare_birthdate`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateParameterCommitment(
        ProofType.BIRTHDATE,
        nowTimestamp,
        getUnixTimestamp(new Date(1988, 10, 12)),
        getUnixTimestamp(new Date(1988, 10, 12)),
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("greater than", async () => {
      const query: Query = {
        birthdate: { gte: new Date(1988, 10, 11) },
      }
      // const inputs = await getBirthdateCircuitInputs(helper.passport as any, query, SALT)
      const inputs = await getBirthdateCircuitInputs(
        helper.passport as any,
        query,
        3n,
        0n,
        0n,
        nowTimestamp,
      )
      if (!inputs)
        throw new Error("Unable to generate compare-birthdate greater than circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `compare_birthdate`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateParameterCommitment(
        ProofType.BIRTHDATE,
        nowTimestamp,
        getUnixTimestamp(new Date(1988, 10, 11)),
        0,
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("less than", async () => {
      const query: Query = {
        birthdate: { lte: new Date(1988, 10, 15) },
      }
      // const inputs = await getBirthdateCircuitInputs(helper.passport as any, query, SALT)
      const inputs = await getBirthdateCircuitInputs(
        helper.passport as any,
        query,
        3n,
        0n,
        0n,
        nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate compare-birthdate less than circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `compare_birthdate`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateParameterCommitment(
        ProofType.BIRTHDATE,
        nowTimestamp,
        0,
        getUnixTimestamp(new Date(1988, 10, 15)),
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("between", async () => {
      const query: Query = {
        birthdate: { gte: new Date(1988, 10, 11), lte: new Date(1988, 10, 15) },
      }
      // const inputs = await getBirthdateCircuitInputs(helper.passport as any, query, SALT)
      const inputs = await getBirthdateCircuitInputs(
        helper.passport as any,
        query,
        3n,
        0n,
        0n,
        nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate compare-birthdate between circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `compare_birthdate`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateParameterCommitment(
        ProofType.BIRTHDATE,
        nowTimestamp,
        getUnixTimestamp(new Date(1988, 10, 11)),
        getUnixTimestamp(new Date(1988, 10, 15)),
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })
  })

  describe("compare-birthdate evm", () => {
    let circuit: Circuit
    beforeAll(async () => {
      circuit = Circuit.from("compare_birthdate_evm")
    })
    afterAll(async () => {
      await circuit.destroy()
    })

    test("equal", async () => {
      const query: Query = {
        // Remember months start at 0 so 10 is November
        birthdate: { eq: new Date(1988, 10, 12) },
      }
      // const inputs = await getBirthdateCircuitInputs(helper.passport as any, query, SALT)
      const inputs = await getBirthdateCircuitInputs(
        helper.passport as any,
        query,
        3n,
        0n,
        0n,
        nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate compare-birthdate equal circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `compare_birthdate_evm`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateEVMParameterCommitment(
        ProofType.BIRTHDATE,
        nowTimestamp,
        getUnixTimestamp(new Date(1988, 10, 12)),
        getUnixTimestamp(new Date(1988, 10, 12)),
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
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
      // const inputs = await getExpiryDateCircuitInputs(helper.passport as any, query, SALT)
      const inputs = await getExpiryDateCircuitInputs(
        helper.passport as any,
        query,
        3n,
        0n,
        0n,
        nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate compare-expirydate equal circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `compare_expiry`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateParameterCommitment(
        ProofType.EXPIRY_DATE,
        nowTimestamp,
        getUnixTimestamp(new Date(2030, 0, 1)),
        getUnixTimestamp(new Date(2030, 0, 1)),
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("range", async () => {
      const query: Query = {
        expiry_date: { range: [new Date(2025, 0, 1), new Date(2035, 0, 1)] },
      }
      // const inputs = await getExpiryDateCircuitInputs(helper.passport as any, query, SALT)
      const inputs = await getExpiryDateCircuitInputs(
        helper.passport as any,
        query,
        3n,
        0n,
        0n,
        nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate compare-expirydate range circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `compare_expiry`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateParameterCommitment(
        ProofType.EXPIRY_DATE,
        nowTimestamp,
        getUnixTimestamp(new Date(2025, 0, 1)),
        getUnixTimestamp(new Date(2035, 0, 1)),
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("disclose", async () => {
      const query: Query = {
        expiry_date: { disclose: true },
      }
      // const inputs = await getExpiryDateCircuitInputs(helper.passport as any, query, SALT)
      const inputs = await getExpiryDateCircuitInputs(
        helper.passport as any,
        query,
        3n,
        0n,
        0n,
        nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate compare-expirydate disclose circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `compare_expiry`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateParameterCommitment(
        ProofType.EXPIRY_DATE,
        nowTimestamp,
        getUnixTimestamp(new Date(2030, 0, 1)),
        getUnixTimestamp(new Date(2030, 0, 1)),
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("greater than", async () => {
      const query: Query = {
        expiry_date: { gte: new Date(2025, 0, 1) },
      }
      // const inputs = await getExpiryDateCircuitInputs(helper.passport as any, query, SALT)
      const inputs = await getExpiryDateCircuitInputs(
        helper.passport as any,
        query,
        3n,
        0n,
        0n,
        nowTimestamp,
      )
      if (!inputs)
        throw new Error("Unable to generate compare-expirydate greater than circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `compare_expiry`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateParameterCommitment(
        ProofType.EXPIRY_DATE,
        nowTimestamp,
        getUnixTimestamp(new Date(2025, 0, 1)),
        0,
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("less than", async () => {
      const query: Query = {
        expiry_date: { lte: new Date(2035, 0, 1) },
      }
      // const inputs = await getExpiryDateCircuitInputs(helper.passport as any, query, SALT)
      const inputs = await getExpiryDateCircuitInputs(
        helper.passport as any,
        query,
        3n,
        0n,
        0n,
        nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate compare-expirydate less than circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `compare_expiry`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateParameterCommitment(
        ProofType.EXPIRY_DATE,
        nowTimestamp,
        0,
        getUnixTimestamp(new Date(2035, 0, 1)),
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("between", async () => {
      const query: Query = {
        expiry_date: { gte: new Date(2025, 0, 1), lte: new Date(2035, 0, 1) },
      }
      // const inputs = await getExpiryDateCircuitInputs(helper.passport as any, query, SALT)
      const inputs = await getExpiryDateCircuitInputs(
        helper.passport as any,
        query,
        3n,
        0n,
        0n,
        nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate compare-expirydate between circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `compare_expiry`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateParameterCommitment(
        ProofType.EXPIRY_DATE,
        nowTimestamp,
        getUnixTimestamp(new Date(2025, 0, 1)),
        getUnixTimestamp(new Date(2035, 0, 1)),
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })
  })

  describe("compare-expiry evm", () => {
    let circuit: Circuit
    beforeAll(async () => {
      circuit = Circuit.from("compare_expiry_evm")
    })
    afterAll(async () => {
      await circuit.destroy()
    })

    test("equal", async () => {
      const query: Query = {
        expiry_date: { eq: new Date(2030, 0, 1) },
      }
      // const inputs = await getExpiryDateCircuitInputs(helper.passport as any, query, SALT)
      const inputs = await getExpiryDateCircuitInputs(
        helper.passport as any,
        query,
        3n,
        0n,
        0n,
        nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate compare-expirydate equal circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `compare_expiry_evm`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateEVMParameterCommitment(
        ProofType.EXPIRY_DATE,
        nowTimestamp,
        getUnixTimestamp(new Date(2030, 0, 1)),
        getUnixTimestamp(new Date(2030, 0, 1)),
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })
  })

  describe("bind", () => {
    let circuit: Circuit
    beforeAll(async () => {
      circuit = Circuit.from("bind")
    })
    afterAll(async () => {
      await circuit.destroy()
    })

    test("bind to address", async () => {
      const query: Query = {
        bind: { user_address: "0x04Fb06E8BF44eC60b6A99D2F98551172b2F2dED8" },
      }
      const inputs = await getBindCircuitInputs(helper.passport as any, query, SALT)
      if (!inputs) throw new Error("Unable to generate compare-expirydate equal circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `bind`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const boundData = formatBoundData(query.bind!)
      const calculatedParamCommitment = await getBindParameterCommitment(boundData)
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })
  })

  describe("bind evm", () => {
    let circuit: Circuit
    beforeAll(async () => {
      circuit = Circuit.from("bind_evm")
    })
    afterAll(async () => {
      await circuit.destroy()
    })

    test("bind to address", async () => {
      const query: Query = {
        bind: { user_address: "0x04Fb06E8BF44eC60b6A99D2F98551172b2F2dED8" },
      }
      const inputs = await getBindCircuitInputs(helper.passport as any, query, SALT)
      if (!inputs) throw new Error("Unable to generate compare-expirydate equal circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `bind_evm`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const boundData = formatBoundData(query.bind!)
      const calculatedParamCommitment = await getBindEVMParameterCommitment(boundData)
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(
        EXPECTED_NULLIFIER,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })
  })
})

describe("subcircuits - RSA PKCS - SHA-1", () => {
  const helper = new TestHelper()
  const cscaCerts: PackagedCertificate[] = []
  const FIXTURES_PATH = path.join(__dirname, "fixtures")
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

  let globalNullifier: bigint

  beforeAll(async () => {
    // Add CSCA certificate test fixtures
    const fixtureCSCACerts = JSON.parse(
      fs.readFileSync(path.join(FIXTURES_PATH, "csca-packaged-certs.json"), "utf8"),
    ).certificates
    cscaCerts.push(...fixtureCSCACerts)

    // Johnny Silverhand's MRZ
    const mrz =
      "P<AUSSILVERHAND<<JOHNNY<<<<<<<<<<<<<<<<<<<<<PA1234567_AUS881112_M300101_<CYBERCITY<<<<<<"
    const dg1 = Binary.fromHex("615B5F1F58").concat(Binary.from(mrz))

    // Generate CSCA and DSC signing certificates
    const { cscPem, dsc, dscKeys } = await generateSigningCertificates({
      cscSigningHashAlgorithm: "SHA-1",
      cscKeyType: "RSA",
      cscKeySize: 4096,
      dscSigningHashAlgorithm: "SHA-1",
      dscKeyType: "RSA",
      dscKeySize: 2048,
    })
    // Generate SOD and sign it with DSC keypair
    const { sod } = await generateSod(dg1, [dsc], "SHA-1")
    const { sod: signedSod } = await signSod(sod, dscKeys, "SHA-1")

    // Add newly generated CSCA certificate to the list
    cscaCerts.push(convertPemToPackagedCertificate(cscPem))

    // Load passport data into helper
    const contentInfoWrappedSod = serializeAsn(wrapSodInContentInfo(signedSod))
    await helper.loadPassport(dg1, Binary.from(contentInfoWrappedSod))
    helper.setCertificates(cscaCerts)
  })

  describe("dsc", () => {
    test("rsa pkcs 4096", async () => {
      const circuit = Circuit.from(`sig_check_dsc_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_4096_sha1`)
      const inputs = await helper.generateCircuitInputs("dsc")
      const proof = await circuit.prove(inputs, {
        circuitName: `sig_check_dsc_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_4096_sha1`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      expect(proof.publicInputs.length).toEqual(2)
      const merkleRoot = getMerkleRootFromDSCProof(proof)
      expect(merkleRoot).toBeDefined()
      dscCommitment = getCommitmentFromDSCProof(proof)
      await circuit.destroy()
    }, 30000)
  })

  describe("id", () => {
    test("rsa pkcs 2048", async () => {
      const circuit = Circuit.from(`sig_check_id_data_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_2048_sha1`)
      const inputs = await helper.generateCircuitInputs("id")
      const proof = await circuit.prove(inputs, {
        circuitName: `sig_check_id_data_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_2048_sha1`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIDDataProof(proof)
      idDataCommitment = getCommitmentOutFromIDDataProof(proof)
      expect(commitmentIn).toEqual(dscCommitment)
      await circuit.destroy()
    }, 30000)
  })

  describe("integrity", () => {
    test("data integrity check", async () => {
      const circuit = Circuit.from("data_check_integrity_sa_sha1_dg_sha1")
      const inputs = await helper.generateCircuitInputs("integrity", nowTimestamp)
      const proof = await circuit.prove(inputs, {
        circuitName: `data_check_integrity_sa_sha1_dg_sha1`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIntegrityProof(proof)
      expect(commitmentIn).toEqual(idDataCommitment)
      integrityCheckCommitment = getCommitmentOutFromIntegrityProof(proof)
      const currentDate = getCurrentDateFromIntegrityProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
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
      let inputs = await getDiscloseCircuitInputs(helper.passport as any, query, SALT)
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      const proof = await circuit.prove(inputs, {
        witness: await circuit.solve(inputs),

        circuitName: `disclose_bytes`,
        useCli: true,
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
      let inputs = await getDiscloseCircuitInputs(helper.passport as any, query, SALT)
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      const proof = await circuit.prove(inputs, {
        witness: await circuit.solve(inputs),

        circuitName: `disclose_bytes`,
        useCli: true,
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

describe("subcircuits - RSA PKCS - SHA-224 integrity check", () => {
  const helper = new TestHelper()
  const cscaCerts: PackagedCertificate[] = []
  const FIXTURES_PATH = path.join(__dirname, "fixtures")
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

  let globalNullifier: bigint

  beforeAll(async () => {
    // Add CSCA certificate test fixtures
    const fixtureCSCACerts = JSON.parse(
      fs.readFileSync(path.join(FIXTURES_PATH, "csca-packaged-certs.json"), "utf8"),
    ).certificates
    cscaCerts.push(...fixtureCSCACerts)

    // Johnny Silverhand's MRZ
    const mrz =
      "P<AUSSILVERHAND<<JOHNNY<<<<<<<<<<<<<<<<<<<<<PA1234567_AUS881112_M300101_<CYBERCITY<<<<<<"
    const dg1 = Binary.fromHex("615B5F1F58").concat(Binary.from(mrz))

    // Generate CSCA and DSC signing certificates
    const { cscPem, dsc, dscKeys } = await generateSigningCertificates({
      cscSigningHashAlgorithm: "SHA-256",
      cscKeyType: "RSA",
      cscKeySize: 4096,
      dscSigningHashAlgorithm: "SHA-256",
      dscKeyType: "RSA",
      dscKeySize: 2048,
    })
    // Generate SOD and sign it with DSC keypair
    const { sod } = await generateSod(dg1, [dsc], "SHA-224")
    const { sod: signedSod } = await signSod(sod, dscKeys, "SHA-256")

    // Add newly generated CSCA certificate to the list
    cscaCerts.push(convertPemToPackagedCertificate(cscPem))

    // Load passport data into helper
    const contentInfoWrappedSod = serializeAsn(wrapSodInContentInfo(signedSod))
    await helper.loadPassport(dg1, Binary.from(contentInfoWrappedSod))
    helper.setCertificates(cscaCerts)
  })

  describe("dsc", () => {
    test("rsa pkcs 4096", async () => {
      const circuit = Circuit.from(`sig_check_dsc_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_4096_sha256`)
      const inputs = await helper.generateCircuitInputs("dsc")
      const proof = await circuit.prove(inputs, {
        circuitName: `sig_check_dsc_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_4096_sha256`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      expect(proof.publicInputs.length).toEqual(2)
      const merkleRoot = getMerkleRootFromDSCProof(proof)
      expect(merkleRoot).toBeDefined()
      dscCommitment = getCommitmentFromDSCProof(proof)
      await circuit.destroy()
    }, 30000)
  })

  describe("id", () => {
    test("rsa pkcs 2048", async () => {
      const circuit = Circuit.from(`sig_check_id_data_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_2048_sha256`)
      const inputs = await helper.generateCircuitInputs("id")
      const proof = await circuit.prove(inputs, {
        circuitName: `sig_check_id_data_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_2048_sha256`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIDDataProof(proof)
      idDataCommitment = getCommitmentOutFromIDDataProof(proof)
      expect(commitmentIn).toEqual(dscCommitment)
      await circuit.destroy()
    }, 30000)
  })

  describe("integrity", () => {
    test("data integrity check", async () => {
      const circuit = Circuit.from("data_check_integrity_sa_sha224_dg_sha224")
      const inputs = await helper.generateCircuitInputs("integrity", nowTimestamp)
      const proof = await circuit.prove(inputs, {
        circuitName: `data_check_integrity_sa_sha224_dg_sha224`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIntegrityProof(proof)
      expect(commitmentIn).toEqual(idDataCommitment)
      integrityCheckCommitment = getCommitmentOutFromIntegrityProof(proof)
      const currentDate = getCurrentDateFromIntegrityProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
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
      const proof = await circuit.prove(inputs, {
        witness: await circuit.solve(inputs),

        circuitName: `disclose_bytes`,
        useCli: true,
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
      const proof = await circuit.prove(inputs, {
        witness: await circuit.solve(inputs),

        circuitName: `disclose_bytes`,
        useCli: true,
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

describe("subcircuits - ECDSA NIST P-384 and P-256", () => {
  const helper = new TestHelper()
  const cscaCerts: PackagedCertificate[] = []
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
      "P<AUSSILVERHAND<<JOHNNY<MATTHEW<<<<<<<<<<<<<PA1234567_AUS881112_M300101_<CYBERCITY<<<<<<"
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
    cscaCerts.push(convertPemToPackagedCertificate(cscPem))
    // Load passport data into helper
    const contentInfoWrappedSod = serializeAsn(wrapSodInContentInfo(signedSod))
    await helper.loadPassport(dg1, Binary.from(contentInfoWrappedSod))
    helper.setCertificates(cscaCerts)
  })

  describe("dsc", () => {
    test("ecdsa nist p-384", async () => {
      const circuit = Circuit.from(`sig_check_dsc_tbs_${MAX_TBS_LENGTH}_ecdsa_nist_p384_sha384`)
      const inputs = await helper.generateCircuitInputs("dsc")
      const proof = await circuit.prove(inputs, {
        circuitName: `sig_check_dsc_tbs_${MAX_TBS_LENGTH}_ecdsa_nist_p384_sha384`,
        useCli: true,
      })
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
      const proof = await circuit.prove(inputs, {
        circuitName: `sig_check_id_data_tbs_${MAX_TBS_LENGTH}_ecdsa_nist_p256_sha256`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIDDataProof(proof)
      idDataCommitment = getCommitmentOutFromIDDataProof(proof)
      expect(commitmentIn).toEqual(dscCommitment)
      await circuit.destroy()
    }, 30000)
  })

  describe("integrity", () => {
    test("data integrity check", async () => {
      const circuit = Circuit.from("data_check_integrity_sa_sha384_dg_sha384")
      const inputs = await helper.generateCircuitInputs("integrity", nowTimestamp)
      const proof = await circuit.prove(inputs, {
        circuitName: `data_check_integrity_sa_sha384_dg_sha384`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIntegrityProof(proof)
      expect(commitmentIn).toEqual(idDataCommitment)
      integrityCheckCommitment = getCommitmentOutFromIntegrityProof(proof)
      const currentDate = getCurrentDateFromIntegrityProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
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
      let inputs = await getDiscloseCircuitInputs(helper.passport as any, query, SALT)
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `disclose_bytes`,
        useCli: true,
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
      let inputs = await getDiscloseCircuitInputs(helper.passport as any, query, SALT)
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      const proof = await circuit.prove(inputs, {
        witness: await circuit.solve(inputs),

        circuitName: `disclose_bytes`,
        useCli: true,
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
  const cscaCerts: PackagedCertificate[] = []
  const FIXTURES_PATH = path.join(__dirname, "fixtures")
  const DSC_KEYPAIR_PATH = path.join(FIXTURES_PATH, "dsc-keypair-ecdsa.json")
  const MAX_TBS_LENGTH = 700
  let dscCommitment: bigint
  let idDataCommitment: bigint
  let integrityCheckCommitment: bigint
  // We need to store the nullifier
  // as we cannot compare to a constant value
  // since ECDSA signatures are not deterministic
  let globalNullifier: bigint

  beforeAll(async () => {
    // Johnny Silverhand's MRZ
    const mrz =
      "P<AUSSILVERHAND<<JOHNNY<<<<<<<<<<<<<<<<<<<<<PA1234567_AUS881112_M300101_<CYBERCITY<<<<<<"
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
    cscaCerts.push(convertPemToPackagedCertificate(cscPem))
    // Load passport data into helper
    const contentInfoWrappedSod = serializeAsn(wrapSodInContentInfo(signedSod))
    await helper.loadPassport(dg1, Binary.from(contentInfoWrappedSod))
    helper.setCertificates(cscaCerts)
  })

  describe("dsc", () => {
    test("ecdsa nist p-521", async () => {
      const circuit = Circuit.from(`sig_check_dsc_tbs_${MAX_TBS_LENGTH}_ecdsa_nist_p521_sha512`)
      const inputs = await helper.generateCircuitInputs("dsc")
      const proof = await circuit.prove(inputs, {
        circuitName: `sig_check_dsc_tbs_${MAX_TBS_LENGTH}_ecdsa_nist_p521_sha512`,
        useCli: true,
      })
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
      const proof = await circuit.prove(inputs, {
        circuitName: `sig_check_id_data_tbs_${MAX_TBS_LENGTH}_ecdsa_nist_p384_sha384`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIDDataProof(proof)
      idDataCommitment = getCommitmentOutFromIDDataProof(proof)
      expect(commitmentIn).toEqual(dscCommitment)
      await circuit.destroy()
    }, 30000)
  })

  describe("integrity", () => {
    test("data integrity check", async () => {
      const circuit = Circuit.from("data_check_integrity_sa_sha512_dg_sha512")
      const inputs = await helper.generateCircuitInputs("integrity", nowTimestamp)
      const proof = await circuit.prove(inputs, {
        circuitName: `data_check_integrity_sa_sha512_dg_sha512`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIntegrityProof(proof)
      expect(commitmentIn).toEqual(idDataCommitment)
      integrityCheckCommitment = getCommitmentOutFromIntegrityProof(proof)
      const currentDate = getCurrentDateFromIntegrityProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
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
      let inputs = await getDiscloseCircuitInputs(helper.passport as any, query, SALT)
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      const proof = await circuit.prove(inputs, {
        witness: await circuit.solve(inputs),

        circuitName: `disclose_bytes`,
        useCli: true,
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
      let inputs = await getDiscloseCircuitInputs(helper.passport as any, query, SALT)
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      const proof = await circuit.prove(inputs, {
        witness: await circuit.solve(inputs),

        circuitName: `disclose_bytes`,
        useCli: true,
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

describe("subcircuits - ECDSA NIST P-256 and Brainpool P-192", () => {
  const helper = new TestHelper()
  const cscaCerts: PackagedCertificate[] = []
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
      "P<AUSSILVERHAND<<JOHNNY<MATTHEW<<<<<<<<<<<<<PA1234567_AUS881112_M300101_<CYBERCITY<<<<<<"
    const dg1 = Binary.fromHex("615B5F1F58").concat(Binary.from(mrz))

    // Generate CSC and DSC signing certificates
    const { cscPem, dsc, dscKeys } = await generateSigningCertificates({
      cscSigningHashAlgorithm: "SHA-1",
      cscKeyType: "ECDSA",
      cscCurve: "P-256",
      dscSigningHashAlgorithm: "SHA-1",
      dscKeyType: "ECDSA",
      dscCurve: "brainpoolP192r1",
    })
    // Generate SOD and sign it with DSC keypair
    const { sod } = await generateSod(dg1, [dsc], "SHA-1")
    const { sod: signedSod } = await signSod(sod, dscKeys, "SHA-1")
    // Add newly generated CSC to masterlist
    cscaCerts.push(convertPemToPackagedCertificate(cscPem))
    // Load passport data into helper
    const contentInfoWrappedSod = serializeAsn(wrapSodInContentInfo(signedSod))
    await helper.loadPassport(dg1, Binary.from(contentInfoWrappedSod))
    helper.setCertificates(cscaCerts)
  })

  describe("dsc", () => {
    test("ecdsa nist p-256", async () => {
      const circuit = Circuit.from(`sig_check_dsc_tbs_${MAX_TBS_LENGTH}_ecdsa_nist_p256_sha1`)
      const inputs = await helper.generateCircuitInputs("dsc")
      const proof = await circuit.prove(inputs, {
        circuitName: `sig_check_dsc_tbs_${MAX_TBS_LENGTH}_ecdsa_nist_p256_sha1`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      expect(proof.publicInputs.length).toEqual(2)
      const merkleRoot = getMerkleRootFromDSCProof(proof)
      expect(merkleRoot).toBeDefined()
      dscCommitment = getCommitmentFromDSCProof(proof)
      await circuit.destroy()
    }, 60000)
  })

  describe("id", () => {
    test("ecdsa brainpool 192r1", async () => {
      const circuit = Circuit.from(
        `sig_check_id_data_tbs_${MAX_TBS_LENGTH}_ecdsa_brainpool_192r1_sha1`,
      )
      const inputs = await helper.generateCircuitInputs("id")
      const proof = await circuit.prove(inputs, {
        circuitName: `sig_check_id_data_tbs_${MAX_TBS_LENGTH}_ecdsa_nist_p192_sha1`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIDDataProof(proof)
      idDataCommitment = getCommitmentOutFromIDDataProof(proof)
      expect(commitmentIn).toEqual(dscCommitment)
      await circuit.destroy()
    }, 30000)
  })

  describe("integrity", () => {
    test("data integrity check", async () => {
      const circuit = Circuit.from("data_check_integrity_sa_sha1_dg_sha1")
      const inputs = await helper.generateCircuitInputs("integrity", nowTimestamp)
      const proof = await circuit.prove(inputs, {
        circuitName: `data_check_integrity_sa_sha1_dg_sha1`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIntegrityProof(proof)
      integrityCheckCommitment = getCommitmentOutFromIntegrityProof(proof)
      expect(commitmentIn).toEqual(idDataCommitment)
      const currentDate = getCurrentDateFromIntegrityProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
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
      const proof = await circuit.prove(inputs, {
        circuitName: `disclose_bytes`,
        useCli: true,
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
      const proof = await circuit.prove(inputs, {
        witness: await circuit.solve(inputs),

        circuitName: `disclose_bytes`,
        useCli: true,
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

describe("subcircuits - ECDSA NIST P-256 and Brainpool P-224", () => {
  const helper = new TestHelper()
  const cscaCerts: PackagedCertificate[] = []
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
      "P<AUSSILVERHAND<<JOHNNY<MATTHEW<<<<<<<<<<<<<PA1234567_AUS881112_M300101_<CYBERCITY<<<<<<"
    const dg1 = Binary.fromHex("615B5F1F58").concat(Binary.from(mrz))

    // Generate CSC and DSC signing certificates
    const { cscPem, dsc, dscKeys } = await generateSigningCertificates({
      cscSigningHashAlgorithm: "SHA-1",
      cscKeyType: "ECDSA",
      cscCurve: "P-256",
      dscSigningHashAlgorithm: "SHA-1",
      dscKeyType: "ECDSA",
      dscCurve: "brainpoolP224r1",
    })
    // Generate SOD and sign it with DSC keypair
    const { sod } = await generateSod(dg1, [dsc], "SHA-1")
    const { sod: signedSod } = await signSod(sod, dscKeys, "SHA-1")
    // Add newly generated CSC to masterlist
    cscaCerts.push(convertPemToPackagedCertificate(cscPem))
    // Load passport data into helper
    const contentInfoWrappedSod = serializeAsn(wrapSodInContentInfo(signedSod))
    await helper.loadPassport(dg1, Binary.from(contentInfoWrappedSod))
    helper.setCertificates(cscaCerts)
  })

  describe("dsc", () => {
    test("ecdsa nist p-256", async () => {
      const circuit = Circuit.from(`sig_check_dsc_tbs_${MAX_TBS_LENGTH}_ecdsa_nist_p256_sha1`)
      const inputs = await helper.generateCircuitInputs("dsc")
      const proof = await circuit.prove(inputs, {
        circuitName: `sig_check_dsc_tbs_${MAX_TBS_LENGTH}_ecdsa_nist_p256_sha1`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      expect(proof.publicInputs.length).toEqual(2)
      const merkleRoot = getMerkleRootFromDSCProof(proof)
      expect(merkleRoot).toBeDefined()
      dscCommitment = getCommitmentFromDSCProof(proof)
      await circuit.destroy()
    }, 60000)
  })

  describe("id", () => {
    test("ecdsa brainpool 224r1", async () => {
      const circuit = Circuit.from(
        `sig_check_id_data_tbs_${MAX_TBS_LENGTH}_ecdsa_brainpool_224r1_sha1`,
      )
      const inputs = await helper.generateCircuitInputs("id")
      const proof = await circuit.prove(inputs, {
        circuitName: `sig_check_id_data_tbs_${MAX_TBS_LENGTH}_ecdsa_nist_p192_sha1`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIDDataProof(proof)
      idDataCommitment = getCommitmentOutFromIDDataProof(proof)
      expect(commitmentIn).toEqual(dscCommitment)
      await circuit.destroy()
    }, 30000)
  })

  describe("integrity", () => {
    test("data integrity check", async () => {
      const circuit = Circuit.from("data_check_integrity_sa_sha1_dg_sha1")
      const inputs = await helper.generateCircuitInputs("integrity", nowTimestamp)
      const proof = await circuit.prove(inputs, {
        circuitName: `data_check_integrity_sa_sha1_dg_sha1`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIntegrityProof(proof)
      integrityCheckCommitment = getCommitmentOutFromIntegrityProof(proof)
      expect(commitmentIn).toEqual(idDataCommitment)
      const currentDate = getCurrentDateFromIntegrityProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
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
      const proof = await circuit.prove(inputs, {
        circuitName: `disclose_bytes`,
        useCli: true,
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
      const proof = await circuit.prove(inputs, {
        witness: await circuit.solve(inputs),

        circuitName: `disclose_bytes`,
        useCli: true,
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

describe("subcircuits - ECDSA NIST P-384 and P-256 - SHA-1", () => {
  const helper = new TestHelper()
  const cscaCerts: PackagedCertificate[] = []
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
      "P<AUSSILVERHAND<<JOHNNY<MATTHEW<<<<<<<<<<<<<PA1234567_AUS881112_M300101_<CYBERCITY<<<<<<"
    const dg1 = Binary.fromHex("615B5F1F58").concat(Binary.from(mrz))

    // Generate CSC and DSC signing certificates
    const { cscPem, dsc, dscKeys } = await generateSigningCertificates({
      cscSigningHashAlgorithm: "SHA-1",
      cscKeyType: "ECDSA",
      cscCurve: "P-384",
      dscSigningHashAlgorithm: "SHA-1",
      dscKeyType: "ECDSA",
      dscCurve: "P-256",
    })
    // Generate SOD and sign it with DSC keypair
    const { sod } = await generateSod(dg1, [dsc], "SHA-1")
    const { sod: signedSod } = await signSod(sod, dscKeys, "SHA-1")
    // Add newly generated CSC to masterlist
    cscaCerts.push(convertPemToPackagedCertificate(cscPem))
    // Load passport data into helper
    const contentInfoWrappedSod = serializeAsn(wrapSodInContentInfo(signedSod))
    await helper.loadPassport(dg1, Binary.from(contentInfoWrappedSod))
    helper.setCertificates(cscaCerts)
  })

  describe("dsc", () => {
    test("ecdsa nist p-384", async () => {
      const circuit = Circuit.from(`sig_check_dsc_tbs_${MAX_TBS_LENGTH}_ecdsa_nist_p384_sha1`)
      const inputs = await helper.generateCircuitInputs("dsc")
      const proof = await circuit.prove(inputs, {
        circuitName: `sig_check_dsc_tbs_${MAX_TBS_LENGTH}_ecdsa_nist_p384_sha1`,
        useCli: true,
      })
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
      const circuit = Circuit.from(`sig_check_id_data_tbs_${MAX_TBS_LENGTH}_ecdsa_nist_p256_sha1`)
      const inputs = await helper.generateCircuitInputs("id")
      const proof = await circuit.prove(inputs, {
        circuitName: `sig_check_id_data_tbs_${MAX_TBS_LENGTH}_ecdsa_nist_p256_sha1`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIDDataProof(proof)
      idDataCommitment = getCommitmentOutFromIDDataProof(proof)
      expect(commitmentIn).toEqual(dscCommitment)
      await circuit.destroy()
    }, 30000)
  })

  describe("integrity", () => {
    test("data integrity check", async () => {
      const circuit = Circuit.from("data_check_integrity_sa_sha1_dg_sha1")
      const inputs = await helper.generateCircuitInputs("integrity", nowTimestamp)
      const proof = await circuit.prove(inputs, {
        circuitName: `data_check_integrity_sa_sha1_dg_sha1`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIntegrityProof(proof)
      integrityCheckCommitment = getCommitmentOutFromIntegrityProof(proof)
      expect(commitmentIn).toEqual(idDataCommitment)
      const currentDate = getCurrentDateFromIntegrityProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
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
      let inputs = await getDiscloseCircuitInputs(helper.passport as any, query, SALT)
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `disclose_bytes`,
        useCli: true,
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
      let inputs = await getDiscloseCircuitInputs(helper.passport as any, query, SALT)
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      const proof = await circuit.prove(inputs, {
        witness: await circuit.solve(inputs),

        circuitName: `disclose_bytes`,
        useCli: true,
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

describe("subcircuits - ECDSA NIST P-521 and Brainpool P-512r1", () => {
  const helper = new TestHelper()
  const cscaCerts: PackagedCertificate[] = []
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
      "P<D<<SILVERHAND<<JOHNNY<<<<<<<<<<<<<<<<<<<<<PA1234567_D<<881112_M300101_<CYBERCITY<<<<<<"
    const dg1 = Binary.fromHex("615B5F1F58").concat(Binary.from(mrz))

    // Generate CSC and DSC signing certificates
    const { cscPem, csc, dsc, dscKeys } = await generateSigningCertificates({
      cscSigningHashAlgorithm: "SHA-512",
      cscKeyType: "ECDSA",
      cscCurve: "P-521",
      dscSigningHashAlgorithm: "SHA-512",
      dscKeyType: "ECDSA",
      dscCurve: "brainpoolP512r1",
      issuingCountry: "DE",
    })
    // Generate SOD and sign it with DSC keypair
    const { sod } = await generateSod(dg1, [dsc], "SHA-512")
    const { sod: signedSod } = await signSod(sod, dscKeys, "SHA-512")
    // Add newly generated CSC to masterlist
    cscaCerts.push(convertPemToPackagedCertificate(cscPem))
    // Load passport data into helper
    const contentInfoWrappedSod = serializeAsn(wrapSodInContentInfo(signedSod))
    await helper.loadPassport(dg1, Binary.from(contentInfoWrappedSod))
    helper.setCertificates(cscaCerts)
  })

  describe("dsc", () => {
    test("ecdsa nist p-521", async () => {
      const circuit = Circuit.from(`sig_check_dsc_tbs_${MAX_TBS_LENGTH}_ecdsa_nist_p521_sha512`)
      const inputs = await helper.generateCircuitInputs("dsc")
      const proof = await circuit.prove(inputs, {
        circuitName: `sig_check_dsc_tbs_${MAX_TBS_LENGTH}_ecdsa_nist_p521_sha512`,
      })
      expect(proof).toBeDefined()
      expect(proof.publicInputs.length).toEqual(2)
      const merkleRoot = getMerkleRootFromDSCProof(proof)
      expect(merkleRoot).toBeDefined()
      dscCommitment = getCommitmentFromDSCProof(proof)
      await circuit.destroy()
    }, 60000)
  })

  describe("id", () => {
    test("ecdsa brainpool p-512r1", async () => {
      const circuit = Circuit.from(
        `sig_check_id_data_tbs_${MAX_TBS_LENGTH}_ecdsa_brainpool_512r1_sha512`,
      )
      const inputs = await helper.generateCircuitInputs("id")
      const proof = await circuit.prove(inputs, {
        circuitName: `sig_check_id_data_tbs_${MAX_TBS_LENGTH}_ecdsa_brainpool_512r1_sha512`,
      })
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIDDataProof(proof)
      idDataCommitment = getCommitmentOutFromIDDataProof(proof)
      expect(commitmentIn).toEqual(dscCommitment)
      await circuit.destroy()
    }, 60000)
  })

  describe("integrity", () => {
    test("data integrity check", async () => {
      const circuit = Circuit.from("data_check_integrity_sa_sha512_dg_sha512")
      const inputs = await helper.generateCircuitInputs("integrity", nowTimestamp)
      const proof = await circuit.prove(inputs, {
        circuitName: `data_check_integrity_sa_sha512_dg_sha512`,
      })
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIntegrityProof(proof)
      integrityCheckCommitment = getCommitmentOutFromIntegrityProof(proof)
      expect(commitmentIn).toEqual(idDataCommitment)
      const currentDate = getCurrentDateFromIntegrityProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
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
      let inputs = await getDiscloseCircuitInputs(helper.passport as any, query, SALT)
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      const proof = await circuit.prove(inputs, {
        witness: await circuit.solve(inputs),

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
      globalNullifier = getNullifierFromDisclosureProof(proof)
      expect(disclosedData.issuingCountry).toBe("D<<")
      expect(disclosedData.nationality).toBe("D<<")
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
      let inputs = await getDiscloseCircuitInputs(helper.passport as any, query, SALT)
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      const proof = await circuit.prove(inputs, {
        witness: await circuit.solve(inputs),

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
      expect(disclosedData.issuingCountry).toBe("")
      expect(disclosedData.nationality).toBe("D<<")
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

  describe("inclusion-check", () => {
    test("nationality", async () => {
      const circuit = Circuit.from("inclusion_check_nationality")
      const query: Query = {
        nationality: { in: ["DEU", "FRA", "USA", "GBR"] },
      }
      const inputs = await getNationalityInclusionCircuitInputs(helper.passport as any, query, SALT)
      if (!inputs) throw new Error("Unable to generate inclusion check circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `inclusion_check_nationality`,
      })
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getCountryParameterCommitment(
        ProofType.NATIONALITY_INCLUSION,
        ["DEU", "FRA", "USA", "GBR"],
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(globalNullifier)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      await circuit.destroy()
    })

    test("issuing country", async () => {
      const circuit = Circuit.from("inclusion_check_issuing_country")
      const query: Query = {
        issuing_country: { in: ["DEU", "FRA", "USA", "GBR"] },
      }
      const inputs = await getIssuingCountryInclusionCircuitInputs(
        helper.passport as any,
        query,
        SALT,
      )
      if (!inputs) throw new Error("Unable to generate inclusion check circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `inclusion_check_issuing_country`,
      })
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getCountryParameterCommitment(
        ProofType.ISSUING_COUNTRY_INCLUSION,
        ["DEU", "FRA", "USA", "GBR"],
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(globalNullifier)
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
      const inputs = await getNationalityExclusionCircuitInputs(helper.passport as any, query, SALT)
      if (!inputs) throw new Error("Unable to generate exclusion check circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `exclusion_check_nationality`,
      })
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      // Note that the order is in ascending order
      // while the original query was not
      // Before being passed to the circuit, the list is sorted in ascending order
      const calculatedParamCommitment = await getCountryParameterCommitment(
        ProofType.NATIONALITY_EXCLUSION,
        ["FRA", "GBR", "USA"],
        true,
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(globalNullifier)
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
        SALT,
      )
      if (!inputs) throw new Error("Unable to generate exclusion check circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `exclusion_check_issuing_country`,
      })
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      // Note that the order is in ascending order
      // while the original query was not
      // Before being passed to the circuit, the list is sorted in ascending order
      const calculatedParamCommitment = await getCountryParameterCommitment(
        ProofType.ISSUING_COUNTRY_EXCLUSION,
        ["FRA", "GBR", "USA"],
        true,
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(globalNullifier)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      await circuit.destroy()
    })
  })
})

describe("subcircuits - RSA PKCS - ZKR Mock Issuer", () => {
  const helper = new TestHelper()
  const cscaCerts: PackagedCertificate[] = []
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

  beforeAll(async () => {
    // Johnny Silverhand's MRZ
    const mrz =
      "P<ZKRSILVERHAND<<JOHNNY<<<<<<<<<<<<<<<<<<<<<PA1234567_ZKR881112_M300101_<CYBERCITY<<<<<<"
    const dg1 = Binary.fromHex("615B5F1F58").concat(Binary.from(mrz))

    // Generate CSC and DSC signing certificates
    const { cscPem, dsc, dscKeys } = await generateSigningCertificates({
      cscSigningHashAlgorithm: "SHA-512",
      cscKeyType: "RSA",
      cscKeySize: 4096,
      dscSigningHashAlgorithm: "SHA-256",
      dscKeyType: "RSA",
      dscKeySize: 2048,
      issuingCountry: "ZK",
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
  })

  describe("dsc", () => {
    test("rsa pkcs 4096", async () => {
      const circuit = Circuit.from(`sig_check_dsc_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_4096_sha512`)
      const inputs = await helper.generateCircuitInputs("dsc")
      const proof = await circuit.prove(inputs, {
        circuitName: `sig_check_dsc_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_4096_sha512`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      expect(proof.publicInputs.length).toEqual(2)
      const merkleRoot = getMerkleRootFromDSCProof(proof)
      expect(merkleRoot).toBeDefined()
      dscCommitment = getCommitmentFromDSCProof(proof)
      await circuit.destroy()
    }, 30000)
  })

  describe("id", () => {
    test("rsa pkcs 2048", async () => {
      const circuit = Circuit.from(`sig_check_id_data_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_2048_sha256`)
      const inputs = await helper.generateCircuitInputs("id")
      const proof = await circuit.prove(inputs, {
        circuitName: `sig_check_id_data_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_2048_sha256`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIDDataProof(proof)
      idDataCommitment = getCommitmentOutFromIDDataProof(proof)
      expect(commitmentIn).toEqual(dscCommitment)
      await circuit.destroy()
    }, 30000)
  })

  describe("integrity", () => {
    test("data integrity check", async () => {
      const circuit = Circuit.from("data_check_integrity_sa_sha256_dg_sha256")
      const inputs = await helper.generateCircuitInputs("integrity", nowTimestamp)
      const proof = await circuit.prove(inputs, {
        circuitName: `data_check_integrity_sa_sha256_dg_sha256`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIntegrityProof(proof)
      integrityCheckCommitment = getCommitmentOutFromIntegrityProof(proof)
      expect(commitmentIn).toEqual(idDataCommitment)
      const currentDate = getCurrentDateFromIntegrityProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
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

    test("disclose some bytes", async () => {
      const query: Query = {
        issuing_country: { disclose: true },
        nationality: { disclose: true },
      }
      let inputs = await getDiscloseCircuitInputs(helper.passport as any, query, SALT)
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      const proof = await circuit.prove(inputs, {
        witness: await circuit.solve(inputs),

        circuitName: `disclose_bytes`,
        useCli: true,
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
      expect(disclosedData.issuingCountry).toBe("ZKR")
      expect(disclosedData.nationality).toBe("ZKR")
      expect(disclosedData.documentType).toBe("other")
      expect(disclosedData.documentNumber).toBe("")
      expect(disclosedData.name).toBe("")
      expect(disclosedData.firstName).toBe("")
      expect(disclosedData.lastName).toBe("")
      expect(isNaN(disclosedData.dateOfBirth.getTime())).toBe(true)
      expect(isNaN(disclosedData.dateOfExpiry.getTime())).toBe(true)
      expect(disclosedData.gender).toBe("")
      // The nullifier must be 1 for mock countries like ZKR
      expect(nullifier).toEqual(1n)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })
  })
})

describe("subcircuits - RSA PKCS - 6144 bits", () => {
  const helper = new TestHelper()
  const cscaCerts: PackagedCertificate[] = []
  const FIXTURES_PATH = path.join(__dirname, "fixtures")
  const MAX_TBS_LENGTH = 1000
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

  let globalNullifier: bigint

  beforeAll(async () => {
    // Add CSCA certificate test fixtures
    const fixtureCSCACerts = JSON.parse(
      fs.readFileSync(path.join(FIXTURES_PATH, "csca-packaged-certs.json"), "utf8"),
    ).certificates
    cscaCerts.push(...fixtureCSCACerts)

    // Johnny Silverhand's MRZ
    const mrz =
      "P<AUSSILVERHAND<<JOHNNY<<<<<<<<<<<<<<<<<<<<<PA1234567_AUS881112_M300101_<CYBERCITY<<<<<<"
    const dg1 = Binary.fromHex("615B5F1F58").concat(Binary.from(mrz))

    // Generate CSCA and DSC signing certificates
    const { cscPem, dsc, dscKeys } = await generateSigningCertificates({
      cscSigningHashAlgorithm: "SHA-256",
      cscKeyType: "RSA",
      cscKeySize: 6144,
      dscSigningHashAlgorithm: "SHA-1",
      dscKeyType: "RSA",
      dscKeySize: 4096,
    })
    // Generate SOD and sign it with DSC keypair
    const { sod } = await generateSod(dg1, [dsc], "SHA-1")
    const { sod: signedSod } = await signSod(sod, dscKeys, "SHA-1")

    // Add newly generated CSCA certificate to the list
    cscaCerts.push(convertPemToPackagedCertificate(cscPem))

    // Load passport data into helper
    const contentInfoWrappedSod = serializeAsn(wrapSodInContentInfo(signedSod))
    await helper.loadPassport(dg1, Binary.from(contentInfoWrappedSod))
    helper.setCertificates(cscaCerts)
  })

  describe("dsc", () => {
    test("rsa pkcs 6144", async () => {
      const circuit = Circuit.from(`sig_check_dsc_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_6144_sha256`)
      const inputs = await helper.generateCircuitInputs("dsc")
      const proof = await circuit.prove(inputs, {
        circuitName: `sig_check_dsc_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_6144_sha256`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      expect(proof.publicInputs.length).toEqual(2)
      const merkleRoot = getMerkleRootFromDSCProof(proof)
      expect(merkleRoot).toBeDefined()
      dscCommitment = getCommitmentFromDSCProof(proof)
      await circuit.destroy()
    }, 30000)
  })

  describe("id", () => {
    test("rsa pkcs 4096", async () => {
      const circuit = Circuit.from(`sig_check_id_data_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_4096_sha1`)
      const inputs = await helper.generateCircuitInputs("id")
      const proof = await circuit.prove(inputs, {
        circuitName: `sig_check_id_data_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_4096_sha1`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIDDataProof(proof)
      idDataCommitment = getCommitmentOutFromIDDataProof(proof)
      expect(commitmentIn).toEqual(dscCommitment)
      await circuit.destroy()
    }, 30000)
  })

  describe("integrity", () => {
    test("data integrity check", async () => {
      const circuit = Circuit.from("data_check_integrity_sa_sha1_dg_sha1")
      const inputs = await helper.generateCircuitInputs("integrity", nowTimestamp)
      const proof = await circuit.prove(inputs, {
        circuitName: `data_check_integrity_sa_sha1_dg_sha1`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIntegrityProof(proof)
      expect(commitmentIn).toEqual(idDataCommitment)
      integrityCheckCommitment = getCommitmentOutFromIntegrityProof(proof)
      const currentDate = getCurrentDateFromIntegrityProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
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
      const proof = await circuit.prove(inputs, {
        witness: await circuit.solve(inputs),

        circuitName: `disclose_bytes`,
        useCli: true,
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
      const proof = await circuit.prove(inputs, {
        witness: await circuit.solve(inputs),

        circuitName: `disclose_bytes`,
        useCli: true,
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
