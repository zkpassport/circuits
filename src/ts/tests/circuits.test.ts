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
} from "@zkpassport/utils"
import {
  generateSigningCertificates,
  loadKeypairFromFile,
  signSod,
  generateSod,
  wrapSodInContentInfo,
  TestHelper,
  Circuit,
  serializeAsn,
} from "@zkpassport/test-utils"
import type { CSCMasterlist, Query } from "@zkpassport/utils"
import { beforeAll, describe, expect, test } from "@jest/globals"
import * as path from "path"

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

  beforeAll(async () => {
    // Johnny Silverhand's MRZ
    const mrz =
      "P<AUSSILVERHAND<<JOHNNY<<<<<<<<<<<<<<<<<<<<<PA1234567_AUS881112_M300101_<CYBERCITY<<<<__"
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

  describe("dsc", () => {
    test("rsa pkcs 4096", async () => {
      const circuit = Circuit.from(`sig_check_dsc_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_4096`)
      const inputs = await helper.generateCircuitInputs("dsc")
      const proof = await circuit.prove(inputs)
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
      const circuit = Circuit.from(`sig_check_id_data_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_2048`)
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
      const circuit = Circuit.from("data_check_integrity")
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
      circuit = Circuit.from("disclose_flags")
    })
    afterAll(async () => {
      await circuit.destroy()
    })

    test("disclose all flags", async () => {
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
      let inputs = await getDiscloseFlagsCircuitInputs(helper.passport as any, query, 0n)
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      const proof = await circuit.prove(inputs, { witness: await circuit.solve(inputs) })
      expect(proof).toBeDefined()
      // Verify the disclosed data
      const disclosedData = DisclosedData.fromProof(proof)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(disclosedData.issuingCountry).toBe("AUS")
      expect(disclosedData.nationality).toBe("AUS")
      expect(disclosedData.documentType).toBe("P")
      expect(disclosedData.documentNumber).toBe("PA1234567")
      expect(disclosedData.name).toBe("SILVERHAND  JOHNNY")
      expect(disclosedData.dateOfBirth).toEqual(new Date(1988, 10, 12))
      expect(disclosedData.dateOfExpiry).toEqual(new Date(2030, 0, 1))
      expect(disclosedData.gender).toBe("M")
      expect(nullifier).toEqual(
        20991360808367981708700314199135452991004225667443406013167051877229082634759n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("disclose some flags", async () => {
      const query: Query = {
        nationality: { disclose: true },
      }
      let inputs = await getDiscloseFlagsCircuitInputs(helper.passport as any, query, 0n)
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      const proof = await circuit.prove(inputs, { witness: await circuit.solve(inputs) })
      expect(proof).toBeDefined()
      // Verify the disclosed data
      const disclosedData = DisclosedData.fromProof(proof)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(disclosedData.issuingCountry).toBe("")
      expect(disclosedData.nationality).toBe("AUS")
      expect(disclosedData.documentType).toBe("")
      expect(disclosedData.documentNumber).toBe("")
      expect(disclosedData.name).toBe("")
      expect(isNaN(disclosedData.dateOfBirth.getTime())).toBe(true)
      expect(isNaN(disclosedData.dateOfExpiry.getTime())).toBe(true)
      expect(disclosedData.gender).toBe("")
      expect(nullifier).toEqual(
        20991360808367981708700314199135452991004225667443406013167051877229082634759n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })
  })

  describe("inclusion-check", () => {
    test("country", async () => {
      const circuit = Circuit.from("inclusion_check_country")
      const query: Query = {
        nationality: { in: ["AUS", "FRA", "USA", "GBR"] },
      }
      const inputs = await getCountryInclusionCircuitInputs(helper.passport as any, query, 0n)
      if (!inputs) throw new Error("Unable to generate inclusion check circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const countryList = getCountryListFromInclusionProof(proof)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(countryList).toEqual(["AUS", "FRA", "USA", "GBR"])
      expect(nullifier).toEqual(
        20991360808367981708700314199135452991004225667443406013167051877229082634759n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      await circuit.destroy()
    })
  })

  describe("exclusion-check", () => {
    test("country", async () => {
      const circuit = Circuit.from("exclusion_check_country")
      const query: Query = {
        nationality: { out: ["FRA", "USA", "GBR"] },
      }
      const inputs = await getCountryExclusionCircuitInputs(helper.passport as any, query, 0n)
      if (!inputs) throw new Error("Unable to generate exclusion check circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const countryList = getCountryListFromExclusionProof(proof)
      const nullifier = getNullifierFromDisclosureProof(proof)
      // Note that the order is in ascending order
      // while the original query was not
      // getCountryExclusionCircuitInputs makes sure the order is ascending
      // as it is required by the circuit
      expect(countryList).toEqual(["FRA", "GBR", "USA"])
      expect(nullifier).toEqual(
        20991360808367981708700314199135452991004225667443406013167051877229082634759n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      await circuit.destroy()
    })
  })

  describe("compare-age", () => {
    test("greater than", async () => {
      const circuit = Circuit.from("compare_age")
      const query: Query = {
        age: { gte: 18 },
      }
      const inputs = await getAgeCircuitInputs(helper.passport as any, query, 0n)
      if (!inputs) throw new Error("Unable to generate compare-age greater than circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const minAge = getMinAgeFromProof(proof)
      const maxAge = getMaxAgeFromProof(proof)
      const nullifier = getNullifierFromDisclosureProof(proof)
      const currentDate = getCurrentDateFromAgeProof(proof)
      expect(minAge).toBe(18)
      expect(maxAge).toBe(0)
      expect(nullifier).toEqual(
        20991360808367981708700314199135452991004225667443406013167051877229082634759n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      expect(currentDate).toEqual(globalCurrentDate)
      await circuit.destroy()
    })

    test("less than", async () => {
      const circuit = Circuit.from("compare_age")
      const age = calculateAge(helper.passport)
      const query: Query = {
        age: { lt: age + 1 },
      }
      const inputs = await getAgeCircuitInputs(helper.passport as any, query, 0n)
      if (!inputs) throw new Error("Unable to generate compare-age less than circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const minAge = getMinAgeFromProof(proof)
      const maxAge = getMaxAgeFromProof(proof)
      const nullifier = getNullifierFromDisclosureProof(proof)
      const currentDate = getCurrentDateFromAgeProof(proof)
      expect(minAge).toBe(0)
      expect(maxAge).toBe(age + 1)
      expect(nullifier).toEqual(
        20991360808367981708700314199135452991004225667443406013167051877229082634759n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      expect(currentDate).toEqual(globalCurrentDate)
      await circuit.destroy()
    })

    test("between", async () => {
      const circuit = Circuit.from("compare_age")
      const age = calculateAge(helper.passport)
      const query: Query = {
        age: { gte: age, lt: age + 2 },
      }
      const inputs = await getAgeCircuitInputs(helper.passport as any, query, 0n)
      if (!inputs) throw new Error("Unable to generate compare-age between circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const minAge = getMinAgeFromProof(proof)
      const maxAge = getMaxAgeFromProof(proof)
      const nullifier = getNullifierFromDisclosureProof(proof)
      const currentDate = getCurrentDateFromAgeProof(proof)
      expect(minAge).toBe(age)
      expect(maxAge).toBe(age + 2)
      expect(nullifier).toEqual(
        20991360808367981708700314199135452991004225667443406013167051877229082634759n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      expect(currentDate).toEqual(globalCurrentDate)
      await circuit.destroy()
    })

    test("equal", async () => {
      const circuit = Circuit.from("compare_age")
      const age = calculateAge(helper.passport)
      const query: Query = {
        age: { eq: age },
      }
      const inputs = await getAgeCircuitInputs(helper.passport as any, query, 0n)
      if (!inputs) throw new Error("Unable to generate compare-age equal circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const minAge = getMinAgeFromProof(proof)
      const maxAge = getMaxAgeFromProof(proof)
      const nullifier = getNullifierFromDisclosureProof(proof)
      const currentDate = getCurrentDateFromAgeProof(proof)
      expect(minAge).toBe(age)
      expect(maxAge).toBe(age)
      expect(nullifier).toEqual(
        20991360808367981708700314199135452991004225667443406013167051877229082634759n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      expect(currentDate).toEqual(globalCurrentDate)
      await circuit.destroy()
    })

    test("disclose", async () => {
      const circuit = Circuit.from("compare_age")
      const query: Query = {
        age: { disclose: true },
      }
      const inputs = await getAgeCircuitInputs(helper.passport as any, query, 0n)
      if (!inputs) throw new Error("Unable to generate compare-age equal circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const age = calculateAge(helper.passport)
      const minAge = getMinAgeFromProof(proof)
      const maxAge = getMaxAgeFromProof(proof)
      const currentDate = getCurrentDateFromAgeProof(proof)
      expect(minAge).toBe(age)
      expect(maxAge).toBe(age)
      expect(nullifier).toEqual(
        20991360808367981708700314199135452991004225667443406013167051877229082634759n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      expect(currentDate).toEqual(globalCurrentDate)
      await circuit.destroy()
    })

    test("range", async () => {
      const circuit = Circuit.from("compare_age")
      const age = calculateAge(helper.passport)
      const query: Query = {
        age: { range: [age - 5, age + 5] },
      }
      const inputs = await getAgeCircuitInputs(helper.passport as any, query, 0n)
      if (!inputs) throw new Error("Unable to generate compare-age range circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const minAge = getMinAgeFromProof(proof)
      const maxAge = getMaxAgeFromProof(proof)
      const currentDate = getCurrentDateFromAgeProof(proof)
      expect(minAge).toBe(age - 5)
      expect(maxAge).toBe(age + 5)
      expect(nullifier).toEqual(
        20991360808367981708700314199135452991004225667443406013167051877229082634759n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      expect(currentDate).toEqual(globalCurrentDate)
      await circuit.destroy()
    })
  })

  describe("compare-birthdate", () => {
    test("equal", async () => {
      const circuit = Circuit.from("compare_birthdate")
      const query: Query = {
        // Remember months start at 0 so 10 is November
        birthdate: { eq: new Date(1988, 10, 12) },
      }
      const inputs = await getBirthdateCircuitInputs(helper.passport as any, query, 0n)
      if (!inputs) throw new Error("Unable to generate compare-birthdate equal circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const minDate = getMinDateFromProof(proof)
      const maxDate = getMaxDateFromProof(proof)
      const currentDate = getCurrentDateFromDateProof(proof)
      expect(minDate).toEqual(new Date(1988, 10, 12))
      expect(maxDate).toEqual(new Date(1988, 10, 12))
      expect(nullifier).toEqual(
        20991360808367981708700314199135452991004225667443406013167051877229082634759n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      expect(currentDate).toEqual(globalCurrentDate)
      await circuit.destroy()
    })

    test("range", async () => {
      const circuit = Circuit.from("compare_birthdate")
      const query: Query = {
        birthdate: { range: [new Date(1988, 10, 11), new Date(1988, 10, 13)] },
      }
      const inputs = await getBirthdateCircuitInputs(helper.passport as any, query, 0n)
      if (!inputs) throw new Error("Unable to generate compare-birthdate range circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const minDate = getMinDateFromProof(proof)
      const maxDate = getMaxDateFromProof(proof)
      const currentDate = getCurrentDateFromDateProof(proof)
      expect(minDate).toEqual(new Date(1988, 10, 11))
      expect(maxDate).toEqual(new Date(1988, 10, 13))
      expect(nullifier).toEqual(
        20991360808367981708700314199135452991004225667443406013167051877229082634759n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      expect(currentDate).toEqual(globalCurrentDate)
      await circuit.destroy()
    })

    test("disclose", async () => {
      const circuit = Circuit.from("compare_birthdate")
      const query: Query = {
        birthdate: { disclose: true },
      }
      const inputs = await getBirthdateCircuitInputs(helper.passport as any, query, 0n)
      if (!inputs) throw new Error("Unable to generate compare-birthdate disclose circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const minDate = getMinDateFromProof(proof)
      const maxDate = getMaxDateFromProof(proof)
      const currentDate = getCurrentDateFromDateProof(proof)
      expect(minDate).toEqual(new Date(1988, 10, 12))
      expect(maxDate).toEqual(new Date(1988, 10, 12))
      expect(nullifier).toEqual(
        20991360808367981708700314199135452991004225667443406013167051877229082634759n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      expect(currentDate).toEqual(globalCurrentDate)
      await circuit.destroy()
    })

    test("greater than", async () => {
      const circuit = Circuit.from("compare_birthdate")
      const query: Query = {
        birthdate: { gte: new Date(1988, 10, 11) },
      }
      const inputs = await getBirthdateCircuitInputs(helper.passport as any, query, 0n)
      if (!inputs)
        throw new Error("Unable to generate compare-birthdate greater than circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const minDate = getMinDateFromProof(proof)
      const maxDate = getMaxDateFromProof(proof)
      const currentDate = getCurrentDateFromDateProof(proof)
      expect(minDate).toEqual(new Date(1988, 10, 11))
      // 11/11/1111 is considered the zero date in the circuit
      // as 00/00/0000 would throw an error
      expect(maxDate).toEqual(new Date(1111, 10, 11))
      expect(nullifier).toEqual(
        20991360808367981708700314199135452991004225667443406013167051877229082634759n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      expect(currentDate).toEqual(globalCurrentDate)
      await circuit.destroy()
    })

    test("less than", async () => {
      const circuit = Circuit.from("compare_birthdate")
      const query: Query = {
        birthdate: { lte: new Date(1988, 10, 15) },
      }
      const inputs = await getBirthdateCircuitInputs(helper.passport as any, query, 0n)
      if (!inputs) throw new Error("Unable to generate compare-birthdate less than circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const minDate = getMinDateFromProof(proof)
      const maxDate = getMaxDateFromProof(proof)
      const currentDate = getCurrentDateFromDateProof(proof)
      expect(minDate).toEqual(new Date(1111, 10, 11))
      expect(maxDate).toEqual(new Date(1988, 10, 15))
      expect(nullifier).toEqual(
        20991360808367981708700314199135452991004225667443406013167051877229082634759n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      expect(currentDate).toEqual(globalCurrentDate)
      await circuit.destroy()
    })

    test("between", async () => {
      const circuit = Circuit.from("compare_birthdate")
      const query: Query = {
        birthdate: { gte: new Date(1988, 10, 11), lte: new Date(1988, 10, 15) },
      }
      const inputs = await getBirthdateCircuitInputs(helper.passport as any, query, 0n)
      if (!inputs) throw new Error("Unable to generate compare-birthdate between circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const minDate = getMinDateFromProof(proof)
      const maxDate = getMaxDateFromProof(proof)
      const currentDate = getCurrentDateFromDateProof(proof)
      expect(minDate).toEqual(new Date(1988, 10, 11))
      expect(maxDate).toEqual(new Date(1988, 10, 15))
      expect(nullifier).toEqual(
        20991360808367981708700314199135452991004225667443406013167051877229082634759n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      expect(currentDate).toEqual(globalCurrentDate)
      await circuit.destroy()
    })
  })

  describe("compare-expiry", () => {
    test("equal", async () => {
      const circuit = Circuit.from("compare_expiry")
      const query: Query = {
        expiry_date: { eq: new Date(2030, 0, 1) },
      }
      const inputs = await getExpiryDateCircuitInputs(helper.passport as any, query, 0n)
      if (!inputs) throw new Error("Unable to generate compare-expirydate equal circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const minDate = getMinDateFromProof(proof)
      const maxDate = getMaxDateFromProof(proof)
      const currentDate = getCurrentDateFromDateProof(proof)
      expect(minDate).toEqual(new Date(2030, 0, 1))
      expect(maxDate).toEqual(new Date(2030, 0, 1))
      expect(nullifier).toEqual(
        20991360808367981708700314199135452991004225667443406013167051877229082634759n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      expect(currentDate).toEqual(globalCurrentDate)
      await circuit.destroy()
    })

    test("range", async () => {
      const circuit = Circuit.from("compare_expiry")
      const query: Query = {
        expiry_date: { range: [new Date(2025, 0, 1), new Date(2035, 0, 1)] },
      }
      const inputs = await getExpiryDateCircuitInputs(helper.passport as any, query, 0n)
      if (!inputs) throw new Error("Unable to generate compare-expirydate range circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const minDate = getMinDateFromProof(proof)
      const maxDate = getMaxDateFromProof(proof)
      const currentDate = getCurrentDateFromDateProof(proof)
      expect(minDate).toEqual(new Date(2025, 0, 1))
      expect(maxDate).toEqual(new Date(2035, 0, 1))
      expect(nullifier).toEqual(
        20991360808367981708700314199135452991004225667443406013167051877229082634759n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      expect(currentDate).toEqual(globalCurrentDate)
      await circuit.destroy()
    })

    test("disclose", async () => {
      const circuit = Circuit.from("compare_expiry")
      const query: Query = {
        expiry_date: { disclose: true },
      }
      const inputs = await getExpiryDateCircuitInputs(helper.passport as any, query, 0n)
      if (!inputs) throw new Error("Unable to generate compare-expirydate disclose circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const minDate = getMinDateFromProof(proof)
      const maxDate = getMaxDateFromProof(proof)
      const currentDate = getCurrentDateFromDateProof(proof)
      expect(minDate).toEqual(new Date(2030, 0, 1))
      expect(maxDate).toEqual(new Date(2030, 0, 1))
      expect(nullifier).toEqual(
        20991360808367981708700314199135452991004225667443406013167051877229082634759n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      expect(currentDate).toEqual(globalCurrentDate)
      await circuit.destroy()
    })

    test("greater than", async () => {
      const circuit = Circuit.from("compare_expiry")
      const query: Query = {
        expiry_date: { gte: new Date(2025, 0, 1) },
      }
      const inputs = await getExpiryDateCircuitInputs(helper.passport as any, query, 0n)
      if (!inputs)
        throw new Error("Unable to generate compare-expirydate greater than circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const minDate = getMinDateFromProof(proof)
      const maxDate = getMaxDateFromProof(proof)
      const currentDate = getCurrentDateFromDateProof(proof)
      expect(minDate).toEqual(new Date(2025, 0, 1))
      expect(maxDate).toEqual(new Date(1111, 10, 11))
      expect(nullifier).toEqual(
        20991360808367981708700314199135452991004225667443406013167051877229082634759n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      expect(currentDate).toEqual(globalCurrentDate)
      await circuit.destroy()
    })

    test("less than", async () => {
      const circuit = Circuit.from("compare_expiry")
      const query: Query = {
        expiry_date: { lte: new Date(2035, 0, 1) },
      }
      const inputs = await getExpiryDateCircuitInputs(helper.passport as any, query, 0n)
      if (!inputs) throw new Error("Unable to generate compare-expirydate less than circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const minDate = getMinDateFromProof(proof)
      const maxDate = getMaxDateFromProof(proof)
      const currentDate = getCurrentDateFromDateProof(proof)
      expect(minDate).toEqual(new Date(1111, 10, 11))
      expect(maxDate).toEqual(new Date(2035, 0, 1))
      expect(nullifier).toEqual(
        20991360808367981708700314199135452991004225667443406013167051877229082634759n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      expect(currentDate).toEqual(globalCurrentDate)
      await circuit.destroy()
    })

    test("between", async () => {
      const circuit = Circuit.from("compare_expiry")
      const query: Query = {
        expiry_date: { gte: new Date(2025, 0, 1), lte: new Date(2035, 0, 1) },
      }
      const inputs = await getExpiryDateCircuitInputs(helper.passport as any, query, 0n)
      if (!inputs) throw new Error("Unable to generate compare-expirydate between circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const nullifier = getNullifierFromDisclosureProof(proof)
      const minDate = getMinDateFromProof(proof)
      const maxDate = getMaxDateFromProof(proof)
      const currentDate = getCurrentDateFromDateProof(proof)
      expect(minDate).toEqual(new Date(2025, 0, 1))
      expect(maxDate).toEqual(new Date(2035, 0, 1))
      expect(nullifier).toEqual(
        20991360808367981708700314199135452991004225667443406013167051877229082634759n,
      )
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
      expect(currentDate).toEqual(globalCurrentDate)
      await circuit.destroy()
    })
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
      "P<AUSSILVERHAND<<JOHNNY<<<<<<<<<<<<<<<<<<<<<PA1234567_AUS881112_M300101_<CYBERCITY<<<<__"
    const dg1 = Binary.fromHex("615B5F1F58").concat(Binary.from(mrz))
    // Load DSC keypair
    const dscKeypair = await loadKeypairFromFile(DSC_KEYPAIR_PATH)

    // Generate CSC and DSC signing certificates
    const { cscPem, dsc, dscKeys } = await generateSigningCertificates({
      cscSigningHashAlgorithm: "SHA-256",
      cscKeyType: "ECDSA",
      cscCurve: "P-384",
      dscSigningHashAlgorithm: "SHA-256",
      dscKeyType: "ECDSA",
      dscCurve: "P-256",
      dscKeypair: dscKeypair,
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

  describe("dsc", () => {
    test("ecdsa nist p-384", async () => {
      const circuit = Circuit.from(`sig_check_dsc_tbs_${MAX_TBS_LENGTH}_ecdsa_nist_p384`)
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
      const circuit = Circuit.from(`sig_check_id_data_tbs_${MAX_TBS_LENGTH}_ecdsa_nist_p256`)
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
      const circuit = Circuit.from("data_check_integrity")
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
      circuit = Circuit.from("disclose_flags")
    })
    afterAll(async () => {
      await circuit.destroy()
    })

    test("disclose all flags", async () => {
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
      let inputs = await getDiscloseFlagsCircuitInputs(helper.passport as any, query, 0n)
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      const proof = await circuit.prove(inputs, { witness: await circuit.solve(inputs) })
      expect(proof).toBeDefined()
      // Verify the disclosed data
      const disclosedData = DisclosedData.fromProof(proof)
      globalNullifier = getNullifierFromDisclosureProof(proof)
      expect(disclosedData.issuingCountry).toBe("AUS")
      expect(disclosedData.nationality).toBe("AUS")
      expect(disclosedData.documentType).toBe("P")
      expect(disclosedData.documentNumber).toBe("PA1234567")
      expect(disclosedData.name).toBe("SILVERHAND  JOHNNY")
      expect(disclosedData.dateOfBirth).toEqual(new Date(1988, 10, 12))
      expect(disclosedData.dateOfExpiry).toEqual(new Date(2030, 0, 1))
      expect(disclosedData.gender).toBe("M")
      expect(globalNullifier).toBeDefined()
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })

    test("disclose some flags", async () => {
      const query: Query = {
        nationality: { disclose: true },
      }
      let inputs = await getDiscloseFlagsCircuitInputs(helper.passport as any, query, 0n)
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      const proof = await circuit.prove(inputs, { witness: await circuit.solve(inputs) })
      expect(proof).toBeDefined()
      // Verify the disclosed data
      const disclosedData = DisclosedData.fromProof(proof)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(disclosedData.issuingCountry).toBe("")
      expect(disclosedData.nationality).toBe("AUS")
      expect(disclosedData.documentType).toBe("")
      expect(disclosedData.documentNumber).toBe("")
      expect(disclosedData.name).toBe("")
      expect(isNaN(disclosedData.dateOfBirth.getTime())).toBe(true)
      expect(isNaN(disclosedData.dateOfExpiry.getTime())).toBe(true)
      expect(disclosedData.gender).toBe("")
      expect(nullifier).toEqual(globalNullifier)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(integrityCheckCommitment)
    })
  })
})
