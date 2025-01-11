import {
  Binary,
  parseCertificate,
  getDiscloseFlagsCircuitInputs,
  getCountryInclusionCircuitInputs,
  getCountryExclusionCircuitInputs,
  getAgeCircuitInputs,
  calculateAge,
  DisclosedData,
  getCountryListFromInclusionProof,
  getCountryListFromExclusionProof,
  getMinAgeFromProof,
  getMaxAgeFromProof,
  getNullifierFromDisclosureProof,
} from "@zkpassport/utils"
import {
  generateSigningCertificates,
  loadDscKeypairFromFile,
  signSodWithRsaKey,
  generateSod,
  wrapSodInContentInfo,
  TestHelper,
  Circuit,
  serializeAsn,
} from "@zkpassport/test-utils"
import type { CSCMasterlist, Query } from "@zkpassport/utils"
import { beforeAll, describe, expect, test } from "@jest/globals"
import * as path from "path"

describe("subcircuits", () => {
  const helper = new TestHelper()
  const masterlist: CSCMasterlist = { certificates: [] }
  const FIXTURES_PATH = path.join(__dirname, "fixtures")
  const DSC_KEYPAIR_PATH = path.join(FIXTURES_PATH, "dsc-keypair.json")
  const MAX_TBS_LENGTH = 700

  beforeAll(async () => {
    // Johnny Silverhand's MRZ
    const mrz =
      "P<AUSSILVERHAND<<JOHNNY<<<<<<<<<<<<<<<<<<<<<PA1234567_AUS881112_M300101_<CYBERCITY<<<<__"
    const dg1 = Binary.fromHex("615B5F1F58").concat(Binary.from(mrz))
    // Load DSC keypair
    const dscKeypair = loadDscKeypairFromFile(DSC_KEYPAIR_PATH)

    // Generate CSC and DSC signing certificates
    const { cscPem, dsc } = generateSigningCertificates({
      cscSigningHashAlgorithm: "sha256",
      cscKeySize: 4096,
      dscKeypair,
    })
    // Generate SOD and sign it with DSC keypair
    const { sod } = generateSod(dg1, [dsc])
    const { sod: signedSod } = signSodWithRsaKey(sod, dscKeypair.privateKey)
    // Add newly generated CSC to masterlist
    masterlist.certificates.push(parseCertificate(cscPem))
    // Load passport data into helper
    const contentInfoWrappedSod = serializeAsn(wrapSodInContentInfo(signedSod))
    await helper.loadPassport(dg1, Binary.from(contentInfoWrappedSod))
    helper.setMasterlist(masterlist)
    helper.passport.dateOfBirth = "881112"
  })

  describe("dsc", () => {
    it("rsa pkcs 4096", async () => {
      const circuit = Circuit.from(`sig_check_dsc_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_4096`)
      const inputs = await helper.generateCircuitInputs("dsc")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
    }, 30000)
  })

  describe("id", () => {
    it("rsa pkcs 2048", async () => {
      const circuit = Circuit.from(`sig_check_id_data_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_2048`)
      const inputs = await helper.generateCircuitInputs("id")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
    }, 30000)
  })

  describe("integrity", () => {
    it("data integrity check", async () => {
      const circuit = Circuit.from("data_check_integrity")
      const inputs = await helper.generateCircuitInputs("integrity")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
    })
  })

  describe("disclose", () => {
    const circuit = Circuit.from("disclose_flags")

    it("disclose all flags", async () => {
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
      expect(nullifier).toEqual(0x08270df6a2f1e90cd6dfe164834a6b0f552981c432515faba5218b541592ccf4n)
    })

    it("disclose some flags", async () => {
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
      expect(nullifier).toEqual(0x08270df6a2f1e90cd6dfe164834a6b0f552981c432515faba5218b541592ccf4n)
    })
  })

  describe("inclusion-check", () => {
    it("country", async () => {
      const circuit = Circuit.from("inclusion_check_country")
      const query: Query = {
        nationality: { in: ["AUS", "FRA", "USA", "GBR"] },
      }
      const inputs = await getCountryInclusionCircuitInputs(helper.passport as any, query, 0n)
      if (!inputs) throw new Error("Unable to generate inclusion check circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const countryList = getCountryListFromInclusionProof(proof)
      expect(countryList).toEqual(["AUS", "FRA", "USA", "GBR"])
    })
  })

  describe("exclusion-check", () => {
    it("country", async () => {
      const circuit = Circuit.from("exclusion_check_country")
      const query: Query = {
        nationality: { out: ["FRA", "USA", "GBR"] },
      }
      const inputs = await getCountryExclusionCircuitInputs(helper.passport as any, query, 0n)
      if (!inputs) throw new Error("Unable to generate exclusion check circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const countryList = getCountryListFromExclusionProof(proof)
      expect(countryList).toEqual(["FRA", "GBR", "USA"])
    })
  })

  describe("compare-age", () => {
    it("greater than", async () => {
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
      expect(minAge).toBe(18)
      expect(maxAge).toBe(0)
    })

    it("less than", async () => {
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
      expect(minAge).toBe(0)
      expect(maxAge).toBe(age + 1)
    })

    it("between", async () => {
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
      expect(minAge).toBe(age)
      expect(maxAge).toBe(age + 2)
    })

    it("equal", async () => {
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
      expect(minAge).toBe(age)
      expect(maxAge).toBe(age)
    })

    it("disclose", async () => {
      const circuit = Circuit.from("compare_age")
      const query: Query = {
        age: { disclose: true },
      }
      const inputs = await getAgeCircuitInputs(helper.passport as any, query, 0n)
      if (!inputs) throw new Error("Unable to generate compare-age equal circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const age = calculateAge(helper.passport)
      const minAge = getMinAgeFromProof(proof)
      const maxAge = getMaxAgeFromProof(proof)
      expect(minAge).toBe(age)
      expect(maxAge).toBe(age)
    })

    it("range", async () => {
      const circuit = Circuit.from("compare_age")
      const age = calculateAge(helper.passport)
      const query: Query = {
        age: { range: [age - 5, age + 5] },
      }
      const inputs = await getAgeCircuitInputs(helper.passport as any, query, 0n)
      if (!inputs) throw new Error("Unable to generate compare-age range circuit inputs")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
      const minAge = getMinAgeFromProof(proof)
      const maxAge = getMaxAgeFromProof(proof)
      expect(minAge).toBe(age - 5)
      expect(maxAge).toBe(age + 5)
    })
  })
})
