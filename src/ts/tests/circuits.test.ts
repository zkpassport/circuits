import { Binary } from "@zkpassport/utils/binary"
import { parseCertificate } from "@zkpassport/utils/csc-manager"
import {
  generateSigningCertificates,
  loadDscKeypairFromFile,
  signSodWithRsaKey,
  generateSod,
  wrapSodInContentInfo,
} from "@zkpassport/utils/passport-reader"
import { TestHelper } from "@zkpassport/utils/test-helper"
import type { CSCMasterlist, Query } from "@zkpassport/utils/types"
import { beforeAll, describe, expect, test } from "bun:test"
import * as path from "path"
import {
  getDiscloseCircuitInputs,
  getDiscloseFlagsCircuitInputs,
} from "@zkpassport/utils/circuit-matcher"
import { DisclosedData, Circuit } from "@zkpassport/utils/circuits"
import { serializeAsn } from "@zkpassport/utils/utils"

describe("subcircuits", () => {
  const helper = new TestHelper()
  const masterlist: CSCMasterlist = { certificates: [] }
  const FIXTURES_PATH = path.join(__dirname, "fixtures")
  const DSC_KEYPAIR_PATH = path.join(FIXTURES_PATH, "dsc-keypair.json")
  const MAX_TBS_LENGTH = 1500

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
    helper.setMaxTbsLength(MAX_TBS_LENGTH)
  })

  describe("dsc", () => {
    test("rsa pkcs 4096", async () => {
      const circuit = Circuit.from(`sig_check_dsc_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_4096`)
      const inputs = await helper.generateCircuitInputs("dsc")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
    })
  })

  describe("id", () => {
    test("rsa pkcs 2048", async () => {
      const circuit = Circuit.from(`sig_check_id_data_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_2048`)
      const inputs = await helper.generateCircuitInputs("id")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
    })
  })

  describe("integrity", () => {
    test("data integrity check", async () => {
      const circuit = Circuit.from("data_check_integrity")
      const inputs = await helper.generateCircuitInputs("integrity")
      const proof = await circuit.prove(inputs)
      expect(proof).toBeDefined()
    })
  })

  describe("disclose", () => {
    const circuit = Circuit.from("disclose_flags")

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
      let inputs = await getDiscloseFlagsCircuitInputs(helper.passport, query)
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      inputs = { ...inputs, salt: 0 }
      const proof = await circuit.prove(inputs, { witness: await circuit.solve(inputs) })
      expect(proof).toBeDefined()
      // Verify the disclosed data
      const disclosedData = DisclosedData.fromProof(proof)
      const nullifier = proof.publicInputs.slice(-1)[0]
      expect(disclosedData.issuingCountry).toBe("AUS")
      expect(disclosedData.nationality).toBe("AUS")
      expect(disclosedData.documentType).toBe("P")
      expect(disclosedData.documentNumber).toBe("PA1234567")
      expect(disclosedData.name).toBe("SILVERHAND  JOHNNY")
      expect(disclosedData.dateOfBirth).toEqual(new Date(1988, 10, 12))
      expect(disclosedData.dateOfExpiry).toEqual(new Date(2030, 0, 1))
      expect(disclosedData.gender).toBe("M")
      expect(nullifier).toEqual(
        "0x215282c6b81a6062e0af454d9615c4582c5a35acff60d3a6cdfd5acee286dbf9",
      )
    })
    test("disclose some flags", async () => {
      const query: Query = {
        nationality: { disclose: true },
      }
      let inputs = await getDiscloseFlagsCircuitInputs(helper.passport, query)
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      inputs = { ...inputs, salt: 0 }
      const proof = await circuit.prove(inputs, { witness: await circuit.solve(inputs) })
      expect(proof).toBeDefined()
      // Verify the disclosed data
      const disclosedData = DisclosedData.fromProof(proof)
      const nullifier = proof.publicInputs.slice(-1)[0]
      expect(disclosedData.issuingCountry).toBeEmpty()
      expect(disclosedData.nationality).toBe("AUS")
      expect(disclosedData.documentType).toBeEmpty()
      expect(disclosedData.documentNumber).toBeEmpty()
      expect(disclosedData.name).toBeEmpty()
      expect(disclosedData.dateOfBirth).toBeEmpty()
      expect(disclosedData.dateOfExpiry).toBeEmpty()
      expect(disclosedData.gender).toBeEmpty()
      expect(nullifier).toEqual(
        "0x215282c6b81a6062e0af454d9615c4582c5a35acff60d3a6cdfd5acee286dbf9",
      )
    })
  })
})
