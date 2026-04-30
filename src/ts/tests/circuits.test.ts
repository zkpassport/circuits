import {
  Binary,
  calculatePackagedCertificatesRoot,
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
  getCurrentDateFromDisclosureProof,
  getCountryWeightedSum,
  rightPadArrayWithZeros,
  getNullifierTypeFromDisclosureProof,
  getOprfPkHashFromDisclosureProof,
  NullifierType,
  getFacematchCircuitInputs,
  getFacematchParameterCommitment,
  getFacematchEvmParameterCommitment,
  packLeBytesAndHashPoseidon2,
  OPRF_ZERO_PROOF,
} from "@zkpassport/utils"
import type { IntegrityToDisclosureSalts, PackagedCertificatesFile, Query } from "@zkpassport/utils"
import { beforeAll, afterAll, describe, expect, test } from "@jest/globals"
import * as path from "path"
import { TestHelper, convertPemToPackagedCertificateV1 } from "../test-helper"
import { generateSigningCertificates, signSod, type HashAlgorithm } from "../passport-generator"
import { loadKeypairFromFile } from "../passport-generator"
import { wrapSodInContentInfo } from "../sod-generator"
import { generateSod } from "../sod-generator"
import { serializeAsn, createUTCDate } from "../utils"
import { Circuit } from "../circuits"
import { evaluateOPRF } from "@zkpassport/utils"
import { poseidon2HashAsync } from "@zkpassport/poseidon2"
import fs from "fs"
import FIXTURES_FACEMATCH from "./fixtures/facematch"
import { AlgorithmIdentifier } from "@peculiar/asn1-x509"
import type { Alpha3Code } from "i18n-iso-countries"
import { id_ecdsaWithSHA512, id_ecdsaWithSHA256, id_ecdsaWithSHA384, id_ecdsaWithSHA224, id_ecdsaWithSHA1 } from "@peculiar/asn1-ecc"
import { id_sha1WithRSAEncryption, id_sha224WithRSAEncryption, id_sha256WithRSAEncryption, id_sha384WithRSAEncryption } from "@peculiar/asn1-rsa"

// Test constants
const SALT = 3n
const INTEGRITY_TO_DISCLOSURE_SALTS: IntegrityToDisclosureSalts = {
  dg1Salt: SALT,
  expiryDateSalt: SALT,
  dg2HashSalt: SALT,
  privateNullifierSalt: SALT,
}
const EXPECTED_NULLIFIER = 0xf03bc01b2dd79b1b8906831e8bd47f1cdf7435e8f38010a9cd1978a1b13a26an
const nowTimestamp = getNowTimestamp()
const FIXTURES_PATH = path.join(__dirname, "fixtures")

// Common MRZ strings
const MRZ_AUS_JOHNNY =
  "P<AUSSILVERHAND<<JOHNNY<<<<<<<<<<<<<<<<<<<<<PA1234567_AUS881112_M300101_<CYBERCITY<<<<<<"
const MRZ_AUS_JOHNNY_MATTHEW =
  "P<AUSSILVERHAND<<JOHNNY<MATTHEW<<<<<<<<<<<<<PA1234567_AUS881112_M300101_<CYBERCITY<<<<<<"
const MRZ_DE_JOHNNY =
  "P<D<<SILVERHAND<<JOHNNY<<<<<<<<<<<<<<<<<<<<<PA1234567_D<<881112_M300101_<CYBERCITY<<<<<<"

// ─── Shared state and helpers ───────────────────────────────────────────────────

interface TestState {
  helper: TestHelper
  packagedCerts: PackagedCertificatesFile
  dscCommitment: bigint
  idDataCommitment: bigint
  integrityCheckCommitment: bigint
  globalNullifier?: bigint
}

function createTestState(): TestState {
  return {
    helper: new TestHelper(),
    packagedCerts: {
      version: 1,
      timestamp: 0,
      root: "",
      certificates: [],
      masterlists: [],
      revocations: [],
    },
    dscCommitment: 0n,
    idDataCommitment: 0n,
    integrityCheckCommitment: 0n,
  }
}

interface PassportSetupConfig {
  mrz: string
  certParams: Parameters<typeof generateSigningCertificates>[0]
  dscKeypairPath?: string
  loadFixtures?: boolean
  sodHash: HashAlgorithm
  sodAlgorithm: AlgorithmIdentifier
  signSodHash: HashAlgorithm
}

async function setupPassport(state: TestState, config: PassportSetupConfig) {
  if (config.loadFixtures) {
    const fixtureData = JSON.parse(
      fs.readFileSync(path.join(FIXTURES_PATH, "csca-packaged-certs.json"), "utf8"),
    )
    state.packagedCerts.certificates.push(...fixtureData.certificates)
  }

  const dg1 = Binary.fromHex("615B5F1F58").concat(Binary.from(config.mrz))

  const certOpts = { ...config.certParams } as any
  if (config.dscKeypairPath) {
    certOpts.dscKeypair = await loadKeypairFromFile(config.dscKeypairPath)
  }

  const { cscPem, dsc, dscKeys } = await generateSigningCertificates(certOpts)
  const { sod } = await generateSod(dg1, [dsc], config.sodHash, config.sodAlgorithm)
  const { sod: signedSod } = await signSod(sod, dscKeys, config.signSodHash)

  state.packagedCerts.certificates.push(await convertPemToPackagedCertificateV1(cscPem))
  state.packagedCerts.timestamp = Math.floor(Date.UTC(2026, 0, 1) / 1000)
  state.packagedCerts.root = await calculatePackagedCertificatesRoot(state.packagedCerts)

  const contentInfoWrappedSod = serializeAsn(wrapSodInContentInfo(signedSod))
  await state.helper.loadPassport(dg1, Binary.from(contentInfoWrappedSod))
  state.helper.setCertificates(state.packagedCerts)
}

// ─── Core pipeline test helpers ─────────────────────────────────────────────────

function describeDscTest(
  state: TestState, circuitName: string, testLabel: string,
  timeout = 30000, useCli = true,
) {
  describe("dsc", () => {
    test(testLabel, async () => {
      const circuit = Circuit.from(circuitName)
      const inputs = await state.helper.generateCircuitInputs("dsc")
      const proof = await circuit.prove(inputs, {
        circuitName,
        useCli,
      })
      expect(proof).toBeDefined()
      expect(proof.publicInputs.length).toEqual(2)
      const merkleRoot = getMerkleRootFromDSCProof(proof)
      expect(merkleRoot).toBeDefined()
      state.dscCommitment = getCommitmentFromDSCProof(proof)
      await circuit.destroy()
    }, timeout)
  })
}

function describeIdTest(
  state: TestState, circuitName: string, testLabel: string,
  timeout = 30000, useCli = true, proveName?: string,
) {
  describe("id", () => {
    test(testLabel, async () => {
      const circuit = Circuit.from(circuitName)
      const inputs = await state.helper.generateCircuitInputs("id")
      const proof = await circuit.prove(inputs, {
        circuitName: proveName ?? circuitName,
        useCli,
      })
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIDDataProof(proof)
      state.idDataCommitment = getCommitmentOutFromIDDataProof(proof)
      expect(commitmentIn).toEqual(state.dscCommitment)
      await circuit.destroy()
    }, timeout)
  })
}

function describeIntegrityTest(
  state: TestState, circuitName: string, timeout = 30000, useCli = true,
) {
  describe("integrity", () => {
    test("data integrity check", async () => {
      const circuit = Circuit.from(circuitName)
      const inputs = await state.helper.generateCircuitInputs("integrity", nowTimestamp)
      const proof = await circuit.prove(inputs, {
        circuitName,
        useCli,
      })
      expect(proof).toBeDefined()
      const commitmentIn = getCommitmentInFromIntegrityProof(proof)
      expect(commitmentIn).toEqual(state.idDataCommitment)
      state.integrityCheckCommitment = getCommitmentOutFromIntegrityProof(proof)
      await circuit.destroy()
    }, timeout)
  })
}

// ─── Disclose test helpers ──────────────────────────────────────────────────────

interface DiscloseAllExpected {
  issuingCountry: string
  nationality: string
  name: string
  firstName: string
  lastName: string
}

interface DiscloseSomeConfig {
  query: Query
  expected: {
    issuingCountry: string
    nationality: string
    name: string
    firstName: string
    lastName: string
  }
}

function describeDiscloseTests(
  state: TestState,
  opts: {
    discloseAll?: DiscloseAllExpected
    discloseSome: DiscloseSomeConfig
    useCli?: boolean
  },
) {
  describe("disclose", () => {
    let circuit: Circuit
    beforeAll(async () => {
      circuit = Circuit.from("disclose_bytes")
    })
    afterAll(async () => {
      await circuit.destroy()
    })

    const proveOpts = (extra?: object) => ({
      circuitName: "disclose_bytes",
      ...(opts.useCli !== false && { useCli: true }),
      ...extra,
    })

    if (opts.discloseAll) {
      const expected = opts.discloseAll
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
        let inputs = await getDiscloseCircuitInputs(
          state.helper.passport as any, query,
          INTEGRITY_TO_DISCLOSURE_SALTS, 0n, 0n, 0n, nowTimestamp,
        )
        if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
        const proof = await circuit.prove(inputs, proveOpts({
          witness: await circuit.solve(inputs),
        }))
        expect(proof).toBeDefined()
        const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
        const disclosedBytes = getDisclosedBytesFromMrzAndMask(
          state.helper.passport.mrz, inputs.disclose_mask,
        )
        const calculatedParamCommitment = await getDiscloseParameterCommitment(
          inputs.disclose_mask, disclosedBytes,
        )
        expect(paramCommitment).toEqual(calculatedParamCommitment)
        const disclosedData = DisclosedData.fromDisclosedBytes(disclosedBytes, "passport")
        state.globalNullifier = getNullifierFromDisclosureProof(proof)
        expect(disclosedData.issuingCountry).toBe(expected.issuingCountry)
        expect(disclosedData.nationality).toBe(expected.nationality)
        expect(disclosedData.documentType).toBe("passport")
        expect(disclosedData.documentNumber).toBe("PA1234567")
        expect(disclosedData.name).toBe(expected.name)
        expect(disclosedData.firstName).toBe(expected.firstName)
        expect(disclosedData.lastName).toBe(expected.lastName)
        expect(disclosedData.dateOfBirth).toEqual(createUTCDate(1988, 10, 12))
        expect(disclosedData.dateOfExpiry).toEqual(createUTCDate(2030, 0, 1))
        expect(disclosedData.gender).toBe("M")
        expect(state.globalNullifier).toBeDefined()
        const commitmentIn = getCommitmentInFromDisclosureProof(proof)
        expect(commitmentIn).toEqual(state.integrityCheckCommitment)
        const currentDate = getCurrentDateFromDisclosureProof(proof)
        expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
      })
    }

    test("disclose some bytes", async () => {
      let inputs = await getDiscloseCircuitInputs(
        state.helper.passport as any, opts.discloseSome.query,
        INTEGRITY_TO_DISCLOSURE_SALTS, 0n, 0n, 0n, nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      const proof = await circuit.prove(inputs, proveOpts({
        witness: await circuit.solve(inputs),
      }))
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const disclosedBytes = getDisclosedBytesFromMrzAndMask(
        state.helper.passport.mrz, inputs.disclose_mask,
      )
      const calculatedParamCommitment = await getDiscloseParameterCommitment(
        inputs.disclose_mask, disclosedBytes,
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const disclosedData = DisclosedData.fromDisclosedBytes(disclosedBytes, "passport")
      const nullifier = getNullifierFromDisclosureProof(proof)
      const exp = opts.discloseSome.expected
      expect(disclosedData.issuingCountry).toBe(exp.issuingCountry)
      expect(disclosedData.nationality).toBe(exp.nationality)
      expect(disclosedData.documentType).toBe("other")
      expect(disclosedData.documentNumber).toBe("")
      expect(disclosedData.name).toBe(exp.name)
      expect(disclosedData.firstName).toBe(exp.firstName)
      expect(disclosedData.lastName).toBe(exp.lastName)
      expect(isNaN(disclosedData.dateOfBirth.getTime())).toBe(true)
      expect(isNaN(disclosedData.dateOfExpiry.getTime())).toBe(true)
      expect(disclosedData.gender).toBe("")
      expect(nullifier).toEqual(state.globalNullifier)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
    })
  })
}

// ─── Inclusion / Exclusion check helpers ────────────────────────────────────────

function describeInclusionCheckTests(
  state: TestState, countries: Alpha3Code[], useCli = true,
) {
  describe("inclusion-check", () => {
    test("nationality", async () => {
      const circuit = Circuit.from("inclusion_check_nationality")
      const query: Query = { nationality: { in: countries } }
      const inputs = await getNationalityInclusionCircuitInputs(
        state.helper.passport as any, query,
        INTEGRITY_TO_DISCLOSURE_SALTS, 0n, 0n, 0n, nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate inclusion check circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: "inclusion_check_nationality",
        useCli,
      })
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getCountryParameterCommitment(
        ProofType.NATIONALITY_INCLUSION, countries,
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(state.globalNullifier)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
      await circuit.destroy()
    })

    test("issuing country", async () => {
      const circuit = Circuit.from("inclusion_check_issuing_country")
      const query: Query = { issuing_country: { in: countries } }
      const inputs = await getIssuingCountryInclusionCircuitInputs(
        state.helper.passport as any, query,
        INTEGRITY_TO_DISCLOSURE_SALTS, 0n, 0n, 0n, nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate inclusion check circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: "inclusion_check_issuing_country",
        useCli,
      })
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getCountryParameterCommitment(
        ProofType.ISSUING_COUNTRY_INCLUSION, countries,
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(state.globalNullifier)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
      await circuit.destroy()
    })
  })
}

function describeExclusionCheckTests(
  state: TestState,
  exclusionCountries: Alpha3Code[],
  sortedExclusionCountries: Alpha3Code[],
  useCli = true,
) {
  describe("exclusion-check", () => {
    test("nationality", async () => {
      const circuit = Circuit.from("exclusion_check_nationality")
      const query: Query = { nationality: { out: exclusionCountries } }
      const inputs = await getNationalityExclusionCircuitInputs(
        state.helper.passport as any, query,
        INTEGRITY_TO_DISCLOSURE_SALTS, 0n, 0n, 0n, nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate exclusion check circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: "exclusion_check_nationality",
        useCli,
      })
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getCountryParameterCommitment(
        ProofType.NATIONALITY_EXCLUSION, sortedExclusionCountries, true,
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(state.globalNullifier)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
      await circuit.destroy()
    })

    test("issuing country", async () => {
      const circuit = Circuit.from("exclusion_check_issuing_country")
      const query: Query = { issuing_country: { out: exclusionCountries } }
      const inputs = await getIssuingCountryExclusionCircuitInputs(
        state.helper.passport as any, query,
        INTEGRITY_TO_DISCLOSURE_SALTS, 0n, 0n, 0n, nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate exclusion check circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: "exclusion_check_issuing_country",
        useCli,
      })
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getCountryParameterCommitment(
        ProofType.ISSUING_COUNTRY_EXCLUSION, sortedExclusionCountries, true,
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(state.globalNullifier)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
      await circuit.destroy()
    })
  })
}

// ─── Common disclose expectations ───────────────────────────────────────────────

const DISCLOSE_ALL_AUS_JOHNNY: DiscloseAllExpected = {
  issuingCountry: "AUS", nationality: "AUS",
  name: "JOHNNY SILVERHAND", firstName: "JOHNNY", lastName: "SILVERHAND",
}
const DISCLOSE_ALL_AUS_JOHNNY_MATTHEW: DiscloseAllExpected = {
  issuingCountry: "AUS", nationality: "AUS",
  name: "JOHNNY MATTHEW SILVERHAND", firstName: "JOHNNY MATTHEW", lastName: "SILVERHAND",
}
const DISCLOSE_ALL_DE_JOHNNY: DiscloseAllExpected = {
  issuingCountry: "D<<", nationality: "D<<",
  name: "JOHNNY SILVERHAND", firstName: "JOHNNY", lastName: "SILVERHAND",
}

function discloseSomeNationalityOnly(nationality: string): DiscloseSomeConfig {
  return {
    query: { nationality: { disclose: true } },
    expected: { issuingCountry: "", nationality, name: "", firstName: "", lastName: "" },
  }
}

function discloseSomeWithNames(nationality: string): DiscloseSomeConfig {
  return {
    query: { nationality: { disclose: true }, firstname: { disclose: true }, lastname: { disclose: true } },
    expected: { issuingCountry: "", nationality, name: "JOHNNY SILVERHAND", firstName: "JOHNNY", lastName: "SILVERHAND" },
  }
}

// ─── Suite config and data-driven generation ────────────────────────────────────

interface SuiteConfig {
  name: string
  setup: PassportSetupConfig
  dscCircuit: string
  dscLabel: string
  dscTimeout?: number
  dscUseCli?: boolean
  idCircuit: string
  idLabel: string
  idTimeout?: number
  idUseCli?: boolean
  idProveName?: string
  integrityCircuit: string
  integrityUseCli?: boolean
  discloseAll?: DiscloseAllExpected
  discloseSome: DiscloseSomeConfig
  discloseUseCli?: boolean
  inclusionCountries?: Alpha3Code[]
  inclusionUseCli?: boolean
  exclusionCountries?: Alpha3Code[]
  sortedExclusionCountries?: Alpha3Code[]
  exclusionUseCli?: boolean
}

const suiteConfigs: SuiteConfig[] = [
  // Suite 2: RSA PKCS - SHA-1
  {
    name: "subcircuits - RSA PKCS - SHA-1",
    setup: {
      mrz: MRZ_AUS_JOHNNY,
      certParams: { cscSigningHashAlgorithm: "SHA-1", cscKeyType: "RSA", cscKeySize: 4096, dscSigningHashAlgorithm: "SHA-1", dscKeyType: "RSA", dscKeySize: 2048 },
      loadFixtures: true,
      sodHash: "SHA-1",
      sodAlgorithm: new AlgorithmIdentifier({ algorithm: id_sha1WithRSAEncryption }),
      signSodHash: "SHA-1",
    },
    dscCircuit: "sig_check_dsc_tbs_700_rsa_pkcs_4096_sha1",
    dscLabel: "rsa pkcs 4096",
    idCircuit: "sig_check_id_data_tbs_700_rsa_pkcs_2048_sha1",
    idLabel: "rsa pkcs 2048",
    integrityCircuit: "data_check_integrity_sa_sha1_dg_sha1",
    discloseAll: DISCLOSE_ALL_AUS_JOHNNY,
    discloseSome: discloseSomeNationalityOnly("AUS"),
  },
  // Suite 3: RSA PKCS - SHA-224 integrity check
  {
    name: "subcircuits - RSA PKCS - SHA-224 integrity check",
    setup: {
      mrz: MRZ_AUS_JOHNNY,
      certParams: { cscSigningHashAlgorithm: "SHA-256", cscKeyType: "RSA", cscKeySize: 4096, dscSigningHashAlgorithm: "SHA-256", dscKeyType: "RSA", dscKeySize: 2048 },
      loadFixtures: true,
      sodHash: "SHA-224",
      sodAlgorithm: new AlgorithmIdentifier({ algorithm: id_sha224WithRSAEncryption }),
      signSodHash: "SHA-256",
    },
    dscCircuit: "sig_check_dsc_tbs_700_rsa_pkcs_4096_sha256",
    dscLabel: "rsa pkcs 4096",
    idCircuit: "sig_check_id_data_tbs_700_rsa_pkcs_2048_sha256",
    idLabel: "rsa pkcs 2048",
    integrityCircuit: "data_check_integrity_sa_sha224_dg_sha224",
    discloseAll: DISCLOSE_ALL_AUS_JOHNNY,
    discloseSome: discloseSomeNationalityOnly("AUS"),
  },
  // Suite 4: ECDSA NIST P-384 and P-256
  {
    name: "subcircuits - ECDSA NIST P-384 and P-256",
    setup: {
      mrz: MRZ_AUS_JOHNNY_MATTHEW,
      certParams: { cscSigningHashAlgorithm: "SHA-384", cscKeyType: "ECDSA", cscCurve: "P-384", dscSigningHashAlgorithm: "SHA-256", dscKeyType: "ECDSA", dscCurve: "P-256" },
      dscKeypairPath: path.join(FIXTURES_PATH, "dsc-keypair-ecdsa.json"),
      sodHash: "SHA-384",
      sodAlgorithm: new AlgorithmIdentifier({ algorithm: id_ecdsaWithSHA384 }),
      signSodHash: "SHA-256",
    },
    dscCircuit: "sig_check_dsc_tbs_700_ecdsa_nist_p384_sha384",
    dscLabel: "ecdsa nist p-384",
    dscTimeout: 60000,
    idCircuit: "sig_check_id_data_tbs_700_ecdsa_nist_p256_sha256",
    idLabel: "ecdsa nist p-256",
    integrityCircuit: "data_check_integrity_sa_sha384_dg_sha384",
    discloseAll: DISCLOSE_ALL_AUS_JOHNNY_MATTHEW,
    discloseSome: discloseSomeWithNames("AUS"),
  },
  // Suite 5: ECDSA NIST P-521 and P-384
  {
    name: "subcircuits - ECDSA NIST P-521 and P-384",
    setup: {
      mrz: MRZ_AUS_JOHNNY,
      certParams: { cscSigningHashAlgorithm: "SHA-512", cscKeyType: "ECDSA", cscCurve: "P-521", dscSigningHashAlgorithm: "SHA-384", dscKeyType: "ECDSA", dscCurve: "P-384" },
      sodHash: "SHA-512",
      sodAlgorithm: new AlgorithmIdentifier({ algorithm: id_ecdsaWithSHA512 }),
      signSodHash: "SHA-384",
    },
    dscCircuit: "sig_check_dsc_tbs_700_ecdsa_nist_p521_sha512",
    dscLabel: "ecdsa nist p-521",
    dscTimeout: 60000,
    idCircuit: "sig_check_id_data_tbs_700_ecdsa_nist_p384_sha384",
    idLabel: "ecdsa nist p-384",
    integrityCircuit: "data_check_integrity_sa_sha512_dg_sha512",
    discloseAll: DISCLOSE_ALL_AUS_JOHNNY,
    discloseSome: discloseSomeNationalityOnly("AUS"),
  },
  // Suite 6: ECDSA NIST P-256 and Brainpool P-192
  {
    name: "subcircuits - ECDSA NIST P-256 and Brainpool P-192",
    setup: {
      mrz: MRZ_AUS_JOHNNY_MATTHEW,
      certParams: { cscSigningHashAlgorithm: "SHA-1", cscKeyType: "ECDSA", cscCurve: "P-256", dscSigningHashAlgorithm: "SHA-1", dscKeyType: "ECDSA", dscCurve: "brainpoolP192r1" },
      sodHash: "SHA-1",
      sodAlgorithm: new AlgorithmIdentifier({ algorithm: id_ecdsaWithSHA1 }),
      signSodHash: "SHA-1",
    },
    dscCircuit: "sig_check_dsc_tbs_700_ecdsa_nist_p256_sha1",
    dscLabel: "ecdsa nist p-256",
    dscTimeout: 60000,
    idCircuit: "sig_check_id_data_tbs_700_ecdsa_brainpool_192r1_sha1",
    idProveName: "sig_check_id_data_tbs_700_ecdsa_nist_p192_sha1",
    idLabel: "ecdsa brainpool 192r1",
    integrityCircuit: "data_check_integrity_sa_sha1_dg_sha1",
    discloseAll: DISCLOSE_ALL_AUS_JOHNNY_MATTHEW,
    discloseSome: discloseSomeWithNames("AUS"),
  },
  // Suite 7: ECDSA NIST P-256 and Brainpool P-224
  {
    name: "subcircuits - ECDSA NIST P-256 and Brainpool P-224",
    setup: {
      mrz: MRZ_AUS_JOHNNY_MATTHEW,
      certParams: { cscSigningHashAlgorithm: "SHA-1", cscKeyType: "ECDSA", cscCurve: "P-256", dscSigningHashAlgorithm: "SHA-1", dscKeyType: "ECDSA", dscCurve: "brainpoolP224r1" },
      sodHash: "SHA-1",
      sodAlgorithm: new AlgorithmIdentifier({ algorithm: id_ecdsaWithSHA1 }),
      signSodHash: "SHA-1",
    },
    dscCircuit: "sig_check_dsc_tbs_700_ecdsa_nist_p256_sha1",
    dscLabel: "ecdsa nist p-256",
    dscTimeout: 60000,
    idCircuit: "sig_check_id_data_tbs_700_ecdsa_brainpool_224r1_sha1",
    idProveName: "sig_check_id_data_tbs_700_ecdsa_nist_p192_sha1",
    idLabel: "ecdsa brainpool 224r1",
    integrityCircuit: "data_check_integrity_sa_sha1_dg_sha1",
    discloseAll: DISCLOSE_ALL_AUS_JOHNNY_MATTHEW,
    discloseSome: discloseSomeWithNames("AUS"),
  },
  // Suite 8: ECDSA NIST P-384 and P-256 - SHA-1
  {
    name: "subcircuits - ECDSA NIST P-384 and P-256 - SHA-1",
    setup: {
      mrz: MRZ_AUS_JOHNNY_MATTHEW,
      certParams: { cscSigningHashAlgorithm: "SHA-1", cscKeyType: "ECDSA", cscCurve: "P-384", dscSigningHashAlgorithm: "SHA-1", dscKeyType: "ECDSA", dscCurve: "P-256" },
      sodHash: "SHA-1",
      sodAlgorithm: new AlgorithmIdentifier({ algorithm: id_ecdsaWithSHA1 }),
      signSodHash: "SHA-1",
    },
    dscCircuit: "sig_check_dsc_tbs_700_ecdsa_nist_p384_sha1",
    dscLabel: "ecdsa nist p-384",
    dscTimeout: 60000,
    idCircuit: "sig_check_id_data_tbs_700_ecdsa_nist_p256_sha1",
    idLabel: "ecdsa nist p-256",
    integrityCircuit: "data_check_integrity_sa_sha1_dg_sha1",
    discloseAll: DISCLOSE_ALL_AUS_JOHNNY_MATTHEW,
    discloseSome: discloseSomeWithNames("AUS"),
  },
  // Suite 9: ECDSA NIST P-521 and Brainpool P-512r1
  {
    name: "subcircuits - ECDSA NIST P-521 and Brainpool P-512r1",
    setup: {
      mrz: MRZ_DE_JOHNNY,
      certParams: { cscSigningHashAlgorithm: "SHA-512", cscKeyType: "ECDSA", cscCurve: "P-521", dscSigningHashAlgorithm: "SHA-512", dscKeyType: "ECDSA", dscCurve: "brainpoolP512r1", issuingCountry: "DE" },
      sodHash: "SHA-512",
      sodAlgorithm: new AlgorithmIdentifier({ algorithm: id_ecdsaWithSHA512 }),
      signSodHash: "SHA-512",
    },
    dscCircuit: "sig_check_dsc_tbs_700_ecdsa_nist_p521_sha512",
    dscLabel: "ecdsa nist p-521",
    dscTimeout: 60000,
    dscUseCli: false,
    idCircuit: "sig_check_id_data_tbs_700_ecdsa_brainpool_512r1_sha512",
    idLabel: "ecdsa brainpool p-512r1",
    idTimeout: 60000,
    idUseCli: false,
    integrityCircuit: "data_check_integrity_sa_sha512_dg_sha512",
    integrityUseCli: false,
    discloseAll: DISCLOSE_ALL_DE_JOHNNY,
    discloseSome: discloseSomeNationalityOnly("D<<"),
    discloseUseCli: false,
    inclusionCountries: ["DEU", "FRA", "USA", "GBR"],
    inclusionUseCli: false,
    exclusionCountries: ["FRA", "USA", "GBR"],
    sortedExclusionCountries: ["FRA", "GBR", "USA"],
    exclusionUseCli: false,
  },
  // Suite 10: ECDSA NIST P-256 and P-192
  {
    name: "subcircuits - ECDSA NIST P-256 and P-192",
    setup: {
      mrz: MRZ_AUS_JOHNNY,
      certParams: { cscSigningHashAlgorithm: "SHA-1", cscKeyType: "ECDSA", cscCurve: "P-256", dscSigningHashAlgorithm: "SHA-1", dscKeyType: "ECDSA", dscCurve: "P-192" },
      sodHash: "SHA-1",
      sodAlgorithm: new AlgorithmIdentifier({ algorithm: id_ecdsaWithSHA1 }),
      signSodHash: "SHA-1",
    },
    dscCircuit: "sig_check_dsc_tbs_700_ecdsa_nist_p256_sha1",
    dscLabel: "ecdsa nist p-256",
    dscTimeout: 60000,
    idCircuit: "sig_check_id_data_tbs_700_ecdsa_nist_p192_sha1",
    idLabel: "ecdsa nist p-192",
    integrityCircuit: "data_check_integrity_sa_sha1_dg_sha1",
    discloseAll: DISCLOSE_ALL_AUS_JOHNNY,
    discloseSome: discloseSomeNationalityOnly("AUS"),
  },
  // Suite 11: ECDSA NIST P-256 and P-224
  {
    name: "subcircuits - ECDSA NIST P-256 and P-224",
    setup: {
      mrz: MRZ_AUS_JOHNNY,
      certParams: { cscSigningHashAlgorithm: "SHA-256", cscKeyType: "ECDSA", cscCurve: "P-256", dscSigningHashAlgorithm: "SHA-256", dscKeyType: "ECDSA", dscCurve: "P-224" },
      sodHash: "SHA-224",
      sodAlgorithm: new AlgorithmIdentifier({ algorithm: id_ecdsaWithSHA224 }),
      signSodHash: "SHA-224",
    },
    dscCircuit: "sig_check_dsc_tbs_700_ecdsa_nist_p256_sha256",
    dscLabel: "ecdsa nist p-256",
    dscTimeout: 60000,
    idCircuit: "sig_check_id_data_tbs_700_ecdsa_nist_p224_sha224",
    idLabel: "ecdsa nist p-224",
    integrityCircuit: "data_check_integrity_sa_sha224_dg_sha224",
    discloseAll: DISCLOSE_ALL_AUS_JOHNNY,
    discloseSome: discloseSomeNationalityOnly("AUS"),
  },
  // Suite 12: ECDSA NIST P-521 and P-521
  {
    name: "subcircuits - ECDSA NIST P-521 and P-521",
    setup: {
      mrz: MRZ_AUS_JOHNNY,
      certParams: { cscSigningHashAlgorithm: "SHA-512", cscKeyType: "ECDSA", cscCurve: "P-521", dscSigningHashAlgorithm: "SHA-512", dscKeyType: "ECDSA", dscCurve: "P-521" },
      sodHash: "SHA-512",
      sodAlgorithm: new AlgorithmIdentifier({ algorithm: id_ecdsaWithSHA512 }),
      signSodHash: "SHA-512",
    },
    dscCircuit: "sig_check_dsc_tbs_700_ecdsa_nist_p521_sha512",
    dscLabel: "ecdsa nist p-521",
    dscTimeout: 60000,
    idCircuit: "sig_check_id_data_tbs_700_ecdsa_nist_p521_sha512",
    idLabel: "ecdsa nist p-521",
    idTimeout: 60000,
    integrityCircuit: "data_check_integrity_sa_sha512_dg_sha512",
    discloseAll: DISCLOSE_ALL_AUS_JOHNNY,
    discloseSome: discloseSomeNationalityOnly("AUS"),
  },
  // Suite 13: ECDSA NIST P-384 and Brainpool P-256r1
  {
    name: "subcircuits - ECDSA NIST P-384 and Brainpool P-256r1",
    setup: {
      mrz: MRZ_AUS_JOHNNY,
      certParams: { cscSigningHashAlgorithm: "SHA-256", cscKeyType: "ECDSA", cscCurve: "P-384", dscSigningHashAlgorithm: "SHA-256", dscKeyType: "ECDSA", dscCurve: "brainpoolP256r1" },
      sodHash: "SHA-256",
      sodAlgorithm: new AlgorithmIdentifier({ algorithm: id_ecdsaWithSHA256 }),
      signSodHash: "SHA-256",
    },
    dscCircuit: "sig_check_dsc_tbs_700_ecdsa_nist_p384_sha256",
    dscLabel: "ecdsa nist p-384",
    dscTimeout: 60000,
    idCircuit: "sig_check_id_data_tbs_700_ecdsa_brainpool_256r1_sha256",
    idLabel: "ecdsa brainpool 256r1",
    integrityCircuit: "data_check_integrity_sa_sha256_dg_sha256",
    discloseAll: DISCLOSE_ALL_AUS_JOHNNY,
    discloseSome: discloseSomeNationalityOnly("AUS"),
  },
  // Suite 14: ECDSA NIST P-521 and Brainpool P-384r1
  {
    name: "subcircuits - ECDSA NIST P-521 and Brainpool P-384r1",
    setup: {
      mrz: MRZ_AUS_JOHNNY,
      certParams: { cscSigningHashAlgorithm: "SHA-384", cscKeyType: "ECDSA", cscCurve: "P-521", dscSigningHashAlgorithm: "SHA-384", dscKeyType: "ECDSA", dscCurve: "brainpoolP384r1" },
      sodHash: "SHA-384",
      sodAlgorithm: new AlgorithmIdentifier({ algorithm: id_ecdsaWithSHA384 }),
      signSodHash: "SHA-384",
    },
    dscCircuit: "sig_check_dsc_tbs_700_ecdsa_nist_p521_sha384",
    dscLabel: "ecdsa nist p-521",
    dscTimeout: 60000,
    idCircuit: "sig_check_id_data_tbs_700_ecdsa_brainpool_384r1_sha384",
    idLabel: "ecdsa brainpool 384r1",
    idTimeout: 60000,
    integrityCircuit: "data_check_integrity_sa_sha384_dg_sha384",
    discloseAll: DISCLOSE_ALL_AUS_JOHNNY,
    discloseSome: discloseSomeNationalityOnly("AUS"),
  },
  // Suite 16: RSA PKCS - 6144 bits
  {
    name: "subcircuits - RSA PKCS - 6144 bits",
    setup: {
      mrz: MRZ_AUS_JOHNNY,
      certParams: { cscSigningHashAlgorithm: "SHA-256", cscKeyType: "RSA", cscKeySize: 6144, dscSigningHashAlgorithm: "SHA-1", dscKeyType: "RSA", dscKeySize: 4096 },
      loadFixtures: true,
      sodHash: "SHA-1",
      sodAlgorithm: new AlgorithmIdentifier({ algorithm: id_sha1WithRSAEncryption }),
      signSodHash: "SHA-1",
    },
    dscCircuit: "sig_check_dsc_tbs_1000_rsa_pkcs_6144_sha256",
    dscLabel: "rsa pkcs 6144",
    idCircuit: "sig_check_id_data_tbs_1000_rsa_pkcs_4096_sha1",
    idLabel: "rsa pkcs 4096",
    integrityCircuit: "data_check_integrity_sa_sha1_dg_sha1",
    discloseAll: DISCLOSE_ALL_AUS_JOHNNY,
    discloseSome: discloseSomeNationalityOnly("AUS"),
  },
]

// Generate test suites from config
for (const config of suiteConfigs) {
  describe(config.name, () => {
    const state = createTestState()

    beforeAll(async () => {
      await setupPassport(state, config.setup)
    })

    describeDscTest(state, config.dscCircuit, config.dscLabel, config.dscTimeout, config.dscUseCli)
    describeIdTest(state, config.idCircuit, config.idLabel, config.idTimeout, config.idUseCli, config.idProveName)
    describeIntegrityTest(state, config.integrityCircuit, undefined, config.integrityUseCli)
    describeDiscloseTests(state, {
      discloseAll: config.discloseAll,
      discloseSome: config.discloseSome,
      useCli: config.discloseUseCli,
    })
    if (config.inclusionCountries) {
      describeInclusionCheckTests(state, config.inclusionCountries, config.inclusionUseCli)
    }
    if (config.exclusionCountries) {
      describeExclusionCheckTests(
        state, config.exclusionCountries, config.sortedExclusionCountries!, config.exclusionUseCli,
      )
    }
  })
}

// ─── Suite 1: RSA PKCS (main) ───────────────────────────────────────────────────

describe("subcircuits - RSA PKCS", () => {
  const state = createTestState()
  const DSC_KEYPAIR_PATH = path.join(FIXTURES_PATH, "dsc-keypair-rsa.json")

  beforeAll(async () => {
    await setupPassport(state, {
      mrz: MRZ_AUS_JOHNNY,
      certParams: {
        cscSigningHashAlgorithm: "SHA-512",
        cscKeyType: "RSA",
        cscKeySize: 4096,
        dscSigningHashAlgorithm: "SHA-256",
        dscKeyType: "RSA",
        dscKeySize: 2048,
      },
      dscKeypairPath: DSC_KEYPAIR_PATH,
      loadFixtures: true,
      sodHash: "SHA-256",
      sodAlgorithm: new AlgorithmIdentifier({ algorithm: id_sha256WithRSAEncryption }),
      signSodHash: "SHA-256",
    })
  })

  describeDscTest(state, "sig_check_dsc_tbs_700_rsa_pkcs_4096_sha512", "rsa pkcs 4096")
  describeIdTest(state, "sig_check_id_data_tbs_700_rsa_pkcs_2048_sha256", "rsa pkcs 2048")
  describeIntegrityTest(state, "data_check_integrity_sa_sha256_dg_sha256")

  describe("facematch ios", () => {
    let iosCircuit: Circuit
    let iosEvmCircuit: Circuit

    beforeAll(() => {
      iosCircuit = Circuit.from("facematch_ios")
      iosEvmCircuit = Circuit.from("facematch_ios_evm")
    })

    afterAll(async () => {
      await iosCircuit.destroy()
      await iosEvmCircuit.destroy()
    })

    test("verify facematch", async () => {
      const query: Query = { facematch: { mode: "regular" } }
      let inputs = await getFacematchCircuitInputs(
        state.helper.passport as any, query, INTEGRITY_TO_DISCLOSURE_SALTS,
        0n, 0n, 0n, nowTimestamp, true,
      )
      if (!inputs) throw new Error("Unable to generate facematch circuit inputs")
      expect(BigInt(inputs.comm_in)).toEqual(state.integrityCheckCommitment)

      const combinedInputs = { ...inputs, ...FIXTURES_FACEMATCH.ios_regular_mode_dev }
      const proof = await iosCircuit.prove(combinedInputs, {
        witness: await iosCircuit.solve(combinedInputs),
        useCli: true,
        circuitName: "facematch_ios",
      })

      const root_key_leaf = 0x2532418a107c5306fa8308c22255792cf77e4a290cbce8a840a642a3e591340bn
      const environment = 0n
      const app_id = new Uint8Array([
        ...new TextEncoder().encode("YL5MS3Z639.app.zkpassport.appattest-prototype"),
      ])
      const app_id_hash = await packLeBytesAndHashPoseidon2(app_id)
      const facematch_mode = 1n
      const calculatedParamCommitment = await getFacematchParameterCommitment(
        root_key_leaf, environment, app_id_hash, facematch_mode,
      )
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      expect(calculatedParamCommitment).toEqual(paramCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(0n)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
    }, 90000)

    test("verify facematch - strict mode", async () => {
      const query: Query = { facematch: { mode: "strict" } }
      let inputs = await getFacematchCircuitInputs(
        state.helper.passport as any, query, INTEGRITY_TO_DISCLOSURE_SALTS,
        0n, 0n, 0n, nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate facematch circuit inputs")
      expect(BigInt(inputs.comm_in)).toEqual(state.integrityCheckCommitment)

      const combinedInputs = { ...inputs, ...FIXTURES_FACEMATCH.ios_strict_mode_prod }
      const proof = await iosCircuit.prove(combinedInputs, {
        witness: await iosCircuit.solve(combinedInputs),
        useCli: true,
        circuitName: "facematch_ios",
      })

      const root_key_leaf = 0x2532418a107c5306fa8308c22255792cf77e4a290cbce8a840a642a3e591340bn
      const environment = 1n
      const app_id = new Uint8Array([
        ...new TextEncoder().encode("YL5MS3Z639.app.zkpassport.zkpassport"),
      ])
      const app_id_hash = await packLeBytesAndHashPoseidon2(app_id)
      const facematch_mode = 2n
      const calculatedParamCommitment = await getFacematchParameterCommitment(
        root_key_leaf, environment, app_id_hash, facematch_mode,
      )
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      expect(calculatedParamCommitment).toEqual(paramCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
    }, 90000)

    test("verify facematch evm", async () => {
      const query: Query = { facematch: { mode: "regular" } }
      let inputs = await getFacematchCircuitInputs(
        state.helper.passport as any, query, INTEGRITY_TO_DISCLOSURE_SALTS,
        0n, 0n, 0n, nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate facematch circuit inputs")
      expect(BigInt(inputs.comm_in)).toEqual(state.integrityCheckCommitment)

      const combinedInputs = { ...inputs, ...FIXTURES_FACEMATCH.ios_regular_mode_prod }
      const proof = await iosEvmCircuit.prove(combinedInputs, {
        witness: await iosEvmCircuit.solve(combinedInputs),
        useCli: true,
        circuitName: "facematch_ios_evm",
      })

      const root_key_leaf = 0x2532418a107c5306fa8308c22255792cf77e4a290cbce8a840a642a3e591340bn
      const environment = 1n
      const app_id = new Uint8Array([
        ...new TextEncoder().encode("YL5MS3Z639.app.zkpassport.zkpassport"),
      ])
      const app_id_hash = await packLeBytesAndHashPoseidon2(app_id)
      const facematch_mode = 1n
      const calculatedParamCommitment = await getFacematchEvmParameterCommitment(
        root_key_leaf, environment, app_id_hash, facematch_mode,
      )
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      expect(calculatedParamCommitment).toEqual(paramCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
    }, 90000)
  })

  describe("facematch android", () => {
    let androidCircuit: Circuit
    let androidEvmCircuit: Circuit

    beforeAll(() => {
      androidCircuit = Circuit.from(
        "facematch_android_rk_rsa_ik_count_3_ik_ecdsa_p384_sha384_ik_ecdsa_p256_sha256_ik_ecdsa_p256_sha256",
      )
      androidEvmCircuit = Circuit.from(
        "facematch_android_rk_rsa_ik_count_3_ik_ecdsa_p384_sha384_ik_ecdsa_p256_sha256_ik_ecdsa_p256_sha256_evm",
      )
    })

    afterAll(async () => {
      await androidCircuit.destroy()
      await androidEvmCircuit.destroy()
    })

    test("verify facematch", async () => {
      const query: Query = { facematch: { mode: "regular" } }
      let inputs = await getFacematchCircuitInputs(
        state.helper.passport as any, query, INTEGRITY_TO_DISCLOSURE_SALTS,
        0n, 0n, 0n, nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate facematch circuit inputs")
      expect(BigInt(inputs.comm_in)).toEqual(state.integrityCheckCommitment)

      const combinedInputs = { ...inputs, ...FIXTURES_FACEMATCH.android_regular_mode_dev }
      const proof = await androidCircuit.prove(combinedInputs, {
        witness: await androidCircuit.solve(combinedInputs),
        useCli: true,
        circuitName:
          "facematch_android_rk_rsa_ik_count_3_ik_ecdsa_p384_sha384_ik_ecdsa_p256_sha256_ik_ecdsa_p256_sha256",
      })

      const root_key_leaf = 0x16700a2d9168a194fc85f237af5829b5a2be05b8ae8ac4879ada34cf54a9c211n
      const environment = 0n
      const app_id = new Uint8Array([...new TextEncoder().encode("app.zkpassport.zkpassport")])
      const app_id_hash = await packLeBytesAndHashPoseidon2(app_id)
      const facematch_mode = 1n
      const calculatedParamCommitment = await getFacematchParameterCommitment(
        root_key_leaf, environment, app_id_hash, facematch_mode,
      )
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      expect(calculatedParamCommitment).toEqual(paramCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
    }, 90000)

    test("verify facematch evm", async () => {
      const query: Query = { facematch: { mode: "strict" } }
      let inputs = await getFacematchCircuitInputs(
        state.helper.passport as any, query, INTEGRITY_TO_DISCLOSURE_SALTS,
        0n, 0n, 0n, nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate facematch circuit inputs")
      expect(BigInt(inputs.comm_in)).toEqual(state.integrityCheckCommitment)

      const combinedInputs = { ...inputs, ...FIXTURES_FACEMATCH.android_strict_mode_dev }
      const proof = await androidEvmCircuit.prove(combinedInputs, {
        witness: await androidEvmCircuit.solve(combinedInputs),
        useCli: true,
        circuitName:
          "facematch_android_rk_rsa_ik_count_3_ik_ecdsa_p384_sha384_ik_ecdsa_p256_sha256_ik_ecdsa_p256_sha256_evm",
      })

      const root_key_leaf = 0x16700a2d9168a194fc85f237af5829b5a2be05b8ae8ac4879ada34cf54a9c211n
      const environment = 0n
      const app_id = new Uint8Array([...new TextEncoder().encode("app.zkpassport.zkpassport")])
      const app_id_hash = await packLeBytesAndHashPoseidon2(app_id)
      const facematch_mode = 2n
      const calculatedParamCommitment = await getFacematchEvmParameterCommitment(
        root_key_leaf, environment, app_id_hash, facematch_mode,
      )
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      expect(calculatedParamCommitment).toEqual(paramCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
    }, 90000)
  })

  describe("disclose", () => {
    let circuit: Circuit
    beforeAll(async () => { circuit = Circuit.from("disclose_bytes") })
    afterAll(async () => { await circuit.destroy() })

    test("disclose all bytes", async () => {
      const query: Query = {
        issuing_country: { disclose: true }, nationality: { disclose: true },
        document_type: { disclose: true }, document_number: { disclose: true },
        fullname: { disclose: true }, birthdate: { disclose: true },
        expiry_date: { disclose: true }, gender: { disclose: true },
      }
      let inputs = await getDiscloseCircuitInputs(
        state.helper.passport as any, query, INTEGRITY_TO_DISCLOSURE_SALTS, 0n, 0n, 0n, nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      const proof = await circuit.prove(inputs, {
        witness: await circuit.solve(inputs), useCli: true, circuitName: "disclose_bytes",
      })
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const disclosedBytes = getDisclosedBytesFromMrzAndMask(state.helper.passport.mrz, inputs.disclose_mask)
      const calculatedParamCommitment = await getDiscloseParameterCommitment(inputs.disclose_mask, disclosedBytes)
      expect(paramCommitment).toEqual(calculatedParamCommitment)
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
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
      expect(nullifierType).toEqual(NullifierType.NON_SALTED)
      const oprfPkHash = getOprfPkHashFromDisclosureProof(proof)
      expect(oprfPkHash).toEqual(0n)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
    })

    test("disclose some bytes", async () => {
      const query: Query = { nationality: { disclose: true } }
      let inputs = await getDiscloseCircuitInputs(
        state.helper.passport as any, query, INTEGRITY_TO_DISCLOSURE_SALTS, 0n, 0n, 0n, nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      const proof = await circuit.prove(inputs, {
        witness: await circuit.solve(inputs), useCli: true, circuitName: "disclose_bytes",
      })
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const disclosedBytes = getDisclosedBytesFromMrzAndMask(state.helper.passport.mrz, inputs.disclose_mask)
      const calculatedParamCommitment = await getDiscloseParameterCommitment(inputs.disclose_mask, disclosedBytes)
      expect(paramCommitment).toEqual(calculatedParamCommitment)
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
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
      expect(nullifierType).toEqual(NullifierType.NON_SALTED)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
    })
  })

  describe("disclose evm", () => {
    let circuit: Circuit
    beforeAll(async () => { circuit = Circuit.from("disclose_bytes_evm") })
    afterAll(async () => { await circuit.destroy() })

    test("disclose all bytes", async () => {
      const query: Query = {
        issuing_country: { disclose: true }, nationality: { disclose: true },
        document_type: { disclose: true }, document_number: { disclose: true },
        fullname: { disclose: true }, birthdate: { disclose: true },
        expiry_date: { disclose: true }, gender: { disclose: true },
      }
      let inputs = await getDiscloseCircuitInputs(
        state.helper.passport as any, query, INTEGRITY_TO_DISCLOSURE_SALTS, 0n, 0n, 0n, nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      const proof = await circuit.prove(inputs, {
        witness: await circuit.solve(inputs), useCli: true, circuitName: "disclose_bytes_evm",
      })
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const disclosedBytes = getDisclosedBytesFromMrzAndMask(state.helper.passport.mrz, inputs.disclose_mask)
      const calculatedParamCommitment = await getDiscloseEVMParameterCommitment(inputs.disclose_mask, disclosedBytes)
      expect(paramCommitment).toEqual(calculatedParamCommitment)
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
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
      expect(nullifierType).toEqual(NullifierType.NON_SALTED)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
    })

    test("disclose some bytes", async () => {
      const query: Query = { nationality: { disclose: true } }
      let inputs = await getDiscloseCircuitInputs(
        state.helper.passport as any, query, INTEGRITY_TO_DISCLOSURE_SALTS, 0n, 0n, 0n, nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      const proof = await circuit.prove(inputs, {
        witness: await circuit.solve(inputs), useCli: true, circuitName: "disclose_bytes_evm",
      })
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const disclosedBytes = getDisclosedBytesFromMrzAndMask(state.helper.passport.mrz, inputs.disclose_mask)
      const calculatedParamCommitment = await getDiscloseEVMParameterCommitment(inputs.disclose_mask, disclosedBytes)
      expect(paramCommitment).toEqual(calculatedParamCommitment)
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
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
      expect(nullifierType).toEqual(NullifierType.NON_SALTED)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
    })
  })

  describe("inclusion-check", () => {
    test("nationality", async () => {
      const circuit = Circuit.from("inclusion_check_nationality")
      const query: Query = {
        nationality: { in: ["AUS", "FRA", "USA", "GBR"] },
      }
      const inputs = await getNationalityInclusionCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
        0n,
        0n,
        nowTimestamp,
      )
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
      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
      expect(nullifierType).toEqual(NullifierType.NON_SALTED)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
      await circuit.destroy()
    })

    test("issuing country", async () => {
      const circuit = Circuit.from("inclusion_check_issuing_country")
      const query: Query = {
        issuing_country: { in: ["AUS", "FRA", "USA", "GBR"] },
      }
      const inputs = await getIssuingCountryInclusionCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
        0n,
        0n,
        nowTimestamp,
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
      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
      expect(nullifierType).toEqual(NullifierType.NON_SALTED)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
      await circuit.destroy()
    })
  })

  describe("inclusion-check evm", () => {
    test("nationality", async () => {
      const circuit = Circuit.from("inclusion_check_nationality_evm")
      const query: Query = {
        nationality: { in: ["AUS", "FRA", "USA", "GBR"] },
      }
      const inputs = await getNationalityInclusionCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
        0n,
        0n,
        nowTimestamp,
      )
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
      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
      expect(nullifierType).toEqual(NullifierType.NON_SALTED)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
      await circuit.destroy()
    }, 30000)

    test("issuing country", async () => {
      const circuit = Circuit.from("inclusion_check_issuing_country_evm")
      const query: Query = {
        issuing_country: { in: ["AUS", "FRA", "USA", "GBR"] },
      }
      const inputs = await getIssuingCountryInclusionCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
        0n,
        0n,
        nowTimestamp,
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
      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
      expect(nullifierType).toEqual(NullifierType.NON_SALTED)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
      await circuit.destroy()
    }, 30000)
  })

  describe("exclusion-check", () => {
    test("nationality", async () => {
      const circuit = Circuit.from("exclusion_check_nationality")
      const query: Query = {
        nationality: { out: ["FRA", "USA", "GBR"] },
      }
      const inputs = await getNationalityExclusionCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
        0n,
        0n,
        nowTimestamp,
      )
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
      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
      expect(nullifierType).toEqual(NullifierType.NON_SALTED)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
      await circuit.destroy()
    })

    test("issuing country", async () => {
      const circuit = Circuit.from("exclusion_check_issuing_country")
      const query: Query = {
        issuing_country: { out: ["FRA", "USA", "GBR"] },
      }
      const inputs = await getIssuingCountryExclusionCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
        0n,
        0n,
        nowTimestamp,
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
      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
      expect(nullifierType).toEqual(NullifierType.NON_SALTED)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
      await circuit.destroy()
    })

    test("sanctions exclusion check", async () => {
      const circuit = Circuit.from("exclusion_check_sanctions")
      const sanctions = await SanctionsBuilder.create()
      const inputs = await getSanctionsExclusionCheckCircuitInputs(
        state.helper.passport as any,
        true,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
        undefined,
        undefined,
        nowTimestamp,
        OPRF_ZERO_PROOF,
        sanctions,
      )

      if (!inputs) throw new Error("Unable to generate sanctions circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `exclusion_check_sanctions`,
      })
      expect(proof).toBeDefined()

      const calculatedParamCommitment = await sanctions.getSanctionsParameterCommitment(true)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
      expect(nullifierType).toEqual(NullifierType.NON_SALTED)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
      await circuit.destroy()
    }, 10000)
  })

  describe("exclusion-check evm", () => {
    test("nationality", async () => {
      const circuit = Circuit.from("exclusion_check_nationality_evm")
      const query: Query = {
        nationality: { out: ["FRA", "USA", "GBR"] },
      }
      const inputs = await getNationalityExclusionCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
        0n,
        0n,
        nowTimestamp,
      )
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
      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
      expect(nullifierType).toEqual(NullifierType.NON_SALTED)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
      await circuit.destroy()
    }, 30000)

    test("nationality - should fail if the list is not sorted", async () => {
      const circuit = Circuit.from("exclusion_check_nationality_evm")
      const query: Query = {
        nationality: { out: ["FRA", "USA", "GBR"] },
      }
      const inputs = await getNationalityExclusionCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
        0n,
        0n,
        nowTimestamp,
      )
      // Override the country list to be unsorted
      const unsortedCountryList: number[] = []
      for (let i = 0; i < (query.nationality?.out ?? []).length; i++) {
        const country: string = (query.nationality?.out ?? [])[i]
        unsortedCountryList.push(getCountryWeightedSum(country as any))
      }
      inputs.country_list = rightPadArrayWithZeros(unsortedCountryList, 200) as any
      if (!inputs) throw new Error("Unable to generate exclusion check circuit inputs")
      // The circuit execution will throw an error if the list is not sorted
      await expect(
        circuit.prove(inputs, {
          circuitName: `exclusion_check_nationality_evm`,
          useCli: true,
        }),
      ).rejects.toThrow("Circuit execution failed: Country list is not sorted in ascending order")
      await circuit.destroy()
    }, 30000)

    test("issuing country", async () => {
      const circuit = Circuit.from("exclusion_check_issuing_country_evm")
      const query: Query = {
        issuing_country: { out: ["FRA", "USA", "GBR"] },
      }
      const inputs = await getIssuingCountryExclusionCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
        0n,
        0n,
        nowTimestamp,
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
      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
      expect(nullifierType).toEqual(NullifierType.NON_SALTED)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
      await circuit.destroy()
    }, 30000)

    test("sanctions exclusion check", async () => {
      const sanctions = await SanctionsBuilder.create()
      const circuit = Circuit.from("exclusion_check_sanctions_evm")

      const inputs = await getSanctionsExclusionCheckCircuitInputs(
        state.helper.passport as any,
        true,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
        undefined,
        undefined,
        nowTimestamp,
        OPRF_ZERO_PROOF,
        sanctions,
      )
      if (!inputs) throw new Error("Unable to generate sanctions circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `exclusion_check_sanctions_evm`,
      })
      expect(proof).toBeDefined()

      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await sanctions.getSanctionsEvmParameterCommitment(true)
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
      expect(nullifierType).toEqual(NullifierType.NON_SALTED)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
      await circuit.destroy()
    }, 10000)

    test("issuing country - should fail if the list is not sorted", async () => {
      const circuit = Circuit.from("exclusion_check_issuing_country_evm")
      const query: Query = {
        issuing_country: { out: ["FRA", "USA", "GBR"] },
      }
      const inputs = await getIssuingCountryExclusionCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
        0n,
        0n,
        nowTimestamp,
      )
      // Override the country list to be unsorted
      const unsortedCountryList: number[] = []
      for (let i = 0; i < (query.issuing_country?.out ?? []).length; i++) {
        const country: string = (query.issuing_country?.out ?? [])[i]
        unsortedCountryList.push(getCountryWeightedSum(country as any))
      }
      inputs.country_list = rightPadArrayWithZeros(unsortedCountryList, 200) as any
      if (!inputs) throw new Error("Unable to generate exclusion check circuit inputs")
      // The circuit execution will throw an error if the list is not sorted
      await expect(
        circuit.prove(inputs, {
          circuitName: `exclusion_check_issuing_country_evm`,
          useCli: true,
        }),
      ).rejects.toThrow("Circuit execution failed: Country list is not sorted in ascending order")
      await circuit.destroy()
    }, 30000)
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
      const inputs = await getAgeCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
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
      const calculatedParamCommitment = await getAgeParameterCommitment(18, 0)
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
      expect(nullifierType).toEqual(NullifierType.NON_SALTED)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
    })

    test("less than", async () => {
      const age = calculateAge(state.helper.passport)
      const query: Query = {
        age: { lt: age + 1 },
      }
      const inputs = await getAgeCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
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
      const calculatedParamCommitment = await getAgeParameterCommitment(0, age)
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
      expect(nullifierType).toEqual(NullifierType.NON_SALTED)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
    })

    test("between", async () => {
      const age = calculateAge(state.helper.passport)
      const query: Query = {
        age: { gte: age, lt: age + 2 },
      }
      const inputs = await getAgeCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
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
      const calculatedParamCommitment = await getAgeParameterCommitment(age, age + 1)
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
      expect(nullifierType).toEqual(NullifierType.NON_SALTED)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
    })

    test("equal", async () => {
      const age = calculateAge(state.helper.passport)
      const query: Query = {
        age: { eq: age },
      }
      const inputs = await getAgeCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
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
      const calculatedParamCommitment = await getAgeParameterCommitment(age, age)
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
      expect(nullifierType).toEqual(NullifierType.NON_SALTED)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
    })

    test("disclose", async () => {
      const query: Query = {
        age: { disclose: true },
      }
      const inputs = await getAgeCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
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
      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
      expect(nullifierType).toEqual(NullifierType.NON_SALTED)
      const age = calculateAge(state.helper.passport)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getAgeParameterCommitment(age, age)
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
    })

    test("range", async () => {
      const age = calculateAge(state.helper.passport)
      const query: Query = {
        age: { range: [age - 5, age + 5] },
      }
      const inputs = await getAgeCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
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
      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
      expect(nullifierType).toEqual(NullifierType.NON_SALTED)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getAgeParameterCommitment(age - 5, age + 5)
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
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
      const inputs = await getAgeCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
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
      const calculatedParamCommitment = await getAgeEVMParameterCommitment(18, 0)
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
      expect(nullifierType).toEqual(NullifierType.NON_SALTED)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
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
      const inputs = await getBirthdateCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
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
      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
      expect(nullifierType).toEqual(NullifierType.NON_SALTED)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateParameterCommitment(
        ProofType.BIRTHDATE,
        getUnixTimestamp(new Date(1988, 10, 12)),
        getUnixTimestamp(new Date(1988, 10, 12)),
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
    })

    test("range", async () => {
      const query: Query = {
        birthdate: { range: [new Date(1988, 10, 11), new Date(1988, 10, 13)] },
      }
      const inputs = await getBirthdateCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
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
      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
      expect(nullifierType).toEqual(NullifierType.NON_SALTED)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateParameterCommitment(
        ProofType.BIRTHDATE,
        getUnixTimestamp(new Date(1988, 10, 11)),
        getUnixTimestamp(new Date(1988, 10, 13)),
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
    })

    test("disclose", async () => {
      const query: Query = {
        birthdate: { disclose: true },
      }
      const inputs = await getBirthdateCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
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
      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
      expect(nullifierType).toEqual(NullifierType.NON_SALTED)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateParameterCommitment(
        ProofType.BIRTHDATE,
        getUnixTimestamp(new Date(1988, 10, 12)),
        getUnixTimestamp(new Date(1988, 10, 12)),
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
    })

    test("greater than", async () => {
      const query: Query = {
        birthdate: { gte: new Date(1928, 10, 11) },
      }
      const inputs = await getBirthdateCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
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
      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
      expect(nullifierType).toEqual(NullifierType.NON_SALTED)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateParameterCommitment(
        ProofType.BIRTHDATE,
        getUnixTimestamp(new Date(1928, 10, 11)),
        0,
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
    })

    test("less than", async () => {
      const query: Query = {
        birthdate: { lte: new Date(1988, 10, 15) },
      }
      const inputs = await getBirthdateCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
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
      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
      expect(nullifierType).toEqual(NullifierType.NON_SALTED)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const calculatedParamCommitment = await getDateParameterCommitment(
        ProofType.BIRTHDATE,
        0,
        getUnixTimestamp(new Date(1988, 10, 15)),
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
    })

    test("between", async () => {
      const query: Query = {
        birthdate: { gte: new Date(1988, 10, 11), lte: new Date(1988, 10, 15) },
      }
      const inputs = await getBirthdateCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
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
        getUnixTimestamp(new Date(1988, 10, 11)),
        getUnixTimestamp(new Date(1988, 10, 15)),
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
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
      const inputs = await getBirthdateCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
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
        getUnixTimestamp(new Date(1988, 10, 12)),
        getUnixTimestamp(new Date(1988, 10, 12)),
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
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
      const inputs = await getExpiryDateCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
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
        getUnixTimestamp(new Date(2030, 0, 1)),
        getUnixTimestamp(new Date(2030, 0, 1)),
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
    })

    test("range", async () => {
      const query: Query = {
        expiry_date: { range: [new Date(2025, 0, 1), new Date(2035, 0, 1)] },
      }
      const inputs = await getExpiryDateCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
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
        getUnixTimestamp(new Date(2025, 0, 1)),
        getUnixTimestamp(new Date(2035, 0, 1)),
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
    })

    test("disclose", async () => {
      const query: Query = {
        expiry_date: { disclose: true },
      }
      const inputs = await getExpiryDateCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
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
        getUnixTimestamp(new Date(2030, 0, 1)),
        getUnixTimestamp(new Date(2030, 0, 1)),
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
    })

    test("greater than", async () => {
      const query: Query = {
        expiry_date: { gte: new Date(2025, 0, 1) },
      }
      const inputs = await getExpiryDateCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
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
        getUnixTimestamp(new Date(2025, 0, 1)),
        0,
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
    })

    test("less than", async () => {
      const query: Query = {
        expiry_date: { lte: new Date(2035, 0, 1) },
      }
      const inputs = await getExpiryDateCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
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
        0,
        getUnixTimestamp(new Date(2035, 0, 1)),
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
    })

    test("between", async () => {
      const query: Query = {
        expiry_date: { gte: new Date(2025, 0, 1), lte: new Date(2035, 0, 1) },
      }
      const inputs = await getExpiryDateCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
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
        getUnixTimestamp(new Date(2025, 0, 1)),
        getUnixTimestamp(new Date(2035, 0, 1)),
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
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
      const inputs = await getExpiryDateCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
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
        getUnixTimestamp(new Date(2030, 0, 1)),
        getUnixTimestamp(new Date(2030, 0, 1)),
      )
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
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
      const inputs = await getBindCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
        0n,
        0n,
        nowTimestamp,
      )
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
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
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
      const inputs = await getBindCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
        0n,
        0n,
        nowTimestamp,
      )
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
      expect(nullifier).toEqual(EXPECTED_NULLIFIER)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
    })
  })

  describe("salted OPRF nullifier", () => {
    let circuit: Circuit
    beforeAll(async () => {
      circuit = Circuit.from("disclose_bytes")
    })
    afterAll(async () => {
      await circuit.destroy()
    })

    test("should produce valid proof with OPRF-based salted nullifier", async () => {
      const query: Query = {
        nationality: { disclose: true },
      }
      const scope = 12345n
      const subscope = 67890n
      let inputs = await getDiscloseCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n, // nullifier_secret placeholder - will be overridden
        scope,
        subscope,
        nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")

      // Get the private_nullifier from the circuit inputs and compute OPRF with it as the input.
      // blindingFactor and auth are unused when options.mock is true.
      const privateNullifier = BigInt(inputs.salted_private_nullifier.value as string)
      const { oprfProof, oprfOutput, publicKey } = await evaluateOPRF(
        privateNullifier,
        0n,
        {} as any,
        { mock: true },
      )

      // Override nullifier_secret and oprf_proof
      inputs.nullifier_secret = `0x${oprfOutput.toString(16)}`
      inputs.oprf_proof = oprfProof

      const proof = await circuit.prove(inputs, {
        witness: await circuit.solve(inputs),
        useCli: true,
        circuitName: `disclose_bytes`,
      })
      expect(proof).toBeDefined()

      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
      expect(nullifierType).toEqual(NullifierType.SALTED)

      const nullifier = getNullifierFromDisclosureProof(proof)
      expect(nullifier).not.toEqual(0n)

      // Verify oprf_pk_hash matches poseidon2Hash([pk.x, pk.y])
      const oprfPkHash = getOprfPkHashFromDisclosureProof(proof)
      const expectedPkHash = await poseidon2HashAsync([publicKey.x, publicKey.y])
      expect(oprfPkHash).toEqual(expectedPkHash)
    })
  })
})

describe("subcircuits - RSA PKCS - ZKR Mock Issuer", () => {
  const state = createTestState()

  beforeAll(async () => {
    await setupPassport(state, {
      mrz: "P<ZKRSILVERHAND<<JOHNNY<<<<<<<<<<<<<<<<<<<<<PA1234567_ZKR881112_M300101_<CYBERCITY<<<<<<",
      certParams: {
        cscSigningHashAlgorithm: "SHA-512",
        cscKeyType: "RSA",
        cscKeySize: 4096,
        dscSigningHashAlgorithm: "SHA-256",
        dscKeyType: "RSA",
        dscKeySize: 2048,
        issuingCountry: "ZK",
      },
      sodHash: "SHA-256",
      sodAlgorithm: new AlgorithmIdentifier({ algorithm: id_sha256WithRSAEncryption }),
      signSodHash: "SHA-256",
    })
  })

  describeDscTest(state, "sig_check_dsc_tbs_700_rsa_pkcs_4096_sha512", "rsa pkcs 4096")
  describeIdTest(state, "sig_check_id_data_tbs_700_rsa_pkcs_2048_sha256", "rsa pkcs 2048")
  describeIntegrityTest(state, "data_check_integrity_sa_sha256_dg_sha256")

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
      let inputs = await getDiscloseCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
        0n,
        0n,
        nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      const proof = await circuit.prove(inputs, {
        witness: await circuit.solve(inputs),

        circuitName: `disclose_bytes`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const disclosedBytes = getDisclosedBytesFromMrzAndMask(
        state.helper.passport.mrz,
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
      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
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
      expect(nullifierType).toEqual(NullifierType.NON_SALTED_MOCK)
      expect(nullifier).toBeDefined()
      expect(nullifier).not.toEqual(1n)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
    })
  })
})

describe("subcircuits - RSA PKCS - German passport", () => {
  const state = createTestState()

  beforeAll(async () => {
    await setupPassport(state, {
      mrz: "P<D<<MUELLER<<JOHANNES<<<<<<<<<<<<<<<<<<<<<<PA1234567_D<<881112_M300101_<<<<<<<<<<<<<<<<",
      certParams: {
        cscSigningHashAlgorithm: "SHA-512",
        cscKeyType: "RSA",
        cscKeySize: 4096,
        dscSigningHashAlgorithm: "SHA-256",
        dscKeyType: "RSA",
        dscKeySize: 2048,
        issuingCountry: "DE",
      },
      sodHash: "SHA-256",
      sodAlgorithm: new AlgorithmIdentifier({ algorithm: id_sha256WithRSAEncryption }),
      signSodHash: "SHA-256",
    })
  })

  describeDscTest(state, "sig_check_dsc_tbs_700_rsa_pkcs_4096_sha512", "rsa pkcs 4096")
  describeIdTest(state, "sig_check_id_data_tbs_700_rsa_pkcs_2048_sha256", "rsa pkcs 2048")
  describeIntegrityTest(state, "data_check_integrity_sa_sha256_dg_sha256")

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
        fullname: { disclose: true },
      }
      let inputs = await getDiscloseCircuitInputs(
        state.helper.passport as any,
        query,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
        0n,
        0n,
        nowTimestamp,
      )
      if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
      const proof = await circuit.prove(inputs, {
        witness: await circuit.solve(inputs),

        circuitName: `disclose_bytes`,
        useCli: true,
      })
      expect(proof).toBeDefined()
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      const disclosedBytes = getDisclosedBytesFromMrzAndMask(
        state.helper.passport.mrz,
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
      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
      expect(disclosedData.issuingCountry).toBe("D<<")
      expect(disclosedData.nationality).toBe("D<<")
      expect(disclosedData.documentType).toBe("other")
      expect(disclosedData.documentNumber).toBe("")
      expect(disclosedData.name).toBe("JOHANNES MUELLER")
      expect(disclosedData.firstName).toBe("JOHANNES")
      expect(disclosedData.lastName).toBe("MUELLER")
      expect(isNaN(disclosedData.dateOfBirth.getTime())).toBe(true)
      expect(isNaN(disclosedData.dateOfExpiry.getTime())).toBe(true)
      expect(disclosedData.gender).toBe("")
      expect(nullifierType).toEqual(NullifierType.NON_SALTED)
      expect(nullifier).toBeDefined()
      expect(nullifier).not.toEqual(1n)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
    })
  })

  describe("sanctions", () => {
    test("sanctions exclusion check", async () => {
      const circuit = Circuit.from("exclusion_check_sanctions")
      const sanctions = await SanctionsBuilder.create()
      const inputs = await getSanctionsExclusionCheckCircuitInputs(
        state.helper.passport as any,
        true,
        INTEGRITY_TO_DISCLOSURE_SALTS,
        0n,
        undefined,
        undefined,
        nowTimestamp,
        undefined, // oprfProof — defaults to OPRF_ZERO_PROOF for non-salted
        sanctions,
      )

      if (!inputs) throw new Error("Unable to generate sanctions circuit inputs")
      const proof = await circuit.prove(inputs, {
        circuitName: `exclusion_check_sanctions`,
      })
      expect(proof).toBeDefined()

      const calculatedParamCommitment = await sanctions.getSanctionsParameterCommitment(true)
      const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
      expect(paramCommitment).toEqual(calculatedParamCommitment)
      const nullifier = getNullifierFromDisclosureProof(proof)
      const nullifierType = getNullifierTypeFromDisclosureProof(proof)
      expect(nullifierType).toEqual(NullifierType.NON_SALTED)
      expect(nullifier).toBeDefined()
      expect(nullifier).not.toEqual(1n)
      const commitmentIn = getCommitmentInFromDisclosureProof(proof)
      expect(commitmentIn).toEqual(state.integrityCheckCommitment)
      const currentDate = getCurrentDateFromDisclosureProof(proof)
      expect(currentDate.getTime()).toEqual(nowTimestamp * 1000)
      await circuit.destroy()
    }, 10000)
  })
})
