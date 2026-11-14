import {
  Binary,
  calculatePackagedCertificatesRoot,
  calculateCircuitRoot,
  getCircuitMerkleProof,
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
  SaltedValue,
} from "@zkpassport/utils"
import type { IntegrityToDisclosureSalts, PackagedCertificatesFile, Query } from "@zkpassport/utils"
import { beforeAll, afterAll, describe, expect, test } from "@jest/globals"
import * as path from "path"
import { TestHelper, convertPemToPackagedCertificateV1 } from "../test-helper"
import {
  generateSigningCertificates,
  generateSod,
  type HashAlgorithm,
  loadKeypairFromFile,
  signSod,
  wrapSodInContentInfo,
} from "@zkpassport/utils/passport-generator"
import { serializeAsn, createUTCDate } from "../utils"
import { Circuit } from "../circuits"
import { evaluateOPRF } from "@zkpassport/utils"
import { poseidon2HashAsync } from "@zkpassport/poseidon2"
import fs from "fs"
import FIXTURES_FACEMATCH from "./fixtures/facematch"
import {
  ATTESTATION_KEY_TYPE_APPLE,
  ATTESTATION_KEY_TYPE_GOOGLE,
  ATTESTATION_TYPE_FACE_MATCH,
  FACEMATCH_MODE_REGULAR,
  FACEMATCH_MODE_STRICT,
  buildAndroidAttestedIdInputs,
  buildIosAttestedIdInputs,
  calculateAttestationParamCommitment,
  calculateAttestedIdCommitment,
  calculateTier2PrivateNullifier,
  getExpiryDate,
  padDg1,
} from "./attested-id"
import { sha256, sha384 } from "@noble/hashes/sha2.js"
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
// The integrity check proof's public inputs: comm_in, then its outputs comm_out and credential_scheme
const CREDENTIAL_SCHEME_ICAO_CHIP = 100n
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
      expect(proof.publicInputs).toHaveLength(3)
      const [commitmentIn, commitmentOut, credentialScheme] = proof.publicInputs.map(BigInt)
      expect(commitmentIn).toEqual(state.idDataCommitment)
      expect(credentialScheme).toEqual(CREDENTIAL_SCHEME_ICAO_CHIP)
      state.integrityCheckCommitment = commitmentOut
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
  name: "JOHNNY MATTHEW SILVERHAND", firstName: "JOHNNY", lastName: "SILVERHAND",
}
const DISCLOSE_ALL_DE_JOHNNY: DiscloseAllExpected = {
  issuingCountry: "DEU", nationality: "DEU",
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
    discloseSome: discloseSomeNationalityOnly("DEU"),
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

    // Generating RSA keys of up to 6144 bits can outlast jest's 5 s default for hooks
    beforeAll(async () => {
      await setupPassport(state, config.setup)
    }, 60000)

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
      expect(disclosedData.issuingCountry).toBe("DEU")
      expect(disclosedData.nationality).toBe("DEU")
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

describe("attested id (Tier 2)", () => {
  const SALTS = { dg1Salt: 11n, expiryDateSalt: 12n, dg2HashSalt: 13n, privateNullifierSalt: 14n }
  // A TD3 passport DG1: "P<FRADOE<<JANE...", X12345678, born 1990-02-01, expiring 2030-04-03
  const PASSPORT_DG1 = Binary.fromHex("615B5F1F58")
    .concat(
      Binary.from(
        "P<FRADOE<<JANE<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<X12345678<FRA9002016F3004035<<<<<<<<<<<<<<04",
      ),
    )
    .toUInt8Array()
  // The ICAO 9303 sample TD1 ID card, expired in 2012: the base proof does not check expiry
  const ID_CARD_DG1 = Binary.fromHex("615B5F1F5A")
    .concat(
      Binary.from(
        "I<UTOD231458907<<<<<<<<<<<<<<<7408122F1204159UTO<<<<<<<<<<<6ERIKSSON<<ANNA<MARIA<<<<<<<<<<",
      ),
    )
    .toUInt8Array()
  // A US driving licence's barcode, converted to a TD1 MRZ by @zkpassport/utils: "DL" for the
  // document code, the number in its overflow form with the state after it, no nationality
  const LICENSE_DG1 = Binary.fromHex("615B5F1F5A")
    .concat(
      Binary.from(
        "DLUSAD1234567<<7<CA<<<<<<<<<<<9001158F3101159<<<<<<<<<<<<<<4DOE<<JANE<MARIE<<<<<<<<<<<<<<<",
      ),
    )
    .toUInt8Array()
  // Private nullifiers printed by the attested-to-disclosure Noir lib tests
  const PASSPORT_PRIVATE_NULLIFIER =
    0x064c866cb0248d050c72dc3a01c74d839bbc18df5600debb0b2e2ff1a645c447n
  const ID_CARD_PRIVATE_NULLIFIER =
    0x02c7905c961b56ce7050e0cc7873e9d2bbabfca8835d7eb74619eaa3f2a8a5aen
  const PORTRAIT_HASH = sha256(new TextEncoder().encode("portrait"))
  const OTHER_PORTRAIT_HASH = sha256(new TextEncoder().encode("another portrait"))

  describe("ios", () => {
    const CIRCUIT_NAME = "attested_id_ios"
    let circuit: Circuit
    let discloseCircuit: Circuit
    beforeAll(() => {
      circuit = Circuit.from(CIRCUIT_NAME)
      discloseCircuit = Circuit.from("disclose_bytes")
    })
    afterAll(async () => {
      await circuit.destroy()
      await discloseCircuit.destroy()
    })

    const expectSolveToFail = async (inputs: any, message: string) => {
      await expect(circuit.solve(inputs)).rejects.toThrow(message)
    }

    test("passport: proves, and its commitment is consumed by disclose_bytes", async () => {
      const attestation = await buildIosAttestedIdInputs({
        dg1: PASSPORT_DG1,
        portraitHash: PORTRAIT_HASH,
        salts: SALTS,
      })
      const proof = await circuit.prove(attestation.inputs, {
        witness: await circuit.solve(attestation.inputs),
        useCli: true,
        circuitName: CIRCUIT_NAME,
      })
      expect(proof.publicInputs).toHaveLength(4)
      const [attestedDate, commOut, paramCommitment, credentialScheme] =
        proof.publicInputs.map(BigInt)
      // The credential certificate's notBefore, at the start of its day
      expect(attestedDate).toEqual(BigInt(attestation.attestedDate))

      const expected = await calculateAttestedIdCommitment(SALTS, PASSPORT_DG1, PORTRAIT_HASH)
      expect(expected.privateNullifier).toEqual(PASSPORT_PRIVATE_NULLIFIER)
      expect(commOut).toEqual(expected.commitment)
      const rootKeyLeaf = await packLeBytesAndHashPoseidon2(
        new Uint8Array([ATTESTATION_KEY_TYPE_APPLE, ...attestation.rootKey]),
      )
      const appIdHash = await packLeBytesAndHashPoseidon2(
        new TextEncoder().encode(attestation.appId),
      )
      expect(paramCommitment).toEqual(
        await calculateAttestationParamCommitment({
          rootKeyType: ATTESTATION_KEY_TYPE_APPLE,
          rootKey: attestation.rootKey,
          environment: attestation.environment,
          appId: attestation.appId,
          mode: FACEMATCH_MODE_STRICT,
        }),
      )
      // The twin above and the published face match helper differ only in the proof type
      expect(paramCommitment).not.toEqual(
        await getFacematchParameterCommitment(
          rootKeyLeaf,
          BigInt(attestation.environment),
          appIdHash,
          BigInt(FACEMATCH_MODE_STRICT),
        ),
      )
      expect(credentialScheme).toEqual(200n)

      const discloseMask = Array(90).fill(1)
      const discloseInputs = {
        comm_in: `0x${commOut.toString(16)}`,
        current_date: nowTimestamp,
        salted_private_nullifier: SaltedValue.fromValue(
          SALTS.privateNullifierSalt,
          expected.privateNullifier,
        ).formatForInput(),
        salted_expiry_date: SaltedValue.fromValue(
          SALTS.expiryDateSalt,
          getExpiryDate(PASSPORT_DG1),
        ).formatForInput(),
        salted_dg1: SaltedValue.fromValue(
          SALTS.dg1Salt,
          Array.from(padDg1(PASSPORT_DG1)),
        ).formatForInput(),
        salted_dg2_hash: SaltedValue.fromValue(
          SALTS.dg2HashSalt,
          expected.dg2HashNormalized,
        ).formatForInput(),
        salted_dg2_hash_type: SaltedValue.fromValue(SALTS.dg2HashSalt, 3n).formatForInput(),
        disclose_mask: discloseMask,
        nullifier_secret: "0x0",
        oprf_proof: OPRF_ZERO_PROOF,
        service_scope: "0x0",
        service_subscope: "0x0",
      }
      const discloseProof = await discloseCircuit.prove(discloseInputs as any, {
        witness: await discloseCircuit.solve(discloseInputs as any),
        useCli: true,
        circuitName: "disclose_bytes",
      })
      expect(getCommitmentInFromDisclosureProof(discloseProof)).toEqual(commOut)
      expect(getNullifierTypeFromDisclosureProof(discloseProof)).toEqual(NullifierType.NON_SALTED)
      expect(getNullifierFromDisclosureProof(discloseProof)).toEqual(
        await poseidon2HashAsync([expected.privateNullifier, 0n, 0n]),
      )
      const mrz = Buffer.from(PASSPORT_DG1.subarray(5)).toString()
      const disclosedBytes = getDisclosedBytesFromMrzAndMask(mrz, discloseMask)
      expect(getParameterCommitmentFromDisclosureProof(discloseProof)).toEqual(
        await getDiscloseParameterCommitment(discloseMask, disclosedBytes),
      )
      const disclosedData = DisclosedData.fromDisclosedBytes(disclosedBytes, "passport")
      expect(disclosedData.issuingCountry).toBe("FRA")
      expect(disclosedData.documentNumber).toBe("X12345678")
      expect(disclosedData.name).toBe("JANE DOE")
      expect(disclosedData.dateOfBirth).toEqual(createUTCDate(1990, 1, 1))
      expect(disclosedData.dateOfExpiry).toEqual(createUTCDate(2030, 3, 3))
    }, 120000)

    test("ID card (TD1): proves", async () => {
      const attestation = await buildIosAttestedIdInputs({
        dg1: ID_CARD_DG1,
        portraitHash: PORTRAIT_HASH,
        salts: SALTS,
      })
      const proof = await circuit.prove(attestation.inputs, {
        witness: await circuit.solve(attestation.inputs),
        useCli: true,
        circuitName: CIRCUIT_NAME,
      })
      const [, commOut, , credentialScheme] = proof.publicInputs.map(BigInt)
      const expected = await calculateAttestedIdCommitment(SALTS, ID_CARD_DG1, PORTRAIT_HASH)
      expect(expected.privateNullifier).toEqual(ID_CARD_PRIVATE_NULLIFIER)
      expect(commOut).toEqual(expected.commitment)
      expect(credentialScheme).toEqual(200n)
    }, 90000)

    test("driving licence (TD1 from its barcode): proves, with the state in its nullifier", async () => {
      const attestation = await buildIosAttestedIdInputs({
        dg1: LICENSE_DG1,
        portraitHash: PORTRAIT_HASH,
        salts: SALTS,
      })
      const proof = await circuit.prove(attestation.inputs, {
        witness: await circuit.solve(attestation.inputs),
        useCli: true,
        circuitName: CIRCUIT_NAME,
      })
      const [, commOut] = proof.publicInputs.map(BigInt)
      const expected = await calculateAttestedIdCommitment(SALTS, LICENSE_DG1, PORTRAIT_HASH)
      expect(commOut).toEqual(expected.commitment)
      const otherState = Uint8Array.from(LICENSE_DG1)
      otherState.set(new TextEncoder().encode("NV"), 5 + 17)
      expect(await calculateTier2PrivateNullifier(otherState)).not.toEqual(
        expected.privateNullifier,
      )
    }, 90000)

    test("fails when the attested digest is not over the DG1 and portrait", async () => {
      const attestation = await buildIosAttestedIdInputs({
        dg1: PASSPORT_DG1,
        portraitHash: OTHER_PORTRAIT_HASH,
        salts: SALTS,
      })
      await expectSolveToFail(
        { ...attestation.inputs, portrait_hash: Array.from(PORTRAIT_HASH) },
        "Attested digest does not match DG1 and portrait",
      )
      const tamperedDg1 = [...attestation.inputs.salted_dg1.value]
      tamperedDg1[49] = "Y".charCodeAt(0)
      await expectSolveToFail(
        {
          ...attestation.inputs,
          salted_dg1: { ...attestation.inputs.salted_dg1, value: tamperedDg1 },
        },
        "Attested digest does not match DG1 and portrait",
      )
    })

    test("fails with a chip face match's attestation", async () => {
      // A forged chip could make its DG2 hash equal any attested digest, so only the camera
      // read's own attestation type is accepted
      const attestation = await buildIosAttestedIdInputs({
        dg1: PASSPORT_DG1,
        portraitHash: PORTRAIT_HASH,
        salts: SALTS,
        attestationType: ATTESTATION_TYPE_FACE_MATCH,
      })
      await expectSolveToFail(attestation.inputs, "Attestation is not for an attested ID")
    })

    test("fails with a regular face match", async () => {
      const attestation = await buildIosAttestedIdInputs({
        dg1: PASSPORT_DG1,
        portraitHash: PORTRAIT_HASH,
        salts: SALTS,
        mode: FACEMATCH_MODE_REGULAR,
      })
      await expectSolveToFail(attestation.inputs, "Tier 2 requires a strict face match")
    })

    test("fails when the attested digest is not 32 bytes", async () => {
      const attestation = await buildIosAttestedIdInputs({
        dg1: PASSPORT_DG1,
        portraitHash: PORTRAIT_HASH,
        salts: SALTS,
        digest: sha384(new TextEncoder().encode("portrait")),
        digestAlgorithmOid: "608648016503040202",
      })
      await expectSolveToFail(attestation.inputs, "Attested digest must be a SHA-256 digest")
    })

    test("fails when the app ID differs from the credential certificate's", async () => {
      const attestation = await buildIosAttestedIdInputs({
        dg1: PASSPORT_DG1,
        portraitHash: PORTRAIT_HASH,
        salts: SALTS,
        credentialAppId: "ABCDE12345.app.other.test",
      })
      await expectSolveToFail(attestation.inputs, "Failed to verify app_id")
    })
  })

  describe("android", () => {
    const CIRCUIT_NAME = "attested_id_android_rk_ecdsa_ik_count_1_ik_ecdsa_p256_sha256"
    let circuit: Circuit
    beforeAll(() => {
      circuit = Circuit.from(CIRCUIT_NAME)
    })
    afterAll(async () => {
      await circuit.destroy()
    })

    test("passport: proves", async () => {
      const attestation = await buildAndroidAttestedIdInputs({
        dg1: PASSPORT_DG1,
        portraitHash: PORTRAIT_HASH,
        salts: SALTS,
        currentDate: nowTimestamp,
      })
      const proof = await circuit.prove(attestation.inputs, {
        witness: await circuit.solve(attestation.inputs),
        useCli: true,
        circuitName: CIRCUIT_NAME,
      })
      expect(proof.publicInputs).toHaveLength(4)
      const [currentDate, commOut, paramCommitment, credentialScheme] =
        proof.publicInputs.map(BigInt)
      expect(currentDate).toEqual(BigInt(nowTimestamp))
      const expected = await calculateAttestedIdCommitment(SALTS, PASSPORT_DG1, PORTRAIT_HASH)
      expect(commOut).toEqual(expected.commitment)
      expect(paramCommitment).toEqual(
        await calculateAttestationParamCommitment({
          rootKeyType: ATTESTATION_KEY_TYPE_GOOGLE,
          rootKey: attestation.rootKey,
          environment: attestation.environment,
          appId: attestation.appId,
          integrityPublicKey: attestation.playIntegrityPublicKey,
          mode: FACEMATCH_MODE_STRICT,
        }),
      )
      expect(credentialScheme).toEqual(201n)
    }, 120000)

    test("fails with a regular face match", async () => {
      const attestation = await buildAndroidAttestedIdInputs({
        dg1: PASSPORT_DG1,
        portraitHash: PORTRAIT_HASH,
        salts: SALTS,
        currentDate: nowTimestamp,
        mode: FACEMATCH_MODE_REGULAR,
      })
      await expect(circuit.solve(attestation.inputs)).rejects.toThrow(
        "Tier 2 requires a strict face match",
      )
    })

    test("fails when the attested digest is not over the DG1 and portrait", async () => {
      const attestation = await buildAndroidAttestedIdInputs({
        dg1: PASSPORT_DG1,
        portraitHash: OTHER_PORTRAIT_HASH,
        salts: SALTS,
        currentDate: nowTimestamp,
      })
      await expect(
        circuit.solve({ ...attestation.inputs, portrait_hash: Array.from(PORTRAIT_HASH) }),
      ).rejects.toThrow("Attested digest does not match DG1 and portrait")
    })

    test("fails with a chip face match's attestation", async () => {
      const attestation = await buildAndroidAttestedIdInputs({
        dg1: PASSPORT_DG1,
        portraitHash: PORTRAIT_HASH,
        salts: SALTS,
        currentDate: nowTimestamp,
        attestationType: ATTESTATION_TYPE_FACE_MATCH,
      })
      await expect(circuit.solve(attestation.inputs)).rejects.toThrow(
        "Attestation is not for an attested ID",
      )
    })

    test("fails when the date is not the integrity token's", async () => {
      const attestation = await buildAndroidAttestedIdInputs({
        dg1: PASSPORT_DG1,
        portraitHash: PORTRAIT_HASH,
        salts: SALTS,
        currentDate: nowTimestamp - 40 * 24 * 60 * 60,
      })
      // An old attestation can't be passed off as recent
      await expect(
        circuit.solve({ ...attestation.inputs, current_date: nowTimestamp }),
      ).rejects.toThrow("Date is not the integrity token's")
    })

    test("fails when the integrity token was not signed by the Play Integrity key", async () => {
      const attestation = await buildAndroidAttestedIdInputs({
        dg1: PASSPORT_DG1,
        portraitHash: PORTRAIT_HASH,
        salts: SALTS,
        currentDate: nowTimestamp,
      })
      const signature = [...attestation.inputs.integrity_token_signature]
      signature[63] ^= 1
      await expect(
        circuit.solve({ ...attestation.inputs, integrity_token_signature: signature }),
      ).rejects.toThrow("Failed to verify integrity token signature")
    })
  })

  describe("outer proof", () => {
    type Subproof = { proof: string[]; publicInputs: string[]; vkey: string[]; vkeyHash: string }

    const recursiveProof = async (circuit: Circuit, name: string, inputs: any): Promise<Subproof> => {
      const proof = await circuit.prove(inputs, {
        witness: await circuit.solve(inputs, true),
        useCli: true,
        circuitName: name,
        recursive: true,
      })
      const vkey = (await circuit.getVerificationKey({ evm: false })).vkeyFields
      const vkeyHash = `0x${(await poseidon2HashAsync(vkey.map((x: string) => BigInt(x)))).toString(16)}`
      return { proof: proof.proof, publicInputs: proof.publicInputs, vkey, vkeyHash }
    }

    // The disclosure proof built on an attested ID's commitment, as the app makes it
    const discloseOn = async (commOut: bigint, dg1: Uint8Array) => {
      const expected = await calculateAttestedIdCommitment(SALTS, dg1, PORTRAIT_HASH)
      const discloseCircuit = Circuit.from("disclose_bytes")
      const inputs = {
        comm_in: `0x${commOut.toString(16)}`,
        current_date: nowTimestamp,
        salted_private_nullifier: SaltedValue.fromValue(
          SALTS.privateNullifierSalt,
          expected.privateNullifier,
        ).formatForInput(),
        salted_expiry_date: SaltedValue.fromValue(
          SALTS.expiryDateSalt,
          getExpiryDate(dg1),
        ).formatForInput(),
        salted_dg1: SaltedValue.fromValue(SALTS.dg1Salt, Array.from(padDg1(dg1))).formatForInput(),
        salted_dg2_hash: SaltedValue.fromValue(
          SALTS.dg2HashSalt,
          expected.dg2HashNormalized,
        ).formatForInput(),
        salted_dg2_hash_type: SaltedValue.fromValue(SALTS.dg2HashSalt, 3n).formatForInput(),
        disclose_mask: Array(90).fill(1),
        nullifier_secret: "0x0",
        oprf_proof: OPRF_ZERO_PROOF,
        service_scope: "0x0",
        service_subscope: "0x0",
      }
      const proof = await recursiveProof(discloseCircuit, "disclose_bytes", inputs)
      await discloseCircuit.destroy()
      return proof
    }

    const outerInputs = async (attested: Subproof, disclose: Subproof, scheme: bigint) => {
      const circuitManifest = {
        version: "0.23.0",
        root: await calculateCircuitRoot({ hashes: [attested.vkeyHash, disclose.vkeyHash] }),
        circuits: {
          attested: { hash: attested.vkeyHash, size: 1 },
          disclose: { hash: disclose.vkeyHash, size: 1 },
        },
      } as any
      const leaf = async (subproof: Subproof, publicInputs: string[]) => {
        const { path, index } = await getCircuitMerkleProof(subproof.vkeyHash, circuitManifest)
        return {
          vkey: subproof.vkey,
          proof: subproof.proof,
          public_inputs: publicInputs,
          key_hash: subproof.vkeyHash,
          tree_hash_path: path,
          tree_index: index.toString(),
        }
      }
      const d = disclose.publicInputs
      return {
        certificate_registry_root: "0x1",
        circuit_registry_root: circuitManifest.root,
        current_date: nowTimestamp,
        service_scope: "0x0",
        service_subscope: "0x0",
        param_commitments: [attested.publicInputs[attested.publicInputs.length - 2], d[4]],
        nullifier_type: d[5],
        scoped_nullifier: d[6],
        oprf_pk_hash: d[7],
        credential_scheme: `0x${scheme.toString(16)}`,
        attested_id_proof: await leaf(attested, attested.publicInputs),
        disclosure_proofs: [await leaf(disclose, [d[0], d[6], d[5], d[7]])],
      }
    }

    const proveOuter = async (name: string, inputs: any) => {
      const circuit = Circuit.from(name)
      const proof = await circuit.prove(inputs, {
        witness: await circuit.solve(inputs, true),
        useCli: true,
        circuitName: name,
        recursive: true,
      })
      const unprefixed = { ...proof, proof: proof.proof.map((x) => x.replace(/^0x/, "")) }
      expect(await circuit.verify(unprefixed, true)).toBe(true)
      await circuit.destroy()
      return proof
    }

    const expectOuterToFail = async (name: string, inputs: any, message: string) => {
      const circuit = Circuit.from(name)
      await expect(circuit.solve(inputs, true)).rejects.toThrow(message)
      await circuit.destroy()
    }

    test("ios: wraps the attested ID proof and a disclosure proof built on it, if recent", async () => {
      const attestedCircuit = Circuit.from("attested_id_ios")
      const attestation = await buildIosAttestedIdInputs({
        dg1: PASSPORT_DG1,
        portraitHash: PORTRAIT_HASH,
        salts: SALTS,
      })
      const attested = await recursiveProof(attestedCircuit, "attested_id_ios", attestation.inputs)
      await attestedCircuit.destroy()
      const disclose = await discloseOn(BigInt(attested.publicInputs[1]), PASSPORT_DG1)
      const inputs = await outerInputs(attested, disclose, 200n)

      const proof = await proveOuter("outer_attested_id_count_2", inputs)
      const publicInputs = proof.publicInputs.map(BigInt)
      // The chip outer's layout: roots, date, scopes, param commitments, then the trailing four
      expect(publicInputs).toHaveLength(11)
      expect(publicInputs[5]).toEqual(BigInt(attested.publicInputs[2]))
      expect(publicInputs[6]).toEqual(BigInt(disclose.publicInputs[4]))
      expect(publicInputs[publicInputs.length - 1]).toEqual(200n)

      // The face match must be recent: within 30 days of the outer proof
      await expectOuterToFail(
        "outer_attested_id_count_2",
        { ...inputs, current_date: nowTimestamp + 31 * 24 * 60 * 60 },
        "Attested ID proof is not recent",
      )

      // Not a Tier 2 scheme, or not the one the attested ID proof states
      await expectOuterToFail(
        "outer_attested_id_count_2",
        { ...inputs, credential_scheme: "0x64" },
        "Not a Tier 2 credential scheme",
      )
      await expectOuterToFail(
        "outer_attested_id_count_2",
        { ...inputs, credential_scheme: "0xc9" },
        "Credential scheme from attested ID circuit != expected credential scheme",
      )
      await expectOuterToFail(
        "outer_attested_id_count_2",
        { ...inputs, param_commitments: ["0x1", inputs.param_commitments[1]] },
        "Attested ID parameter commitment != first parameter commitment",
      )
      const otherDisclose = { ...inputs.disclosure_proofs[0] }
      otherDisclose.public_inputs = ["0x2", ...otherDisclose.public_inputs.slice(1)]
      await expectOuterToFail(
        "outer_attested_id_count_2",
        { ...inputs, disclosure_proofs: [otherDisclose] },
        "Commitment out from attested ID circuit != commitment in from disclosure circuit",
      )
    }, 600000)

    test("android: wraps the attested ID proof, which must be recent", async () => {
      const name = "attested_id_android_rk_ecdsa_ik_count_1_ik_ecdsa_p256_sha256"
      const attestedCircuit = Circuit.from(name)
      const attestation = await buildAndroidAttestedIdInputs({
        dg1: PASSPORT_DG1,
        portraitHash: PORTRAIT_HASH,
        salts: SALTS,
        currentDate: nowTimestamp,
      })
      const attested = await recursiveProof(attestedCircuit, name, attestation.inputs)
      await attestedCircuit.destroy()
      const disclose = await discloseOn(BigInt(attested.publicInputs[1]), PASSPORT_DG1)
      const inputs = await outerInputs(attested, disclose, 201n)

      // The same outer circuit as iOS: both attested ID proofs have the same public inputs
      const proof = await proveOuter("outer_attested_id_count_2", inputs)
      const publicInputs = proof.publicInputs.map(BigInt)
      expect(publicInputs[5]).toEqual(BigInt(attested.publicInputs[2]))
      expect(publicInputs[publicInputs.length - 1]).toEqual(201n)

      await expectOuterToFail(
        "outer_attested_id_count_2",
        { ...inputs, current_date: nowTimestamp + 31 * 24 * 60 * 60 },
        "Attested ID proof is not recent",
      )
    }, 600000)
  })
})
