import { poseidon2HashAsync } from "@zkpassport/poseidon2"
import type { PackagedCertificate, Query } from "@zkpassport/utils"
import {
  Binary,
  ProofType,
  convertPemToPackagedCertificate,
  formatBoundData,
  getAgeCircuitInputs,
  getBindCircuitInputs,
  getBirthdateCircuitInputs,
  getCircuitMerkleProof,
  getCountryFromWeightedSum,
  getDiscloseCircuitInputs,
  getDisclosedBytesFromMrzAndMask,
  getExpiryDateCircuitInputs,
  getIssuingCountryExclusionCircuitInputs,
  getIssuingCountryInclusionCircuitInputs,
  getNationalityExclusionCircuitInputs,
  getNationalityInclusionCircuitInputs,
  getSanctionsExclusionCheckCircuitInputs,
  getNowTimestamp,
  getOuterCircuitInputs,
  getParameterCommitmentFromDisclosureProof,
  getServiceScopeHash,
  getServiceSubscopeHash,
  rightPadArrayWithZeros,
  getFacematchCircuitInputs,
  getFacematchEvmParameterCommitment,
  packLeBytesAndHashPoseidon2,
  ProofTypeLength,
} from "@zkpassport/utils"
import * as path from "path"
import * as fs from "fs"
import { Circuit } from "../circuits"
import { generateSigningCertificates, loadKeypairFromFile, signSod } from "../passport-generator"
import { generateSod, wrapSodInContentInfo } from "../sod-generator"
import { TestHelper } from "../test-helper"
import { serializeAsn } from "../utils"
import circuitManifest from "../tests/fixtures/circuit-manifest.json"
import { numberToBytesBE } from "@noble/curves/utils"
import FIXTURES_FACEMATCH from "./fixtures/facematch"

interface SubproofData {
  proof: string[]
  publicInputs: string[]
  vkey: string[]
  vkeyHash: string
  paramCommitment?: bigint
}

class FixtureGenerator {
  private helper = new TestHelper()
  private cscaCerts: PackagedCertificate[] = []
  private subproofs = new Map<number, SubproofData>()
  private readonly FIXTURES_PATH = path.join(__dirname, "..", "tests", "fixtures")
  private readonly DSC_KEYPAIR_PATH = path.join(this.FIXTURES_PATH, "dsc-keypair-rsa.json")
  private readonly MAX_TBS_LENGTH = 700
  private readonly nowTimestamp = getNowTimestamp()

  async setupPassport() {
    console.log("Setting up passport data...")
    const mrz =
      "P<AUSSILVERHAND<<JOHNNY<<<<<<<<<<<<<<<<<<<<<PA1234567_AUS881112_M300101_<CYBERCITY<<<<\0\0"
    const dg1 = Binary.fromHex("615B5F1F58").concat(Binary.from(mrz))
    const dscKeypair = await loadKeypairFromFile(this.DSC_KEYPAIR_PATH)

    const { cscPem, dsc, dscKeys } = await generateSigningCertificates({
      cscSigningHashAlgorithm: "SHA-512",
      cscKeyType: "RSA",
      cscKeySize: 4096,
      dscSigningHashAlgorithm: "SHA-256",
      dscKeyType: "RSA",
      dscKeySize: 2048,
      dscKeypair,
    })

    const { sod } = await generateSod(dg1, [dsc], "SHA-256")
    const { sod: signedSod } = await signSod(sod, dscKeys, "SHA-256")
    this.cscaCerts.push(convertPemToPackagedCertificate(cscPem))

    const contentInfoWrappedSod = serializeAsn(wrapSodInContentInfo(signedSod))
    await this.helper.loadPassport(dg1, Binary.from(contentInfoWrappedSod))
    this.helper.setCertificates(this.cscaCerts)
  }

  async generateBaseSubproofs() {
    console.log("Generating base subproofs (0-2)...")

    // CSC to DSC proof
    const cscToDscCircuit = Circuit.from(
      `sig_check_dsc_tbs_${this.MAX_TBS_LENGTH}_rsa_pkcs_4096_sha512`,
    )
    const cscToDscInputs = await this.helper.generateCircuitInputs("dsc")
    const cscToDscProof = await cscToDscCircuit.prove(cscToDscInputs, {
      recursive: true,
      useCli: true,
      circuitName: `sig_check_dsc_tbs_${this.MAX_TBS_LENGTH}_rsa_pkcs_4096_sha512`,
    })
    const cscToDscVkey = (await cscToDscCircuit.getVerificationKey({ evm: false })).vkeyFields
    const cscToDscVkeyHash = `0x${(
      await poseidon2HashAsync(cscToDscVkey.map((x) => BigInt(x)))
    ).toString(16)}`
    this.subproofs.set(0, {
      proof: cscToDscProof.proof,
      publicInputs: cscToDscProof.publicInputs,
      vkey: cscToDscVkey,
      vkeyHash: cscToDscVkeyHash,
    })
    await cscToDscCircuit.destroy()

    // ID Data to Integrity proof
    const idDataCircuit = Circuit.from(
      `sig_check_id_data_tbs_${this.MAX_TBS_LENGTH}_rsa_pkcs_2048_sha256`,
    )
    const idDataInputs = await this.helper.generateCircuitInputs("id")
    const idDataProof = await idDataCircuit.prove(idDataInputs, {
      recursive: true,
      useCli: true,
      circuitName: `sig_check_id_data_tbs_${this.MAX_TBS_LENGTH}_rsa_pkcs_2048_sha256`,
    })
    const idDataVkey = (await idDataCircuit.getVerificationKey({ evm: false })).vkeyFields
    const idDataVkeyHash = `0x${(
      await poseidon2HashAsync(idDataVkey.map((x) => BigInt(x)))
    ).toString(16)}`
    this.subproofs.set(1, {
      proof: idDataProof.proof,
      publicInputs: idDataProof.publicInputs,
      vkey: idDataVkey,
      vkeyHash: idDataVkeyHash,
    })
    await idDataCircuit.destroy()

    // Integrity proof
    const integrityCircuit = Circuit.from("data_check_integrity_sa_sha256_dg_sha256")
    const integrityInputs = await this.helper.generateCircuitInputs("integrity")
    const integrityProof = await integrityCircuit.prove(integrityInputs, {
      recursive: true,
      useCli: true,
      circuitName: `data_check_integrity_sa_sha256_dg_sha256`,
    })
    const integrityVkey = (await integrityCircuit.getVerificationKey({ evm: false })).vkeyFields
    const integrityVkeyHash = `0x${(
      await poseidon2HashAsync(integrityVkey.map((x) => BigInt(x)))
    ).toString(16)}`
    this.subproofs.set(2, {
      proof: integrityProof.proof,
      publicInputs: integrityProof.publicInputs,
      vkey: integrityVkey,
      vkeyHash: integrityVkeyHash,
    })
    await integrityCircuit.destroy()
  }

  async generateDiscloseProof(): Promise<{ subproof: SubproofData; committedInputs: string }> {
    console.log("Generating disclose proof...")

    const discloseCircuit = Circuit.from("disclose_bytes_evm")
    const query: Query = {
      nationality: { disclose: true },
      document_type: { disclose: true },
      document_number: { disclose: true },
      fullname: { disclose: true },
      birthdate: { disclose: true },
      gender: { disclose: true },
    }

    const inputs = await getDiscloseCircuitInputs(
      this.helper.passport as any,
      query,
      3n,
      0n,
      getServiceScopeHash("zkpassport.id"),
      getServiceSubscopeHash("bigproof"),
      this.nowTimestamp,
    )
    if (!inputs) throw new Error("Unable to generate disclose circuit inputs")

    const proof = await discloseCircuit.prove(inputs, {
      recursive: true,
      useCli: true,
      circuitName: `disclose_bytes_evm`,
    })

    const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
    const disclosedBytes = getDisclosedBytesFromMrzAndMask(
      this.helper.passport.mrz,
      inputs.disclose_mask,
    )
    const vkey = (await discloseCircuit.getVerificationKey({ evm: false })).vkeyFields
    const vkeyHash = `0x${(await poseidon2HashAsync(vkey.map((x) => BigInt(x)))).toString(16)}`

    const committedInputs =
      ProofType.DISCLOSE.toString(16).padStart(2, "0") + ProofTypeLength[ProofType.DISCLOSE].evm.toString(16).padStart(4, "0") +
      inputs.disclose_mask.map((x: number) => x.toString(16).padStart(2, "0")).join("") +
      disclosedBytes.map((x: number) => x.toString(16).padStart(2, "0")).join("")

    await discloseCircuit.destroy()

    return {
      subproof: {
        proof: proof.proof,
        publicInputs: proof.publicInputs,
        vkey,
        vkeyHash,
        paramCommitment,
      },
      committedInputs,
    }
  }

  async generateBindProof(): Promise<{ subproof: SubproofData; committedInputs: string }> {
    console.log("Generating bind proof...")

    const bindQuery: Query = {
      bind: {
        user_address: "0x04Fb06E8BF44eC60b6A99D2F98551172b2F2dED8",
        chain: "local_anvil",
        custom_data: "email:test@test.com,customer_id:1234567890",
      },
    }

    const inputs = await getBindCircuitInputs(
      this.helper.passport as any,
      bindQuery,
      3n,
      0n,
      getServiceScopeHash("zkpassport.id"),
      getServiceSubscopeHash("bigproof"),
      this.nowTimestamp,
    )
    if (!inputs) throw new Error("Unable to generate bind circuit inputs")

    const bindCircuit = Circuit.from("bind_evm")
    const proof = await bindCircuit.prove(inputs, {
      recursive: true,
      useCli: true,
      circuitName: `bind_evm`,
    })

    const paramCommitment = getParameterCommitmentFromDisclosureProof(proof)
    const vkey = (await bindCircuit.getVerificationKey({ evm: false })).vkeyFields
    const vkeyHash = `0x${(await poseidon2HashAsync(vkey.map((x) => BigInt(x)))).toString(16)}`

    const committedInputs =
      ProofType.BIND.toString(16).padStart(2, "0") + ProofTypeLength[ProofType.BIND].evm.toString(16).padStart(4, "0") +
      rightPadArrayWithZeros(formatBoundData(bindQuery.bind!), 509)
        .map((x) => x.toString(16).padStart(2, "0"))
        .join("")

    await bindCircuit.destroy()

    return {
      subproof: {
        proof: proof.proof,
        publicInputs: proof.publicInputs,
        vkey,
        vkeyHash,
        paramCommitment,
      },
      committedInputs,
    }
  }

  async generateFacematchProof(): Promise<{ subproof: SubproofData; committedInputs: string }> {
    console.log("Generating facematch proof...")

    const facematchCircuit = Circuit.from("facematch_ios_evm")
    const inputs = await getFacematchCircuitInputs(
      this.helper.passport as any,
      { facematch: { mode: "regular" } },
      3n,
      0n,
      getServiceScopeHash("zkpassport.id"),
      getServiceSubscopeHash("bigproof"),
      this.nowTimestamp,
    )
    if (!inputs) throw new Error("Unable to generate facematch circuit inputs")

    const combinedInputs = { ...inputs, ...FIXTURES_FACEMATCH }
    const facematchProof = await facematchCircuit.prove(combinedInputs, {
      useCli: true,
      recursive: true,
      circuitName: "facematch_ios_evm",
    })
    const root_key_leaf = 0x2532418a107c5306fa8308c22255792cf77e4a290cbce8a840a642a3e591340bn
    const environment = 1n
    const app_id = new Uint8Array([
      ...new TextEncoder().encode("YL5MS3Z639.app.zkpassport.zkpassport"),
    ])
    const app_id_hash = await packLeBytesAndHashPoseidon2(app_id)
    // On iOS, the integrity public key hash is 0 since it's logic specific to Android
    const integrityPubKeyHash = 0n
    const facematch_mode = 1n
    const paramCommitment = getParameterCommitmentFromDisclosureProof(facematchProof)
    const vkey = (await facematchCircuit.getVerificationKey({ evm: false })).vkeyFields
    const vkeyHash = `0x${(await poseidon2HashAsync(vkey.map((x) => BigInt(x)))).toString(16)}`

    const committedInputs =
      ProofType.FACEMATCH.toString(16).padStart(2, "0") + ProofTypeLength[ProofType.FACEMATCH].evm.toString(16).padStart(4, "0") + Array.from(numberToBytesBE(root_key_leaf, 32))
      .map((x) => x.toString(16).padStart(2, "0"))
      .join("") + environment.toString(16).padStart(2, "0") + Array.from(numberToBytesBE(app_id_hash, 32)).map((x) => x.toString(16).padStart(2, "0")).join("") + Array.from(numberToBytesBE(integrityPubKeyHash, 32)).map((x) => x.toString(16).padStart(2, "0")).join("") + facematch_mode.toString(16).padStart(2, "0")

    await facematchCircuit.destroy()

    return {
      subproof: {
        proof: facematchProof.proof,
        publicInputs: facematchProof.publicInputs,
        vkey,
        vkeyHash,
        paramCommitment,
      },
      committedInputs,
    }
  }

  async generateAdditionalProofs(): Promise<{
    subproofs: SubproofData[]
    committedInputs: string
  }> {
    console.log("Generating additional proofs for 13 subproofs test...")

    const additionalSubproofs: SubproofData[] = []
    let allCommittedInputs = ""

    // Helper function to create a simple proof
    const createProof = async (
      circuitName: string,
      inputsGetter: () => Promise<any>,
      query: Query,
      proofType: ProofType,
      formatCommittedInputs: (inputs: any) => string,
    ) => {
      const circuit = Circuit.from(circuitName)
      const inputs = await inputsGetter()
      if (!inputs) throw new Error(`Unable to generate ${circuitName} inputs`)

      const proof = await circuit.prove(inputs, {
        recursive: true,
        useCli: true,
        circuitName,
      })

      const vkey = (await circuit.getVerificationKey({ evm: false })).vkeyFields
      const vkeyHash = `0x${(await poseidon2HashAsync(vkey.map((x) => BigInt(x)))).toString(16)}`

      allCommittedInputs += proofType.toString(16).padStart(2, "0") + ProofTypeLength[proofType].evm.toString(16).padStart(4, "0") + formatCommittedInputs(inputs)

      await circuit.destroy()

      return {
        proof: proof.proof,
        publicInputs: proof.publicInputs,
        vkey,
        vkeyHash,
        paramCommitment: getParameterCommitmentFromDisclosureProof(proof),
      }
    }

    // Nationality inclusion
    additionalSubproofs.push(
      await createProof(
        "inclusion_check_nationality_evm",
        () =>
          getNationalityInclusionCircuitInputs(
            this.helper.passport as any,
            { nationality: { in: ["AUS", "FRA", "USA", "GBR"] } },
            3n,
            0n,
            getServiceScopeHash("zkpassport.id"),
            getServiceSubscopeHash("bigproof"),
            this.nowTimestamp,
          ),
        { nationality: { in: ["AUS", "FRA", "USA", "GBR"] } },
        ProofType.NATIONALITY_INCLUSION,
        (inputs) =>
          rightPadArrayWithZeros(
            inputs.country_list.map((c: string) => Array.from(new TextEncoder().encode(c))).flat(),
            600,
          )
            .map((x) => x.toString(16).padStart(2, "0"))
            .join(""),
      ),
    )

    // Nationality exclusion
    additionalSubproofs.push(
      await createProof(
        "exclusion_check_nationality_evm",
        () =>
          getNationalityExclusionCircuitInputs(
            this.helper.passport as any,
            { nationality: { out: ["ESP", "PRT", "ITA"] } },
            3n,
            0n,
            getServiceScopeHash("zkpassport.id"),
            getServiceSubscopeHash("bigproof"),
            this.nowTimestamp,
          ),
        { nationality: { out: ["ESP", "PRT", "ITA"] } },
        ProofType.NATIONALITY_EXCLUSION,
        (inputs) =>
          rightPadArrayWithZeros(
            inputs.country_list
              .map((c: number) =>
                Array.from(new TextEncoder().encode(getCountryFromWeightedSum(c))),
              )
              .flat(),
            600,
          )
            .map((x) => x.toString(16).padStart(2, "0"))
            .join(""),
      ),
    )

    // Issuing country inclusion
    additionalSubproofs.push(
      await createProof(
        "inclusion_check_issuing_country_evm",
        () =>
          getIssuingCountryInclusionCircuitInputs(
            this.helper.passport as any,
            { issuing_country: { in: ["AUS", "FRA", "USA", "GBR"] } },
            3n,
            0n,
            getServiceScopeHash("zkpassport.id"),
            getServiceSubscopeHash("bigproof"),
            this.nowTimestamp,
          ),
        { issuing_country: { in: ["AUS", "FRA", "USA", "GBR"] } },
        ProofType.ISSUING_COUNTRY_INCLUSION,
        (inputs) =>
          rightPadArrayWithZeros(
            inputs.country_list.map((c: string) => Array.from(new TextEncoder().encode(c))).flat(),
            600,
          )
            .map((x) => x.toString(16).padStart(2, "0"))
            .join(""),
      ),
    )

    // Issuing country exclusion
    additionalSubproofs.push(
      await createProof(
        "exclusion_check_issuing_country_evm",
        () =>
          getIssuingCountryExclusionCircuitInputs(
            this.helper.passport as any,
            { issuing_country: { out: ["ESP", "PRT", "ITA"] } },
            3n,
            0n,
            getServiceScopeHash("zkpassport.id"),
            getServiceSubscopeHash("bigproof"),
            this.nowTimestamp,
          ),
        { issuing_country: { out: ["ESP", "PRT", "ITA"] } },
        ProofType.ISSUING_COUNTRY_EXCLUSION,
        (inputs) =>
          rightPadArrayWithZeros(
            inputs.country_list
              .map((c: number) =>
                Array.from(new TextEncoder().encode(getCountryFromWeightedSum(c))),
              )
              .flat(),
            600,
          )
            .map((x) => x.toString(16).padStart(2, "0"))
            .join(""),
      ),
    )

    // Age proof
    additionalSubproofs.push(
      await createProof(
        "compare_age_evm",
        () =>
          getAgeCircuitInputs(
            this.helper.passport as any,
            { age: { gte: 18 } },
            3n,
            0n,
            getServiceScopeHash("zkpassport.id"),
            getServiceSubscopeHash("bigproof"),
            this.nowTimestamp,
          ),
        { age: { gte: 18 } },
        ProofType.AGE,
        (inputs) =>
          inputs.min_age_required.toString(16).padStart(2, "0") +
          inputs.max_age_required.toString(16).padStart(2, "0"),
      ),
    )

    // Expiry date proof
    additionalSubproofs.push(
      await createProof(
        "compare_expiry_evm",
        () =>
          getExpiryDateCircuitInputs(
            this.helper.passport as any,
            { expiry_date: { gte: new Date(this.nowTimestamp * 1000) } },
            3n,
            0n,
            getServiceScopeHash("zkpassport.id"),
            getServiceSubscopeHash("bigproof"),
            this.nowTimestamp,
          ),
        { expiry_date: { gte: new Date(this.nowTimestamp * 1000) } },
        ProofType.EXPIRY_DATE,
        (inputs) =>
          Array.from(numberToBytesBE(inputs.min_date, 8))
            .map((x: number) => x.toString(16).padStart(2, "0"))
            .join("") +
          Array.from(numberToBytesBE(inputs.max_date, 8))
            .map((x: number) => x.toString(16).padStart(2, "0"))
            .join(""),
      ),
    )

    // Birthdate proof
    additionalSubproofs.push(
      await createProof(
        "compare_birthdate_evm",
        () =>
          getBirthdateCircuitInputs(
            this.helper.passport as any,
            { birthdate: { lte: new Date(this.nowTimestamp * 1000) } },
            3n,
            0n,
            getServiceScopeHash("zkpassport.id"),
            getServiceSubscopeHash("bigproof"),
            this.nowTimestamp,
          ),
        { birthdate: { lte: new Date(this.nowTimestamp * 1000) } },
        ProofType.BIRTHDATE,
        (inputs) =>
          Array.from(numberToBytesBE(inputs.min_date, 8))
            .map((x: number) => x.toString(16).padStart(2, "0"))
            .join("") +
          Array.from(numberToBytesBE(inputs.max_date, 8))
            .map((x) => x.toString(16).padStart(2, "0"))
            .join(""),
      ),
    )

    // Sanctions proof
    additionalSubproofs.push(
      await createProof(
        "exclusion_check_sanctions_evm",
        () => getSanctionsExclusionCheckCircuitInputs(
          this.helper.passport as any,
          true,
          3n, 
          0n,
          getServiceScopeHash("zkpassport.id"),
          getServiceSubscopeHash("bigproof"),
          this.nowTimestamp,
        ),
        { sanctions: { countries: "all", lists: "all" } },
        ProofType.SANCTIONS_EXCLUSION,
        (inputs) => inputs.root.slice(2).padStart(64, "0") + inputs.is_strict.toString(16).padStart(2, "0"),
      ),
    )

    return { subproofs: additionalSubproofs, committedInputs: allCommittedInputs }
  }

  async generateOuterProof(
    subproofData: SubproofData[],
    circuitName: string,
    evmCircuitName: string,
  ) {
    console.log(`Generating outer proof for ${circuitName}...`)

    const circuit = Circuit.from(circuitName)
    const merkleProofs = await Promise.all(
      subproofData.map((s) => getCircuitMerkleProof(s.vkeyHash, circuitManifest)),
    )

    const baseSubproofs = [this.subproofs.get(0)!, this.subproofs.get(1)!, this.subproofs.get(2)!]

    const disclosureSubproofs = subproofData.slice(3)

    const inputs = await getOuterCircuitInputs(
      {
        proof: baseSubproofs[0].proof,
        publicInputs: baseSubproofs[0].publicInputs,
        vkey: baseSubproofs[0].vkey,
        keyHash: baseSubproofs[0].vkeyHash,
        treeHashPath: merkleProofs[0].path,
        treeIndex: merkleProofs[0].index.toString(),
      },
      {
        proof: baseSubproofs[1].proof,
        publicInputs: baseSubproofs[1].publicInputs,
        vkey: baseSubproofs[1].vkey,
        keyHash: baseSubproofs[1].vkeyHash,
        treeHashPath: merkleProofs[1].path,
        treeIndex: merkleProofs[1].index.toString(),
      },
      {
        proof: baseSubproofs[2].proof,
        publicInputs: baseSubproofs[2].publicInputs,
        vkey: baseSubproofs[2].vkey,
        keyHash: baseSubproofs[2].vkeyHash,
        treeHashPath: merkleProofs[2].path,
        treeIndex: merkleProofs[2].index.toString(),
      },
      disclosureSubproofs.map((subproof, idx) => ({
        proof: subproof.proof,
        publicInputs: subproof.publicInputs,
        vkey: subproof.vkey,
        keyHash: subproof.vkeyHash,
        treeHashPath: merkleProofs[3 + idx].path,
        treeIndex: merkleProofs[3 + idx].index.toString(),
      })),
      circuitManifest.root,
    )

    const proof = await circuit.prove(inputs, {
      useCli: true,
      circuitName: evmCircuitName,
      recursive: false,
      evm: true,
      disableZK: true,
    })

    await circuit.destroy()
    return proof
  }

  async writeFixturesToFiles(fixtures: {
    validProof: string
    validPublicInputs: string[]
    validCommittedInputs: string
    allSubproofsProof: string
    allSubproofsPublicInputs: string[]
    allSubproofsCommittedInputs: string
  }) {
    const outputPath = path.join(__dirname, "..", "..", "solidity", "test", "fixtures")

    if (!fs.existsSync(outputPath)) {
      fs.mkdirSync(outputPath, { recursive: true })
    }

    console.log("Writing fixtures to files...")

    // Write proof files (hex)
    fs.writeFileSync(path.join(outputPath, "valid_proof.hex"), fixtures.validProof)
    fs.writeFileSync(path.join(outputPath, "all_subproofs_proof.hex"), fixtures.allSubproofsProof)

    // Write public inputs files (JSON)
    fs.writeFileSync(
      path.join(outputPath, "valid_public_inputs.json"),
      JSON.stringify({ inputs: fixtures.validPublicInputs }, null, 2),
    )
    fs.writeFileSync(
      path.join(outputPath, "all_subproofs_public_inputs.json"),
      JSON.stringify({ inputs: fixtures.allSubproofsPublicInputs }, null, 2),
    )

    // Write committed inputs files (hex)
    fs.writeFileSync(
      path.join(outputPath, "valid_committed_inputs.hex"),
      fixtures.validCommittedInputs,
    )
    fs.writeFileSync(
      path.join(outputPath, "all_subproofs_committed_inputs.hex"),
      fixtures.allSubproofsCommittedInputs,
    )

    console.log("All fixtures written successfully!")
  }

  async generate() {
    console.log("Starting fixture generation...")

    await this.setupPassport()
    await this.generateBaseSubproofs()

    // Generate 5 subproofs fixtures
    const { subproof: discloseSubproof, committedInputs: discloseCommittedInputs } =
      await this.generateDiscloseProof()
    this.subproofs.set(3, discloseSubproof)

    const { subproof: bindSubproof, committedInputs: bindCommittedInputs } =
      await this.generateBindProof()

    const fiveSubproofsData = [
      this.subproofs.get(0)!,
      this.subproofs.get(1)!,
      this.subproofs.get(2)!,
      discloseSubproof,
      bindSubproof,
    ]

    const outerProof5 = await this.generateOuterProof(
      fiveSubproofsData,
      "outer_count_5",
      "outer_count_5",
    )

    // Generate 13 subproofs fixtures
    const { subproofs: additionalSubproofs, committedInputs: additionalCommittedInputs } =
      await this.generateAdditionalProofs()

    const { subproof: facematchSubproof, committedInputs: facematchCommittedInputs } =
      await this.generateFacematchProof()

    const elevenSubproofsData = [
      this.subproofs.get(0)!,
      this.subproofs.get(1)!,
      this.subproofs.get(2)!,
      discloseSubproof,
      ...additionalSubproofs,
      facematchSubproof,
    ]

    const outerProof13 = await this.generateOuterProof(
      elevenSubproofsData,
      "outer_count_13",
      "outer_count_13",
    )

    const fixtures = {
      validProof: outerProof5.proof.map((x) => x.replace("0x", "")).join(""),
      validPublicInputs: outerProof5.publicInputs,
      validCommittedInputs: discloseCommittedInputs + bindCommittedInputs,
      allSubproofsProof: outerProof13.proof.map((x) => x.replace("0x", "")).join(""),
      allSubproofsPublicInputs: outerProof13.publicInputs,
      allSubproofsCommittedInputs: discloseCommittedInputs + additionalCommittedInputs + facematchCommittedInputs,
    }

    await this.writeFixturesToFiles(fixtures)
    console.log("Fixture generation completed successfully!")
  }
}

async function main() {
  try {
    const generator = new FixtureGenerator()
    await generator.generate()
  } catch (error) {
    console.error("Error generating fixtures:", error)
    process.exit(1)
  }
}

;(async () => {
  await main()
})()
