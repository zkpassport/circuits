import { expect, beforeAll, describe, test } from "bun:test"
import { Noir } from "@noir-lang/noir_js"
import { CompiledCircuit, ProofData, type InputMap } from "@noir-lang/types"
import { BarretenbergBackend } from "@noir-lang/backend_barretenberg"
import { compileCircuit, genCSC, getCertificates, loadCircuit } from "./helpers"
import { generateRSAKeyPair, signData } from "./helpers/rsa"
import { getRSAPublicKeyParams } from "./helpers/rsa"
import { bigIntToFields } from "./helpers/conversion"
import { generateCSCToDSCInputs } from "./helpers/proof"
import "./helpers/extensions"
import { BB_THREADS } from "./helpers/constants"
import path from "path"

describe("dsc - rsa pkcs", () => {
  let noir: Noir
  let backend: BarretenbergBackend
  let proof: ProofData
  let circuit: CompiledCircuit

  beforeAll(async () => {
    // Load circuit and initialise Noir.js using UltraHonk backend
    // NOTE: First compile the circuit before running the tests: nargo compile --package sig_check_dsc_rsa_pkcs_2048
    circuit = await loadCircuit("sig_check_dsc_rsa_pkcs_2048")
    // circuit = await compileCircuit(path.resolve("src/noir/bin/sig-check/dsc/rsa/pkcs/2048"))
    backend = new BarretenbergBackend(circuit, { threads: BB_THREADS })
    noir = new Noir(circuit)
  })

  test(
    "csc-to-dsc",
    async () => {
      // Create mock tbs data
      const tbsData: Buffer = Buffer.from("Hello, world!")
      // Generate RSA key pair
      const { privateKey, publicKey } = generateRSAKeyPair()
      const publicKeyParams = getRSAPublicKeyParams(publicKey)
      // Sign the tbs
      const signature = signData(privateKey, tbsData)

      // Generate mock certificates
      const certificates = getCertificates()
      const csc = genCSC(
        "AUS",
        "sha256WithRSAEncryption",
        privateKey,
        bigIntToFields(publicKeyParams.modulus) as number[],
        65537,
      )
      certificates.unshift(csc)

      // Generate inputs for the circuit
      const inputs: InputMap = await generateCSCToDSCInputs(
        certificates[0],
        certificates,
        tbsData,
        signature,
      )
      const { witness } = await noir.execute(inputs)
      proof = await backend.generateProof(witness)
      expect(proof.proof instanceof Uint8Array).toBeTrue
    },
    { timeout: 60000 },
  )

  // test("Should verify valid proof for correct input", async () => {
  //   const verification = await backend.verifyProof(proof)
  //   expect(verification).toBeTrue
  // })

  // test('Should fail to generate valid proof for incorrect input', async () => {
  //   try {
  //     const input = { x: 1, y: 1 }
  //     const { witness } = await noir.execute(input)
  //     await backend.generateProof(witness)
  //   } catch (err) {
  //     expect(err instanceof Error).toBeTrue
  //     const error = err as Error
  //     expect(error.message).toContain('Cannot satisfy constraint')
  //   }
  // })
})
