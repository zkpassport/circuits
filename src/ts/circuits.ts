import { CompiledCircuit, InputMap, Noir } from "@noir-lang/noir_js"
import { ProofData } from "@noir-lang/types"
import { UltraHonkBackend } from "@aztec/bb.js"
import fs from "fs"
import path from "path"
import os from "os"
import { exec } from "child_process"
import { promisify } from "util"
import { getNumberOfPublicInputs, getProofData } from "@zkpassport/utils"

const BB_THREADS = 8

const execAsync = promisify(exec)
const writeFileAsync = promisify(fs.writeFile)

export class Circuit {
  private manifest: CompiledCircuit
  private name: string
  public backend?: UltraHonkBackend
  public noir?: Noir

  constructor(manifest: CompiledCircuit, name: string) {
    this.manifest = manifest
    this.name = name
  }

  async init() {
    if (!this.backend) {
      this.backend = new UltraHonkBackend(this.manifest.bytecode, {
        threads: BB_THREADS,
      })
      if (!this.backend) throw new Error("Error initializing backend")
    }
    if (!this.noir) {
      this.noir = new Noir(this.manifest)
      if (!this.noir) throw new Error("Error initializing noir")
    }
  }

  async destroy() {
    if (!this.backend) return
    await this.backend!.destroy()
    this.backend = undefined
  }

  async solve(inputs: InputMap): Promise<Uint8Array> {
    await this.init()
    const { witness } = await this.noir!.execute(inputs)
    if (!witness) throw new Error("Error solving witness")
    return witness
  }

  async prove(
    inputs: InputMap,
    options?: { witness?: Uint8Array; useCli?: boolean; circuitName?: string },
  ): Promise<ProofData> {
    await this.init()
    const witness = options?.witness ?? (await this.solve(inputs))
    let proof: ProofData
    if (options?.useCli) {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "prover-"))
      const witnessPath = path.join(tempDir, "witness.gz")
      const circuitPath = path.join(tempDir, "circuit.json")
      const proofPath = path.join(tempDir, "proof")
      await writeFileAsync(witnessPath, witness)
      await writeFileAsync(circuitPath, JSON.stringify(this.manifest))
      const proveCommand = `bb prove --scheme ultra_honk --recursive --init_kzg_accumulator --honk_recursion 1 -b ${circuitPath} -w ${witnessPath} -o ${tempDir}`

      console.log(`Executing: ${proveCommand}`)
      const startTime = Date.now()
      const { stdout, stderr } = await execAsync(proveCommand, {
        cwd: tempDir,
      })
      const endTime = Date.now()
      const elapsedTime = (endTime - startTime) / 1000
      console.log(`Elapsed time: ${elapsedTime.toFixed(2)} seconds`)
      console.log("stdout:", stdout)
      console.log("stderr:", stderr)

      // Check if proof file was created
      if (!fs.existsSync(proofPath)) {
        throw new Error("Proof file was not created")
      }
      // Read the proof file and encode as base64
      const proofHex = fs.readFileSync(proofPath).toString("hex")
      proof = getProofData(proofHex, getNumberOfPublicInputs(options?.circuitName ?? ""))
    } else {
      proof = await this.backend!.generateProof(witness)
    }
    return proof
  }

  async proveRecursiveProof(inputs: InputMap): Promise<{ proof: ProofData; artifacts: any }> {
    const proof = await this.prove(inputs)
    if (!this.backend) throw new Error("Backend not initialized")
    const artifacts = await this.backend.generateRecursiveProofArtifacts(
      proof.proof,
      proof.publicInputs.length,
    )
    return { proof, artifacts }
  }

  async verify(proof: ProofData) {
    await this.init()
    if (!this.backend) throw new Error("Backend not initialized")
    return await this.backend.verifyProof(proof)
  }

  async getVerificationKey() {
    await this.init()
    if (!this.backend) throw new Error("Backend not initialized")
    return await this.backend.getVerificationKey()
  }

  static from(fileName: string): Circuit {
    if (!path) throw new Error("Path is not available in this environment")
    const isFullPath = path.isAbsolute(fileName) || fileName.includes("/")
    const circuitPath = isFullPath ? fileName : path.resolve(`target/${fileName}.json`)
    try {
      if (!fs) throw new Error("Read file sync is not available in this environment")
      const manifest = JSON.parse(fs.readFileSync(circuitPath, "utf-8"))
      const name = path.basename(fileName, ".json")
      return new Circuit(manifest, name)
    } catch (error) {
      if (error instanceof Error && error.name === "ENOENT") {
        throw new Error(`No such file: target/${fileName}.json`)
      }
      throw error
    }
  }

  getName(): string {
    return this.name
  }
}
