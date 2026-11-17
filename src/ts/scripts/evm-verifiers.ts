import fs from "fs"
import path from "path"
import { snakeToPascal } from "../utils"

/** The Solidity verifiers bb writes for the EVM circuits */
export const SOLIDITY_VERIFIERS_DIR = "src/solidity/src/ultra-honk-verifiers"
/** The list the deploy scripts deploy, and a release build records in build-info.json */
export const EVM_VERIFIERS_PATH = "src/solidity/evm-verifiers.json"

/** A circuit whose proofs are verified on chain, and the verifier contract that does it */
export interface EvmVerifier {
  circuit: string
  /** The file in ultra-honk-verifiers that holds the circuit's HonkVerifier */
  contractFile: string
  vkeyHash: string
}

/** An outer circuit, which the packager packages a second time as an EVM circuit */
export function isOuterCircuit(name: string): boolean {
  return name.startsWith("outer_") && !name.startsWith("outer_evm_")
}

/** The EVM circuit the packager makes from an outer circuit */
export function evmCircuitName(outerCircuit: string): string {
  return outerCircuit.replace(/^outer_/, "outer_evm_")
}

/** The file bb writes the EVM circuit's verifier to */
export function verifierContractFile(evmCircuit: string): string {
  return `${snakeToPascal(evmCircuit)}.sol`.replace("Evm", "")
}

/**
 * The EVM verifiers of a manifest's circuits: one for each outer circuit, from its EVM circuit's
 * vkey hash. Throws unless the manifest's EVM circuits and the verifier contracts in verifiersDir
 * are exactly those.
 */
export function evmVerifiers(
  circuits: Record<string, { hash: string }>,
  verifiersDir: string = SOLIDITY_VERIFIERS_DIR,
): EvmVerifier[] {
  const problems: string[] = []
  const verifiers: EvmVerifier[] = []
  const outerCircuits = Object.keys(circuits)
    .filter(isOuterCircuit)
    .sort((a, b) => a.localeCompare(b, "en", { numeric: true }))
  for (const outerCircuit of outerCircuits) {
    const circuit = evmCircuitName(outerCircuit)
    const contractFile = verifierContractFile(circuit)
    if (!circuits[circuit]) {
      problems.push(`${outerCircuit} has no EVM circuit ${circuit}`)
      continue
    }
    if (!fs.existsSync(path.join(verifiersDir, contractFile))) {
      problems.push(`${circuit} has no verifier ${contractFile}`)
      continue
    }
    const hash = circuits[circuit].hash.replace(/^0x/, "")
    verifiers.push({ circuit, contractFile, vkeyHash: `0x${hash.padStart(64, "0")}` })
  }

  const listed = new Set(verifiers.map(({ circuit }) => circuit))
  for (const circuit of Object.keys(circuits)) {
    if (circuit.startsWith("outer_evm_") && !listed.has(circuit)) {
      problems.push(`${circuit} is an EVM circuit without an outer circuit`)
    }
  }
  const contractFiles = new Set(verifiers.map(({ contractFile }) => contractFile))
  for (const file of fs.readdirSync(verifiersDir)) {
    if (!contractFiles.has(file)) {
      problems.push(`${path.join(verifiersDir, file)} verifies none of the manifest's circuits`)
    }
  }

  if (problems.length > 0) {
    throw new Error(`The EVM verifiers don't match the circuits:\n  ${problems.join("\n  ")}`)
  }
  return verifiers
}

export function writeEvmVerifiers(verifiers: EvmVerifier[], file: string = EVM_VERIFIERS_PATH) {
  fs.writeFileSync(file, JSON.stringify(verifiers, null, 2) + "\n")
}
