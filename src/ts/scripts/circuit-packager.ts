import { poseidon2Hash } from "@zkpassport/poseidon2"
import { PromisePool } from "@zkpassport/utils"
import { calculateCircuitRoot } from "@zkpassport/utils/registry"
import { exec, execSync } from "child_process"
import fs from "fs"
import type { Blockstore } from "interface-blockstore"
import path from "path"
import { promisify } from "util"
import { gzipAsync, initBarretenberg, destroyBarretenberg } from "../utils"
import { Barretenberg } from "@aztec-foundation/bb.js"
import {
  evmCircuitName,
  evmVerifiers,
  EVM_VERIFIERS_PATH,
  isOuterCircuit,
  SOLIDITY_VERIFIERS_DIR,
  verifierContractFile,
  writeEvmVerifiers,
} from "./evm-verifiers"

let barretenberg: Barretenberg

const TARGET_DIR = "target"
const PACKAGED_DIR = path.join(TARGET_DIR, "packaged")
const PACKAGED_CIRCUITS_DIR = path.join(TARGET_DIR, "packaged/circuits")
const MAX_CONCURRENT_PROCESSES = 40

/**
 * Calculates the IPFS CIDv0 of the given data
 * @param data The input data used to calculate the IPFS CIDv0
 * @param options Options for calculating the IPFS CIDv0
 * @param options.gzip Whether to gzip the data before calculating the CIDv0
 * @returns The resulting IPFS CIDv0
 */
async function getIpfsCidv0(
  data: Buffer,
  { gzip = false }: { gzip?: boolean } = {},
): Promise<string> {
  if (gzip) data = await gzipAsync(data)

  const { importer } = await import("ipfs-unixfs-importer")

  // Create a mock memory blockstore that does nothing
  const blockstore: Blockstore = { get: async () => {}, put: async () => {} } as any
  for await (const result of importer([{ content: data }], blockstore, {
    cidVersion: 0,
    rawLeaves: false,
    wrapWithDirectory: false,
  })) {
    return result.cid.toString()
  }
  throw new Error("Failed to generate CIDv0")
}

const getPackageJsonBBVersion = () => {
  const packageJsonPath = path.resolve(__dirname, "../../../package.json")
  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf8"))
  const expectedBBVersion = packageJson.dependencies["@aztec-foundation/bb.js"].replace(
    /[^0-9a-zA-Z\.\-]/i,
    "",
  )
  return expectedBBVersion
}

function checkBBVersion() {
  try {
    // Read package.json to get expected bb version
    const expectedBBVersion = getPackageJsonBBVersion()
    if (!expectedBBVersion) {
      throw new Error("Couldn't find bb version in package.json")
    }
    // Get installed bb version for comparison
    const installedBBVersion = execSync("bb --version").toString().trim().replace(/^v/i, "")
    if (!installedBBVersion) {
      throw new Error(`Failed to parse bb version output: ${installedBBVersion}`)
    }
    // TODO: Uncomment this once the bb MacOS binaries are back
    // as the version string is not correct for locally built bb binaries
    /* if (installedBBVersion !== expectedBBVersion) {
      throw new Error(
        `bb version mismatch. Expected ${expectedBBVersion} but found ${installedBBVersion}. Change bb version using: bbup -v ${expectedBBVersion}`,
      )
    }*/
  } catch (error: any) {
    if (error.message.includes("command not found")) {
      console.error(
        "Error: bb is not installed. Visit https://noir-lang.org for installation instructions.",
      )
    } else {
      console.error("Error:", error.message)
    }
    process.exit(1)
  }
}

checkBBVersion()

// Create packaged directory if it doesn't exist
if (!fs.existsSync(PACKAGED_CIRCUITS_DIR)) {
  fs.mkdirSync(PACKAGED_CIRCUITS_DIR, { recursive: true })
}

// Get all JSON files from target directory
// `--only name1,name2` packages just those circuits, for a local manifest of a subset
const onlyArg = process.argv.find((arg) => arg.startsWith("--only="))
const only = onlyArg ? new Set(onlyArg.slice("--only=".length).split(",")) : null

const files = fs
  .readdirSync(TARGET_DIR)
  .filter(
    (file) =>
      !file.endsWith(".vkey.json") && !file.endsWith(".size.json") && file.endsWith(".json"),
  )
  .filter((file) => !only || only.has(file.replace(".json", "")))

// Promisify exec
const execAsync = promisify(exec)
const execPromise = (cmd: string) => execAsync(cmd, { maxBuffer: 100 * 1024 * 1024 })

// Process a single file
const processFile = async (
  file: string,
  evm: boolean = false,
  outputName: string = file.replace(".json", ""),
  generateSolidityVerifier: boolean = false,
): Promise<boolean> => {
  const inputPath = path.join(TARGET_DIR, file)
  const outputPath = path.join(PACKAGED_CIRCUITS_DIR, `${outputName}.json`)
  const vkeyPath = path.join(TARGET_DIR, `${outputName}_vkey`)
  const gateCountPath = path.join(TARGET_DIR, `${outputName}.size.json`)
  const solidityVerifierPath = path.join(SOLIDITY_VERIFIERS_DIR, verifierContractFile(outputName))
  try {
    // Read the input file and check whether it contains the string "unconstrained main"
    const inputContent = fs.readFileSync(inputPath, "utf-8")
    const isUnconstrained = inputContent.includes("unconstrained main")

    if (isUnconstrained) {
      throw new Error(
        `Unconstrained circuit detected: ${file}. Please remove any unconstrained circuits and rebuild them constrained.`,
      )
    }

    if (fs.existsSync(outputPath)) {
      console.log(`Skipping ${file} (already packaged)`)
      return true
    }

    // Run bb command to get bb version and generate circuit vkey
    // const bbVersion = (await execPromise("bb --version")).stdout.trim().replace(/^v/i, "")
    // TODO: Switch back to the above once the bb MacOS binaries are back
    const bbVersion = getPackageJsonBBVersion()
    console.log(`Generating vkey: ${file}`)
    fs.mkdirSync(vkeyPath, { recursive: true })
    await execPromise(
      `bb write_vk -t ${evm ? "evm" : "noir-recursive"} -b "${inputPath}" -o "${vkeyPath}"`,
    )
    await execPromise(`bb gates -t noir-recursive -b "${inputPath}" > "${gateCountPath}"`)
    if (generateSolidityVerifier) {
      await execPromise(
        `bb write_solidity_verifier -t evm-no-zk --optimized -k "${vkeyPath}/vk" -o "${solidityVerifierPath}"`,
      )
    }

    // Get Poseidon2 hash of vkey
    //const vkeyAsFieldsJson = JSON.parse(fs.readFileSync(`${vkeyPath}/vk_fields.json`, "utf-8"))
    //const vkeyAsFields = vkeyAsFieldsJson.map((v: any) => BigInt(v))
    const vkeyHash = `0x${Buffer.from(fs.readFileSync(`${vkeyPath}/vk_hash`)).toString("hex")}`
    const vkey = Buffer.from(fs.readFileSync(`${vkeyPath}/vk`)).toString("base64")

    // Clean up vkey files
    fs.unlinkSync(`${vkeyPath}/vk`)
    fs.unlinkSync(`${vkeyPath}/vk_hash`)
    fs.rmdirSync(vkeyPath)

    // Read and parse the input file
    const jsonContent = JSON.parse(fs.readFileSync(inputPath, "utf-8"))
    const gateCountFileContent = JSON.parse(fs.readFileSync(gateCountPath, "utf-8"))
    const gateCount = gateCountFileContent.functions[0].circuit_size
    fs.unlinkSync(gateCountPath)

    // Create packaged circuit object
    const packagedCircuit: {
      [key: string]: unknown
    } = {
      name: outputName,
      noir_version: jsonContent.noir_version,
      bb_version: bbVersion,
      size: gateCount,
      abi: jsonContent.abi,
      bytecode: jsonContent.bytecode,
      vkey: vkey,
      vkey_hash: vkeyHash,
      hash: jsonContent.hash,
    }

    // Write the packaged circuit file
    fs.writeFileSync(outputPath, JSON.stringify(packagedCircuit, null, 2))
    console.log(`Saved packaged circuit: ${outputPath}`)
    return true
  } catch (error: any) {
    if (error?.status !== undefined && error.status !== 0) {
      console.error(
        `Error processing file ${inputPath}: Command failed with exit code ${error.status}`,
      )
    } else {
      console.error("Error processing file " + inputPath, error)
    }
    return false
  }
}

// Process files with controlled concurrency
const processFiles = async () => {
  let hasErrors = false

  // Split files into two groups: outer proof circuits and the other circuits
  const outerFiles = files.filter((file) => isOuterCircuit(file.replace(".json", "")))
  const otherFiles = files.filter((file) => !isOuterCircuit(file.replace(".json", "")))

  // Process outer proof circuits one at a time
  if (outerFiles.length > 0) {
    console.log(`Processing ${outerFiles.length} outer proof circuits sequentially...`)
    for (const file of outerFiles) {
      console.log(
        `Memory intensive processing of outer proof circuit: ${file} (no concurrent processing)`,
      )
      console.log(`Generating the standard outer proof packaged circuit...`)
      const success = await processFile(file, false, file.replace(".json", ""), false)
      if (!success) {
        hasErrors = true
      }
      console.log(`Generating the EVM-optimised outer proof packaged circuit...`)
      const successEvm = await processFile(
        file,
        true,
        evmCircuitName(file.replace(".json", "")),
        true,
      )
      if (!successEvm) {
        hasErrors = true
      }
    }
  }

  // Process other circuits with concurrency
  if (otherFiles.length > 0) {
    console.log(`Processing ${otherFiles.length} regular circuits with concurrency...`)
    const pool = new PromisePool(MAX_CONCURRENT_PROCESSES)
    await Promise.all(
      otherFiles.map(async (file) => {
        await pool.add(async () => {
          const success = await processFile(file)
          if (!success) hasErrors = true
        })
      }),
    )
    // Wait for all files to be processed
    await pool.drain()
  }

  // Exit with error code if any file failed to process
  if (hasErrors) {
    process.exit(1)
  }
}

interface CircuitManifest {
  version: string
  root: string
  circuits: {
    [key: string]: {
      hash: string
      size: string
      cid: string
    }
  }
}

async function generateCircuitManifest(files: string[]) {
  const circuitManifestPath = path.join(PACKAGED_DIR, "manifest.json")
  console.log(`Generating circuit manifest for ${files.length} circuits`)

  // Get version from package.json
  const packageJsonFile = path.join(__dirname, "../../../package.json")
  const { version } = JSON.parse(fs.readFileSync(packageJsonFile, "utf-8"))

  // Add circuits to manifest
  let manifest: CircuitManifest = { version, root: "", circuits: {} }
  const circuits = await Promise.all(
    files.map(async (file) => {
      const circuitBuffer = fs.readFileSync(path.join(PACKAGED_CIRCUITS_DIR, file))
      const json = JSON.parse(circuitBuffer.toString("utf-8"))
      const cid = await getIpfsCidv0(circuitBuffer, { gzip: true })
      return {
        name: json.name,
        hash: json.vkey_hash,
        cid,
        size: json.size,
      }
    }),
  )
  circuits.sort((a, b) => a.name.localeCompare(b.name))
  for (const circuit of circuits) {
    manifest.circuits[circuit.name] = {
      hash: circuit.hash,
      cid: circuit.cid,
      size: circuit.size,
    }
  }
  // Calculate circuit root
  const circuitHashes = circuits.map((circuit) => circuit.hash)
  manifest.root = await calculateCircuitRoot({ hashes: circuitHashes })
  console.log("Circuit root:", manifest.root)

  // Save circuit manifest
  fs.writeFileSync(circuitManifestPath, JSON.stringify(manifest, null, 2))
  console.log(`Saved circuit manifest: ${circuitManifestPath}`)
  return manifest
}

async function main() {
  // Start timing
  const startTime = Date.now()
  try {
    barretenberg = await initBarretenberg()
    await processFiles()
    // Generate manifest
    const packagedFiles = fs
      .readdirSync(PACKAGED_CIRCUITS_DIR)
      .filter((file) => file.endsWith(".json"))
    const manifest = await generateCircuitManifest(packagedFiles)
    if (only) {
      console.log(`Not updating ${EVM_VERIFIERS_PATH}: --only packages a subset of the circuits`)
    } else {
      // The verifiers the deploy scripts deploy, checked against the manifest and the verifier contracts
      const verifiers = evmVerifiers(manifest.circuits)
      writeEvmVerifiers(verifiers)
      console.log(`Saved the ${verifiers.length} EVM verifiers: ${EVM_VERIFIERS_PATH}`)
    }
  } catch (error) {
    console.error("Fatal error:", error)
    process.exit(1)
  } finally {
    // Print total time taken
    const duration = (Date.now() - startTime) / 1000 // convert to seconds
    const minutes = Math.floor(duration / 60)
    const seconds = Math.floor(duration % 60)
    if (minutes > 0) {
      console.log(`Total time taken: ${minutes}m ${seconds}s`)
    } else if (seconds >= 0) {
      console.log(`Total time taken: ${seconds}s`)
    }
    await destroyBarretenberg(barretenberg)
  }
}

// Wrap the main function call in an IIFE to avoid top-level await issues
;(async () => {
  await main()
})()
