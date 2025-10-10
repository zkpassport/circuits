import { poseidon2Hash } from "@zkpassport/poseidon2"
import { PromisePool } from "@zkpassport/utils"
import { calculateCircuitRoot } from "@zkpassport/utils/registry"
import { exec, execSync } from "child_process"
import fs from "fs"
import type { Blockstore } from "interface-blockstore"
import path from "path"
import { promisify } from "util"
import { snakeToPascal, gzipAsync, initBarretenberg, destroyBarretenberg } from "../utils"
import { Barretenberg } from "@aztec/bb.js"

let barretenberg: Barretenberg

const TARGET_DIR = "target"
const PACKAGED_DIR = path.join(TARGET_DIR, "packaged")
const PACKAGED_CIRCUITS_DIR = path.join(TARGET_DIR, "packaged/circuits")
const MAX_CONCURRENT_PROCESSES = 10
const DEPLOY_SOL_PATH = "src/solidity/script/Deploy.s.sol"
const ADD_VERIFIERS_SOL_PATH = "src/solidity/script/AddVerifiers.s.sol"
const DEPLOY_WITH_EXISTING_VERIFIERS_SOL_PATH =
  "src/solidity/script/DeployWithExistingVerifiers.s.sol"

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
  const expectedBBVersion = packageJson.dependencies["@aztec/bb.js"].replace(
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
const files = fs
  .readdirSync(TARGET_DIR)
  .filter((file) => !file.endsWith(".vkey.json") && file.endsWith(".json"))

// Promisify exec
const execPromise = promisify(exec)

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
  const solidityVerifierPath = path.join(
    "src/solidity/src/ultra-honk-verifiers",
    `${snakeToPascal(outputName)}.sol`.replace("Evm", ""),
  )
  try {
    // Skip if output file already exists
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
      `bb write_vk --scheme ultra_honk${
        evm ? " --oracle_hash keccak" : ""
      } -b "${inputPath}" -o "${vkeyPath}"`,
    )
    if (!evm) {
      await execPromise(
        `bb gates --scheme ultra_honk -b "${inputPath}" > "${gateCountPath}"`,
      )
    }
    if (generateSolidityVerifier) {
      await execPromise(
        `bb write_solidity_verifier --scheme ultra_honk --disable_zk -k "${vkeyPath}/vk" -o "${solidityVerifierPath}"`,
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
    let gateCount = 0
    if (!evm) {
      const gateCountFileContent = JSON.parse(fs.readFileSync(gateCountPath, "utf-8"))
      gateCount = gateCountFileContent.functions[0].circuit_size
      fs.unlinkSync(gateCountPath)
    }

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

// Get all outer EVM vkey hashes from packaged circuit files
const getOuterkeyHashes = (): { count: number; hash: string }[] => {
  console.log("Collecting vkey hashes from packaged circuit files...")
  const vkeyHashes: { count: number; hash: string }[] = []

  try {
    // Get all packaged JSON files
    const packagedFiles = fs
      .readdirSync(PACKAGED_CIRCUITS_DIR)
      .filter((file) => file.endsWith(".json"))

    // Filter for outer_evm_count files and extract their vkey hashes
    for (const file of packagedFiles) {
      if (file.startsWith("outer_count_")) {
        const countMatch = file.match(/outer_count_(\d+)\.json/)
        if (countMatch && countMatch[1]) {
          const count = parseInt(countMatch[1])
          const filePath = path.join(PACKAGED_CIRCUITS_DIR, file)

          // Read the packaged circuit file
          const fileContent = fs.readFileSync(filePath, "utf-8")
          const packagedCircuit = JSON.parse(fileContent)

          if (packagedCircuit.vkey_hash) {
            // Ensure the hash has the proper 0x prefix and length
            let hash = packagedCircuit.vkey_hash as string
            // Remove "0x" prefix if present
            const hashWithoutPrefix = hash.startsWith("0x") ? hash.substring(2) : hash
            // Ensure even number of characters by adding leading zero if needed
            const paddedHash =
              hashWithoutPrefix.length % 2 === 1 ? `0${hashWithoutPrefix}` : hashWithoutPrefix
            // Normalize the hash format to always have 0x prefix
            const normalizedHash = `0x${paddedHash}`

            vkeyHashes.push({
              count,
              hash: normalizedHash,
            })
            console.log(`Collected vkey hash for outer_count_${count}: ${normalizedHash}`)
          }
        }
      }
    }

    // Sort by count in ascending order
    vkeyHashes.sort((a, b) => a.count - b.count)

    return vkeyHashes
  } catch (error) {
    console.error("Error collecting vkey hashes:", error)
    return []
  }
}

const updateVkeyHashesInSolidityDeployScript = (filePath: string) => {
  // Get vkey hashes from packaged files
  const outerVkeyHashes = getOuterkeyHashes()

  if (outerVkeyHashes.length === 0) {
    console.log("No outer vkey hashes found to update in Deploy.s.sol")
    return
  }

  console.log("Updating Deploy.s.sol with vkey hashes...")

  try {
    // Read the Deploy.s.sol file
    const content = fs.readFileSync(filePath, "utf-8")

    // Find the vkeyHashes array section
    const vkeyHashesRegex = /(bytes32\[\] public vkeyHashes = \[)([\s\S]*?)(\];)/

    // Generate the new vkey hashes content
    const newVkeyHashesContent = outerVkeyHashes
      .map(
        ({ count, hash }) =>
          `    // Outer (${count} subproofs)\n    bytes32(hex"${hash
            .substring(2)
            .padStart(64, "0")}")`,
      )
      .join(",\n")

    // Replace the old vkey hashes with the new ones
    const updatedContent = content.replace(
      vkeyHashesRegex,
      (match, prefix, _, suffix) => `${prefix}\n${newVkeyHashesContent}\n  ${suffix}`,
    )

    // Write the updated file
    fs.writeFileSync(filePath, updatedContent)
    console.log(`Updated vkey hashes in ${filePath}`)
  } catch (error) {
    console.error(`Error updating ${filePath}:`, error)
  }
}

// Update Deploy.s.sol file with vkey hashes
const updateDeploySol = () => {
  updateVkeyHashesInSolidityDeployScript(DEPLOY_SOL_PATH)
}

const updateAddVerifiersSol = () => {
  updateVkeyHashesInSolidityDeployScript(ADD_VERIFIERS_SOL_PATH)
}

const updateDeployWithExistingVerifiersSol = () => {
  updateVkeyHashesInSolidityDeployScript(DEPLOY_WITH_EXISTING_VERIFIERS_SOL_PATH)
}

// Process files with controlled concurrency
const processFiles = async () => {
  let hasErrors = false

  // Split files into two groups: outer proof circuits and the other circuits
  const outerFiles = files.filter((file) => file.startsWith("outer"))
  const otherFiles = files.filter((file) => !file.startsWith("outer"))

  // Process outer proof circuits one at a time
  if (outerFiles.length > 0) {
    console.log(`Processing ${outerFiles.length} outer proof circuits sequentially...`)
    for (const file of outerFiles) {
      console.log(
        `Memory intensive processing of outer proof circuit: ${file} (no concurrent processing)`,
      )
      console.log(`Generating the standard outer proof packaged circuit...`)
      const success = await processFile(file, true, file.replace(".json", ""), true)
      if (!success) {
        hasErrors = true
      }
      /*console.log(`Generating the EVM-optimised outer proof packaged circuit...`)
      const successEvm = await processFile(
        file,
        true,
        file.replace("outer_count", "outer_evm_count").replace(".json", ""),
        true,
        // Disable the fully ZK property for outer proof circuits meant
        // to be verified onchain as the subproofs are already ZK and it's cheaper
        // to verify a non ZK proof onchain
        true,
      )
      if (!successEvm) {
        hasErrors = true
      }*/
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

  // Update Deploy.s.sol with the vkey hashes
  updateDeploySol()
  // Update AddVerifiers.s.sol with the vkey hashes
  updateAddVerifiersSol()
  // Update DeployWithExistingVerifiers.s.sol with the vkey hashes
  updateDeployWithExistingVerifiersSol()

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
    await generateCircuitManifest(packagedFiles)
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
