import fs from "fs"
import path from "path"
import { exec } from "child_process"
import { promisify } from "util"
import { poseidon2Hash } from "@zkpassport/poseidon2"
import { snakeToPascal } from "../utils"
import { execSync } from "child_process"

const TARGET_DIR = "target"
const PACKAGED_DIR = path.join(TARGET_DIR, "packaged")
const MAX_CONCURRENT_PROCESSES = 10
const DEPLOY_SOL_PATH = "src/solidity/script/Deploy.s.sol"

// Promise pool for controlled concurrency
class PromisePool {
  private queue: (() => Promise<void>)[] = []
  private activePromises = 0

  constructor(private maxConcurrent: number) {}

  async add(fn: () => Promise<void>) {
    if (this.activePromises >= this.maxConcurrent) {
      // Queue the task if we're at max concurrency
      await new Promise<void>((resolve) => {
        this.queue.push(async () => {
          await fn()
          resolve()
        })
      })
    } else {
      // Execute immediately if under the concurrency limit
      this.activePromises++
      try {
        await fn()
      } finally {
        this.activePromises--
        // Process next queued task if any
        if (this.queue.length > 0) {
          const next = this.queue.shift()!
          this.add(next)
        }
      }
    }
  }
}

function checkBBVersion() {
  try {
    // Read package.json to get expected bb version
    const packageJsonPath = path.resolve(__dirname, "../../../package.json")
    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf8"))
    const expectedBBVersion = packageJson.dependencies["@aztec/bb.js"].replace(/[^0-9\.]/i, "")
    if (!expectedBBVersion) {
      throw new Error("Couldn't find bb version in package.json")
    }
    // Get installed bb version for comparison
    const installedBBVersion = execSync("bb --version").toString().trim().replace(/^v/i, "")
    if (!installedBBVersion) {
      throw new Error(`Failed to parse bb version output: ${installedBBVersion}`)
    }
    if (installedBBVersion !== expectedBBVersion) {
      throw new Error(
        `bb version mismatch. Expected ${expectedBBVersion} but found ${installedBBVersion}. Change bb version using: bbup -v ${expectedBBVersion}`,
      )
    }
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
if (!fs.existsSync(PACKAGED_DIR)) {
  fs.mkdirSync(PACKAGED_DIR, { recursive: true })
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
  recursive: boolean = true,
  evm: boolean = false,
  outputName: string = file.replace(".json", ""),
  generateSolidityVerifier: boolean = false,
): Promise<boolean> => {
  const inputPath = path.join(TARGET_DIR, file)
  const outputPath = path.join(PACKAGED_DIR, `${outputName}.json`)
  const vkeyPath = path.join(TARGET_DIR, `${outputName}.vkey.json`)
  const gateCountPath = path.join(TARGET_DIR, `${outputName}.size.json`)
  const solidityVerifierPath = path.join(
    "src/solidity/src",
    `${snakeToPascal(outputName)}.sol`.replace("Evm", ""),
  )
  try {
    // Skip if output file already exists
    if (fs.existsSync(outputPath)) {
      console.log(`Skipping ${file} - output file already exists at ${outputPath}`)
      return true
    }

    // Run bb command to get bb version and generate circuit vkey
    const bbVersion = (await execPromise("bb --version")).stdout.trim()
    console.log(`Generating vkey for ${file}...`)
    await execPromise(`mkdir -p ${vkeyPath}`)
    await execPromise(
      `bb write_vk --scheme ultra_honk ${recursive ? "--recursive --init_kzg_accumulator" : ""} ${
        evm ? "--oracle_hash keccak" : ""
      } --honk_recursion 1 --output_format bytes_and_fields -b "${inputPath}" -o "${vkeyPath}"`,
    )
    await execPromise(`bb gates --scheme ultra_honk -b "${inputPath}" > "${gateCountPath}"`)
    if (generateSolidityVerifier) {
      await execPromise(
        `bb write_solidity_verifier --scheme ultra_honk -k "${vkeyPath}/vk" -o "${solidityVerifierPath}"`,
      )
    }

    // Get Poseidon2 hash of vkey
    const vkeyAsFieldsJson = JSON.parse(fs.readFileSync(`${vkeyPath}/vk_fields.json`, "utf-8"))
    const vkeyAsFields = vkeyAsFieldsJson.map((v: any) => BigInt(v))
    const vkeyHash = `0x${poseidon2Hash(vkeyAsFields).toString(16)}`
    const vkey = Buffer.from(fs.readFileSync(`${vkeyPath}/vk`)).toString("base64")
    // Clean up vkey files
    await execPromise(`rm -rf ${vkeyPath}`)

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

// Get all outer EVM vkey hashes from packaged circuit files
const getOuterEvmVkeyHashes = (): { count: number; hash: string }[] => {
  console.log("Collecting vkey hashes from packaged circuit files...")
  const vkeyHashes: { count: number; hash: string }[] = []

  try {
    // Get all packaged JSON files
    const packagedFiles = fs.readdirSync(PACKAGED_DIR).filter((file) => file.endsWith(".json"))

    // Filter for outer_evm_count files and extract their vkey hashes
    for (const file of packagedFiles) {
      if (file.startsWith("outer_evm_count_")) {
        const countMatch = file.match(/outer_evm_count_(\d+)\.json/)
        if (countMatch && countMatch[1]) {
          const count = parseInt(countMatch[1])
          const filePath = path.join(PACKAGED_DIR, file)

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
            console.log(`Collected vkey hash for outer_evm_count_${count}: ${normalizedHash}`)
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

// Update Deploy.s.sol file with vkey hashes
const updateDeploySol = () => {
  // Get vkey hashes from packaged files
  const outerEvmVkeyHashes = getOuterEvmVkeyHashes()

  if (outerEvmVkeyHashes.length === 0) {
    console.log("No outer EVM vkey hashes found to update in Deploy.s.sol")
    return
  }

  console.log("Updating Deploy.s.sol with vkey hashes...")

  try {
    // Read the Deploy.s.sol file
    const deploySolContent = fs.readFileSync(DEPLOY_SOL_PATH, "utf-8")

    // Find the vkeyHashes array section
    const vkeyHashesRegex = /(bytes32\[\] public vkeyHashes = \[)([\s\S]*?)(\];)/

    // Generate the new vkey hashes content
    const newVkeyHashesContent = outerEvmVkeyHashes
      .map(
        ({ count, hash }) =>
          `        // Outer (${count} subproofs)\n        bytes32(hex"${hash
            .substring(2)
            .padStart(64, "0")}")`,
      )
      .join(",\n")

    // Replace the old vkey hashes with the new ones
    const updatedContent = deploySolContent.replace(
      vkeyHashesRegex,
      (match, prefix, _, suffix) => `${prefix}\n${newVkeyHashesContent}\n${suffix}`,
    )

    // Write the updated file
    fs.writeFileSync(DEPLOY_SOL_PATH, updatedContent)
    console.log(`Updated vkey hashes in ${DEPLOY_SOL_PATH}`)
  } catch (error) {
    console.error("Error updating Deploy.s.sol:", error)
  }
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
      const success = await processFile(file)
      if (!success) {
        hasErrors = true
      }
      console.log(`Generating the EVM-optimised outer proof packaged circuit...`)
      const successEvm = await processFile(
        file,
        false,
        true,
        file.replace("outer_count", "outer_evm_count").replace(".json", ""),
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
    const promises: Promise<void>[] = []

    for (const file of otherFiles) {
      const promise = pool.add(async () => {
        const success = await processFile(file)
        if (!success) {
          hasErrors = true
        }
      })
      promises.push(promise)
    }

    // Wait for all other files to be processed
    await Promise.all(promises)
  }

  // Update Deploy.s.sol with the vkey hashes
  updateDeploySol()

  // Exit with error code if any file failed to process
  if (hasErrors) {
    process.exit(1)
  }
}

// Start timing
const startTime = Date.now()

// Run the async process
processFiles()
  .catch((error) => {
    console.error("Fatal error:", error)
    process.exit(1)
  })
  .finally(() => {
    const duration = (Date.now() - startTime) / 1000 // convert to seconds
    const minutes = Math.floor(duration / 60)
    const seconds = Math.floor(duration % 60)

    if (minutes > 0) {
      console.log(`Total time taken: ${minutes}m ${seconds}s`)
    } else if (seconds > 0) {
      console.log(`Total time taken: ${seconds}s`)
    }
  })
