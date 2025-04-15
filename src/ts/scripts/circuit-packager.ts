import fs from "fs"
import path from "path"
import { exec } from "child_process"
import { promisify } from "util"
import { poseidon2Hash } from "@zkpassport/poseidon2"
import { snakeToPascal } from "../utils"

const TARGET_DIR = "target"
const PACKAGED_DIR = path.join(TARGET_DIR, "packaged")
const MAX_CONCURRENT_PROCESSES = 10

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
