import fs from "fs"
import path from "path"
import { exec } from "child_process"
import { promisify } from "util"
import { poseidon2Hash } from "@zkpassport/poseidon2"

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

// Process files with controlled concurrency
const processFiles = async () => {
  const pool = new PromisePool(MAX_CONCURRENT_PROCESSES)
  const promises: Promise<void>[] = []
  let hasErrors = false

  for (const file of files) {
    const inputPath = path.join(TARGET_DIR, file)
    const outputPath = path.join(PACKAGED_DIR, file)
    const vkeyPath = path.join(TARGET_DIR, file.replace(".json", ""))
    const gateCountPath = path.join(TARGET_DIR, file.replace(".json", ".size.json"))

    const promise = pool.add(async () => {
      try {
        // Skip if output file already exists
        if (fs.existsSync(outputPath)) {
          console.log(`Skipping ${file} - output file already exists at ${outputPath}`)
          return
        }

        // Run bb command to get bb version and generate circuit vkey
        const bbVersion = (await execPromise("bb --version")).stdout.trim()
        console.log(`Generating vkey for ${file}...`)
        await execPromise(`mkdir -p ${vkeyPath}`)
        await execPromise(
          `bb write_vk --scheme ultra_honk --recursive --honk_recursion 1 --init_kzg_accumulator --output_format bytes_and_fields -b "${inputPath}" -o "${vkeyPath}"`,
        )
        await execPromise(`bb gates --scheme ultra_honk -b "${inputPath}" > "${gateCountPath}"`)

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
          name: file.replace(".json", ""),
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
      } catch (error: any) {
        if (error?.status !== undefined && error.status !== 0) {
          console.error(
            `Error processing file ${inputPath}: Command failed with exit code ${error.status}`,
          )
        } else {
          console.error("Error processing file " + inputPath, error)
        }
        hasErrors = true
      }
    })
    promises.push(promise)
  }

  // Wait for all files to be processed
  await Promise.all(promises)

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
