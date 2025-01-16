import fs from "fs"
import path from "path"
import { exec } from "child_process"
import { promisify } from "util"

const TARGET_DIR = "target"
const PACKAGED_DIR = path.join(TARGET_DIR, "packaged")
const KEEP_KEYS = ["noir_version", "abi", "bytecode"]
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
const files = fs.readdirSync(TARGET_DIR).filter((file) => file.endsWith(".json"))

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
    const vkeyPath = path.join(TARGET_DIR, file.replace(".json", ".vkey"))

    const promise = pool.add(async () => {
      try {
        // Skip if output file already exists
        if (fs.existsSync(outputPath)) {
          console.log(`Skipping ${file} - output file already exists at ${outputPath}`)
          return
        }

        // Run bb command to generate vkey file
        console.log(`Generating vkey for ${file}...`)
        await execPromise(
          `bb write_vk_ultra_honk -v -b "${inputPath}" -o "${vkeyPath}" --recursive`,
        )

        // Read and parse the input file
        const jsonContent = JSON.parse(fs.readFileSync(inputPath, "utf-8"))

        // Create new object with only keys we're keeping
        const filteredContent = Object.fromEntries(
          Object.entries(jsonContent).filter(([key]) => KEEP_KEYS.includes(key)),
        )

        // Read vkey file as binary and convert to base64
        const vkeyData = fs.readFileSync(vkeyPath)
        filteredContent.vkey = Buffer.from(vkeyData).toString("base64")

        // Write the filtered content to the output file
        fs.writeFileSync(outputPath, JSON.stringify(filteredContent, null, 2))
        console.log(`Successfully processed ${inputPath} -> ${outputPath}`)

        // Clean up vkey file
        fs.unlinkSync(vkeyPath)
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
