import { CloudFrontClient, CreateInvalidationCommand } from "@aws-sdk/client-cloudfront"
import { HeadObjectCommand, PutObjectCommand, S3Client } from "@aws-sdk/client-s3"
import * as fsSync from "fs"
import * as fs from "fs/promises"
import * as path from "path"
import { promisify } from "util"
import { gzip } from "zlib"

const gzipAsync = promisify(gzip)
interface CircuitArtifact {
  name: string
  hash: string
  path: string
}

// Promise pool for controlled concurrency
class PromisePool {
  private queue: (() => Promise<void>)[] = []
  private activePromises = 0

  constructor(private concurrency: number) {}

  async add(fn: () => Promise<void>) {
    if (this.activePromises >= this.concurrency) {
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

class CircuitPublisher {
  private s3: S3Client
  private cloudfront: CloudFrontClient
  private bucket: string
  private distributionId: string

  constructor(bucket: string, distributionId: string, region: string = "us-east-1") {
    this.s3 = new S3Client({ region })
    this.cloudfront = new CloudFrontClient({ region })
    this.bucket = bucket
    this.distributionId = distributionId
  }

  private async uploadIfNotExists(
    filePath: string,
    circuitName: string,
    hash: string,
  ): Promise<void> {
    const artifactKey = `artifacts/${circuitName}_${hash}.json.gz`
    try {
      // Check if this circuit has been uploaded already
      await this.s3.send(
        new HeadObjectCommand({
          Bucket: this.bucket,
          Key: artifactKey,
        }),
      )
      console.log(`Artifact ${circuitName}_${hash} already exists, skipping`)
    } catch {
      // Upload new circuit
      const content = await fs.readFile(filePath)
      const gzippedContent = await gzipAsync(content)
      await this.s3.send(
        new PutObjectCommand({
          Bucket: this.bucket,
          Key: artifactKey,
          Body: gzippedContent,
          ContentType: "application/json",
          ContentEncoding: "gzip",
        }),
      )
      console.log(`Uploaded ${path.basename(filePath)} to artifacts/${circuitName}_${hash}.json.gz`)
    }
  }

  private async createVersionSymlink(
    version: string,
    circuitName: string,
    hash: string,
  ): Promise<void> {
    const versionKey = `versions/${version}/${circuitName}.json.gz`
    await this.s3.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: versionKey,
        WebsiteRedirectLocation: `/artifacts/${circuitName}_${hash}.json.gz`,
        Body: Buffer.from(""),
        ContentType: "application/json",
        ContentEncoding: "gzip",
      }),
    )
    console.log(
      `Created version redirect ${versionKey} -> artifacts/${circuitName}_${hash}.json.gz`,
    )
  }

  private async createHashSymlink(hash: string, circuitName: string): Promise<void> {
    const hashKey = `hashes/${hash}.json.gz`
    await this.s3.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: hashKey,
        WebsiteRedirectLocation: `/artifacts/${circuitName}_${hash}.json.gz`,
        Body: Buffer.from(""),
        ContentType: "application/json",
        ContentEncoding: "gzip",
      }),
    )
  }

  private async invalidateCache(version: string): Promise<void> {
    await this.cloudfront.send(
      new CreateInvalidationCommand({
        DistributionId: this.distributionId,
        InvalidationBatch: {
          CallerReference: `publish-${version}-${Date.now()}`,
          Paths: {
            Quantity: 1,
            Items: [`/versions/${version}/*`],
          },
        },
      }),
    )
  }

  async publishCircuits(
    version: string,
    circuitDir: string = "target/packaged",
    concurrency: number = 10,
  ): Promise<void> {
    const startTime = Date.now()
    const artifacts: CircuitArtifact[] = []

    if (concurrency !== 10) {
      console.log(`Using concurrency: ${concurrency}`)
    }

    // Process each circuit
    const files = await fs.readdir(circuitDir)
    const jsonFiles = files.filter((file) => file.endsWith(".json"))
    console.log(`Found ${jsonFiles.length} JSON files to process`)

    // First, read and prepare all files
    for (const file of jsonFiles) {
      const fileName = path.basename(file)
      console.log(`Processing ${fileName}`)
      const filePath = path.join(circuitDir, file)
      const content = await fs.readFile(filePath, "utf8")
      const json = JSON.parse(content)
      if (!json.vkey_hash) {
        throw new Error(`No vkey_hash found in ${filePath}`)
      }
      const hash = json.vkey_hash.replace("0x", "")
      if (!json.name) {
        throw new Error(`No name found in ${filePath}`)
      }

      artifacts.push({
        name: json.name,
        hash,
        path: filePath,
      })
    }

    // Create promise pool for concurrent uploads
    const pool = new PromisePool(concurrency)
    const uploadPromises: Promise<void>[] = []

    // Upload artifacts concurrently with controlled concurrency
    console.log(`Uploading artifacts with concurrency ${concurrency}...`)
    let processedCount = 0
    const totalCount = artifacts.length

    for (const artifact of artifacts) {
      const currentCount = ++processedCount
      const shortHash = artifact.hash.substring(0, 16)

      uploadPromises.push(
        pool.add(async () => {
          try {
            console.log(`Uploading artifact ${artifact.name} (${currentCount}/${totalCount})...`)
            await this.uploadIfNotExists(artifact.path, artifact.name, shortHash)
          } catch (error) {
            console.error(`Error uploading ${artifact.name}: ${error}`)
          }
        }),
      )
    }

    // Wait for all uploads to complete
    await Promise.all(uploadPromises)

    // Create version symlinks
    console.log(`Creating version ${version} symlinks...`)
    const symlinkPromises: Promise<void>[] = []

    // Reset for symlink creation
    processedCount = 0

    for (const artifact of artifacts) {
      const currentCount = ++processedCount
      const shortHash = artifact.hash.substring(0, 16)

      symlinkPromises.push(
        pool.add(async () => {
          try {
            console.log(`Creating symlinks for ${artifact.name} (${currentCount}/${totalCount})...`)
            await this.createVersionSymlink(version, artifact.name, shortHash)
            await this.createHashSymlink(artifact.hash, artifact.name)
          } catch (error) {
            console.error(`Error creating symlinks for ${artifact.name}: ${error}`)
          }
        }),
      )
    }

    // Wait for all symlink creations to complete
    await Promise.all(symlinkPromises)

    // Invalidate CloudFront cache for the version
    console.log("Invalidating CloudFront cache...")
    await this.invalidateCache(version)

    const duration = (Date.now() - startTime) / 1000 // convert to seconds
    const minutes = Math.floor(duration / 60)
    const seconds = Math.floor(duration % 60)

    if (minutes > 0) {
      console.log(`Total time taken: ${minutes}m ${seconds}s`)
    } else if (seconds > 0) {
      console.log(`Total time taken: ${seconds}s`)
    }

    console.log("Circuit publishing complete!")
  }
}

// Default concurrency value
const DEFAULT_CONCURRENCY = 10

// CLI entrypoint
if (require.main === module) {
  // Parse arguments
  const args = process.argv.slice(2)

  // Extract version if provided
  let versionArg = args.find((arg) => !arg.startsWith("--"))
  let version = versionArg

  // Parse --concurrency argument if provided
  let concurrency = DEFAULT_CONCURRENCY
  const concurrencyArg = args.find((arg) => arg.startsWith("--concurrency="))
  if (concurrencyArg) {
    const value = concurrencyArg.split("=")[1]
    const parsed = parseInt(value, 10)
    if (!isNaN(parsed) && parsed > 0) {
      concurrency = parsed
    } else {
      console.warn(`Invalid --concurrency value. Using default: ${DEFAULT_CONCURRENCY}`)
    }
  }

  // If no version provided as a direct argument, try package.json
  if (!version) {
    // Use version from package.json if not provided as argument
    const packageJson = JSON.parse(fsSync.readFileSync("package.json", "utf-8"))
    version = packageJson.version
    if (!version) {
      console.error("No version provided and no version found in package.json")
      process.exit(1)
    }
    console.log(`Using version from package.json: ${version}`)
  }

  if (!process.env.AWS_ACCESS_KEY_ID || !process.env.AWS_SECRET_ACCESS_KEY) {
    console.error("Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables")
    process.exit(1)
  }
  if (
    !process.env.CIRCUIT_BUCKET ||
    !process.env.CLOUDFRONT_DISTRIBUTION_ID ||
    !process.env.AWS_REGION
  ) {
    console.error(
      "Please set CIRCUIT_BUCKET, CLOUDFRONT_DISTRIBUTION_ID, AWS_REGION environment variables",
    )
    process.exit(1)
  }

  const bucket = process.env.CIRCUIT_BUCKET
  const distributionId = process.env.CLOUDFRONT_DISTRIBUTION_ID
  const region = process.env.AWS_REGION

  const publisher = new CircuitPublisher(bucket, distributionId, region)
  publisher.publishCircuits(version, "target/packaged", concurrency).catch(console.error)
}
