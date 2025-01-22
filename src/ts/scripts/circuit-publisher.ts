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

  async publishCircuits(version: string, circuitDir: string = "target/packaged"): Promise<void> {
    const artifacts: CircuitArtifact[] = []

    // Process each circuit
    const files = await fs.readdir(circuitDir)
    for (const file of files) {
      if (!file.endsWith(".json")) continue
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

      // Upload to artifacts folder if not exists
      await this.uploadIfNotExists(filePath, json.name, hash.substring(0, 16))

      artifacts.push({
        name: json.name,
        hash,
        path: filePath,
      })
    }

    // Create version symlinks
    console.log(`Creating version ${version} symlinks...`)
    for (const artifact of artifacts) {
      await this.createVersionSymlink(version, artifact.name, artifact.hash.substring(0, 16))
      await this.createHashSymlink(artifact.hash, artifact.name)
    }

    // Invalidate CloudFront cache for the version
    console.log("Invalidating CloudFront cache...")
    await this.invalidateCache(version)

    console.log("Circuit publishing complete!")
  }
}

// CLI entrypoint
if (require.main === module) {
  let version = process.argv[2]
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
  publisher.publishCircuits(version).catch(console.error)
}
