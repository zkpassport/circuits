import * as fs from "fs/promises"
import * as path from "path"
import { performance } from "perf_hooks"
import { Circuit } from "../circuits"
import { TestHelper } from "../test-helper"
import { Binary } from "@zkpassport/utils"
import { InputMap } from "@noir-lang/noir_js"

interface BenchmarkResult {
  iteration: number
  witnessGenerationTime: number
  proofGenerationTime: number
  totalTime: number
  memoryUsed?: number
}

interface BenchmarkOptions {
  iterations: number
  tbsSize: number
  useCli: boolean
  warmup: boolean
  outputFormat: "json" | "csv" | "console"
  outputFile?: string
}

class ECDSABenchmark {
  private circuit!: Circuit
  private testHelper: TestHelper
  private inputs!: InputMap
  private options: BenchmarkOptions
  private results: BenchmarkResult[] = []

  constructor(options: Partial<BenchmarkOptions> = {}) {
    this.testHelper = new TestHelper()
    this.options = {
      iterations: 10,
      tbsSize: 1500,
      useCli: false,
      warmup: true,
      outputFormat: "console",
      ...options,
    }
  }

  async setup() {
    console.log("🔧 Setting up benchmark...")
    
    // Load circuit
    const circuitName = `sig_check_id_data_tbs_${this.options.tbsSize}_ecdsa_nist_p256_sha256`
    console.log(`  Loading circuit: ${circuitName}`)
    this.circuit = Circuit.from(circuitName)
    
    // Load US passport test data
    const testDataDir = path.join(__dirname, "..", "tests", "fixtures", "us-passport")
    console.log(`  Loading test data from: ${testDataDir}`)
    
    const dg1 = Binary.from(await fs.readFile(path.join(testDataDir, "john-doe-dg1.bin")))
    const sod = Binary.from(await fs.readFile(path.join(testDataDir, "john-doe-us-passport-ecdsa-p256-sha256.sod")))
    
    // Load CSCA certificates (needed for DSC verification)
    const cscaCertsPath = path.join(__dirname, "..", "tests", "fixtures", "csca-packaged-certs.json")
    const cscaCerts = JSON.parse(await fs.readFile(cscaCertsPath, "utf-8"))
    this.testHelper.setCertificates(cscaCerts)
    
    // Load passport data
    await this.testHelper.loadPassport(dg1, sod)
    
    // Generate circuit inputs
    console.log("  Generating circuit inputs...")
    this.inputs = await this.testHelper.generateCircuitInputs("id")
    
    // Initialize circuit
    await this.circuit.init(false)
    
    console.log("✅ Setup complete\n")
  }

  async warmup() {
    if (!this.options.warmup) return
    
    console.log("🔥 Running warmup...")
    try {
      await this.circuit.prove(this.inputs, {
        useCli: this.options.useCli,
        circuitName: `sig_check_id_data_tbs_${this.options.tbsSize}_ecdsa_nist_p256_sha256`,
      })
      console.log("✅ Warmup complete\n")
    } catch (error) {
      console.error("❌ Warmup failed:", error)
    }
  }

  async runBenchmark() {
    console.log(`🏃 Running ${this.options.iterations} iterations...`)
    console.log(`  Method: ${this.options.useCli ? "CLI (bb binary)" : "In-process (bb.js)"}\n`)
    
    for (let i = 0; i < this.options.iterations; i++) {
      console.log(`  Iteration ${i + 1}/${this.options.iterations}`)
      
      const result = await this.runSingleIteration(i + 1)
      this.results.push(result)
      
      console.log(`    Witness: ${result.witnessGenerationTime.toFixed(2)}ms`)
      console.log(`    Proof:   ${result.proofGenerationTime.toFixed(2)}ms`)
      console.log(`    Total:   ${result.totalTime.toFixed(2)}ms`)
      
      if (result.memoryUsed) {
        console.log(`    Memory:  ${(result.memoryUsed / 1024 / 1024).toFixed(2)}MB`)
      }
      console.log()
    }
  }

  private async runSingleIteration(iteration: number): Promise<BenchmarkResult> {
    const startTotal = performance.now()
    const initialMemory = process.memoryUsage().heapUsed
    
    // Measure witness generation
    const startWitness = performance.now()
    const witness = await this.circuit.solve(this.inputs)
    const witnessTime = performance.now() - startWitness
    
    // Measure proof generation
    const startProof = performance.now()
    await this.circuit.prove(this.inputs, {
      witness,
      useCli: this.options.useCli,
      circuitName: `sig_check_id_data_tbs_${this.options.tbsSize}_ecdsa_nist_p256_sha256`,
    })
    const proofTime = performance.now() - startProof
    
    const totalTime = performance.now() - startTotal
    const memoryUsed = process.memoryUsage().heapUsed - initialMemory
    
    return {
      iteration,
      witnessGenerationTime: witnessTime,
      proofGenerationTime: proofTime,
      totalTime,
      memoryUsed: memoryUsed > 0 ? memoryUsed : undefined,
    }
  }

  async analyze() {
    if (this.results.length === 0) return
    
    const witnesssTimes = this.results.map(r => r.witnessGenerationTime)
    const proofTimes = this.results.map(r => r.proofGenerationTime)
    const totalTimes = this.results.map(r => r.totalTime)
    
    const stats = {
      iterations: this.results.length,
      witness: {
        avg: this.average(witnesssTimes),
        min: Math.min(...witnesssTimes),
        max: Math.max(...witnesssTimes),
        stdDev: this.standardDeviation(witnesssTimes),
      },
      proof: {
        avg: this.average(proofTimes),
        min: Math.min(...proofTimes),
        max: Math.max(...proofTimes),
        stdDev: this.standardDeviation(proofTimes),
      },
      total: {
        avg: this.average(totalTimes),
        min: Math.min(...totalTimes),
        max: Math.max(...totalTimes),
        stdDev: this.standardDeviation(totalTimes),
      },
    }
    
    console.log("\n📊 Benchmark Results")
    console.log("═══════════════════")
    console.log(`Circuit: sig_check_id_data_tbs_${this.options.tbsSize}_ecdsa_nist_p256_sha256`)
    console.log(`Method: ${this.options.useCli ? "CLI (bb binary)" : "In-process (bb.js)"}`)
    console.log(`Iterations: ${stats.iterations}`)
    console.log()
    console.log("Witness Generation:")
    console.log(`  Average: ${stats.witness.avg.toFixed(2)}ms`)
    console.log(`  Min:     ${stats.witness.min.toFixed(2)}ms`)
    console.log(`  Max:     ${stats.witness.max.toFixed(2)}ms`)
    console.log(`  StdDev:  ${stats.witness.stdDev.toFixed(2)}ms`)
    console.log()
    console.log("Proof Generation:")
    console.log(`  Average: ${stats.proof.avg.toFixed(2)}ms`)
    console.log(`  Min:     ${stats.proof.min.toFixed(2)}ms`)
    console.log(`  Max:     ${stats.proof.max.toFixed(2)}ms`)
    console.log(`  StdDev:  ${stats.proof.stdDev.toFixed(2)}ms`)
    console.log()
    console.log("Total Time:")
    console.log(`  Average: ${stats.total.avg.toFixed(2)}ms`)
    console.log(`  Min:     ${stats.total.min.toFixed(2)}ms`)
    console.log(`  Max:     ${stats.total.max.toFixed(2)}ms`)
    console.log(`  StdDev:  ${stats.total.stdDev.toFixed(2)}ms`)
    
    await this.saveResults(stats)
  }

  private async saveResults(stats: any) {
    if (this.options.outputFormat === "console") return
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-")
    const filename = this.options.outputFile || 
      `ecdsa-p256-benchmark-${timestamp}.${this.options.outputFormat}`
    
    if (this.options.outputFormat === "json") {
      const data = {
        metadata: {
          circuit: `sig_check_id_data_tbs_${this.options.tbsSize}_ecdsa_nist_p256_sha256`,
          signatureAlgorithm: "ECDSA",
          curve: "P-256 (secp256r1)",
          hashAlgorithm: "SHA-256",
          method: this.options.useCli ? "CLI" : "In-process",
          iterations: this.options.iterations,
          timestamp: new Date().toISOString(),
        },
        summary: stats,
        details: this.results,
      }
      await fs.writeFile(filename, JSON.stringify(data, null, 2))
    } else if (this.options.outputFormat === "csv") {
      const headers = "iteration,witness_ms,proof_ms,total_ms,memory_bytes\n"
      const rows = this.results.map(r => 
        `${r.iteration},${r.witnessGenerationTime},${r.proofGenerationTime},${r.totalTime},${r.memoryUsed || ""}`
      ).join("\n")
      await fs.writeFile(filename, headers + rows)
    }
    
    console.log(`\n💾 Results saved to: ${filename}`)
  }

  async cleanup() {
    await this.circuit.destroy()
  }

  private average(numbers: number[]): number {
    return numbers.reduce((a, b) => a + b, 0) / numbers.length
  }

  private standardDeviation(numbers: number[]): number {
    const avg = this.average(numbers)
    const squaredDiffs = numbers.map(n => Math.pow(n - avg, 2))
    return Math.sqrt(this.average(squaredDiffs))
  }
}

// CLI interface
async function main() {
  const args = process.argv.slice(2)
  const options: Partial<BenchmarkOptions> = {}
  
  // Parse command line arguments
  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case "--iterations":
      case "-i":
        options.iterations = parseInt(args[++i])
        break
      case "--tbs-size":
      case "-t":
        options.tbsSize = parseInt(args[++i])
        break
      case "--cli":
        options.useCli = true
        break
      case "--no-warmup":
        options.warmup = false
        break
      case "--format":
      case "-f":
        options.outputFormat = args[++i] as "json" | "csv" | "console"
        break
      case "--output":
      case "-o":
        options.outputFile = args[++i]
        break
      case "--help":
      case "-h":
        console.log(`
ECDSA P-256 + SHA-256 Benchmark Tool

Usage: tsx benchmark-ecdsa-p256.ts [options]

Options:
  -i, --iterations <n>    Number of iterations (default: 10)
  -t, --tbs-size <n>      TBS certificate size (default: 1500)
  --cli                   Use CLI mode (bb binary) instead of in-process
  --no-warmup             Skip warmup iteration
  -f, --format <format>   Output format: json|csv|console (default: console)
  -o, --output <file>     Output filename (auto-generated if not specified)
  -h, --help              Show this help message

Examples:
  tsx benchmark-ecdsa-p256.ts
  tsx benchmark-ecdsa-p256.ts -i 20 --cli
  tsx benchmark-ecdsa-p256.ts -i 100 -f json -o results.json
        `)
        process.exit(0)
    }
  }
  
  const benchmark = new ECDSABenchmark(options)
  
  try {
    await benchmark.setup()
    await benchmark.warmup()
    await benchmark.runBenchmark()
    await benchmark.analyze()
    await benchmark.cleanup()
  } catch (error) {
    console.error("\n❌ Benchmark failed:", error)
    process.exit(1)
  }
}

// Run if called directly
if (require.main === module) {
  main()
}