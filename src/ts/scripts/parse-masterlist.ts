import { parseCertificates } from "@/lib/csc-manager"
import { CSC } from "@/types"
import fs from "fs"
import path from "path"

interface DuplicateStats {
  totalCertificates: number
  duplicatesFound: number
  uniqueCertificates: number
}

function processCertificateFile(
  filePath: string,
  allCertificates: CSC[],
  uniquePubkeys: Set<string>,
): DuplicateStats {
  const stats: DuplicateStats = {
    totalCertificates: 0,
    duplicatesFound: 0,
    uniqueCertificates: 0,
  }

  try {
    const pemContent = fs.readFileSync(filePath, "utf8")
    const certificates = parseCertificates(pemContent)
    stats.totalCertificates = certificates.length

    console.log(`Processing ${certificates.length} certificates from ${filePath}`)

    for (const cert of certificates) {
      const pubkeyString = JSON.stringify(cert.public_key)
      if (!uniquePubkeys.has(pubkeyString)) {
        uniquePubkeys.add(pubkeyString)
        stats.uniqueCertificates++
      } else {
        stats.duplicatesFound++
      }
      allCertificates.push(cert)
    }
  } catch (error) {
    console.error(`Error processing certificate file ${filePath}:`, error)
  }

  return stats
}

function main(): void {
  const args = process.argv.slice(2)
  const uniquePubkeys = new Set<string>()
  const allCertificates: CSC[] = []
  let totalStats: DuplicateStats = {
    totalCertificates: 0,
    duplicatesFound: 0,
    uniqueCertificates: 0,
  }

  if (args.length !== 1) {
    console.log(`Usage: ${process.argv[1]} <path_to_certificate_or_directory>`)
    return
  }

  const inputPath = args[0]
  const stats = fs.statSync(inputPath)

  if (stats.isDirectory()) {
    fs.readdirSync(inputPath)
      .filter((file) => path.extname(file) === ".cer")
      .forEach((file) => {
        const fileStats = processCertificateFile(
          path.join(inputPath, file),
          allCertificates,
          uniquePubkeys,
        )
        totalStats.totalCertificates += fileStats.totalCertificates
        totalStats.duplicatesFound += fileStats.duplicatesFound
        totalStats.uniqueCertificates += fileStats.uniqueCertificates
      })
  } else if (stats.isFile()) {
    totalStats = processCertificateFile(inputPath, allCertificates, uniquePubkeys)
  } else {
    console.log(`Error: ${inputPath} is neither a valid file nor directory`)
    return
  }

  // Sort certificates by country
  allCertificates.sort((a, b) => a.country.localeCompare(b.country))

  const output = {
    certificates: allCertificates,
  }

  fs.writeFileSync("csc-masterlist-foo.json", JSON.stringify(output, null, 2))

  console.log("\nProcessing Summary:")
  console.log(`Total certificates processed: ${totalStats.totalCertificates}`)
  console.log(`Unique public keys: ${totalStats.uniqueCertificates}`)
  console.log(`Duplicate keys detected: ${totalStats.duplicatesFound}`)
  console.log("\nResults have been written to csc-masterlist.json")
}

main()
