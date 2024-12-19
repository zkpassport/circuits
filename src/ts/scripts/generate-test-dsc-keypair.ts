import forge from "node-forge"
import * as path from "path"
import { saveDscKeypairToFile } from "../lib/passport-reader/passport-generator"

// Generate a new DSC keypair
console.log("Generating DSC keypair...")
const dscKeys = forge.pki.rsa.generateKeyPair({ bits: 2048 })

// Save to fixtures directory
const fixturesDir = path.join(__dirname, "../../../fixtures")
const keypairPath = path.join(fixturesDir, "test-dsc-keypair.json")
saveDscKeypairToFile(dscKeys, keypairPath)
console.log(`DSC keypair saved to ${keypairPath}`)
