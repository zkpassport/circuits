import * as path from "path"
import { generateRsaKeyPair, generateEcdsaKeyPair, saveKeypairToFile } from "../passport-generator"

// Generate a new DSC keypair
console.log("Generating DSC keypair...")
const rsaDscKeys = await generateRsaKeyPair(2048)
const ecdsaDscKeys = await generateEcdsaKeyPair("P-256")

// Save to fixtures directory
const fixturesDir = path.join(__dirname, "../tests/fixtures")
const rsaKeypairPath = path.join(fixturesDir, "dsc-keypair-rsa.json")
const ecdsaKeypairPath = path.join(fixturesDir, "dsc-keypair-ecdsa.json")
saveKeypairToFile(rsaDscKeys, rsaKeypairPath)
saveKeypairToFile(ecdsaDscKeys, ecdsaKeypairPath)
console.log(`DSC keypair saved to ${rsaKeypairPath}`)
console.log(`DSC keypair saved to ${ecdsaKeypairPath}`)
