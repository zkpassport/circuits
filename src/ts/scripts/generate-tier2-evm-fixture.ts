/**
 * Generates a Tier 2 outer EVM proof over a synthetic iOS attestation, for the on-chain
 * verification test in zkpassport-packages' registry-contracts:
 *
 *   attested_id_ios_evm + disclose_bytes_evm → outer_attested_id_count_2 (EVM, no ZK)
 *
 * Writes proof.hex, public_inputs.json, committed_inputs.hex and attestation.json, and the
 * outer circuit's Solidity verifier, to the directory given as the first argument. Needs
 * attested_id_ios_evm, disclose_bytes_evm and outer_attested_id_count_2 compiled into target/.
 *
 *   npx tsx src/ts/scripts/generate-tier2-evm-fixture.ts <out dir>
 */
import { exec } from "child_process"
import * as fs from "fs"
import * as os from "os"
import * as path from "path"
import { promisify } from "util"
import { poseidon2HashAsync } from "@zkpassport/poseidon2"
import {
  calculateCircuitRoot,
  getCircuitMerkleProof,
  getDisclosedBytesFromMrzAndMask,
  getScopeHash,
  getServiceScopeHash,
  OPRF_ZERO_PROOF,
  packLeBytesAndHashPoseidon2,
  SaltedValue,
} from "@zkpassport/utils"
import { sha256 } from "@noble/hashes/sha2.js"
import { Circuit } from "../circuits"
import {
  buildIosAttestedIdInputs,
  calculateAttestedIdCommitment,
  getExpiryDate,
  padDg1,
} from "../tests/attested-id"

const execAsync = promisify(exec)

const DOMAIN = "zkpassport.id"
const SCOPE = "tier2"
const SALTS = { dg1Salt: 11n, expiryDateSalt: 12n, dg2HashSalt: 13n, privateNullifierSalt: 14n }
const DG1 = Buffer.concat([
  Buffer.from("615B5F1F58", "hex"),
  Buffer.from(
    "P<FRADOE<<JANE<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<X12345678<FRA9002016F3004035<<<<<<<<<<<<<<04",
  ),
])
const PORTRAIT_HASH = sha256(new TextEncoder().encode("portrait"))
const ATTESTATION_KEY_TYPE_APPLE = 1
const PROOF_TYPE_ATTESTED_ID = 11
const PROOF_TYPE_DISCLOSE = 0

type Subproof = { proof: string[]; publicInputs: string[]; vkey: string[]; vkeyHash: string }

const hex = (value: bigint | number, bytes: number) => value.toString(16).padStart(bytes * 2, "0")

async function recursiveProof(name: string, inputs: any): Promise<Subproof> {
  const circuit = Circuit.from(name)
  const proof = await circuit.prove(inputs, {
    witness: await circuit.solve(inputs, true),
    useCli: true,
    circuitName: name,
    recursive: true,
  })
  const vkey = (await circuit.getVerificationKey({ evm: false })).vkeyFields
  const vkeyHash = `0x${(await poseidon2HashAsync(vkey.map((x) => BigInt(x)))).toString(16)}`
  await circuit.destroy()
  return { proof: proof.proof, publicInputs: proof.publicInputs, vkey, vkeyHash }
}

async function main() {
  const outDir = process.argv[2]
  if (!outDir) throw new Error("Usage: generate-tier2-evm-fixture.ts <out dir>")
  fs.mkdirSync(outDir, { recursive: true })
  const now = Math.floor(Date.now() / 1000)
  const dg1 = new Uint8Array(DG1)

  const attestation = await buildIosAttestedIdInputs({
    dg1,
    portraitHash: PORTRAIT_HASH,
    salts: SALTS,
  })
  const attested = await recursiveProof("attested_id_ios_evm", attestation.inputs)

  const expected = await calculateAttestedIdCommitment(SALTS, dg1, PORTRAIT_HASH)
  const discloseMask = Array(90).fill(1)
  const disclose = await recursiveProof("disclose_bytes_evm", {
    comm_in: attested.publicInputs[1],
    current_date: now,
    salted_private_nullifier: SaltedValue.fromValue(
      SALTS.privateNullifierSalt,
      expected.privateNullifier,
    ).formatForInput(),
    salted_expiry_date: SaltedValue.fromValue(SALTS.expiryDateSalt, getExpiryDate(dg1)).formatForInput(),
    salted_dg1: SaltedValue.fromValue(SALTS.dg1Salt, Array.from(padDg1(dg1))).formatForInput(),
    salted_dg2_hash: SaltedValue.fromValue(
      SALTS.dg2HashSalt,
      expected.dg2HashNormalized,
    ).formatForInput(),
    salted_dg2_hash_type: SaltedValue.fromValue(SALTS.dg2HashSalt, 3n).formatForInput(),
    disclose_mask: discloseMask,
    nullifier_secret: "0x0",
    oprf_proof: OPRF_ZERO_PROOF,
    service_scope: `0x${getServiceScopeHash(DOMAIN).toString(16)}`,
    service_subscope: `0x${getScopeHash(SCOPE).toString(16)}`,
  })

  const circuitManifest = {
    version: "0.23.0",
    root: await calculateCircuitRoot({ hashes: [attested.vkeyHash, disclose.vkeyHash] }),
    circuits: {
      attested: { hash: attested.vkeyHash, size: 1 },
      disclose: { hash: disclose.vkeyHash, size: 1 },
    },
  } as any
  const leaf = async (subproof: Subproof, publicInputs: string[]) => {
    const { path: treePath, index } = await getCircuitMerkleProof(subproof.vkeyHash, circuitManifest)
    return {
      vkey: subproof.vkey,
      proof: subproof.proof,
      public_inputs: publicInputs,
      key_hash: subproof.vkeyHash,
      tree_hash_path: treePath,
      tree_index: index.toString(),
    }
  }
  const d = disclose.publicInputs
  const outerInputs = {
    certificate_registry_root: "0x1",
    circuit_registry_root: circuitManifest.root,
    current_date: now,
    service_scope: d[2],
    service_subscope: d[3],
    param_commitments: [attested.publicInputs[2], d[4]],
    nullifier_type: d[5],
    scoped_nullifier: d[6],
    oprf_pk_hash: d[7],
    credential_scheme: attested.publicInputs[3],
    attested_id_proof: await leaf(attested, attested.publicInputs),
    disclosure_proofs: [await leaf(disclose, [d[0], d[6], d[5], d[7]])],
  }

  const outer = Circuit.from("outer_attested_id_count_2")
  const outerProof = await outer.prove(outerInputs as any, {
    witness: await outer.solve(outerInputs as any, true),
    useCli: true,
    circuitName: "outer_attested_id_count_2",
    evm: true,
    disableZK: true,
  })

  // The verifier for this outer circuit, from the same vkey the proof was made with
  const { vkeyBytes } = await outer.getVerificationKey({ evm: true })
  await outer.destroy()
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tier2-vk-"))
  fs.writeFileSync(path.join(tempDir, "vk"), vkeyBytes)
  await execAsync(
    `bb write_solidity_verifier -t evm-no-zk --optimized -k "${path.join(tempDir, "vk")}" -o "${path.join(outDir, "OuterAttestedIdCount2.sol")}"`,
  )
  fs.rmSync(tempDir, { recursive: true, force: true })

  // The committed inputs as the SDK builds them for the contract, in parameter commitment order
  const rootKeyLeaf = await packLeBytesAndHashPoseidon2(
    new Uint8Array([ATTESTATION_KEY_TYPE_APPLE, ...attestation.rootKey]),
  )
  const appIdHash = await packLeBytesAndHashPoseidon2(new TextEncoder().encode(attestation.appId))
  const attestedEntry =
    hex(PROOF_TYPE_ATTESTED_ID, 1) +
    hex(98, 2) +
    hex(rootKeyLeaf, 32) +
    hex(attestation.environment, 1) +
    hex(appIdHash, 32) +
    hex(0, 32) +
    hex(2, 1)
  const mrz = DG1.subarray(5).toString()
  const disclosedBytes = getDisclosedBytesFromMrzAndMask(mrz, discloseMask)
  const discloseEntry =
    hex(PROOF_TYPE_DISCLOSE, 1) +
    hex(180, 2) +
    discloseMask.map((x) => hex(x, 1)).join("") +
    disclosedBytes.map((x) => hex(x, 1)).join("")

  fs.writeFileSync(path.join(outDir, "proof.hex"), outerProof.proof.map((x) => x.replace(/^0x/, "")).join(""))
  fs.writeFileSync(
    path.join(outDir, "public_inputs.json"),
    JSON.stringify(outerProof.publicInputs.map((x) => `0x${x.replace(/^0x/, "").padStart(64, "0")}`), null, 2) + "\n",
  )
  fs.writeFileSync(path.join(outDir, "committed_inputs.hex"), attestedEntry + discloseEntry)
  fs.writeFileSync(
    path.join(outDir, "attestation.json"),
    JSON.stringify(
      {
        domain: DOMAIN,
        scope: SCOPE,
        currentDate: now,
        rootKeyHash: `0x${hex(rootKeyLeaf, 32)}`,
        appIdHash: `0x${hex(appIdHash, 32)}`,
      },
      null,
      2,
    ) + "\n",
  )
  console.log(`Wrote the Tier 2 outer EVM proof fixture to ${outDir}`)
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
