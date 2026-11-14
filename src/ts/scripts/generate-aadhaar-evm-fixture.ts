// An outer_aadhaar_count_3 EVM proof (aadhaar_id + facematch_ios_evm over a synthetic attestation +
// disclose_bytes_evm) for the registry-contracts tests.
//   npx tsx src/ts/scripts/generate-aadhaar-evm-fixture.ts <out dir>
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
  ATTESTATION_KEY_TYPE_APPLE,
  ATTESTATION_TYPE_FACE_MATCH,
  buildIosAttestedIdInputs,
  FACEMATCH_MODE_REGULAR,
  getExpiryDate,
} from "../tests/attested-id"

const execAsync = promisify(exec)

const DOMAIN = "zkpassport.id"
const SCOPE = "aadhaar"
const SALTS = { dg1Salt: 11n, expiryDateSalt: 12n, dg2HashSalt: 13n, privateNullifierSalt: 14n }
const PROOF_TYPE_DISCLOSE = 0
const PROOF_TYPE_FACEMATCH = 10
const FIXTURE = JSON.parse(
  fs.readFileSync(path.join(__dirname, "..", "tests", "fixtures", "aadhaar.json"), "utf8"),
)

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

async function getPhotoHash(): Promise<Uint8Array> {
  const { qr_data: data, qr_data_length: length, delimiter_indices: delimiters } = FIXTURE.inputs
  const photo = Uint8Array.from(data.slice(delimiters[delimiters.length - 1] + 1, length))
  const photoHash = sha256(photo)
  if ((await packLeBytesAndHashPoseidon2(photoHash)) !== BigInt(FIXTURE.photoHashNormalized)) {
    throw new Error("The fixture's photo hash does not match its QR code")
  }
  return photoHash
}

export async function generateAadhaarEvmFixture(
  outDir: string,
  { writeVerifier = true }: { writeVerifier?: boolean } = {},
) {
  fs.mkdirSync(outDir, { recursive: true })
  const now = Math.floor(Date.now() / 1000)
  const dg1 = new Uint8Array(FIXTURE.dg1)
  const serviceScope = `0x${getServiceScopeHash(DOMAIN).toString(16)}`
  const serviceSubscope = `0x${getScopeHash(SCOPE).toString(16)}`

  const aadhaar = await recursiveProof("aadhaar_id", FIXTURE.inputs)
  const commOut = aadhaar.publicInputs[1]
  const committed = {
    comm_in: commOut,
    current_date: now,
    salted_private_nullifier: SaltedValue.fromValue(
      SALTS.privateNullifierSalt,
      BigInt(FIXTURE.privateNullifier),
    ).formatForInput(),
    salted_expiry_date: SaltedValue.fromValue(SALTS.expiryDateSalt, getExpiryDate(dg1)).formatForInput(),
    salted_dg1: SaltedValue.fromValue(SALTS.dg1Salt, FIXTURE.dg1).formatForInput(),
    salted_dg2_hash: SaltedValue.fromValue(
      SALTS.dg2HashSalt,
      BigInt(FIXTURE.photoHashNormalized),
    ).formatForInput(),
    salted_dg2_hash_type: SaltedValue.fromValue(SALTS.dg2HashSalt, 3n).formatForInput(),
    nullifier_secret: "0x0",
    service_scope: serviceScope,
    service_subscope: serviceSubscope,
  }

  const attestation = await buildIosAttestedIdInputs({
    dg1,
    portraitHash: new Uint8Array(32),
    salts: SALTS,
    digest: await getPhotoHash(),
    attestationType: ATTESTATION_TYPE_FACE_MATCH,
    mode: FACEMATCH_MODE_REGULAR,
  })
  const a = attestation.inputs
  const facematch = await recursiveProof("facematch_ios_evm", {
    ...committed,
    root_key: a.root_key,
    intermediate_key: a.intermediate_key,
    intermediate_tbs: a.intermediate_tbs,
    intermediate_sig: a.intermediate_sig,
    credential_tbs: a.credential_tbs,
    credential_sig: a.credential_sig,
    auth_data: a.auth_data,
    client_data: a.client_data,
    environment: a.environment,
    app_id: a.app_id,
    facematch_mode: FACEMATCH_MODE_REGULAR,
  })
  const discloseMask = Array(90).fill(1)
  const disclose = await recursiveProof("disclose_bytes_evm", {
    ...committed,
    disclose_mask: discloseMask,
    oprf_proof: OPRF_ZERO_PROOF,
  })

  const circuitManifest = {
    version: "0.23.0",
    root: await calculateCircuitRoot({
      hashes: [aadhaar.vkeyHash, facematch.vkeyHash, disclose.vkeyHash],
    }),
    circuits: {
      aadhaar: { hash: aadhaar.vkeyHash, size: 1 },
      facematch: { hash: facematch.vkeyHash, size: 1 },
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
  const f = facematch.publicInputs
  const d = disclose.publicInputs
  const outerInputs = {
    certificate_registry_root: aadhaar.publicInputs[0],
    circuit_registry_root: circuitManifest.root,
    current_date: now,
    service_scope: d[2],
    service_subscope: d[3],
    param_commitments: [f[4], d[4]],
    nullifier_type: d[5],
    scoped_nullifier: d[6],
    oprf_pk_hash: d[7],
    credential_scheme: aadhaar.publicInputs[2],
    aadhaar_id_proof: await leaf(aadhaar, aadhaar.publicInputs),
    disclosure_proofs: [
      await leaf(facematch, [f[0], f[6], f[5], f[7]]),
      await leaf(disclose, [d[0], d[6], d[5], d[7]]),
    ],
  }

  const outer = Circuit.from("outer_aadhaar_count_3")
  const outerProof = await outer.prove(outerInputs as any, {
    witness: await outer.solve(outerInputs as any, true),
    useCli: true,
    circuitName: "outer_aadhaar_count_3",
    evm: true,
    disableZK: true,
  })

  if (writeVerifier) {
    const { vkeyBytes } = await outer.getVerificationKey({ evm: true })
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "aadhaar-vk-"))
    fs.writeFileSync(path.join(tempDir, "vk"), vkeyBytes)
    await execAsync(
      `bb write_solidity_verifier -t evm-no-zk --optimized -k "${path.join(tempDir, "vk")}" -o "${path.join(outDir, "OuterAadhaarCount3.sol")}"`,
    )
    fs.rmSync(tempDir, { recursive: true, force: true })
  }
  await outer.destroy()

  const rootKeyLeaf = await packLeBytesAndHashPoseidon2(
    new Uint8Array([ATTESTATION_KEY_TYPE_APPLE, ...attestation.rootKey]),
  )
  const appIdHash = await packLeBytesAndHashPoseidon2(new TextEncoder().encode(attestation.appId))
  const facematchEntry =
    hex(PROOF_TYPE_FACEMATCH, 1) +
    hex(98, 2) +
    hex(rootKeyLeaf, 32) +
    hex(attestation.environment, 1) +
    hex(appIdHash, 32) +
    hex(0, 32) +
    hex(FACEMATCH_MODE_REGULAR, 1)
  const mrz = Buffer.from(dg1.subarray(5, 93)).toString()
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
  fs.writeFileSync(path.join(outDir, "committed_inputs.hex"), facematchEntry + discloseEntry)
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
  console.log(`Wrote the Aadhaar outer EVM proof fixture to ${outDir}`)
}

if (process.argv[1]?.endsWith("generate-aadhaar-evm-fixture.ts")) {
  const outDir = process.argv[2]
  if (!outDir) throw new Error("Usage: generate-aadhaar-evm-fixture.ts <out dir>")
  generateAadhaarEvmFixture(outDir).catch((error) => {
    console.error(error)
    process.exit(1)
  })
}
