import { LeanIMT } from "@zk-kit/lean-imt"
import { BarretenbergSync, Fr } from "@aztec/bb.js"
import { uint8ArrayToBigInt } from "./conversion"

const bb = await BarretenbergSync.initSingleton()

// NOTE: height is currently not used because we're using a _lean_ imt that doesn't yet support padding
export async function computeMerkleProof(height: number, leaves: Buffer[], leaf: Buffer) {
  const hash = (a: bigint, b: bigint) =>
    uint8ArrayToBigInt(bb.poseidon2Hash([new Fr(a), new Fr(b)]).value)
  const tree = new LeanIMT(
    hash,
    leaves.map((leaf) => BigInt(uint8ArrayToBigInt(new Uint8Array(leaf)))),
  )
  const index = leaves.findIndex((l) => l.equals(leaf))
  if (index === -1) throw new Error("Leaf not found in leaves")
  const proof = tree.generateProof(index)
  return {
    root: proof.root.toField(),
    index: proof.index,
    path: proof.siblings.map((x) => x.toField()),
  }
}
