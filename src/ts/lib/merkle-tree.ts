import { Binary } from "@/lib/binary"
import { BarretenbergSync, Fr } from "@aztec/bb.js"
import { LeanIMT } from "@zk-kit/lean-imt"

const bb = await BarretenbergSync.initSingleton()

// NOTE: height is currently not used because we're using a _lean_ imt that doesn't yet support padding
export async function computeMerkleProof(height: number, leaves: Binary[], index: number) {
  if (index < 0 || index >= leaves.length) throw new Error("Invalid index")
  const hash = (a: bigint, b: bigint) =>
    uint8ArrayToBigInt(bb.poseidon2Hash([new Fr(a), new Fr(b)]).value)
  const tree = new LeanIMT(
    hash,
    leaves.map((leaf) => leaf.toBigInt()),
  )
  const proof = tree.generateProof(index)
  return {
    root: "0x" + proof.root.toString(16),
    index: proof.index,
    path: proof.siblings.map((x) => "0x" + x.toString(16)),
  }
}

function uint8ArrayToBigInt(uint8Array: Uint8Array): bigint {
  return BigInt(
    `0x${Array.from(uint8Array)
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("")}`,
  )
}
