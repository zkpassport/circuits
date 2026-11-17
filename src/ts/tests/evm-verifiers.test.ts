import fs from "fs"
import os from "os"
import path from "path"
import { describe, expect, it } from "@jest/globals"
import { EVM_VERIFIERS_PATH, evmVerifiers } from "../scripts/evm-verifiers"
import manifest from "./fixtures/circuit-manifest.json"

const hash = (n: number) => `0x${n.toString(16).padStart(64, "0")}`

function verifiersDir(files: string[]): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "evm-verifiers-"))
  for (const file of files) fs.writeFileSync(path.join(dir, file), "")
  return dir
}

describe("evmVerifiers", () => {
  it("is the committed list for the packaged circuits", () => {
    const committed = JSON.parse(fs.readFileSync(EVM_VERIFIERS_PATH, "utf-8"))
    expect(committed).toEqual(evmVerifiers(manifest.circuits))
  })

  it("lists each outer circuit's EVM circuit, with its verifier and vkey hash", () => {
    const circuits = {
      outer_count_4: { hash: hash(1) },
      outer_evm_count_4: { hash: "0x2a" },
      outer_aadhaar_count_10: { hash: hash(3) },
      outer_evm_aadhaar_count_10: { hash: hash(4) },
      outer_aadhaar_count_2: { hash: hash(5) },
      outer_evm_aadhaar_count_2: { hash: hash(6) },
      disclose_bytes: { hash: hash(7) },
    }
    const dir = verifiersDir([
      "OuterCount4.sol",
      "OuterAadhaarCount2.sol",
      "OuterAadhaarCount10.sol",
    ])
    expect(evmVerifiers(circuits, dir)).toEqual([
      {
        circuit: "outer_evm_aadhaar_count_2",
        contractFile: "OuterAadhaarCount2.sol",
        vkeyHash: hash(6),
      },
      {
        circuit: "outer_evm_aadhaar_count_10",
        contractFile: "OuterAadhaarCount10.sol",
        vkeyHash: hash(4),
      },
      { circuit: "outer_evm_count_4", contractFile: "OuterCount4.sol", vkeyHash: hash(0x2a) },
    ])
  })

  it("rejects an outer circuit without an EVM circuit", () => {
    const circuits = { outer_count_4: { hash: hash(1) } }
    expect(() => evmVerifiers(circuits, verifiersDir([]))).toThrow(
      "outer_count_4 has no EVM circuit outer_evm_count_4",
    )
  })

  it("rejects an EVM circuit without a verifier", () => {
    const circuits = { outer_count_4: { hash: hash(1) }, outer_evm_count_4: { hash: hash(2) } }
    expect(() => evmVerifiers(circuits, verifiersDir([]))).toThrow(
      "outer_evm_count_4 has no verifier OuterCount4.sol",
    )
  })

  it("rejects an EVM circuit without an outer circuit", () => {
    const circuits = { outer_evm_count_4: { hash: hash(2) } }
    expect(() => evmVerifiers(circuits, verifiersDir(["OuterCount4.sol"]))).toThrow(
      "outer_evm_count_4 is an EVM circuit without an outer circuit",
    )
  })

  it("rejects a verifier for none of the circuits", () => {
    const circuits = { outer_count_4: { hash: hash(1) }, outer_evm_count_4: { hash: hash(2) } }
    const dir = verifiersDir(["OuterCount4.sol", "OuterCount5.sol"])
    expect(() => evmVerifiers(circuits, dir)).toThrow(
      "OuterCount5.sol verifies none of the manifest's circuits",
    )
  })
})
