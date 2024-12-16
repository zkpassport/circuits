import { Binary } from "@/lib/binary"
import { Circuit } from "@/lib/circuits"
import { TestHelper } from "@/lib/test-helper"
import { beforeAll, describe, it } from "bun:test"

describe("subcircuits", () => {
  const helper = new TestHelper()
  const circuits: {
    dsc: Circuit
    id: Circuit
    integrity: Circuit
    disclose: Circuit
    outer: Circuit
  } = {} as any

  beforeAll(async () => {
    circuits.dsc = Circuit.from("sig_check_dsc_rsa_pkcs_4096")
    circuits.id = Circuit.from("sig_check_id_data_rsa_pkcs_2048")
    circuits.integrity = Circuit.from("data_check_integrity")
    circuits.disclose = Circuit.from("disclose_bytes")
    circuits.outer = Circuit.from("outer")

    await helper.loadPassportDataFromFile("dg1.bin", "sod.bin")
  })

  it("should generate dsc proof", async () => {
    const inputs = await helper.generateCircuitInputs("dsc")
    const proof = await circuits.dsc.prove(inputs)
    console.log("proof", proof)
  })

  it("should generate id proof", async () => {
    const inputs = await helper.generateCircuitInputs("id")
    const proof = await circuits.id.prove(inputs)
    console.log("proof", proof)
  })

  it("should generate integrity proof", async () => {
    const inputs = await helper.generateCircuitInputs("integrity")
    const proof = await circuits.integrity.prove(inputs)
    console.log("proof", proof)
  })

  it("should generate disclose proof", async () => {
    const inputs = await helper.generateCircuitInputs("disclose")
    console.log("inputs", inputs)
    const proof = await circuits.disclose.prove(inputs)
    console.log("proof", proof.publicInputs)

    const nullifier = proof.publicInputs.slice(-1)[0]
    const disclosed_bytes = Binary.from(
      proof.publicInputs
        .slice(-91, -1)
        .map((hex) => parseInt(hex, 16))
        .map((byte) => (byte === 0 ? " ".charCodeAt(0) : byte)),
    )
    console.log("nullifier", nullifier)
    console.log("disclosed_bytes", disclosed_bytes.toString("ascii"))
  })

  // it("should generate outer proof", async () => {
  //   const discloseInputs = await helper.generateCircuitInputs("disclose")
  //   console.log("discloseInputs", discloseInputs)
  //   const discloseArtifacts = await circuits.disclose.proveRecursiveProof(discloseInputs)
  //   console.log("discloseArtifacts", discloseArtifacts)
  //   const outerInputs = await helper.generateCircuitInputs("outer")
  //   const outerProof = await circuits.outer.prove(outerInputs)
  //   console.log("outerProof", outerProof)
  // })
})
