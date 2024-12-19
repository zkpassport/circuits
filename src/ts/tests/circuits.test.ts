import { Binary } from "@/lib/binary"
import { Circuit } from "@/lib/circuits"
import { parseCertificate } from "@/lib/csc-manager"
import {
  generateSigningCertificates,
  loadDscKeypairFromFile,
  signSodWithRsaKey,
} from "@/lib/passport-reader/passport-generator"
import { generateSod, wrapSodInContentInfo } from "@/lib/passport-reader/sod-generator"
import { TestHelper } from "@/lib/test-helper"
import { CSCMasterlist } from "@/types"
import { CertificateChoices } from "@peculiar/asn1-cms"
import { AsnSerializer } from "@peculiar/asn1-schema"
import { beforeAll, describe, expect, it } from "bun:test"
import * as path from "path"

describe("subcircuits", () => {
  const helper = new TestHelper()
  const circuits: {
    dsc: Circuit
    id: Circuit
    integrity: Circuit
    disclose: Circuit
  } = {} as any

  const masterlist: CSCMasterlist = { certificates: [] }
  const FIXTURES_PATH = path.join(__dirname, "fixtures")
  const DSC_KEYPAIR_PATH = path.join(FIXTURES_PATH, "dsc-keypair.json")
  const MAX_TBS_LENGTH = 1500

  beforeAll(async () => {
    circuits.dsc = Circuit.from(`sig_check_dsc_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_4096`)
    circuits.id = Circuit.from(`sig_check_id_data_tbs_${MAX_TBS_LENGTH}_rsa_pkcs_2048`)
    circuits.integrity = Circuit.from("data_check_integrity")
    circuits.disclose = Circuit.from("disclose_bytes")

    // Johnny Silverhand's MRZ
    const mrz =
      "P<AUSSILVERHAND<<JOHNNY<<<<<<<<<<<<<<<<<<<<<PA1234567_AUS881112_M300101_<CYBERCITY<<<<__"
    const dg1 = Binary.fromHex("615B5F1F58").concat(Binary.from(mrz))
    // Load DSC keypair
    const dscKeypair = loadDscKeypairFromFile(DSC_KEYPAIR_PATH)
    // Generate CSC and DSC signing certificates
    const { cscPem, dsc } = generateSigningCertificates({
      cscSigningHashAlgorithm: "sha256",
      cscKeySize: 4096,
      dscKeypair,
    })
    // Generate SOD and sign it with DSC keypair
    const { sod } = generateSod(dg1, [new CertificateChoices({ certificate: dsc })])
    const { sod: signedSod } = signSodWithRsaKey(sod, dscKeypair.privateKey)
    // Add newly generated CSC to masterlist
    masterlist.certificates.push(parseCertificate(cscPem))
    // Load passport data into helper
    const contentInfoWrappedSod = AsnSerializer.serialize(wrapSodInContentInfo(signedSod))
    await helper.loadPassport(dg1, Binary.from(contentInfoWrappedSod))
    helper.setMasterlist(masterlist)
    helper.setMaxTbsLength(MAX_TBS_LENGTH)
  })

  it("generate dsc proof", async () => {
    const inputs = await helper.generateCircuitInputs("dsc")
    const proof = await circuits.dsc.prove(inputs)
    expect(proof).toBeDefined()
  })

  it("generate id proof", async () => {
    const inputs = await helper.generateCircuitInputs("id")
    const proof = await circuits.id.prove(inputs)
    expect(proof).toBeDefined()
  })

  it("generate integrity proof", async () => {
    const inputs = await helper.generateCircuitInputs("integrity")
    const proof = await circuits.integrity.prove(inputs)
    expect(proof).toBeDefined()
  })

  it("generate disclose proof", async () => {
    const inputs = await helper.generateCircuitInputs("disclose")
    const proof = await circuits.disclose.prove(inputs)
    expect(proof).toBeDefined()

    const nullifier = proof.publicInputs.slice(-1)[0]
    const disclosed_bytes = Binary.from(
      proof.publicInputs
        .slice(-91, -1)
        .map((hex) => parseInt(hex, 16))
        .map((byte) => (byte === 0 ? " ".charCodeAt(0) : byte)),
    )
    expect(nullifier).toEqual("0x215282c6b81a6062e0af454d9615c4582c5a35acff60d3a6cdfd5acee286dbf9")
    expect(disclosed_bytes.toString("ascii").trim().split(" ").filter(Boolean)).toEqual([
      "SILVERHAND<<JOHNNY<<<<<<<<<<<<<<<<<<<<<",
      "AUS881112",
    ])
  })
})
