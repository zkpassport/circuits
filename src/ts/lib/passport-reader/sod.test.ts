import { Binary } from "@/lib/binary"
import { beforeAll, describe, expect, it } from "bun:test"
import { readFile } from "fs/promises"
import { SOD } from "./sod"
import path from "path"

const FIXTURES_PATH = "src/ts/tests/fixtures"

describe("SOD", () => {
  let sodBytes: Binary
  let sod: SOD

  beforeAll(async () => {
    const sodFile = path.resolve(FIXTURES_PATH, "EF_SOD.bin")
    sodBytes = Binary.from(await readFile(sodFile))
    sod = SOD.fromBinary(sodBytes)
  })

  it("should parse basic SOD properties", () => {
    expect(sod.version).toBe(3)
    expect(sod.digestAlgorithms).toEqual(["SHA256"])
  })

  it("should parse eContent data correctly", () => {
    const eContent = sod.encapContentInfo.eContent
    expect(eContent.version).toBe(0)
    expect(eContent.hashAlgorithm).toBe("SHA256")

    // Verify data group hash values
    const dgHashes = eContent.dataGroupHashValues.values
    expect(Object.keys(dgHashes).length).toBe(5)
    expect(dgHashes[1].toHex()).toBe(
      "0x4170ca879fce6a22ffef1567ff88079f415c66ead250ab5f23781ac2cdbf42b6",
    )
    expect(dgHashes[2].toHex()).toBe(
      "0xa9a1b09dfd598087ab3fce4ae2ec65b1a1525bd258bfc27df4419f8a65e54745",
    )
  })

  it("should parse signer info correctly", () => {
    const signerInfo = sod.signerInfo
    expect(signerInfo.version).toBe(1)
    expect(signerInfo.digestAlgorithm).toBe("SHA256")
    // TODO: Consider adding rsaPSS to signatureAlgorithm types
    expect(signerInfo.signatureAlgorithm.name as string).toBe("rsaPSS")

    // Verify signed attributes
    expect(signerInfo.signedAttrs.contentType).toBe("mRTDSignatureData")
    expect(signerInfo.signedAttrs.messageDigest.toHex()).toBe(
      "0x0420b46a0d05e280f398efeeebff67e78c736add15e75670b1ad4c6c534e8187b9d6",
    )
  })

  it("should parse certificate information correctly", () => {
    const cert = sod.certificate
    const tbs = cert.tbs

    // Check certificate validity dates
    expect(tbs.validity.notBefore).toEqual(new Date("2013-12-16T21:43:18.000Z"))
    expect(tbs.validity.notAfter).toEqual(new Date("2014-12-11T21:43:18.000Z"))

    // Verify issuer and subject
    expect(tbs.issuer).toBe(
      "countryName=DE, organizationName=HJP Consulting, organizationalUnitName=Country Signer, commonName=HJP PB CS",
    )
    expect(tbs.subject).toBe(
      "countryName=DE, organizationName=HJP Consulting, organizationalUnitName=Document Signer, commonName=HJP PB DS",
    )

    // Check certificate extensions
    expect(tbs.extensions.has("keyUsage")).toBe(true)
    expect(tbs.extensions.has("authorityKeyIdentifier")).toBe(true)
    expect(tbs.extensions.has("subjectKeyIdentifier")).toBe(true)
    expect(tbs.extensions.get("keyUsage").critical).toBe(true)
  })

  it("should parse signature algorithms correctly", () => {
    const cert = sod.certificate

    // Check signature algorithms
    // TODO: Consider adding rsaPSS to signatureAlgorithm types
    expect(cert.signatureAlgorithm.name as string).toBe("rsaPSS")
    expect(cert.tbs.subjectPublicKeyInfo.signatureAlgorithm.name).toBe("rsaEncryption")

    // Verify signature exists
    expect(cert.signature).toBeTruthy()
    expect(sod.signerInfo.signature).toBeTruthy()
  })
})
