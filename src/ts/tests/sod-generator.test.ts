import { id_signedData, SignedData } from "@peculiar/asn1-cms"
import { AsnConvert } from "@peculiar/asn1-schema"
import { Version } from "@peculiar/asn1-x509"
import { describe, it, expect } from "@jest/globals"
import { generateSampleDSC, generateSod } from "../sod-generator"
import { Binary } from "@zkpassport/utils"
import { createHash } from "crypto"
import { ASN, id_sha256 } from "../asn"

describe("SOD", () => {
  const dg1 = Binary.from(new Uint8Array(32).buffer)
  const dg1Hash = createHash("sha256").update(dg1.toBuffer()).digest()

  it("generate SOD", async () => {
    const { contentInfo } = await generateSod(dg1)
    expect(contentInfo.contentType).toBe(id_signedData)
    // Verify the structure can be parsed back
    const sod = AsnConvert.parse(contentInfo.content, SignedData)
    const eContent = AsnConvert.parse(
      sod?.encapContentInfo?.eContent?.single!,
      ASN.LDSSecurityObject,
    )
    // Verify the decoded content
    expect(eContent.version).toBe(ASN.LDSSecurityObjectVersion.v0)
    expect(eContent.hashAlgorithm.algorithm).toBe(id_sha256)
    expect(eContent.dataGroups.length).toBe(2)
    expect(eContent.dataGroups[0].number).toBe(ASN.DataGroupNumber.dataGroup1)
    expect(eContent.dataGroups[1].number).toBe(ASN.DataGroupNumber.dataGroup2)
    expect(Binary.from(eContent.dataGroups[0].hash)).toEqual(Binary.from(dg1Hash))
    // Verify signer info
    expect(sod.signerInfos.length).toBe(1)
    const decodedSignerInfo = sod.signerInfos[0]
    expect(decodedSignerInfo.version).toBe(1)
    expect(decodedSignerInfo?.signedAttrs?.length).toBe(3)
    // Verify certificates
    expect(Array.isArray(sod.certificates)).toBe(true)
    expect(sod.certificates?.length).toBe(0) // Default empty certificates
  })

  it("generate SOD with sample DSC", async () => {
    const sampleDSC = generateSampleDSC()
    const { contentInfo } = await generateSod(dg1, [sampleDSC])
    // Verify the structure can be parsed back
    const sod = AsnConvert.parse(contentInfo.content, SignedData)
    // Verify certificates
    expect(Array.isArray(sod.certificates)).toBe(true)
    expect(sod!.certificates!.length).toBe(1)
    const cert = sod!.certificates![0]!.certificate
    expect(!!cert).toBe(true)
    expect(cert!.tbsCertificate.version).toBe(Version.v3)
    expect(cert!.tbsCertificate.serialNumber.byteLength).toBe(5)
  })
})
