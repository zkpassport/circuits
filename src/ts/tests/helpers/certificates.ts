import { certificates } from "../fixtures/csc-masterlist.json"
import { BarretenbergSync, Fr } from "@aztec/bb.js"
import { CSC } from "../../types"

const registry_id = 1n
const cert_type = 1n

export function getLeafFromCertificate(
  hashFunc: (input: Fr[]) => Fr,
  cert: { public_key: number[]; issuing_country: string },
): Buffer {
  const { issuing_country, public_key } = cert
  return Buffer.from(
    hashFunc([
      new Fr(registry_id),
      new Fr(cert_type),
      ...Array.from(issuing_country).map((char) => new Fr(BigInt(char.charCodeAt(0)))),
      ...public_key.map((x) => new Fr(BigInt(x))),
    ]).toBuffer(),
  )
}

const bb = await BarretenbergSync.initSingleton()
export function poseidon2Hash(input: Fr[]) {
  return bb.poseidon2Hash(input)
}

export function getCertificates(): CSC[] {
  return certificates as CSC[]
}

export function getCertificateLeaves(certificates: CSC[]): Buffer[] {
  return certificates
    .map((cert) => getLeafFromCertificate(poseidon2Hash, cert))
    .filter((x): x is Buffer => x !== null)
}

export function genCSC(
  country: string,
  signatureAlgorithm: string,
  privateKey: string,
  publicKey: number[],
  exponent: number,
): CSC {
  return {
    authority_key_identifier: "",
    issuing_country: country,
    signature_algorithm: signatureAlgorithm,
    key_size: publicKey.length * 8,
    private_key: privateKey,
    public_key: publicKey,
    exponent: exponent,
    private_key_usage_period: {
      not_before: 1384732565,
      not_after: 1510962965,
    },
    validity: {
      not_before: 1384732915,
      not_after: 1889654166,
    },
  }
}
