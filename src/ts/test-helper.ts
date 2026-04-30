import { InputMap } from "@noir-lang/noir_js"
import {
  Binary,
  getDiscloseCircuitInputs,
  getDSCCircuitInputs,
  getIDDataCircuitInputs,
  getIntegrityCheckCircuitInputs,
  getNowTimestamp,
  PassportReader,
  packLeBytesAndHashPoseidon2,
  getCertificateIssuerCountry,
  getSignatureAlgorithmType,
  getRSAInfo,
  getECDSAInfo,
  getKeySize,
  getAuthorityKeyId,
  getSubjectKeyId,
  getPrivateKeyUsagePeriod,
  countryCodeAlpha2ToAlpha3,
  OIDS_TO_PUBKEY_TYPE,
  type PackagedCertificate,
  type PackagedCertificatesFile,
  type PassportViewModel,
  type Query,
} from "@zkpassport/utils"
import { AsnParser } from "@peculiar/asn1-schema"
import { Certificate as X509Certificate } from "@peculiar/asn1-x509"
import fs from "fs/promises"
import path from "path"

type CircuitType = "dsc" | "id" | "integrity" | "disclose"

export class TestHelper {
  private passportReader = new PassportReader()
  public passport!: PassportViewModel
  private packagedCerts!: PackagedCertificatesFile

  setCertificates(packagedCerts: PackagedCertificatesFile) {
    this.packagedCerts = packagedCerts
  }

  async generateCircuitInputs(
    circuitType: CircuitType,
    nowTimestamp: number = getNowTimestamp(),
  ): Promise<InputMap> {
    switch (circuitType) {
      case "dsc": {
        const inputs = await getDSCCircuitInputs(this.passport as any, 1n, this.packagedCerts)
        if (!inputs) throw new Error("Unable to generate DSC circuit inputs")
        return inputs
      }
      case "id": {
        const inputs = await getIDDataCircuitInputs(this.passport as any, 1n, 2n)
        if (!inputs) throw new Error("Unable to generate ID data circuit inputs")
        return inputs
      }
      case "integrity": {
        const inputs = await getIntegrityCheckCircuitInputs(
          this.passport as any,
          2n,
          {
            dg1Salt: 3n,
            expiryDateSalt: 3n,
            dg2HashSalt: 3n,
            privateNullifierSalt: 3n,
          },
        )
        if (!inputs) throw new Error("Unable to generate integrity check circuit inputs")
        return inputs
      }
      case "disclose": {
        const query: Query = {
          fullname: { disclose: true },
          nationality: { disclose: true },
          birthdate: { disclose: true },
        }
        const inputs = await getDiscloseCircuitInputs(this.passport as any, query, {
          dg1Salt: 3n,
          expiryDateSalt: 3n,
          dg2HashSalt: 3n,
          privateNullifierSalt: 3n,
        }, 0n, 0n, 0n, nowTimestamp)
        if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
        return inputs
      }
    }
  }

  public async loadPassportDataFromFile(dg1FileName: string, sodFileName: string): Promise<void> {
    const FIXTURES_PATH = "src/ts/tests/fixtures"
    if (!fs || !path) {
      throw new Error("File system operations are only available in Node.js environment")
    }
    const dg1 = Binary.from(await fs.readFile(path.resolve(FIXTURES_PATH, dg1FileName)))
    const sod = Binary.from(await fs.readFile(path.resolve(FIXTURES_PATH, sodFileName)))
    this.passportReader.loadPassport(dg1, sod)
    this.passport = this.passportReader.getPassportViewModel() as any
  }

  public async loadPassport(dg1: Binary, sod: Binary): Promise<void> {
    this.passportReader.loadPassport(dg1, sod)
    this.passport = this.passportReader.getPassportViewModel() as any
  }
}

export function utcDateToUnixTimestamp(year: number, month: number, day: number) {
  return Math.floor(Date.UTC(year, month - 1, day) / 1000)
}

function pemToDer(pem: string): Uint8Array {
  const b64 = pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s+/g, "")
  return new Uint8Array(Buffer.from(b64, "base64"))
}

// Build a v1 PackagedCertificate from a PEM-encoded x509 cert.
export async function convertPemToPackagedCertificateV1(
  pem: string,
): Promise<PackagedCertificate> {
  const der = pemToDer(pem)
  const x509 = AsnParser.parse(der, X509Certificate)
  const fingerprintBig = await packLeBytesAndHashPoseidon2(der)
  const fingerprint = `0x${fingerprintBig.toString(16).padStart(64, "0")}`

  const validity = x509.tbsCertificate.validity
  const notBefore = Math.floor(validity.notBefore.getTime().getTime() / 1000)
  const notAfter = Math.floor(validity.notAfter.getTime().getTime() / 1000)

  const countryAlpha2 = getCertificateIssuerCountry(x509)
  if (!countryAlpha2 || countryAlpha2.length !== 2)
    throw new Error(`Invalid country code on cert: ${countryAlpha2}`)
  const country = countryCodeAlpha2ToAlpha3(countryAlpha2)

  const publicKeyOID = x509.tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm
  const publicKeyType =
    OIDS_TO_PUBKEY_TYPE[publicKeyOID as keyof typeof OIDS_TO_PUBKEY_TYPE] ?? publicKeyOID

  const common = {
    country,
    signature_algorithm: getSignatureAlgorithmType(x509),
    validity: { not_before: notBefore, not_after: notAfter },
    authority_key_identifier: getAuthorityKeyId(x509),
    subject_key_identifier: getSubjectKeyId(x509),
    private_key_usage_period: getPrivateKeyUsagePeriod(x509),
    fingerprint,
  }

  if (publicKeyType === "rsaEncryption" || publicKeyType === "rsassa-pss") {
    const rsa = getRSAInfo(x509.tbsCertificate.subjectPublicKeyInfo)
    return {
      ...common,
      public_key: {
        type: "RSA",
        modulus: `0x${rsa.modulus.toString(16)}`,
        exponent: Number(rsa.exponent),
        key_size: getKeySize(x509.tbsCertificate.subjectPublicKeyInfo),
      },
    } as PackagedCertificate
  }
  if (publicKeyType === "ecPublicKey") {
    const ec = getECDSAInfo(x509.tbsCertificate.subjectPublicKeyInfo)
    const half = ec.publicKey.length / 2
    return {
      ...common,
      public_key: {
        type: "EC",
        curve: ec.curve,
        key_size: ec.keySize,
        // Strip uncompressed-point 0x04 prefix
        public_key_x: `0x${Buffer.from(ec.publicKey.slice(1, half + 1)).toString("hex")}`,
        public_key_y: `0x${Buffer.from(ec.publicKey.slice(half + 1)).toString("hex")}`,
      },
    } as PackagedCertificate
  }
  throw new Error(`Unsupported public key type for test cert: ${publicKeyType}`)
}
