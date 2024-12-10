import { Binary } from "@/lib/binary"
import { PassportViewModel } from "@/types"
import { p256 } from "@noble/curves/p256"
import { p384 } from "@noble/curves/p384"
import { p521 } from "@noble/curves/p521"
import { ContentInfo, SignedData } from "@peculiar/asn1-cms"
import { ECParameters } from "@peculiar/asn1-ecc"
import { RSAPublicKey } from "@peculiar/asn1-rsa"
import { AsnParser } from "@peculiar/asn1-schema"
import { TBSCertificate } from "@peculiar/asn1-x509"
import { BRAINPOOL_CURVES, CURVE_OIDS, HASH_OIDS, RSA_OIDS } from "./constants"
import { LDS } from "./lds"

export class PassportReader {
  lds: LDS

  getPassportViewModel(): PassportViewModel {
    // TODO: Implement the remaining properties
    return {
      mrz: this.lds.dg1.toString("ascii"),
      name: "",
      dateOfBirth: "",
      nationality: this.lds.dg1.slice(59, 62).toString("ascii"),
      gender: "",
      passportNumber: "",
      passportExpiry: "",
      firstName: "",
      lastName: "",
      photo: "",
      originalPhoto: "",
      LDSVersion: this.lds.ldsVersion.toString(),
      // TODO: Improve this
      dataGroups: [
        {
          groupNumber: 1,
          name: "DG1",
          hash: this.lds.dataGroups[0].hash.toNumberArray(),
          value: this.lds.dg1.toNumberArray(),
        },
      ],
      chipAuthSupported: false,
      chipAuthSuccess: false,
      chipAuthFailed: false,
      sod: this.lds.sod.toNumberArray(),
      signedAttributes: this.lds.signedAttr.bytes.toNumberArray(),
      signedAttributesHashAlgorithm: this.lds.signedAttr.hashAlgorithm.name,
      eContent: this.lds.eContent.bytes.toNumberArray(),
      eContentHashAlgorithm: this.lds.eContent.hashAlgorithm.name,
      cmsVersion: this.lds.cmsVersion.toString(),
      dscSignatureAlgorithm: this.lds.tbs.signatureAlgorithm.name,
      dscSignature: this.lds.tbs.signature.toNumberArray(),
      tbsCertificate: this.lds.tbs.bytes.toNumberArray(),
      sodSignature: this.lds.signedAttr.signature.toNumberArray(),
      sodSignatureAlgorithm: this.lds.signedAttr.signatureAlgorithm.name,
    }
  }

  public loadPassport(dg1: Binary, sod: Binary) {
    this.lds = LDS.fromPassportData(dg1, sod)
  }
}

function getSODContent(passport: PassportViewModel): SignedData {
  const sod =
    passport.sod && passport.sod[0] == 119 && (passport.sod[1] == -126 || passport.sod[1] == 130)
      ? passport.sod.slice(4)
      : passport.sod
  const cert = AsnParser.parse(new Uint8Array(sod!), ContentInfo)
  const signedData = AsnParser.parse(cert.content, SignedData)
  return signedData
}

function decodeOID(bytes: number[]): string {
  // First byte represents first two numbers: first = byte / 40, second = byte % 40
  const firstNumber = Math.floor(bytes[2] / 40)
  const secondNumber = bytes[2] % 40
  const values = [firstNumber, secondNumber]
  let value = 0
  // Process remaining bytes
  for (let i = 3; i < bytes.length; i++) {
    // For each byte, check if highest bit is 1
    if (bytes[i] & 0x80) {
      // If highest bit is 1, we continue reading next byte
      value = (value << 7) + (bytes[i] & 0x7f)
    } else {
      // If highest bit is 0, this is the last byte of this number
      value = (value << 7) + bytes[i]
      values.push(value)
      value = 0
    }
  }
  return values.join(".")
}

function getEContentHashAlgorithm(passport: PassportViewModel): string {
  const eContent = getEContent(passport)
  const oidOffset = 9
  const oidLength = eContent[oidOffset + 1]
  const oidBytes = eContent.slice(oidOffset, oidOffset + oidLength + 2)
  return HASH_OIDS[decodeOID(oidBytes) as keyof typeof HASH_OIDS] ?? ""
}

function getEContent(passport: PassportViewModel): number[] {
  const signedData = getSODContent(passport)
  return Array.from(
    new Uint8Array(signedData.encapContentInfo.eContent?.single?.buffer ?? new ArrayBuffer(0)),
  )
}

function getSignedAttributesHashingAlgorithm(passport: PassportViewModel): string {
  const signedData = getSODContent(passport)
  return HASH_OIDS[signedData.digestAlgorithms[0].algorithm as keyof typeof HASH_OIDS] ?? ""
}

function getSODCMSVersion(passport: PassportViewModel): string {
  const signedData = getSODContent(passport)
  return signedData.version.toString()
}

export function extractTBS(passport: PassportViewModel): TBSCertificate | null {
  const signedData = getSODContent(passport)
  const tbsCertificate = signedData.certificates
    ? signedData.certificates[0]?.certificate?.tbsCertificate
    : null
  return tbsCertificate ?? null
}

function fromBytesToBigInt(bytes: number[]): bigint {
  return BigInt("0x" + Buffer.from(bytes).toString("hex"))
}

function fromArrayBufferToBigInt(buffer: ArrayBuffer): bigint {
  return BigInt("0x" + Buffer.from(buffer).toString("hex"))
}

function getCurveName(ecParams: ECParameters): string {
  if (ecParams.namedCurve) {
    return CURVE_OIDS[ecParams.namedCurve as keyof typeof CURVE_OIDS] ?? ""
  }
  if (!ecParams.specifiedCurve) {
    return ""
  }
  const a = fromArrayBufferToBigInt(ecParams.specifiedCurve.curve.a)
  const b = fromArrayBufferToBigInt(ecParams.specifiedCurve.curve.b)
  const n = fromArrayBufferToBigInt(ecParams.specifiedCurve.order)
  const p = fromArrayBufferToBigInt(ecParams.specifiedCurve.fieldID.parameters.slice(2))

  if (a == p256.CURVE.a && b == p256.CURVE.b && n == p256.CURVE.n && p == p256.CURVE.p) {
    return "P-256"
  } else if (a == p384.CURVE.a && b == p384.CURVE.b && n == p384.CURVE.n && p == p384.CURVE.p) {
    return "P-384"
  } else if (a == p521.CURVE.a && b == p521.CURVE.b && n == p521.CURVE.n && p == p521.CURVE.p) {
    return "P-521"
  }

  for (const key in BRAINPOOL_CURVES) {
    if (
      a == BRAINPOOL_CURVES[key as keyof typeof BRAINPOOL_CURVES].a &&
      b == BRAINPOOL_CURVES[key as keyof typeof BRAINPOOL_CURVES].b &&
      n == BRAINPOOL_CURVES[key as keyof typeof BRAINPOOL_CURVES].n &&
      p == BRAINPOOL_CURVES[key as keyof typeof BRAINPOOL_CURVES].p
    ) {
      return key
    }
  }

  return `unknown curve`
}

export function getECDSAInfo(tbsCertificate: TBSCertificate): {
  curve: string
  publicKey: Uint8Array
} {
  const parsedParams = AsnParser.parse(
    tbsCertificate.subjectPublicKeyInfo.algorithm.parameters!,
    ECParameters,
  )
  return {
    curve: getCurveName(parsedParams),
    publicKey: new Uint8Array(tbsCertificate!.subjectPublicKeyInfo.subjectPublicKey),
  }
}

export function getRSAInfo(tbsCertificate: TBSCertificate): {
  modulus: bigint
  exponent: bigint
  type: "pkcs" | "pss"
} {
  const parsedKey = AsnParser.parse(
    tbsCertificate.subjectPublicKeyInfo.subjectPublicKey!,
    RSAPublicKey,
  )
  const type =
    RSA_OIDS[tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm as keyof typeof RSA_OIDS] ?? ""
  return {
    modulus: fromArrayBufferToBigInt(parsedKey.modulus),
    exponent: fromArrayBufferToBigInt(parsedKey.publicExponent),
    type: type.includes("pss") ? "pss" : "pkcs",
  }
}

function getSignatureAlgorithmType(signatureAlgorithm: string): "RSA" | "ECDSA" | "" {
  if (signatureAlgorithm.toLowerCase().includes("rsa")) {
    return "RSA"
  } else if (signatureAlgorithm.toLowerCase().includes("ecdsa")) {
    return "ECDSA"
  }
  return ""
}

export function getSodSignatureAlgorithmType(passport: PassportViewModel): "RSA" | "ECDSA" | "" {
  if (passport.sodSignatureAlgorithm?.toLowerCase().includes("rsa")) {
    return "RSA"
  } else if (passport.sodSignatureAlgorithm?.toLowerCase().includes("ecdsa")) {
    return "ECDSA"
  }
  return ""
}

export function getDSCSignatureAlgorithmType(passport: PassportViewModel): "RSA" | "ECDSA" | "" {
  if (passport.dscSignatureAlgorithm?.toLowerCase().includes("rsa")) {
    return "RSA"
  } else if (passport.dscSignatureAlgorithm?.toLowerCase().includes("ecdsa")) {
    return "ECDSA"
  }
  return ""
}
