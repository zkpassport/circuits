import { AsnParser } from "@peculiar/asn1-schema"
import {
  PrivateKeyUsagePeriod,
  TBSCertificate,
  Certificate as X509Certificate,
} from "@peculiar/asn1-x509"
import { ECParameters } from "@peculiar/asn1-ecc"
import { RSAPublicKey } from "@peculiar/asn1-rsa"
import { p256 } from "@noble/curves/p256"
import { p384 } from "@noble/curves/p384"
import { p521 } from "@noble/curves/p521"
import { alpha2ToAlpha3, Alpha3Code } from "i18n-iso-countries"
import { Certificate, SignatureAlgorithm } from "@/types"

const OIDS_TO_DESCRIPTION: Record<string, string> = {
  "1.2.840.113549.1.1.1": "rsaEncryption",
  "1.2.840.10045.2.1": "ecPublicKey",
  "1.2.840.113549.1.1.5": "sha1-with-rsa-signature",
  "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
  "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
  "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
  "1.2.840.113549.1.1.10": "rsassa-pss",
  "1.2.840.10045.4.1": "ecdsa-with-SHA1",
  "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
  "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
  "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
}

const CURVE_OIDS = {
  "1.2.840.10045.3.1.7": "P-256",
  "1.3.132.0.34": "P-384",
  "1.3.132.0.35": "P-521",
  "1.3.36.3.3.2.8.1.1.1": "BrainpoolP160r1",
  "1.3.36.3.3.2.8.1.1.2": "BrainpoolP160t1",
  "1.3.36.3.3.2.8.1.1.3": "BrainpoolP192r1",
  "1.3.36.3.3.2.8.1.1.4": "BrainpoolP192t1",
  "1.3.36.3.3.2.8.1.1.5": "BrainpoolP224r1",
  "1.3.36.3.3.2.8.1.1.6": "BrainpoolP224t1",
  "1.3.36.3.3.2.8.1.1.7": "BrainpoolP256r1",
  "1.3.36.3.3.2.8.1.1.8": "BrainpoolP256t1",
  "1.3.36.3.3.2.8.1.1.9": "BrainpoolP320r1",
  "1.3.36.3.3.2.8.1.1.10": "BrainpoolP320t1",
  "1.3.36.3.3.2.8.1.1.11": "BrainpoolP384r1",
  "1.3.36.3.3.2.8.1.1.12": "BrainpoolP384t1",
  "1.3.36.3.3.2.8.1.1.13": "BrainpoolP512r1",
  "1.3.36.3.3.2.8.1.1.14": "BrainpoolP512t1",
}

const BRAINPOOL_CURVES = {
  BrainpoolP160r1: {
    a: 0x340e7be2a280eb74e2be61bada745d97e8f7c300n,
    b: 0x1e589a8595423412134faa2dbdec95c8d8675e58n,
    n: 0xe95e4a5f737059dc60df5991d45029409e60fc09n,
    p: 0xe95e4a5f737059dc60dfc7ad95b3d8139515620fn,
  },
  brainpoolP160t1: {
    a: 0xe95e4a5f737059dc60dfc7ad95b3d8139515620cn,
    b: 0x7a556b6dae535b7b51ed2c4d7daa7a0b5c55f380n,
    n: 0xe95e4a5f737059dc60df5991d45029409e60fc09n,
    p: 0xe95e4a5f737059dc60dfc7ad95b3d8139515620fn,
  },
  brainpoolP192r1: {
    a: 0x6a91174076b1e0e19c39c031fe8685c1cae040e5c69a28efn,
    b: 0x469a28ef7c28cca3dc721d044f4496bcca7ef4146fbf25c9n,
    n: 0xc302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1n,
    p: 0xc302f41d932a36cda7a3463093d18db78fce476de1a86297n,
  },
  brainpoolP192t1: {
    a: 0xc302f41d932a36cda7a3463093d18db78fce476de1a86294n,
    b: 0x13d56ffaec78681e68f9deb43b35bec2fb68542e27897b79n,
    n: 0xc302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1n,
    p: 0xc302f41d932a36cda7a3463093d18db78fce476de1a86297n,
  },
  brainpoolP224r1: {
    a: 0x68a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43n,
    b: 0x2580f63ccfe44138870713b1a92369e33e2135d266dbb372386c400bn,
    n: 0xd7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939fn,
    p: 0xd7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ffn,
  },
  brainpoolP224t1: {
    a: 0xd7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0fcn,
    b: 0x4b337d934104cd7bef271bf60ced1ed20da14c08b3bb64f18a60888dn,
    n: 0xd7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939fn,
    p: 0xd7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ffn,
  },
  brainpoolP256r1: {
    a: 0x7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9n,
    b: 0x26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6n,
    n: 0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7n,
    p: 0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377n,
  },
  brainpoolP256t1: {
    a: 0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5374n,
    b: 0x662c61c430d84ea4fe66a7733d0b76b7bf93ebc4af2f49256ae58101fee92b04n,
    n: 0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7n,
    p: 0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377n,
  },
  brainpoolP320r1: {
    a: 0x3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f492f375a97d860eb4n,
    b: 0x520883949dfdbc42d3ad198640688a6fe13f41349554b49acc31dccd884539816f5eb4ac8fb1f1a6n,
    n: 0xd35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311n,
    p: 0xd35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27n,
  },
  brainpoolP320t1: {
    a: 0xd35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e24n,
    b: 0xa7f561e038eb1ed560b3d147db782013064c19f27ed27c6780aaf77fb8a547ceb5b4fef422340353n,
    n: 0xd35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311n,
    p: 0xd35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27n,
  },
  brainpoolP384r1: {
    a: 0x7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826n,
    b: 0x4a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11n,
    n: 0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565n,
    p: 0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53n,
  },
  brainpoolP384t1: {
    a: 0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec50n,
    b: 0x7f519eada7bda81bd826dba647910f8c4b9346ed8ccdc64e4b1abd11756dce1d2074aa263b88805ced70355a33b471een,
    n: 0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565n,
    p: 0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53n,
  },
  brainpoolP512r1: {
    a: 0x7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94can,
    b: 0x3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723n,
    n: 0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069n,
    p: 0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3n,
  },
  brainpoolP512t1: {
    a: 0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3n,
    b: 0x7cbbbcf9441cfab76e1890e46884eae321f70c0bcb4981527897504bec3e36a62bcdfa2304976540f6450085f2dae145c22553b465763689180ea2571867423en,
    n: 0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069n,
    p: 0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3n,
  },
}

export function getCurveName(ecParams: ECParameters): string {
  if (ecParams.namedCurve) {
    return CURVE_OIDS[ecParams.namedCurve as keyof typeof CURVE_OIDS] ?? ""
  }
  if (!ecParams.specifiedCurve) {
    return ""
  }
  const a = BigInt(`0x${Buffer.from(ecParams.specifiedCurve.curve.a).toString("hex")}`)
  const b = BigInt(`0x${Buffer.from(ecParams.specifiedCurve.curve.b).toString("hex")}`)
  const n = BigInt(`0x${Buffer.from(ecParams.specifiedCurve.order).toString("hex")}`)
  const p = BigInt(
    `0x${Buffer.from(ecParams.specifiedCurve.fieldID.parameters.slice(2)).toString("hex")}`,
  )

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
} {
  try {
    const parsedKey = AsnParser.parse(
      tbsCertificate.subjectPublicKeyInfo.subjectPublicKey!,
      RSAPublicKey,
    )
    return {
      modulus: BigInt(`0x${Buffer.from(parsedKey.modulus).toString("hex")}`),
      exponent: BigInt(`0x${Buffer.from(parsedKey.publicExponent).toString("hex")}`),
    }
  } catch (e) {
    console.error("Error parsing RSA key:", e)
    return {
      modulus: BigInt(0),
      exponent: BigInt(0),
    }
  }
}

export function parseCertificate(content: Buffer | string): Certificate {
  if (typeof content === "string") {
    // Remove PEM headers and convert to binary
    const b64 = content.replace(/(-----(BEGIN|END) CERTIFICATE-----|[\n\r])/g, "")
    content = Buffer.from(b64, "base64")
  }
  // Parse using @peculiar/asn1-schema
  const x509 = AsnParser.parse(content, X509Certificate)

  // Extract common fields
  let countryCode: string = "Unknown"
  // Iterate over the issuer values to find the country code
  for (const val of x509.tbsCertificate.issuer.values()) {
    if (val[0].type === "2.5.4.6") {
      countryCode = val[0].value.printableString?.toUpperCase() ?? "Unknown"
      const temp = countryCode
      countryCode = alpha2ToAlpha3(countryCode) ?? "N/A"
      // Some country codes are re not ISO 3166-1 alpha-2 codes
      // or do not correspond to any specific nation (e.g. EU, UN)
      if (countryCode === "N/A" && !!temp) {
        countryCode = temp.length === 2 ? `${temp}_` : temp
      }
    }
  }
  const notBefore = Math.floor(
    new Date(x509.tbsCertificate.validity.notBefore.getTime()).getTime() / 1000,
  )
  const notAfter = Math.floor(
    new Date(x509.tbsCertificate.validity.notAfter.getTime()).getTime() / 1000,
  )

  // Get the public key
  const spkiAlgorithm =
    OIDS_TO_DESCRIPTION[
      x509.tbsCertificate.subjectPublicKeyInfo.algorithm
        .algorithm as keyof typeof OIDS_TO_DESCRIPTION
    ] ?? x509.tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm

  // Check if it's RSA by examining the algorithm identifier
  const isRSA = spkiAlgorithm.toLowerCase().includes("rsa")

  const signatureAlgorithm =
    OIDS_TO_DESCRIPTION[
      x509.tbsCertificate.signature.algorithm as keyof typeof OIDS_TO_DESCRIPTION
    ] ?? x509.tbsCertificate.signature.algorithm

  const publicKeyType =
    OIDS_TO_DESCRIPTION[
      x509.tbsCertificate.subjectPublicKeyInfo.algorithm
        .algorithm as keyof typeof OIDS_TO_DESCRIPTION
    ] ?? x509.tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm

  if (publicKeyType === "rsaEncryption") {
    const rsaInfo = getRSAInfo(x509.tbsCertificate)
    return {
      signature_algorithm: signatureAlgorithm as SignatureAlgorithm,
      public_key: {
        type: publicKeyType,
        modulus: `0x${rsaInfo.modulus.toString(16)}`,
        exponent: Number(rsaInfo.exponent),
        scheme: signatureAlgorithm.includes("pss") ? "pss" : "pkcs",
      },
      country: countryCode as Alpha3Code,
      validity: {
        not_before: notBefore,
        not_after: notAfter,
      },
      key_size: rsaInfo.modulus.toString(2).length,
      authority_key_identifier: getAuthorityKeyId(x509),
      subject_key_identifier: getSubjectKeyId(x509),
      private_key_usage_period: getPrivateKeyUsagePeriod(x509),
    }
  } else if (publicKeyType === "ecPublicKey") {
    const ecdsaInfo = getECDSAInfo(x509.tbsCertificate)
    return {
      signature_algorithm: signatureAlgorithm as SignatureAlgorithm,
      public_key: {
        type: publicKeyType,
        curve: ecdsaInfo.curve,
        // The first byte is 0x04, which is the prefix for uncompressed public keys
        // so we get rid of it
        public_key_x: `0x${Buffer.from(
          ecdsaInfo.publicKey.slice(1, ecdsaInfo.publicKey.length / 2 + 1),
        ).toString("hex")}`,
        public_key_y: `0x${Buffer.from(
          ecdsaInfo.publicKey.slice(ecdsaInfo.publicKey.length / 2 + 1),
        ).toString("hex")}`,
      },
      country: countryCode as Alpha3Code,
      validity: {
        not_before: notBefore,
        not_after: notAfter,
      },
      key_size: ((ecdsaInfo.publicKey.length - 1) / 2) * 8,
      authority_key_identifier: getAuthorityKeyId(x509),
      subject_key_identifier: getSubjectKeyId(x509),
      private_key_usage_period: getPrivateKeyUsagePeriod(x509),
    }
  } else {
    throw new Error("Unsupported public key type")
  }
}

export function parseCertificates(pemContent: string): Certificate[] {
  const certificates: Certificate[] = []
  try {
    // Split the PEM content into individual certificates
    const pemRegex = /(-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----)/g
    const matches = pemContent.match(pemRegex) || []

    for (const certPem of matches) {
      // Remove PEM headers and convert to binary
      const b64 = certPem.replace(/(-----(BEGIN|END) CERTIFICATE-----|[\n\r])/g, "")
      const binary = Buffer.from(b64, "base64")

      try {
        certificates.push(parseCertificate(binary))
      } catch (certError) {
        console.error("Error parsing individual certificate:", certError)
      }
    }
  } catch (error) {
    console.error("Error parsing certificates:", error)
  }

  return certificates
}

// Helper function to get Authority Key Identifier
function getAuthorityKeyId(cert: X509Certificate): string | undefined {
  const authKeyExt = cert.tbsCertificate.extensions?.find(
    (ext) => ext.extnID === "2.5.29.35", // Authority Key Identifier OID
  )

  if (authKeyExt?.extnValue) {
    // Remove the first two bytes of the authority key identifier
    return `0x${Buffer.from(authKeyExt.extnValue.buffer.slice(2)).toString("hex")}`
  }
  return undefined
}

function getSubjectKeyId(cert: X509Certificate): string | undefined {
  const subjKeyExt = cert.tbsCertificate.extensions?.find(
    (ext) => ext.extnID === "2.5.29.14", // Subject Key Identifier OID
  )

  if (subjKeyExt?.extnValue) {
    // Remove the first two bytes of the subject key identifier
    return `0x${Buffer.from(subjKeyExt.extnValue.buffer.slice(2)).toString("hex")}`
  }
  return undefined
}

// Helper function to get Private Key Usage Period
function getPrivateKeyUsagePeriod(
  cert: X509Certificate,
): { not_before?: number; not_after?: number } | undefined {
  const pkupExt = cert.tbsCertificate.extensions?.find(
    (ext) => ext.extnID === "2.5.29.16", // Private Key Usage Period OID
  )

  if (pkupExt?.extnValue) {
    const pkup = AsnParser.parse(pkupExt.extnValue, PrivateKeyUsagePeriod)
    return {
      not_before: pkup.notBefore ? Math.floor(pkup.notBefore.getTime() / 1000) : undefined,
      not_after: pkup.notAfter ? Math.floor(pkup.notAfter.getTime() / 1000) : undefined,
    }
  }
  return undefined
}
