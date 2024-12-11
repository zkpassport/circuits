import cscMasterlistFile from "@/assets/certificates/csc-masterlist.json"
import {
  CERTIFICATE_PAD_EMPTY_LEAVES,
  CERTIFICATE_REGISTRY_HEIGHT,
  CERTIFICATE_REGISTRY_ID,
  DG1_INPUT_SIZE,
  SIGNED_ATTR_INPUT_SIZE,
} from "@/lib/constants"
import { computeMerkleProof } from "@/lib/merkle-tree"
import {
  CSC,
  CSCMasterlist,
  ECDSACSCPublicKey,
  ECDSADSCDataInputs,
  IDCredential,
  IDDataInputs,
  PassportViewModel,
  Query,
  RSACSCPublicKey,
  RSADSCDataInputs,
} from "@/types"
import { bytesToHex } from "@noble/hashes/utils"
import { AsnParser } from "@peculiar/asn1-schema"
import { AuthorityKeyIdentifier, PrivateKeyUsagePeriod } from "@peculiar/asn1-x509"
import { format } from "date-fns"
import { redcLimbsFromBytes } from "./barrett-reduction"
import { Binary } from "./binary"
import {
  calculatePrivateNullifier,
  getCertificateLeafHash,
  hashSaltCountrySignedAttrDg1PrivateNullifier,
  hashSaltCountryTbs,
  hashSaltDg1PrivateNullifier,
} from "./circuits"
import {
  extractTBS,
  getDSCSignatureAlgorithmType,
  getECDSAInfo,
  getRSAInfo,
  getSodSignatureAlgorithmType,
} from "./passport-reader/passport-reader"
import {
  bigintToBytes,
  bigintToNumber,
  getBitSize,
  getOffsetInArray,
  padArrayWithZeros,
} from "./utils"

export function isSignatureAlgorithmSupported(
  passport: PassportViewModel,
  signatureAlgorithm: "RSA" | "ECDSA" | "",
): boolean {
  const tbsCertificate = extractTBS(passport)
  if (!tbsCertificate) {
    return false
  }
  if (signatureAlgorithm === "ECDSA") {
    const ecdsaInfo = getECDSAInfo(tbsCertificate)
    return ecdsaInfo.curve === "P-256"
  } else if (signatureAlgorithm === "RSA") {
    const rsaInfo = getRSAInfo(tbsCertificate)
    const modulusBits = getBitSize(rsaInfo.modulus)
    return (
      (modulusBits === 1024 ||
        modulusBits === 2048 ||
        modulusBits === 3072 ||
        modulusBits === 4096) &&
      (rsaInfo.exponent === 3n || rsaInfo.exponent === 65537n)
    )
  }
  return false
}

export function isDocumentSODSupported(passport: PassportViewModel): boolean {
  const signatureAlgorithm = getSodSignatureAlgorithmType(passport)
  return isSignatureAlgorithmSupported(passport, signatureAlgorithm)
}

export function isDocumentDSCSupported(passport: PassportViewModel): boolean {
  const signatureAlgorithm = getDSCSignatureAlgorithmType(passport)
  return isSignatureAlgorithmSupported(passport, signatureAlgorithm)
}

export function getCSCMasterlist(): CSCMasterlist {
  return cscMasterlistFile
}

export function getCSCForPassport(passport: PassportViewModel): CSC | null {
  const tbsCertificate = extractTBS(passport)
  const cscMasterlist = getCSCMasterlist()
  const extensions = tbsCertificate?.extensions

  const privateKeyUsagePeriodOID = "2.5.29.16"
  const privateKeyUsagePeriod = AsnParser.parse(
    extensions?.find((ext: any) => ext.extnID === privateKeyUsagePeriodOID)
      ?.extnValue as BufferSource,
    PrivateKeyUsagePeriod,
  )
  const notBefore = (privateKeyUsagePeriod?.notBefore?.getTime() || 0) / 1000
  const notAfter = (privateKeyUsagePeriod?.notAfter?.getTime() || 0) / 1000

  // TODO: Get this from TBS certificate instead of DG1
  const country = passport?.nationality === "D<<" ? "DEU" : passport?.nationality

  const authorityKeyIdentifierOID = "2.5.29.35"
  const authorityKeyIdentifier = AsnParser.parse(
    extensions?.find((ext: any) => ext.extnID === authorityKeyIdentifierOID)
      ?.extnValue as BufferSource,
    AuthorityKeyIdentifier,
  )
  const formattedKeyIdentifier = bytesToHex(
    new Uint8Array(authorityKeyIdentifier.keyIdentifier?.buffer ?? []),
  )

  const checkAgainstPrivateKeyUsagePeriod = (cert: CSC) => {
    return (
      cert.private_key_usage_period &&
      cert.private_key_usage_period?.not_before &&
      cert.private_key_usage_period?.not_after &&
      notBefore >= (cert.private_key_usage_period?.not_before || 0) &&
      notAfter <= (cert.private_key_usage_period?.not_after || 0)
    )
  }

  const checkAgainstAuthorityKeyIdentifier = (cert: CSC) => {
    return cert.subject_key_identifier?.replace("0x", "") === formattedKeyIdentifier
  }

  const certificate = cscMasterlist.certificates.find((cert) => {
    return (
      cert.country.toLowerCase() === country.toLowerCase() &&
      (checkAgainstAuthorityKeyIdentifier(cert) || checkAgainstPrivateKeyUsagePeriod(cert))
    )
  })
  if (!certificate) {
    console.warn(
      `Could not find CSC for DSC. Country: ${country} Key identifier: ${formattedKeyIdentifier}`,
    )
  }
  return certificate ?? null
}

function getDSCDataInputs(
  passport: PassportViewModel,
): ECDSADSCDataInputs | RSADSCDataInputs | null {
  const signatureAlgorithm = getSodSignatureAlgorithmType(passport)
  const tbsCertificate = extractTBS(passport)
  if (!tbsCertificate) {
    return null
  }
  if (signatureAlgorithm === "ECDSA") {
    const ecdsaInfo = getECDSAInfo(tbsCertificate)
    return {
      tbs_certificate: padArrayWithZeros(passport?.tbsCertificate ?? [], 1500),
      pubkey_offset_in_tbs: getOffsetInArray(
        passport?.tbsCertificate ?? [],
        Array.from(ecdsaInfo.publicKey.slice(0, 32)),
      ),
      dsc_pubkey_x: Array.from(ecdsaInfo.publicKey.slice(0, 32)),
      dsc_pubkey_y: Array.from(ecdsaInfo.publicKey.slice(32)),
    }
  } else {
    const { modulus, exponent } = getRSAInfo(tbsCertificate)
    const modulusBytes = bigintToBytes(modulus)
    return {
      dsc_pubkey: modulusBytes,
      exponent: bigintToNumber(exponent),
      dsc_pubkey_redc_param: redcLimbsFromBytes(modulusBytes),
      tbs_certificate: padArrayWithZeros(passport?.tbsCertificate ?? [], 1500),
      pubkey_offset_in_tbs: getOffsetInArray(passport?.tbsCertificate ?? [], modulusBytes),
    }
  }
}

function getIDDataInputs(passport: PassportViewModel): IDDataInputs {
  const dg1 = passport?.dataGroups.find((dg) => dg.groupNumber === 1)
  const dg1Offset = getOffsetInArray(passport?.eContent ?? [], dg1?.hash ?? [])
  const id_data = {
    // Padded with 0s to make it 700 bytes
    e_content: padArrayWithZeros(passport?.eContent ?? [], 700),
    e_content_size: passport?.eContent?.length ?? 0,
    dg1_offset_in_e_content: dg1Offset,
    // Padded to 200 bytes with 0s
    signed_attributes: padArrayWithZeros(passport?.signedAttributes ?? [], 200),
    signed_attributes_size: passport?.signedAttributes?.length ?? 0,
    // Padded to 95 bytes with 0s
    dg1: padArrayWithZeros(dg1?.value ?? [], 95),
  }
  return id_data
}

export async function getDSCCircuitInputs(passport: PassportViewModel): Promise<any> {
  const csc = getCSCForPassport(passport)
  if (!csc) return null

  const cscMasterlist = getCSCMasterlist()
  const leaves = cscMasterlist.certificates.map((l) => Binary.fromHex(getCertificateLeafHash(l)))
  const index = cscMasterlist.certificates.findIndex((l) => l === csc)
  // Fill up leaves to CERTIFICATE_PAD_EMPTY_LEAVES
  const emptyLeavesNeeded = CERTIFICATE_PAD_EMPTY_LEAVES - leaves.length
  if (emptyLeavesNeeded > 0) {
    const emptyLeaves = Array(emptyLeavesNeeded).fill(Binary.fromHex("00".repeat(32)))
    leaves.push(...emptyLeaves)
  }
  const merkleProof = await computeMerkleProof(CERTIFICATE_REGISTRY_HEIGHT, leaves, index)

  const inputs = {
    certificate_registry_root: merkleProof.root,
    certificate_registry_index: merkleProof.index,
    certificate_registry_hash_path: merkleProof.path,
    certificate_registry_id: CERTIFICATE_REGISTRY_ID,
    certificate_type: 1,
    country: csc.country,
  }

  const signatureAlgorithm = getDSCSignatureAlgorithmType(passport)
  if (signatureAlgorithm === "ECDSA") {
    const cscPublicKey = csc?.public_key as ECDSACSCPublicKey
    const publicKeyXBytes = Buffer.from(cscPublicKey.public_key_x ?? "", "hex")
    const publicKeyYBytes = Buffer.from(cscPublicKey.public_key_y ?? "", "hex")
    return {
      ...inputs,
      csc_pubkey_x: Array.from(publicKeyXBytes),
      csc_pubkey_y: Array.from(publicKeyYBytes),
      dsc_signature: passport?.dscSignature ?? [],
      tbs_certificate: padArrayWithZeros(passport?.tbsCertificate ?? [], 1500),
      tbs_certificate_len: passport?.tbsCertificate?.length,
    }
  } else if (signatureAlgorithm === "RSA") {
    const cscPublicKey = csc?.public_key as RSACSCPublicKey
    const modulusBytes = bigintToBytes(BigInt(cscPublicKey.modulus))
    return {
      ...inputs,
      tbs_certificate: padArrayWithZeros(passport?.tbsCertificate ?? [], 1500),
      tbs_certificate_len: passport?.tbsCertificate?.length,
      dsc_signature: passport?.dscSignature ?? [],
      csc_pubkey: modulusBytes,
      csc_pubkey_redc_param: redcLimbsFromBytes(modulusBytes),
      exponent: cscPublicKey.exponent,
    }
  }
}

export function getIDDataCircuitInputs(passport: PassportViewModel): any {
  const idData = getIDDataInputs(passport)
  const dscData = getDSCDataInputs(passport)
  if (!dscData || !idData) return null

  const commIn = hashSaltCountryTbs(
    0n,
    passport.nationality, // TODO: Use country from CSC/DSC here
    Binary.from(passport.tbsCertificate),
  )

  const inputs = {
    dg1: idData.dg1,
    signed_attributes: idData.signed_attributes,
    signed_attributes_size: idData.signed_attributes_size,
    e_content: idData.e_content,
    e_content_size: idData.e_content_size,
    dg1_offset_in_e_content: idData.dg1_offset_in_e_content,
    comm_in: commIn.toHex(),
  }

  const signatureAlgorithm = getSodSignatureAlgorithmType(passport)
  if (signatureAlgorithm === "ECDSA") {
    return {
      ...inputs,
      tbs_certificate: dscData.tbs_certificate,
      pubkey_offset_in_tbs: dscData.pubkey_offset_in_tbs,
      dsc_pubkey_x: (dscData as ECDSADSCDataInputs).dsc_pubkey_x,
      dsc_pubkey_y: (dscData as ECDSADSCDataInputs).dsc_pubkey_y,
      sod_signature: passport?.sodSignature ?? [],
      signed_attributes: idData.signed_attributes,
      signed_attributes_size: idData.signed_attributes_size,
    }
  } else if (signatureAlgorithm === "RSA") {
    return {
      ...inputs,
      dsc_pubkey: (dscData as RSADSCDataInputs).dsc_pubkey,
      exponent: (dscData as RSADSCDataInputs).exponent,
      sod_signature: passport?.sodSignature ?? [],
      dsc_pubkey_redc_param: (dscData as RSADSCDataInputs).dsc_pubkey_redc_param,
      tbs_certificate: (dscData as RSADSCDataInputs).tbs_certificate,
      pubkey_offset_in_tbs: (dscData as RSADSCDataInputs).pubkey_offset_in_tbs,
      signed_attributes: idData.signed_attributes,
      signed_attributes_size: idData.signed_attributes_size,
    }
  }
}

export function getIntegrityCheckCircuitInputs(passport: PassportViewModel): any {
  const dscData = getDSCDataInputs(passport)
  if (!dscData) return null
  const idData = getIDDataInputs(passport)
  if (!idData) return null

  const privateNullifier = calculatePrivateNullifier(
    Binary.from(idData.dg1).padEnd(DG1_INPUT_SIZE),
    Binary.from(passport.sodSignature),
  )
  const comm_in = hashSaltCountrySignedAttrDg1PrivateNullifier(
    0n,
    passport.nationality, // TODO: Use country from CSC/DSC here
    Binary.from(passport.signedAttributes).padEnd(SIGNED_ATTR_INPUT_SIZE),
    BigInt(passport.signedAttributes.length),
    Binary.from(idData.dg1).padEnd(DG1_INPUT_SIZE),
    privateNullifier.toBigInt(),
  )

  return {
    current_date: format(new Date(), "yyyyMMdd"),
    dg1: idData.dg1,
    signed_attributes: idData.signed_attributes,
    signed_attributes_size: idData.signed_attributes_size,
    e_content: idData.e_content,
    e_content_size: idData.e_content_size,
    dg1_offset_in_e_content: idData.dg1_offset_in_e_content,
    comm_in: comm_in,
    private_nullifier: privateNullifier.toHex(),
  }
}

export function getFirstNameRange(passport: PassportViewModel): [number, number] {
  const mrz = passport?.mrz
  const isIDCard = mrz.length == 90
  const lastNameStartIndex = isIDCard ? 60 : 5
  const firstNameStartIndex = getOffsetInArray(mrz.split(""), ["<", "<"], lastNameStartIndex) + 2
  const firstNameEndIndex = getOffsetInArray(mrz.split(""), ["<", "<"], firstNameStartIndex)
  return [firstNameStartIndex, firstNameEndIndex]
}

export function getLastNameRange(passport: PassportViewModel): [number, number] {
  const mrz = passport?.mrz
  const isIDCard = mrz.length == 90
  const lastNameStartIndex = isIDCard ? 60 : 5
  const lastNameEndIndex = getOffsetInArray(mrz.split(""), ["<", "<"], lastNameStartIndex)
  return [lastNameStartIndex, lastNameEndIndex]
}

export function getFullNameRange(passport: PassportViewModel): [number, number] {
  const mrz = passport?.mrz
  const isIDCard = mrz.length == 90
  return [isIDCard ? 60 : 5, isIDCard ? 90 : 44]
}

function getBirthdateRange(passport: PassportViewModel): [number, number] {
  const mrz = passport?.mrz
  const isIDCard = mrz.length == 90
  return [isIDCard ? 30 : 57, isIDCard ? 36 : 63]
}

function getDocumentNumberRange(passport: PassportViewModel): [number, number] {
  const mrz = passport?.mrz
  const isIDCard = mrz.length == 90
  return [isIDCard ? 5 : 44, isIDCard ? 14 : 53]
}

function getNationalityRange(passport: PassportViewModel): [number, number] {
  const mrz = passport?.mrz
  const isIDCard = mrz.length == 90
  return [isIDCard ? 45 : 54, isIDCard ? 48 : 57]
}

function getExpiryDateRange(passport: PassportViewModel): [number, number] {
  const mrz = passport?.mrz
  const isIDCard = mrz.length == 90
  return [isIDCard ? 38 : 65, isIDCard ? 44 : 71]
}

function getGenderRange(passport: PassportViewModel): [number, number] {
  const mrz = passport?.mrz
  const isIDCard = mrz.length == 90
  return [isIDCard ? 37 : 64, isIDCard ? 38 : 65]
}

export function getDiscloseCircuitInputs(passport: PassportViewModel, query: Query): any {
  const idData = getIDDataInputs(passport)
  if (!idData) return null
  const privateNullifier = calculatePrivateNullifier(
    Binary.from(idData.dg1).padEnd(DG1_INPUT_SIZE),
    Binary.from(passport.sodSignature),
  )
  const commIn = hashSaltDg1PrivateNullifier(
    0n,
    Binary.from(idData.dg1).padEnd(DG1_INPUT_SIZE),
    privateNullifier.toBigInt(),
  )

  const discloseMask = Array(90).fill(0)
  let fieldsToDisclose: { [key in IDCredential]: boolean } = {} as any
  for (const field in query) {
    if (query[field as IDCredential]?.disclose) {
      fieldsToDisclose[field as IDCredential] = true
    }
  }
  for (const field in fieldsToDisclose) {
    if (fieldsToDisclose[field as IDCredential]) {
      switch (field as IDCredential) {
        case "firstname":
          const firstNameRange = getFirstNameRange(passport)
          discloseMask.fill(1, firstNameRange[0], firstNameRange[1])
          break
        case "lastname":
          const lastNameRange = getLastNameRange(passport)
          discloseMask.fill(1, lastNameRange[0], lastNameRange[1])
          break
        case "fullname":
          const fullNameRange = getFullNameRange(passport)
          discloseMask.fill(1, fullNameRange[0], fullNameRange[1])
          break
        case "birthdate":
          const birthdateRange = getBirthdateRange(passport)
          discloseMask.fill(1, birthdateRange[0], birthdateRange[1])
          break
        case "document_number":
          const documentNumberRange = getDocumentNumberRange(passport)
          discloseMask.fill(1, documentNumberRange[0], documentNumberRange[1])
          break
        case "nationality":
          const nationalityRange = getNationalityRange(passport)
          discloseMask.fill(1, nationalityRange[0], nationalityRange[1])
          break
        case "document_type":
          discloseMask.fill(1, 0, 2)
          break
        case "expiry_date":
          const expiryDateRange = getExpiryDateRange(passport)
          discloseMask.fill(1, expiryDateRange[0], expiryDateRange[1])
          break
        case "gender":
          const genderRange = getGenderRange(passport)
          discloseMask.fill(1, genderRange[0], genderRange[1])
          break
        case "issuing_country":
          discloseMask.fill(1, 2, 5)
          break
      }
    }
  }
  return {
    dg1: idData.dg1,
    disclose_mask: discloseMask,
    comm_in: commIn.toHex(),
    private_nullifier: privateNullifier.toHex(),
    service_scope: 0,
    service_subscope: 0,
  }
}
