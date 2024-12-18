import type { Alpha2Code, Alpha3Code, CountryName } from "i18n-iso-countries"
import type { SOD } from "@/lib/passport-reader"

export type SavedPassport = {
  id: string
  name: string
}

export type MySettings = {
  activePassport: string
  passports: SavedPassport[]
  showResetDataButton: boolean
}

export type DataGroupInfo = {
  groupNumber: number
  name: string
  hash: number[]
  value: number[]
}

export type PassportViewModel = {
  mrz: string
  name: string
  dateOfBirth: string
  nationality: string
  gender: string
  passportNumber: string
  passportExpiry: string
  firstName: string
  lastName: string
  photo: string
  originalPhoto: string

  chipAuthSupported: boolean
  chipAuthSuccess: boolean
  chipAuthFailed: boolean

  LDSVersion: string

  dataGroups: DataGroupInfo[]
  dataGroupsHashAlgorithm: string

  // Matches the subject key identifier of the CSC
  dscAuthorityKeyIdentifier?: string
  dscDistinguishedName?: string
  dscCountry?: string
  dscValidity?: { notBefore: Date; notAfter: Date }
  dscSignatureAlgorithm?: string
  dscPublicKeyAlgorithm?: string
  dscSignature?: number[]

  sod: SOD
  sodSignatureAlgorithm?: string
  sodSignature: number[]
  sodVersion: string
  eContent: number[]
  eContentHash: string
  eContentHashAlgorithm: string
  signedAttributesHashAlgorithm: string
  signedAttributes: number[]
  tbsCertificate: number[]
  appVersion: string
}

export type RSACertificate = {
  signatureAlgorithm?: string
  issuer?: string
  modulus?: string // Using string to represent BigUInt
  exponent?: number
}

export type SubmitProofResponse = {
  success: boolean
  message?: string
  error?: string
  code?: string
  country?: string
}

export type ScanRequestResponse = {
  success: boolean
  message?: string
  code?: string
}

export type ParameterKind = "string" | "array" | "struct" | "field" | "integer"

export type ParameterType = {
  kind: ParameterKind
  length?: number
  type?: ParameterType
  fields?: Parameter[]
}

export type Parameter = {
  name: string
  type: ParameterType
  visibility: "private" | "public"
}

export type Circuit = {
  noir_version: `${number}.${number}.${number}+${string}`
  hash: number
  abi: {
    parameters: Parameter[]
    param_witnesses: {
      [key: string]: { start: number; end: number }[]
    }
    return_type: any
    return_witnesses: any[]
    error_types: any
  }
  bytecode: string
  debug_symbols: string
  file_map: {
    [key: string]: {
      source: string
      path: string
    }
  }
  names: string[]
}

export type DisclosableIDCredential =
  | "birthdate"
  | "expiry_date"
  | "nationality"
  | "firstname"
  | "lastname"
  | "fullname"
  | "document_number"
  | "document_type"
  | "issuing_country"
  | "gender"

export type NumericalIDCredential = "age" | "birthdate" | "expiry_date"

export type IDCredential = NumericalIDCredential | DisclosableIDCredential
export type IDCredentialValue<T extends IDCredential> = T extends "nationality" | "issuing_country"
  ? CountryName<{ select: "all" }> | Alpha2Code | Alpha3Code
  : T extends "gender"
  ? "male" | "female"
  : T extends "document_type"
  ? "passport" | "id_card" | "residence_permit" | "other"
  : T extends NumericalIDCredential
  ? number | Date
  : string

export type IDCredentialConfig = {
  eq?: any
  gte?: number | Date
  gt?: number | Date
  lte?: number | Date
  lt?: number | Date
  range?: [number | Date, number | Date]
  in?: any[]
  out?: any[]
  disclose?: boolean
}

export type QueryResultValue = {
  eq?: {
    expected: any
    result: boolean
  }
  gte?: {
    expected: number | Date
    result: boolean
  }
  gt?: {
    expected: number | Date
    result: boolean
  }
  lte?: {
    expected: number | Date
    result: boolean
  }
  lt?: {
    expected: number | Date
    result: boolean
  }
  range?: {
    expected: [number | Date, number | Date]
    result: boolean
  }
  in?: {
    expected: any[]
    result: boolean
  }
  out?: {
    expected: any[]
    result: boolean
  }
  disclose?: {
    result: any
  }
}

export type Query = {
  [key in IDCredential]?: IDCredentialConfig
}

export type QueryResult = {
  [key in IDCredential]?: QueryResultValue
}

export type ProofResult = {
  queryResult: QueryResult
  proof?: string
  verificationKey?: string
}

export type Service = {
  name: string
  logo: string
  purpose: string
}

export type QRCodeData = {
  query: Query | null
  topic: string | null
  pubkey: string | null
  domain: string | null
  service: Service | null
}

export interface JsonRpcRequest {
  jsonrpc: string
  id: string
  origin?: string
  method: string
  params: any
}

export interface JsonRpcResponse {
  jsonrpc: string
  id: string
  result: any
}

export type PassportReaderEvent =
  | "SCAN_STARTED"
  | "PACE_STARTED"
  | "PACE_SUCCEEDED"
  | "PACE_FAILED"
  | "BAC_STARTED"
  | "BAC_SUCCEEDED"
  | "BAC_FAILED"
  | "GET_COM_STARTED"
  | "GET_COM_SUCCEEDED"
  | "GET_COM_FAILED"
  | "GET_SOD_STARTED"
  | "GET_SOD_SUCCEEDED"
  | "GET_DG1_STARTED"
  | "GET_DG1_SUCCEEDED"
  | "GET_DG2_STARTED"
  | "GET_DG2_SUCCEEDED"
  | "GET_DG5_STARTED"
  | "GET_DG5_SUCCEEDED"
  | "GET_DG5_FAILED"
  | "GET_DG7_STARTED"
  | "GET_DG7_SUCCEEDED"
  | "GET_DG7_FAILED"
  | "GET_DG11_STARTED"
  | "GET_DG11_SUCCEEDED"
  | "GET_DG11_FAILED"
  | "GET_DG12_STARTED"
  | "GET_DG12_SUCCEEDED"
  | "GET_DG12_FAILED"
  | "GET_DG13_STARTED"
  | "GET_DG13_SUCCEEDED"
  | "GET_DG13_FAILED"
  | "GET_DG14_STARTED"
  | "GET_DG14_SUCCEEDED"
  | "GET_DG14_FAILED"
  | "GET_DG15_STARTED"
  | "GET_DG15_SUCCEEDED"
  | "GET_DG15_FAILED"
  | "PREP_DATA"
  | "GET_PHOTO_STARTED"
  | "GET_PHOTO_SUCCEEDED"
  | "PASSPORT_READ_FAILED"

export type IDDataInputs = {
  e_content: number[]
  e_content_size: number
  dg1_offset_in_e_content: number
  signed_attributes: number[]
  signed_attributes_size: number
  dg1: number[]
}

export type ECDSADSCDataInputs = {
  tbs_certificate: number[]
  pubkey_offset_in_tbs: number
  dsc_pubkey_x: number[]
  dsc_pubkey_y: number[]
}

export type RSADSCDataInputs = {
  tbs_certificate: number[]
  pubkey_offset_in_tbs: number
  dsc_pubkey: number[]
  exponent: number
  dsc_pubkey_redc_param: number[]
}

export type SignatureAlgorithm =
  | "sha1-with-rsa-signature"
  | "sha256WithRSAEncryption"
  | "sha384WithRSAEncryption"
  | "sha512WithRSAEncryption"
  | "rsassa-pss"
  | "ecdsa-with-SHA1"
  | "ecdsa-with-SHA256"
  | "ecdsa-with-SHA384"
  | "ecdsa-with-SHA512"

export type ECDSACSCPublicKey = {
  type: "ecPublicKey"
  curve: string
  public_key_x: string
  public_key_y: string
}

export type RSACSCPublicKey = {
  type: "rsaEncryption"
  modulus: string
  exponent: number
  scheme: "pkcs" | "pss"
}

export type Certificate = {
  signature_algorithm: SignatureAlgorithm
  public_key: RSACSCPublicKey | ECDSACSCPublicKey
  country: Alpha3Code
  validity: {
    not_before: number
    not_after: number
  }
  key_size: number
  authority_key_identifier?: string
  subject_key_identifier?: string
  private_key_usage_period?: {
    not_before?: number
    not_after?: number
  }
}

export type CSCMasterlist = {
  certificates: Certificate[]
}
