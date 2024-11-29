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

export type CSC = {
  authority_key_identifier: string
  issuing_country: string
  signature_algorithm:
    | string
    | "sha1-with-rsa-signature"
    | "sha256WithRSAEncryption"
    | "sha384WithRSAEncryption"
    | "sha512WithRSAEncryption"
    | "rsassa-pss"
    | "ecdsa-with-SHA1"
    | "ecdsa-with-SHA256"
    | "ecdsa-with-SHA384"
    | "ecdsa-with-SHA512"
  key_size: number
  private_key: string
  public_key: number[]
  exponent: number
  private_key_usage_period: {
    not_after: number
    not_before: number
  }
  validity: {
    not_after: number
    not_before: number
  }
}

export type CSCMasterlist = {
  certificates: CSC[]
}
