import { CSC } from "@/types"
import { getCertificateLeaves } from "./certificates"
import { computeMerkleProof } from "./merkle-tree"
import { redcLimbsFromBytes } from "./barrett-reduction"
import { padArrayWithZeros } from "./utils"
import { CERTIFICATE_REGISTRY_HEIGHT } from "./constants"

export async function generateCSCToDSCInputs(
  certificate: CSC,
  certificates: CSC[],
  tbsData: Buffer,
  signature: Buffer,
) {
  const leaves = getCertificateLeaves(certificates)
  const index = certificates.findIndex((cert) => cert === certificate)
  let merkleProof = await computeMerkleProof(CERTIFICATE_REGISTRY_HEIGHT, leaves, leaves[index])

  const csc_pubkey_redc_param = redcLimbsFromBytes(certificate.public_key)
  //console.log("csc_pubkey_redc_param", JSON.stringify(csc_pubkey_redc_param))
  //console.log("signature", JSON.stringify(signature.toFieldArray()))
  return {
    certificate_registry_root: merkleProof.root,
    certificate_registry_index: merkleProof.index,
    certificate_registry_hash_path: merkleProof.path,
    certificate_registry_id: 1,
    salt: 0,
    country: certificate.issuing_country,
    tbs_certificate: padArrayWithZeros(Array.from(tbsData), 1500),
    tbs_certificate_len: tbsData.length,
    csc_pubkey: certificate.public_key,
    csc_pubkey_redc_param: csc_pubkey_redc_param,
    dsc_signature: signature.toFieldArray(),
    exponent: certificate.exponent,
  }
}
