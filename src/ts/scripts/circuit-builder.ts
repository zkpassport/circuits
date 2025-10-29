import * as fs from "fs"
import * as path from "path"
import { exec, execSync } from "child_process"
import { compileCircuit } from "../utils"
import { CERTIFICATE_REGISTRY_HEIGHT } from "@zkpassport/utils"
import { sign } from "crypto"

// Function to ensure directory exists
function ensureDirectoryExistence(filePath: string) {
  try {
    fs.mkdirSync(path.dirname(filePath), { recursive: true })
  } catch (e) {}
}

const SIGNED_ATTRIBUTES_SIZE = 220

const generatedCircuits: {
  name: string
  path: string
}[] = []

function getHashAlgorithmByteSize(
  hash_algorithm: "sha1" | "sha224" | "sha256" | "sha384" | "sha512",
) {
  if (hash_algorithm === "sha1") {
    return 20
  } else if (hash_algorithm === "sha224") {
    return 28
  } else if (hash_algorithm === "sha256") {
    return 32
  } else if (hash_algorithm === "sha384") {
    return 48
  } else if (hash_algorithm === "sha512") {
    return 64
  }
}

function getHashAlgorithmIdentifier(
  hash_algorithm: "sha1" | "sha224" | "sha256" | "sha384" | "sha512",
) {
  return `${hash_algorithm.toUpperCase()}_IDENTIFIER`
}

function getHashAlgorithmDigestLength(
  hash_algorithm: "sha1" | "sha224" | "sha256" | "sha384" | "sha512",
) {
  return `${hash_algorithm.toUpperCase()}_DIGEST_LENGTH`
}

const NARGO_TEMPLATE = (
  name: string,
  dependencies: {
    name: string
    path: string
  }[],
) => `[package]
name = "${name}"
type = "bin"
authors = ["Theo Madzou", "Michael Elliot"]
compiler_version = ">=1.0.0"

[dependencies]
${dependencies.map(({ name, path }) => `${name} = { path = "${path}" }`).join("\n")}
`

const STATIC_CIRCUITS = [
  { name: "compare_age", path: "./src/noir/bin/compare/age/standard" },
  { name: "compare_age_evm", path: "./src/noir/bin/compare/age/evm" },
  { name: "compare_expiry", path: "./src/noir/bin/compare/expiry/standard" },
  { name: "compare_expiry_evm", path: "./src/noir/bin/compare/expiry/evm" },
  { name: "compare_birthdate", path: "./src/noir/bin/compare/birthdate/standard" },
  { name: "compare_birthdate_evm", path: "./src/noir/bin/compare/birthdate/evm" },
  { name: "disclose_bytes", path: "./src/noir/bin/disclose/bytes/standard" },
  { name: "disclose_bytes_evm", path: "./src/noir/bin/disclose/bytes/evm" },
  { name: "bind", path: "./src/noir/bin/bind/standard" },
  { name: "bind_evm", path: "./src/noir/bin/bind/evm" },
  {
    name: "exclusion_check_issuing_country",
    path: "./src/noir/bin/exclusion-check/issuing-country/standard",
  },
  {
    name: "exclusion_check_issuing_country_evm",
    path: "./src/noir/bin/exclusion-check/issuing-country/evm",
  },
  {
    name: "inclusion_check_issuing_country",
    path: "./src/noir/bin/inclusion-check/issuing-country/standard",
  },
  {
    name: "inclusion_check_issuing_country_evm",
    path: "./src/noir/bin/inclusion-check/issuing-country/evm",
  },
  {
    name: "exclusion_check_nationality",
    path: "./src/noir/bin/exclusion-check/nationality/standard",
  },
  {
    name: "exclusion_check_nationality_evm",
    path: "./src/noir/bin/exclusion-check/nationality/evm",
  },
  {
    name: "inclusion_check_nationality",
    path: "./src/noir/bin/inclusion-check/nationality/standard",
  },
  {
    name: "inclusion_check_nationality_evm",
    path: "./src/noir/bin/inclusion-check/nationality/evm",
  },
  {
    name: "exclusion_check_sanctions",
    path: "./src/noir/bin/exclusion-check/sanctions/standard",
  },
  {
    name: "exclusion_check_sanctions_evm",
    path: "./src/noir/bin/exclusion-check/sanctions/evm",
  },
  {
    name: "facematch_ios",
    path: "./src/noir/bin/facematch/ios/standard",
  },
  {
    name: "facematch_ios_evm",
    path: "./src/noir/bin/facematch/ios/evm",
  },
]

const LIB_CIRCUITS = [
  "src/noir/lib/bind",
  "src/noir/lib/commitment/common",
  "src/noir/lib/commitment/csc-to-dsc",
  "src/noir/lib/commitment/dsc-to-id",
  "src/noir/lib/commitment/integrity-to-disclosure",
  "src/noir/lib/commitment/scoped-nullifier",
  "src/noir/lib/compare/age",
  "src/noir/lib/compare/date",
  "src/noir/lib/data-check/expiry",
  "src/noir/lib/data-check/integrity",
  "src/noir/lib/data-check/tbs-pubkey",
  "src/noir/lib/disclose",
  "src/noir/lib/exclusion-check/country",
  "src/noir/lib/inclusion-check/country",
  "src/noir/lib/sig-check/common",
  "src/noir/lib/sig-check/ecdsa",
  "src/noir/lib/sig-check/rsa",
  "src/noir/lib/utils",
  "src/noir/lib/exclusion-check/sanctions",
  "src/noir/lib/facematch",
]

const WORKSPACE_NARGO_TEMPLATE = (dependencies: string[]) => `[workspace]
members = [${STATIC_CIRCUITS.map(
  ({ path }) => `
    "${path.replace("./", "")}"`,
).join(",")},${dependencies
  .map(
    (path) => `
    "${path.replace("./", "")}"`,
  )
  .join(",")},

    "${LIB_CIRCUITS.join('",\n    "')}"
]
`

const DSC_ECDSA_TEMPLATE = (
  curve_family: string,
  curve_name: string,
  bit_size: number,
  tbs_max_len: number,
  hash_algorithm: "sha1" | "sha224" | "sha256" | "sha384" | "sha512",
  unconstrained: boolean = false,
) => `// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use commitment::commit_to_dsc;
use sig_check_common::${hash_algorithm}_and_check_data_to_sign;
use sig_check_ecdsa::verify_${curve_family}_${curve_name};
use utils::{split_array, types::Alpha3CountryCode};

${unconstrained ? "unconstrained " : ""}fn main(
    certificate_registry_root: pub Field,
    certificate_registry_index: Field,
    certificate_registry_hash_path: [Field; ${CERTIFICATE_REGISTRY_HEIGHT}],
    certificate_tags: [Field; 3],
    salt: Field,
    country: Alpha3CountryCode,
    csc_pubkey_x: [u8; ${Math.ceil(bit_size / 8)}],
    csc_pubkey_y: [u8; ${Math.ceil(bit_size / 8)}],
    dsc_signature: [u8; ${Math.ceil(bit_size / 8) * 2}],
    tbs_certificate: [u8; ${tbs_max_len}],
) -> pub Field {
    // Get the length of tbs_certificate by parsing the ASN.1
    // Safety: This is safe because the length must be correct for the hash and signature to be valid
    let tbs_certificate_len =
        unsafe { utils::unsafe_get_asn1_element_length(tbs_certificate) };
    let (r, s) = split_array(dsc_signature);
    let msg_hash = ${hash_algorithm}_and_check_data_to_sign(tbs_certificate, tbs_certificate_len);
    assert(verify_${curve_family}_${curve_name}(csc_pubkey_x, csc_pubkey_y, r, s, msg_hash), "ECDSA signature verification failed");
    let comm_out = commit_to_dsc(
        certificate_registry_root,
        certificate_registry_index,
        certificate_registry_hash_path,
        certificate_tags,
        country,
        tbs_certificate,
        salt,
        csc_pubkey_x.concat(csc_pubkey_y),
    );
    comm_out
}
`

const DSC_RSA_TEMPLATE = (
  rsa_type: "pss" | "pkcs",
  bit_size: number,
  tbs_max_len: number,
  hash_algorithm: "sha1" | "sha224" | "sha256" | "sha384" | "sha512",
  unconstrained: boolean = false,
) => `// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use commitment::commit_to_dsc;
use sig_check_rsa::verify_signature;
use utils::types::Alpha3CountryCode;

${unconstrained ? "unconstrained " : ""}fn main(
    certificate_registry_root: pub Field,
    certificate_registry_index: Field,
    certificate_registry_hash_path: [Field; ${CERTIFICATE_REGISTRY_HEIGHT}],
    certificate_tags: [Field; 3],
    salt: Field,
    country: Alpha3CountryCode,
    tbs_certificate: [u8; ${tbs_max_len}],
    csc_pubkey: [u8; ${Math.ceil(bit_size / 8)}],
    csc_pubkey_redc_param: [u8; ${Math.ceil(bit_size / 8) + 1}],
    dsc_signature: [u8; ${Math.ceil(bit_size / 8)}],
    exponent: u32,
) -> pub Field {
    // Get the length of tbs_certificate by parsing the ASN.1
    // Safety: This is safe because the length must be correct for the hash and signature to be valid
    let tbs_certificate_len =
        unsafe { utils::unsafe_get_asn1_element_length(tbs_certificate) };
    assert(verify_signature::<${Math.ceil(bit_size / 8)}, ${
  rsa_type === "pss" ? 1 : 0
}, ${tbs_max_len}, ${getHashAlgorithmByteSize(hash_algorithm)}>(
        csc_pubkey,
        dsc_signature,
        csc_pubkey_redc_param,
        exponent,
        tbs_certificate,
        tbs_certificate_len,
    ), "RSA signature verification failed");
    let comm_out = commit_to_dsc(
        certificate_registry_root,
        certificate_registry_index,
        certificate_registry_hash_path,
        certificate_tags,
        country,
        tbs_certificate,
        salt,
        csc_pubkey,
    );
    comm_out
}
`

const ID_DATA_ECDSA_TEMPLATE = (
  curve_family: string,
  curve_name: string,
  bit_size: number,
  tbs_max_len: number,
  hash_algorithm: "sha1" | "sha224" | "sha256" | "sha384" | "sha512",
  unconstrained: boolean = false,
) => `// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use commitment::commit_to_id;
use data_check_tbs_pubkey::verify_ecdsa_pubkey_in_tbs;
use sig_check_common::${hash_algorithm}_and_check_data_to_sign;
use sig_check_ecdsa::verify_${curve_family}_${curve_name};
use utils::{split_array, types::{DG1Data, EContentData, SignedAttrsData}};

${unconstrained ? "unconstrained " : ""}fn main(
    comm_in: pub Field,
    salt_in: Field,
    salt_out: Field,
    dg1: DG1Data,
    dsc_pubkey_x: [u8; ${Math.ceil(bit_size / 8)}],
    dsc_pubkey_y: [u8; ${Math.ceil(bit_size / 8)}],
    sod_signature: [u8; ${Math.ceil(bit_size / 8) * 2}],
    tbs_certificate: [u8; ${tbs_max_len}],
    signed_attributes: SignedAttrsData,
    e_content: EContentData,
) -> pub Field {
    // Get the length of signed_attributes by parsing the ASN.1
    // Safety: This is safe because the length must be correct for the hash and signature to be valid
    let signed_attributes_size =
        unsafe { utils::unsafe_get_asn1_element_length(signed_attributes) };
    let (r, s) = split_array(sod_signature);
    let msg_hash = ${hash_algorithm}_and_check_data_to_sign(signed_attributes, signed_attributes_size);
    verify_ecdsa_pubkey_in_tbs(
        dsc_pubkey_x,
        dsc_pubkey_y,
        tbs_certificate,
    );
    assert(verify_${curve_family}_${curve_name}(dsc_pubkey_x, dsc_pubkey_y, r, s, msg_hash), "ECDSA signature verification failed");
    let comm_out = commit_to_id(
        comm_in,
        salt_in,
        salt_out,
        dg1,
        tbs_certificate,
        sod_signature,
        signed_attributes,
        signed_attributes_size as Field,
        e_content,
    );
    comm_out
}
`

const ID_DATA_RSA_TEMPLATE = (
  rsa_type: "pss" | "pkcs",
  bit_size: number,
  tbs_max_len: number,
  hash_algorithm: "sha1" | "sha224" | "sha256" | "sha384" | "sha512",
  unconstrained: boolean = false,
) => `// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use commitment::commit_to_id;
use data_check_tbs_pubkey::verify_rsa_pubkey_in_tbs;
use sig_check_rsa::verify_signature;
use utils::types::{DG1Data, EContentData, SignedAttrsData};

${unconstrained ? "unconstrained " : ""}fn main(
    comm_in: pub Field,
    salt_in: Field,
    salt_out: Field,
    dg1: DG1Data,
    dsc_pubkey: [u8; ${Math.ceil(bit_size / 8)}],
    dsc_pubkey_redc_param: [u8; ${Math.ceil(bit_size / 8) + 1}],
    sod_signature: [u8; ${Math.ceil(bit_size / 8)}],
    tbs_certificate: [u8; ${tbs_max_len}],
    signed_attributes: SignedAttrsData,
    exponent: u32,
    e_content: EContentData,
) -> pub Field {
    verify_rsa_pubkey_in_tbs(dsc_pubkey, tbs_certificate);
    // Get the length of signed_attributes by parsing the ASN.1
    // Safety: This is safe because the length must be correct for the hash and signature to be valid
    let signed_attributes_size =
        unsafe { utils::unsafe_get_asn1_element_length(signed_attributes) };
    assert(verify_signature::<${Math.ceil(bit_size / 8)}, ${
  rsa_type === "pss" ? 1 : 0
}, ${SIGNED_ATTRIBUTES_SIZE}, ${getHashAlgorithmByteSize(hash_algorithm)}>(
        dsc_pubkey,
        sod_signature,
        dsc_pubkey_redc_param,
        exponent,
        signed_attributes,
        signed_attributes_size,
    ), "RSA signature verification failed");
    let comm_out = commit_to_id(
        comm_in,
        salt_in,
        salt_out,
        dg1,
        tbs_certificate,
        sod_signature,
        signed_attributes,
        signed_attributes_size as Field,
        e_content,
    );
    comm_out
}
`

const DATA_INTEGRITY_CHECK_TEMPLATE = (
  signed_attributes_hash_algorithm: "sha1" | "sha224" | "sha256" | "sha384" | "sha512",
  dg_hash_algorithm: "sha1" | "sha224" | "sha256" | "sha384" | "sha512",
  unconstrained: boolean = false,
) => `// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use commitment::commit_to_disclosure;
use data_check_integrity::{check_dg1_${dg_hash_algorithm}, check_signed_attributes_${signed_attributes_hash_algorithm}, get_dg2_hash_from_econtent};
use utils::{types::{DG1Data, EContentData, SignedAttrsData, SaltedValue}, constants::{${getHashAlgorithmIdentifier(
  dg_hash_algorithm,
)}, ${getHashAlgorithmDigestLength(dg_hash_algorithm)}}};

${unconstrained ? "unconstrained " : ""}fn main(
    comm_in: pub Field,
    salt_in: Field,
    salted_dg1: SaltedValue<DG1Data>,
    expiry_date_salt: Field,
    dg2_hash_salt: Field,
    signed_attributes: SignedAttrsData,
    e_content: EContentData,
    salted_private_nullifier: SaltedValue<Field>,
) -> pub Field {
    // Get the length of e_content by parsing the ASN.1
    // Safety: This is safe because the length must be correct for econtent to hash to
    // the expected digest in signed attributes as checked below in check_signed_attributes_${dg_hash_algorithm}
    let e_content_size =
        unsafe { utils::unsafe_get_asn1_element_length(e_content) };
    // Check the integrity of the data
    check_dg1_${dg_hash_algorithm}(salted_dg1.value, e_content, e_content_size);
    // Get the length of signed_attributes by parsing the ASN.1
    // Safety: This is safe because the length was checked in the ID data circuit and the whole signed attributes
    // was committed over in that same circuit
    let signed_attributes_size =
        unsafe { utils::unsafe_get_asn1_element_length(signed_attributes) };
    check_signed_attributes_${signed_attributes_hash_algorithm}(
        signed_attributes,
        e_content,
        e_content_size,
    );

    // Get the hash of DG2 from eContent
    let dg2_hash = get_dg2_hash_from_econtent(e_content, e_content_size);

    let comm_out = commit_to_disclosure::<${getHashAlgorithmDigestLength(dg_hash_algorithm)}>(
        comm_in,
        salt_in,
        salted_dg1,
        expiry_date_salt,
        SaltedValue::from_value(dg2_hash_salt, dg2_hash),
        SaltedValue::from_value(dg2_hash_salt, ${getHashAlgorithmIdentifier(dg_hash_algorithm)}),
        signed_attributes,
        signed_attributes_size as Field,
        e_content,
        salted_private_nullifier,
    );
    comm_out
}
`

const FACEMATCH_ANDROID_TEMPLATE = (
  root_signature_algorithm: "rsa" | "ecdsa",
  intermediate_signature_algorithms: {
    signature_algorithm: "rsa" | "ecdsa"
    bit_size: number
    hash_algorithm: "sha1" | "sha224" | "sha256" | "sha384" | "sha512"
  }[],
  evm: boolean = false,
  unconstrained: boolean = false,
) => `// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use commitment::nullify;
use data_check_tbs_pubkey::{verify_ecdsa_pubkey_in_tbs, verify_rsa_pubkey_in_tbs};
use data_check_expiry::check_expiry_from_date;
use facematch::{
    android::{get_app_id_from_credential_tbs, constants::INTEGRITY_TOKEN_MAX_LENGTH, token::{verify_integrity_token, verify_nonce, verify_integrity_token_signature, parse_integrity_token}}, calculate_attestation_registry_leaf,
    get_client_data_hash, prepare_client_data_hash_for_signature, get_facematch_mode_from_client_data, get_tbs_hash_sha256,
    get_tbs_hash_sha384, verify_dg2_hash_in_client_data
};
use facematch::constants::{
    APP_ID_MAX_LEN, ATTESTATION_KEY_TYPE_GOOGLE, CLIENT_DATA_MAX_LEN, CREDENTIAL_TBS_MAX_LEN,
};
use facematch::param_commit::{calculate_param_commitment, calculate_param_commitment_sha2};
use sig_check_ecdsa::{verify_nist_p256_blackbox as verify_nist_p256, verify_nist_p384};
use sig_check_rsa::verify_signature;
use utils::{poseidon2_hash_packed, split_array, types::{DG1Data, SaltedValue, MRZExpiryDate}, unsafe_get_asn1_element_length};

${unconstrained ? "unconstrained " : ""}fn main(
    comm_in: pub Field,
    current_date: pub u64,
    salted_private_nullifier: SaltedValue<Field>,
    salted_expiry_date: SaltedValue<MRZExpiryDate>,
    salted_dg1: SaltedValue<DG1Data>,
    salted_dg2_hash: SaltedValue<Field>,
    salted_dg2_hash_type: SaltedValue<u32>,
    // @committed
    // Hash of root_key (the attestation registry leaf) is commitment to (via parameter commitment) and can be verified outside the circuit
    ${root_signature_algorithm === "rsa" ? `
    // There are only two possible root keys, right now the RSA one is the only one used
    // but the new one to be rolled out in February 2026 will be ECDSA P384 so both should be supported
    // c.f. https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate
    root_key: [u8; 512],
    root_key_redc_param: [u8; 513],
    ` : `
    // There are only two possible root keys, right now the RSA one is the only one used
    // but the new one to be rolled out in February 2026 will be ECDSA P384, so support is ready for this one
    // c.f. https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate
    root_key: [u8; 96],
    `}
    // Intermediate certificates from up (root) to bottom (leaf/credential) of the chain
    ${intermediate_signature_algorithms.map(({ signature_algorithm, hash_algorithm, bit_size }, index) => `
    intermediate_${index + 1}_key: [u8; ${signature_algorithm === "rsa" ? Math.ceil(bit_size / 8) : Math.ceil(bit_size / 4)}],
    ${signature_algorithm === "rsa" ? `
    intermediate_${index + 1}_key_redc_param: [u8; ${Math.ceil(bit_size / 8) + 1}],
    ` : ``}
    intermediate_${index + 1}_tbs: [u8; ${signature_algorithm === "rsa" ? 1000 : 500}],
    // ${index === 0 ? "RSA" : intermediate_signature_algorithms[index - 1].signature_algorithm} signature from the ${index === 0 ? "root" : `intermediate certificate #${index}`} over the intermediate certificate #${index + 1} TBS
    intermediate_${index + 1}_sig: [u8; ${index === 0 ? root_signature_algorithm === "rsa" ? 512 : 96 : intermediate_signature_algorithms[index - 1].signature_algorithm === "rsa" ? Math.ceil(intermediate_signature_algorithms[index - 1].bit_size / 8) : Math.ceil(intermediate_signature_algorithms[index - 1].bit_size / 4)}],
    `).join("")}
    // This is the leaf certificate derived from the private key in the KeyStore
    // so we have control over the signature algorithm used (i.e P-256 with SHA256)
    // so client_data_sig will always be P-256 with SHA256
    credential_key: [u8; 64],
    credential_tbs: [u8; CREDENTIAL_TBS_MAX_LEN],
    // ${intermediate_signature_algorithms[intermediate_signature_algorithms.length - 1].signature_algorithm} signature from the third intermediate certificate over the credential certificate TBS
    credential_sig: [u8; ${intermediate_signature_algorithms[intermediate_signature_algorithms.length - 1].signature_algorithm === "rsa" ? Math.ceil(intermediate_signature_algorithms[intermediate_signature_algorithms.length - 1].bit_size / 8) : Math.ceil(intermediate_signature_algorithms[intermediate_signature_algorithms.length - 1].bit_size / 4)}],
    client_data: [u8; CLIENT_DATA_MAX_LEN],
    // P-256 signature from the credential (i.e. leaf) certificate over the client data TBS
    client_data_sig: [u8; 64],
    // @committed
    // environment is committed to (via parameter commitment) and can be verified outside the circuit
    environment: u8, // APP_ATTEST_ENV_DEVELOPMENT (0) or APP_ATTEST_ENV_PRODUCTION (1)
    // @committed
    // Hash of app_id is committed to (via parameter commitment) and can be verified outside the circuit
    app_id: [u8; APP_ID_MAX_LEN],
    // @committed
    // facematch_mode is commitment to (via parameter commitment) and can be verified outside the circuit
    facematch_mode: u8, // FACEMATCH_MODE_REGULAR (1) or FACEMATCH_MODE_STRICT (2)
    // The bytes of the JSON integrity token from Play Integrity API
    integrity_token: [u8; INTEGRITY_TOKEN_MAX_LENGTH],
    // The signature over the integrity token (ECDSA P-256 with SHA-256)
    integrity_token_signature: [u8; 64],
    // @committed
    // Hash of play_integrity_public_key is committed to (via parameter commitment) and can be verified outside the circuit
    // Play Integrity's public key behind the signature over the integrity token
    play_integrity_public_key: [u8; 64],
    nullifier_secret: Field,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field, Field) {
    // Check the ID is not expired
    check_expiry_from_date(salted_expiry_date.value, current_date);

    ${intermediate_signature_algorithms.map(({ signature_algorithm, hash_algorithm, bit_size }, index) => signature_algorithm === "ecdsa" ? `
    let (intermediate_${index + 1}_key_x, intermediate_${index + 1}_key_y) = split_array(intermediate_${index + 1}_key);
    ` : ``).join("")}

    let root_key_leaf = calculate_attestation_registry_leaf(ATTESTATION_KEY_TYPE_GOOGLE, root_key);

    // Verify the intermediate certificate was signed by the root key
    // and the intermediate public key is in the intermediate certificate TBS
    ${intermediate_signature_algorithms[0].signature_algorithm === "ecdsa" ? `
    verify_ecdsa_pubkey_in_tbs(intermediate_1_key_x, intermediate_1_key_y, intermediate_1_tbs);
    ` : `
    verify_rsa_pubkey_in_tbs(intermediate_1_key, intermediate_1_tbs);
    `}
    let intermediate_1_tbs_len = unsafe { unsafe_get_asn1_element_length(intermediate_1_tbs) };
    ${root_signature_algorithm === "rsa" ? `
    assert(verify_signature::<_, 0, _, 32>(root_key, intermediate_1_sig, root_key_redc_param, 65537, intermediate_1_tbs, intermediate_1_tbs_len), "Failed to verify intermediate certificate");
    ` : `
    let (root_key_x, root_key_y) = split_array(root_key);
    let intermediate_1_tbs_hash = get_tbs_hash_sha384(intermediate_1_tbs);
    let (intermediate_1_sig_r, intermediate_1_sig_s) = split_array(intermediate_1_sig);
    assert(verify_nist_p384(root_key_x, root_key_y, intermediate_1_sig_r, intermediate_1_sig_s, intermediate_1_tbs_hash), "Failed to verify intermediate certificate");
    `}

    ${intermediate_signature_algorithms.map(({ signature_algorithm, hash_algorithm, bit_size }, index) => {
     if (index === 0) {
      return ``;
     }
     let result = signature_algorithm === "ecdsa" ? `
      let (intermediate_${index + 1}_key_x, intermediate_${index + 1}_key_y) = split_array(intermediate_${index + 1}_key);
      verify_ecdsa_pubkey_in_tbs(intermediate_${index + 1}_key_x, intermediate_${index + 1}_key_y, intermediate_${index + 1}_tbs);
      let (intermediate_${index + 1}_sig_r, intermediate_${index + 1}_sig_s) = split_array(intermediate_${index + 1}_sig);
      let intermediate_${index + 1}_tbs_hash = get_tbs_hash_${intermediate_signature_algorithms[index - 1].hash_algorithm}(intermediate_${index + 1}_tbs);
      ` : `
      verify_rsa_pubkey_in_tbs(intermediate_${index + 1}_key, intermediate_${index + 1}_tbs);
      let (intermediate_${index + 1}_sig_r, intermediate_${index + 1}_sig_s) = split_array(intermediate_${index + 1}_sig);
      let intermediate_${index + 1}_tbs_hash = get_tbs_hash_${intermediate_signature_algorithms[index - 1].hash_algorithm}(intermediate_${index + 1}_tbs);
      `;
      if (intermediate_signature_algorithms[index - 1].signature_algorithm === "ecdsa") {
        result += `
        assert(verify_nist_p${intermediate_signature_algorithms[index - 1].bit_size}(intermediate_${index}_key_x, intermediate_${index}_key_y, intermediate_${index + 1}_sig_r, intermediate_${index + 1}_sig_s, intermediate_${index + 1}_tbs_hash), "Failed to verify intermediate certificate");
        `;
      } else {
        result += `
        let intermediate_${index + 1}_tbs_len = unsafe { unsafe_get_asn1_element_length(intermediate_${index + 1}_tbs) };
        assert(verify_signature::<_, 0, _, ${getHashAlgorithmByteSize(intermediate_signature_algorithms[index - 1].hash_algorithm)}>(intermediate_${index}_key, intermediate_${index + 1}_sig, intermediate_${index}_key_redc_param, 65537, intermediate_${index + 1}_tbs, intermediate_${index + 1}_tbs_len), "Failed to verify intermediate certificate");
        `;
      }
     return result;
    }).join("")}

    let (credential_key_x, credential_key_y) = split_array(credential_key);
    verify_ecdsa_pubkey_in_tbs(credential_key_x, credential_key_y, credential_tbs);
    ${intermediate_signature_algorithms[intermediate_signature_algorithms.length - 1].signature_algorithm === "ecdsa" ? `
    let (credential_sig_r, credential_sig_s) = split_array(credential_sig);
    ` : ``}
    let credential_tbs_hash = get_tbs_hash_${intermediate_signature_algorithms[intermediate_signature_algorithms.length - 1].hash_algorithm}(credential_tbs);
    ${intermediate_signature_algorithms[intermediate_signature_algorithms.length - 1].signature_algorithm === "ecdsa" ? `
    assert(
         verify_nist_p${intermediate_signature_algorithms[intermediate_signature_algorithms.length - 1].bit_size}(intermediate_${intermediate_signature_algorithms.length}_key_x, intermediate_${intermediate_signature_algorithms.length}_key_y, credential_sig_r, credential_sig_s, credential_tbs_hash),
        "Failed to verify credential certificate",
    );
    ` : `
    let credential_tbs_len = unsafe { unsafe_get_asn1_element_length(credential_tbs) };
    assert(verify_signature::<_, 0, _, ${getHashAlgorithmByteSize(intermediate_signature_algorithms[intermediate_signature_algorithms.length - 1].hash_algorithm)}>(intermediate_${intermediate_signature_algorithms.length}_key, credential_sig, intermediate_${intermediate_signature_algorithms.length}_key_redc_param, 65537, credential_tbs, credential_tbs_len), "Failed to verify credential certificate");
    `}

    let (client_data_sig_r, client_data_sig_s) = split_array(client_data_sig);
    let client_data_len = unsafe { unsafe_get_asn1_element_length(client_data) };
    let client_data_hash = get_client_data_hash(client_data, client_data_len);
    assert(
        verify_nist_p256(credential_key_x, credential_key_y, client_data_sig_r, client_data_sig_s, prepare_client_data_hash_for_signature(client_data_hash)),
        "Failed to verify client data hash",
    );

    // Verify the app ID in the credential certificate TBS matches the expected app ID
    let (tbs_app_id, app_id_length): ([u8; APP_ID_MAX_LEN], u32) =
        get_app_id_from_credential_tbs(credential_tbs);
    assert(tbs_app_id == app_id, "Failed to verify app_id");

    // Verify the facematch mode in client_data matches the expected facematch mode
    assert(
        get_facematch_mode_from_client_data(client_data) == facematch_mode,
        "Failed to verify facematch_mode in client_data",
    );

    // Verify the normalized dg2_hash in client_data matches the expected normalized dg2_hash
    assert(
        verify_dg2_hash_in_client_data(salted_dg2_hash.value, client_data),
        "Failed to verify dg2_hash in client_data",
    );

    // Verify the integrity token
    let parsed_integrity_token = parse_integrity_token(integrity_token);
    let integrity_token_response = verify_integrity_token(parsed_integrity_token, app_id, app_id_length);
    assert(
        integrity_token_response.environment == environment,
        "Failed to verify integrity token environment",
    );

    // Verify the signature over the integrity token
    let (play_integrity_public_key_x, play_integrity_public_key_y) = split_array(play_integrity_public_key);
    assert(
        verify_integrity_token_signature(integrity_token, play_integrity_public_key_x, play_integrity_public_key_y, integrity_token_signature),
        "Failed to verify integrity token signature",
    );

    // Verify the nonce
    assert(
        verify_nonce(integrity_token_response.nonce, client_data_hash, client_data_sig),
        "Failed to verify nonce from integrity token",
    );

    let (nullifier, nullifier_type) = nullify(
        comm_in,
        salted_dg1,
        salted_expiry_date,
        salted_dg2_hash,
        salted_dg2_hash_type,
        salted_private_nullifier,
        service_scope,
        service_subscope,
        nullifier_secret,
    );

    let app_id_hash = poseidon2_hash_packed(app_id, app_id_length);
    let play_integrity_public_key_hash = poseidon2_hash_packed(play_integrity_public_key, play_integrity_public_key.len());
    let param_commitment =
        ${evm ? "calculate_param_commitment_sha2" : "calculate_param_commitment"}(root_key_leaf, environment, app_id_hash, play_integrity_public_key_hash, facematch_mode);

    (param_commitment, nullifier_type, nullifier)
}
`

const OUTER_CIRCUIT_TEMPLATE = (
  disclosure_proofs_count: number,
  unconstrained: boolean = false,
) => `// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
/*
############################################################
# Outer Circuit
############################################################
# Wraps ${
  disclosure_proofs_count + 3
} subproofs (3 base proofs + ${disclosure_proofs_count} disclosure proofs) into a single proof
# by verifying them recursively
############################################################

# Inputs/Outputs
############################################################
certificate_registry_root -> The root of the certificate registry merkle tree
circuit_registry_root -> The root of the circuit registry merkle tree
current_date -> The current date as a string, e.g. 20241103 (used by the integrity check subproof)
service_scope -> The service scope
service_subscope -> The service subscope
param_commitments -> The commitments over the parameters of the disclosure circuits
nullifier_type -> The type of the nullifier
scoped_nullifier -> The scoped nullifier
csc_to_dsc_proof -> The proof of the CSC to DSC circuit
dsc_to_id_data_proof -> The proof of the DSC to ID Data circuit
integrity_check_proof -> The proof of the integrity check circuit
disclosure_proofs -> The proofs of the disclosure circuits
*/

use common::compute_merkle_root;
use outer_lib::{
    CSCtoDSCProof, DisclosureProof, DSCtoIDDataProof, IntegrityCheckProof, poseidon2_hash,
    prepare_disclosure_inputs, prepare_integrity_check_inputs,
};
use utils::constants::{NON_SALTED_NULLIFIER, SALTED_NULLIFIER, NON_SALTED_MOCK_NULLIFIER, SALTED_MOCK_NULLIFIER};
use std::verify_proof_with_type;
global PROOF_TYPE_HONK_ZK: u32 = 7;

fn verify_subproofs(
    // Root of the certificate merkle tree
    certificate_registry_root: Field,
    // Root of the circuit registry merkle tree
    circuit_registry_root: Field,
    // Current date and time as a unix timestamp
    current_date: u64,
    // The commitments over the parameters of the disclosure circuits
    param_commitments: [Field; ${disclosure_proofs_count}],
    // The nullifier service scope (a Pederson hash of the domain)
    service_scope: Field,
    // The service sub-scope
    service_subscope: Field,
    // The type of the nullifier
    nullifier_type: Field,
    // The scoped nullifier: H(private_nullifier,service_scope,service_subscope)
    scoped_nullifier: Field,
    csc_to_dsc_proof: CSCtoDSCProof,
    dsc_to_id_data_proof: DSCtoIDDataProof,
    integrity_check_proof: IntegrityCheckProof,
    disclosure_proofs: [DisclosureProof; ${disclosure_proofs_count}],
) {
    // Verify that all subproofs vkey hashes exist in the circuit tree
    // This way we know for sure that the proofs were generated with valid circuits
    assert_eq(
        circuit_registry_root,
        compute_merkle_root(
            csc_to_dsc_proof.key_hash,
            csc_to_dsc_proof.tree_index,
            csc_to_dsc_proof.tree_hash_path,
        ),
        "CSC to DSC proof vkey hash not found in circuit tree",
    );
    assert_eq(
        circuit_registry_root,
        compute_merkle_root(
            dsc_to_id_data_proof.key_hash,
            dsc_to_id_data_proof.tree_index,
            dsc_to_id_data_proof.tree_hash_path,
        ),
        "DSC to ID Data proof vkey hash not found in circuit tree",
    );
    assert_eq(
        circuit_registry_root,
        compute_merkle_root(
            integrity_check_proof.key_hash,
            integrity_check_proof.tree_index,
            integrity_check_proof.tree_hash_path,
        ),
        "Integrity check proof vkey hash not found in circuit tree",
    );
    for i in 0..disclosure_proofs.len() {
        assert_eq(
            circuit_registry_root,
            compute_merkle_root(
                disclosure_proofs[i].key_hash,
                disclosure_proofs[i].tree_index,
                disclosure_proofs[i].tree_hash_path,
            ),
            "Disclosure proof vkey hash not found in circuit tree",
        );
    }

    // Verify that the vkey hashes are correct
    assert_eq(poseidon2_hash(csc_to_dsc_proof.vkey), csc_to_dsc_proof.key_hash, "CSC to DSC proof vkey hash mismatch");
    assert_eq(poseidon2_hash(dsc_to_id_data_proof.vkey), dsc_to_id_data_proof.key_hash, "DSC to ID Data proof vkey hash mismatch");
    assert_eq(poseidon2_hash(integrity_check_proof.vkey), integrity_check_proof.key_hash, "Integrity check proof vkey hash mismatch");
    for i in 0..disclosure_proofs.len() {
        assert_eq(poseidon2_hash(disclosure_proofs[i].vkey), disclosure_proofs[i].key_hash, "Disclosure proof vkey hash mismatch");
    }

    // Assert that the nullifier type is not the salted nullifier
    // as the salted nullifier is not allowed for now
    // Mock proof salted nullifiers are allowed though
    assert(nullifier_type != SALTED_NULLIFIER, "Salted nullifiers are not allowed for now");
    assert(scoped_nullifier != 0, "Scoped nullifier must be non-zero");

    verify_proof_with_type(
        csc_to_dsc_proof.vkey,
        csc_to_dsc_proof.proof,
        [
            certificate_registry_root,
            csc_to_dsc_proof.public_inputs[0], // comm_out
        ],
        csc_to_dsc_proof.key_hash,
        PROOF_TYPE_HONK_ZK,
    );

    // Commitment out from CSC to DSC circuit == commitment in from DSC to ID Data circuit
    assert_eq(csc_to_dsc_proof.public_inputs[0], dsc_to_id_data_proof.public_inputs[0], "Commitment out from CSC to DSC circuit != commitment in from DSC to ID Data circuit");

    verify_proof_with_type(
        dsc_to_id_data_proof.vkey,
        dsc_to_id_data_proof.proof,
        [
            dsc_to_id_data_proof.public_inputs[0], // comm_in
            dsc_to_id_data_proof.public_inputs[1], // comm_out
        ],
        dsc_to_id_data_proof.key_hash,
        PROOF_TYPE_HONK_ZK,
    );

    // Commitment out from DSC to ID Data circuit == commitment in from integrity check circuit
    assert_eq(dsc_to_id_data_proof.public_inputs[1], integrity_check_proof.public_inputs[0], "Commitment out from DSC to ID Data circuit != commitment in from integrity check circuit");

    verify_proof_with_type(
        integrity_check_proof.vkey,
        integrity_check_proof.proof,
        prepare_integrity_check_inputs(
            integrity_check_proof.public_inputs[0], // comm_in
            integrity_check_proof.public_inputs[1], // comm_out
        ),
        integrity_check_proof.key_hash,
        PROOF_TYPE_HONK_ZK,
    );

    for i in 0..disclosure_proofs.len() {
        // Commitment out from integrity check circuit == commitment in from disclosure circuit
        assert_eq(integrity_check_proof.public_inputs[1], disclosure_proofs[i].public_inputs[0], "Commitment out from integrity check circuit != commitment in from disclosure circuit");

        verify_proof_with_type(
            disclosure_proofs[i].vkey,
            disclosure_proofs[i].proof,
            prepare_disclosure_inputs(
                disclosure_proofs[i].public_inputs[0], // comm_in
                current_date,
                param_commitments[i],
                service_scope,
                service_subscope,
                nullifier_type,
                scoped_nullifier,
            ),
            disclosure_proofs[i].key_hash,
            PROOF_TYPE_HONK_ZK,
        );
    }
}

${unconstrained ? "unconstrained " : ""}fn main(
    // Root of the certificate registry merkle tree
    certificate_registry_root: pub Field,
    // Root of the circuit registry merkle tree
    circuit_registry_root: pub Field,
    current_date: pub u64,
    service_scope: pub Field,
    service_subscope: pub Field,
    param_commitments: pub [Field; ${disclosure_proofs_count}],
    nullifier_type: pub Field,
    scoped_nullifier: pub Field,
    csc_to_dsc_proof: CSCtoDSCProof,
    dsc_to_id_data_proof: DSCtoIDDataProof,
    integrity_check_proof: IntegrityCheckProof,
    disclosure_proofs: [DisclosureProof; ${disclosure_proofs_count}],
) {
    verify_subproofs(
        certificate_registry_root,
        circuit_registry_root,
        current_date,
        param_commitments,
        service_scope,
        service_subscope,
        nullifier_type,
        scoped_nullifier,
        csc_to_dsc_proof,
        dsc_to_id_data_proof,
        integrity_check_proof,
        disclosure_proofs,
    );
}
`

function generateDscEcdsaCircuit(
  curve_family: string,
  curve_name: string,
  bit_size: number,
  tbs_max_len: number,
  hash_algorithm: "sha1" | "sha256" | "sha384" | "sha512",
  unconstrained: boolean = false,
) {
  const noirFile = DSC_ECDSA_TEMPLATE(
    curve_family,
    curve_name,
    bit_size,
    tbs_max_len,
    hash_algorithm,
    unconstrained,
  )
  const name = `sig_check_dsc_tbs_${tbs_max_len}_ecdsa_${curve_family}_${curve_name}_${hash_algorithm}`
  const nargoFile = NARGO_TEMPLATE(name, [
    { name: "sig_check_ecdsa", path: "../../../../../../../../lib/sig-check/ecdsa" },
    { name: "utils", path: "../../../../../../../../lib/utils" },
    { name: "commitment", path: "../../../../../../../../lib/commitment/csc-to-dsc" },
    { name: "sig_check_common", path: "../../../../../../../../lib/sig-check/common" },
  ])
  const folderPath = `./src/noir/bin/sig-check/dsc/tbs_${tbs_max_len}/ecdsa/${curve_family}/${curve_name}/${hash_algorithm}`
  const noirFilePath = `${folderPath}/src/main.nr`
  const nargoFilePath = `${folderPath}/Nargo.toml`
  ensureDirectoryExistence(noirFilePath)
  fs.writeFileSync(noirFilePath, noirFile)
  ensureDirectoryExistence(nargoFilePath)
  fs.writeFileSync(nargoFilePath, nargoFile)
  generatedCircuits.push({ name, path: folderPath })
}

function generateDscRsaCircuit(
  rsa_type: "pss" | "pkcs",
  bit_size: number,
  tbs_max_len: number,
  hash_algorithm: "sha1" | "sha256" | "sha384" | "sha512",
  unconstrained: boolean = false,
) {
  const noirFile = DSC_RSA_TEMPLATE(rsa_type, bit_size, tbs_max_len, hash_algorithm, unconstrained)
  const name = `sig_check_dsc_tbs_${tbs_max_len}_rsa_${rsa_type}_${bit_size}_${hash_algorithm}`
  const nargoFile = NARGO_TEMPLATE(name, [
    { name: "sig_check_rsa", path: "../../../../../../../../lib/sig-check/rsa" },
    { name: "utils", path: "../../../../../../../../lib/utils" },
    { name: "commitment", path: "../../../../../../../../lib/commitment/csc-to-dsc" },
  ])
  const folderPath = `./src/noir/bin/sig-check/dsc/tbs_${tbs_max_len}/rsa/${rsa_type}/${bit_size}/${hash_algorithm}`
  const noirFilePath = `${folderPath}/src/main.nr`
  const nargoFilePath = `${folderPath}/Nargo.toml`
  ensureDirectoryExistence(noirFilePath)
  fs.writeFileSync(noirFilePath, noirFile)
  fs.writeFileSync(nargoFilePath, nargoFile)
  generatedCircuits.push({ name, path: folderPath })
}

function generateIdDataEcdsaCircuit(
  curve_family: string,
  curve_name: string,
  bit_size: number,
  tbs_max_len: number,
  hash_algorithm: "sha1" | "sha224" | "sha256" | "sha384" | "sha512",
  unconstrained: boolean = false,
) {
  const noirFile = ID_DATA_ECDSA_TEMPLATE(
    curve_family,
    curve_name,
    bit_size,
    tbs_max_len,
    hash_algorithm,
    unconstrained,
  )
  const name = `sig_check_id_data_tbs_${tbs_max_len}_ecdsa_${curve_family}_${curve_name}_${hash_algorithm}`
  const nargoFile = NARGO_TEMPLATE(name, [
    { name: "sig_check_ecdsa", path: "../../../../../../../../lib/sig-check/ecdsa" },
    { name: "utils", path: "../../../../../../../../lib/utils" },
    { name: "data_check_tbs_pubkey", path: "../../../../../../../../lib/data-check/tbs-pubkey" },
    { name: "commitment", path: "../../../../../../../../lib/commitment/dsc-to-id" },
    { name: "sig_check_common", path: "../../../../../../../../lib/sig-check/common" },
  ])
  const folderPath = `./src/noir/bin/sig-check/id-data/tbs_${tbs_max_len}/ecdsa/${curve_family}/${curve_name}/${hash_algorithm}`
  const noirFilePath = `${folderPath}/src/main.nr`
  const nargoFilePath = `${folderPath}/Nargo.toml`
  ensureDirectoryExistence(noirFilePath)
  fs.writeFileSync(noirFilePath, noirFile)
  fs.writeFileSync(nargoFilePath, nargoFile)
  generatedCircuits.push({ name, path: folderPath })
}

function generateIdDataRsaCircuit(
  rsa_type: "pss" | "pkcs",
  bit_size: number,
  tbs_max_len: number,
  hash_algorithm: "sha1" | "sha256" | "sha384" | "sha512",
  unconstrained: boolean = false,
) {
  const noirFile = ID_DATA_RSA_TEMPLATE(
    rsa_type,
    bit_size,
    tbs_max_len,
    hash_algorithm,
    unconstrained,
  )
  const name = `sig_check_id_data_tbs_${tbs_max_len}_rsa_${rsa_type}_${bit_size}_${hash_algorithm}`
  const nargoFile = NARGO_TEMPLATE(name, [
    { name: "sig_check_rsa", path: "../../../../../../../../lib/sig-check/rsa" },
    { name: "utils", path: "../../../../../../../../lib/utils" },
    { name: "data_check_tbs_pubkey", path: "../../../../../../../../lib/data-check/tbs-pubkey" },
    { name: "commitment", path: "../../../../../../../../lib/commitment/dsc-to-id" },
  ])
  const folderPath = `./src/noir/bin/sig-check/id-data/tbs_${tbs_max_len}/rsa/${rsa_type}/${bit_size}/${hash_algorithm}`
  const noirFilePath = `${folderPath}/src/main.nr`
  const nargoFilePath = `${folderPath}/Nargo.toml`
  ensureDirectoryExistence(noirFilePath)
  fs.writeFileSync(noirFilePath, noirFile)
  fs.writeFileSync(nargoFilePath, nargoFile)
  generatedCircuits.push({ name, path: folderPath })
}

function generateDataIntegrityCheckCircuit(
  signed_attributes_hash_algorithm: "sha1" | "sha224" | "sha256" | "sha384" | "sha512",
  dg_hash_algorithm: "sha1" | "sha224" | "sha256" | "sha384" | "sha512",
  unconstrained: boolean = false,
) {
  const noirFile = DATA_INTEGRITY_CHECK_TEMPLATE(
    signed_attributes_hash_algorithm,
    dg_hash_algorithm,
    unconstrained,
  )
  const name = `data_check_integrity_sa_${signed_attributes_hash_algorithm}_dg_${dg_hash_algorithm}`
  const nargoFile = NARGO_TEMPLATE(name, [
    { name: "data_check_integrity", path: "../../../../../lib/data-check/integrity" },
    { name: "commitment", path: "../../../../../lib/commitment/integrity-to-disclosure" },
    { name: "utils", path: "../../../../../lib/utils" },
  ])
  const folderPath = `./src/noir/bin/data-check/integrity/sa_${signed_attributes_hash_algorithm}/dg_${dg_hash_algorithm}`
  const noirFilePath = `${folderPath}/src/main.nr`
  const nargoFilePath = `${folderPath}/Nargo.toml`
  ensureDirectoryExistence(noirFilePath)
  fs.writeFileSync(noirFilePath, noirFile)
  ensureDirectoryExistence(nargoFilePath)
  fs.writeFileSync(nargoFilePath, nargoFile)
  generatedCircuits.push({ name, path: folderPath })
}

function generateFaceMatchAndroidCircuit(
  root_signature_algorithm: "rsa" | "ecdsa",
  intermediate_signature_algorithms: {
    signature_algorithm: "rsa" | "ecdsa"
    bit_size: number
    hash_algorithm: "sha1" | "sha224" | "sha256" | "sha384" | "sha512"
  }[],
  evm: boolean = false,
  unconstrained: boolean = false,
) {
  const noirFile = FACEMATCH_ANDROID_TEMPLATE(
    root_signature_algorithm,
    intermediate_signature_algorithms,
    evm,
    unconstrained,
  )  
  const intermediate_certificates_count = intermediate_signature_algorithms.length
  const intermediate_certificates_str = intermediate_signature_algorithms.map(({ signature_algorithm, hash_algorithm, bit_size }) => `ik_${signature_algorithm === "rsa" ? "rsa_" : "ecdsa_p"}${bit_size}_${hash_algorithm}`).join("_")
  const name = `facematch_android_rk_${root_signature_algorithm}_ik_count_${intermediate_certificates_count}_${intermediate_certificates_str}${evm ? "_evm" : ""}`
  const relativePath = `../../../../../../${"../".repeat(intermediate_certificates_count)}`
  const nargoFile = NARGO_TEMPLATE(name, [
    { name: "facematch", path: `${relativePath}lib/facematch` },
    { name: "sig_check_rsa", path: `${relativePath}lib/sig-check/rsa` },
    { name: "sig_check_ecdsa", path: `${relativePath}lib/sig-check/ecdsa` },
    { name: "data_check_tbs_pubkey", path: `${relativePath}lib/data-check/tbs-pubkey` },
    { name: "data_check_expiry", path: `${relativePath}lib/data-check/expiry` },
    { name: "commitment", path: `${relativePath}lib/commitment/scoped-nullifier` },
    { name: "utils", path: `${relativePath}lib/utils` },
  ])
  const intermediate_certificates_path = intermediate_signature_algorithms.map(({ signature_algorithm, hash_algorithm, bit_size }) => `ik_${signature_algorithm === "rsa" ? "rsa_" : "ecdsa_p"}${bit_size}_${hash_algorithm}`).join("/")
  const folderPath = `./src/noir/bin/facematch/android/rk_${root_signature_algorithm}/ik_count_${intermediate_certificates_count}/${intermediate_certificates_path}${evm ? "/evm" : "/standard"}`
  const noirFilePath = `${folderPath}/src/main.nr`
  const nargoFilePath = `${folderPath}/Nargo.toml`
  ensureDirectoryExistence(noirFilePath)
  fs.writeFileSync(noirFilePath, noirFile)
  ensureDirectoryExistence(nargoFilePath)
  fs.writeFileSync(nargoFilePath, nargoFile)
  generatedCircuits.push({ name, path: folderPath })
}

function generateOuterCircuit(disclosure_proofs_count: number, unconstrained: boolean = false) {
  const noirFile = OUTER_CIRCUIT_TEMPLATE(disclosure_proofs_count, unconstrained)
  const name = `outer_count_${disclosure_proofs_count + 3}`
  const nargoFile = NARGO_TEMPLATE(name, [
    { name: "common", path: "../../../../lib/commitment/common" },
    { name: "outer_lib", path: "../../../../lib/outer" },
    { name: "utils", path: "../../../../lib/utils" },
  ])
  const folderPath = `./src/noir/bin/main/outer/count_${disclosure_proofs_count + 3}`
  const noirFilePath = `${folderPath}/src/main.nr`
  const nargoFilePath = `${folderPath}/Nargo.toml`
  ensureDirectoryExistence(noirFilePath)
  fs.writeFileSync(noirFilePath, noirFile)
  fs.writeFileSync(nargoFilePath, nargoFile)
  generatedCircuits.push({ name, path: folderPath })
}

const SIGNATURE_ALGORITHMS_SUPPORTED: {
  type: "ecdsa" | "rsa"
  family: "brainpool" | "nist" | "pss" | "pkcs"
  curve_name?: string
  bit_size: number
}[] = [
  { type: "ecdsa", family: "nist", curve_name: "p192", bit_size: 192 },
  { type: "ecdsa", family: "nist", curve_name: "p224", bit_size: 224 },
  { type: "ecdsa", family: "nist", curve_name: "p256", bit_size: 256 },
  { type: "ecdsa", family: "nist", curve_name: "p384", bit_size: 384 },
  { type: "ecdsa", family: "nist", curve_name: "p521", bit_size: 521 },
  { type: "ecdsa", family: "brainpool", curve_name: "192r1", bit_size: 192 },
  { type: "ecdsa", family: "brainpool", curve_name: "224r1", bit_size: 224 },
  { type: "ecdsa", family: "brainpool", curve_name: "256r1", bit_size: 256 },
  { type: "ecdsa", family: "brainpool", curve_name: "384r1", bit_size: 384 },
  { type: "ecdsa", family: "brainpool", curve_name: "512r1", bit_size: 512 },
  /*{ type: "ecdsa", family: "brainpool", curve_name: "256t1", bit_size: 256 },
  { type: "ecdsa", family: "brainpool", curve_name: "384t1", bit_size: 384 },
  { type: "ecdsa", family: "brainpool", curve_name: "512t1", bit_size: 512 },*/
  { type: "rsa", family: "pss", bit_size: 1024 },
  { type: "rsa", family: "pss", bit_size: 2048 },
  { type: "rsa", family: "pss", bit_size: 3072 },
  { type: "rsa", family: "pss", bit_size: 4096 },
  { type: "rsa", family: "pkcs", bit_size: 1024 },
  { type: "rsa", family: "pkcs", bit_size: 2048 },
  { type: "rsa", family: "pkcs", bit_size: 3072 },
  { type: "rsa", family: "pkcs", bit_size: 4096 },
]

const TBS_MAX_LENGTHS = [700, 1000, 1200, 1600]

const HASH_ALGORITHMS_SUPPORTED = ["sha1", "sha256", "sha384", "sha512"]
// Only used for data integrity check circuits
// As few countries use it for the signature algorithm and we don't want to generate too many circuits
const HASH_ALGORITHMS_SUPPORTED_EXTENDED = ["sha1", "sha224", "sha256", "sha384", "sha512"]

const generateDscCircuits = ({ unconstrained = false }: { unconstrained: boolean }) => {
  console.log("Generating DSC circuits...")
  SIGNATURE_ALGORITHMS_SUPPORTED.forEach(({ type, family, curve_name, bit_size }) => {
    TBS_MAX_LENGTHS.forEach((tbs_max_len) => {
      HASH_ALGORITHMS_SUPPORTED.forEach((hash_algorithm) => {
        if (type === "ecdsa") {
          generateDscEcdsaCircuit(
            family,
            curve_name!,
            bit_size,
            tbs_max_len,
            hash_algorithm as "sha1" | "sha256" | "sha384" | "sha512",
            unconstrained,
          )
        } else {
          if (hash_algorithm === "sha512" && bit_size === 1024) {
            // A sha512 64 bytes hash cannot fit in a 128 bytes (1024 bits) RSA signature`,
            return
          }
          generateDscRsaCircuit(
            family as "pss" | "pkcs",
            bit_size,
            tbs_max_len,
            hash_algorithm as "sha1" | "sha256" | "sha384" | "sha512",
            unconstrained,
          )
        }
      })
    })
  })
  // Generate special cases
  // Moldova: RSA 6144 bit with SHA-1 and SHA-256 (1000 & 1200 bytes TBS)
  generateDscRsaCircuit("pkcs", 6144, 1000, "sha1", unconstrained)
  generateDscRsaCircuit("pkcs", 6144, 1000, "sha256", unconstrained)
  generateDscRsaCircuit("pkcs", 6144, 1200, "sha1", unconstrained)
  generateDscRsaCircuit("pkcs", 6144, 1200, "sha256", unconstrained)
}

const generateIdDataCircuits = ({ unconstrained = false }: { unconstrained: boolean }) => {
  console.log("Generating ID data circuits...")
  SIGNATURE_ALGORITHMS_SUPPORTED.forEach(({ type, family, curve_name, bit_size }) => {
    TBS_MAX_LENGTHS.forEach((tbs_max_len) => {
      HASH_ALGORITHMS_SUPPORTED.forEach((hash_algorithm) => {
        if (type === "ecdsa") {
          generateIdDataEcdsaCircuit(
            family,
            curve_name!,
            bit_size,
            tbs_max_len,
            hash_algorithm as "sha1" | "sha256" | "sha384" | "sha512",
            unconstrained,
          )
        } else {
          if (hash_algorithm === "sha512" && bit_size === 1024) {
            // A sha512 64 bytes hash cannot fit in a 128 bytes (1024 bits) RSA signature`,
            return
          }
          generateIdDataRsaCircuit(
            family as "pss" | "pkcs",
            bit_size,
            tbs_max_len,
            hash_algorithm as "sha1" | "sha256" | "sha384" | "sha512",
            unconstrained,
          )
        }
      })
    })
  })
  // Generate special cases
  // Lithuania: P224 with SHA224 (700 & 1000 bytes TBS)
  generateIdDataEcdsaCircuit("nist", "p224", 224, 700, "sha224", unconstrained)
  generateIdDataEcdsaCircuit("nist", "p224", 224, 1000, "sha224", unconstrained)
}

const generateDataIntegrityCheckCircuits = ({
  unconstrained = false,
}: {
  unconstrained: boolean
}) => {
  console.log("Generating data integrity check circuits...")
  HASH_ALGORITHMS_SUPPORTED_EXTENDED.forEach((signed_attributes_hash_algorithm) => {
    HASH_ALGORITHMS_SUPPORTED_EXTENDED.forEach((dg_hash_algorithm) => {
      generateDataIntegrityCheckCircuit(
        signed_attributes_hash_algorithm as "sha1" | "sha224" | "sha256" | "sha384" | "sha512",
        dg_hash_algorithm as "sha1" | "sha224" | "sha256" | "sha384" | "sha512",
        unconstrained,
      )
    })
  })
}

const generateFaceMatchAndroidCircuits = ({ unconstrained = false }: { unconstrained: boolean }) => {
  const intermediate_signature_algorithms: { signature_algorithm: "ecdsa" | "rsa"; hash_algorithm: "sha256" | "sha384"; bit_size: number }[] = [
    { signature_algorithm: "ecdsa", hash_algorithm: "sha256", bit_size: 256 },
    { signature_algorithm: "ecdsa", hash_algorithm: "sha384", bit_size: 384 },
    { signature_algorithm: "ecdsa", hash_algorithm: "sha256", bit_size: 384 },
    { signature_algorithm: "rsa", hash_algorithm: "sha256", bit_size: 2048 },
    { signature_algorithm: "rsa", hash_algorithm: "sha256", bit_size: 4096 },
  ]
  // Don't generate the circuits for the ECDSA root key as it's not used yet (only in February 2026)
  const root_signature_algorithms: ("rsa" | "ecdsa")[] = ["rsa"]
  console.log("Generating FaceMatch Android circuits...")
  root_signature_algorithms.forEach((root_signature_algorithm) => {
    // Non-EVM
    intermediate_signature_algorithms.forEach((a) => {
      generateFaceMatchAndroidCircuit(root_signature_algorithm, [a], false, unconstrained)
      intermediate_signature_algorithms.forEach((b) => {
        generateFaceMatchAndroidCircuit(root_signature_algorithm, [a, b], false, unconstrained)
        intermediate_signature_algorithms.forEach((c) => {
          generateFaceMatchAndroidCircuit(root_signature_algorithm, [a, b, c], false, unconstrained)
        })
      })
    })
    // EVM
    intermediate_signature_algorithms.forEach((a) => {
      generateFaceMatchAndroidCircuit(root_signature_algorithm, [a], true, unconstrained)
      intermediate_signature_algorithms.forEach((b) => {
        generateFaceMatchAndroidCircuit(root_signature_algorithm, [a, b], true, unconstrained)
        intermediate_signature_algorithms.forEach((c) => {
          generateFaceMatchAndroidCircuit(root_signature_algorithm, [a, b, c], true, unconstrained)
        })
      })
    })
  })
}

const generateOuterCircuits = ({ unconstrained = false }: { unconstrained: boolean }) => {
  console.log("Generating outer circuits...")
  for (let i = 1; i <= 10; i++) {
    generateOuterCircuit(i, unconstrained)
  }
}

/**
 * Fails to compile the circuits.
 *
 * panicked at compiler/noirc_evaluator/src/brillig/brillig_ir/registers.rs:66:9:
 * Stack frame too deep
 *
 * 209 |         const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
 * 210 |         const ptr0 = passStringToWasm0(entry_point, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
 * 211 |         const len0 = WASM_VECTOR_LEN;
 * 212 |         _assertClass(file_source_map, PathToFileSourceMap);
 * 213 |         var ptr1 = file_source_map.__destroy_into_raw();
 * 214 |         wasm.compile_program(retptr, ptr0, len0, isLikeNone(dependency_graph) ? 0 : addHeapObject(dependency_graph), ptr1);
 */
const compileCircuits = async () => {
  SIGNATURE_ALGORITHMS_SUPPORTED.forEach(async ({ type, family, curve_name, bit_size }) => {
    console.log("Compiling circuit for", type, family, curve_name ?? "", bit_size)
    const dscCircuitPath = `./src/noir/bin/sig-check/dsc/${type}/${family}/${
      type === "ecdsa" ? curve_name : bit_size
    }`
    const idDataCircuitPath = `./src/noir/bin/sig-check/id-data/${type}/${family}/${
      type === "ecdsa" ? curve_name : bit_size
    }`
    const dscCircuit = await compileCircuit(path.resolve(dscCircuitPath))
    const idDataCircuit = await compileCircuit(path.resolve(idDataCircuitPath))
    console.log("DSC Circuit:", dscCircuit.abi)
    console.log("ID Data Circuit:", idDataCircuit.abi)
  })
}

const generateWorkspaceToml = () => {
  const workspaceToml = WORKSPACE_NARGO_TEMPLATE(generatedCircuits.map(({ path }) => path))
  fs.writeFileSync("./Nargo.toml", workspaceToml)
}

// Maximum number of concurrent circuit compilations via `nargo compile`
// Default value that can be overridden via CLI using --concurrency=x
const DEFAULT_CONCURRENCY = 10

// Promise pool for controlled concurrency
class PromisePool {
  private queue: (() => Promise<void>)[] = []
  private activePromises = 0

  constructor(private concurrency: number) {}

  async add(fn: () => Promise<void>) {
    if (this.activePromises >= this.concurrency) {
      // Queue the task if we're at max concurrency
      await new Promise<void>((resolve) => {
        this.queue.push(async () => {
          await fn()
          resolve()
        })
      })
    } else {
      // Execute immediately if under the concurrency limit
      this.activePromises++
      try {
        await fn()
      } finally {
        this.activePromises--
        // Process next queued task if any
        if (this.queue.length > 0) {
          const next = this.queue.shift()!
          this.add(next)
        }
      }
    }
  }
}

const ignoreStdErrs = ["Waiting for lock on git dependencies cache..."]

const compileCircuitsWithNargo = async ({
  forceCompilation = false,
  getGateCount = false,
  printStdErr = false,
  concurrency = DEFAULT_CONCURRENCY,
}: {
  forceCompilation?: boolean
  getGateCount?: boolean
  printStdErr?: boolean
  concurrency?: number
} = {}) => {
  const startTime = Date.now()
  const command = getGateCount ? "bash scripts/info.sh" : "nargo compile --force --package"
  if (concurrency != DEFAULT_CONCURRENCY) {
    console.warn(`Using concurrency: ${concurrency}`)
  }
  // Helper function to promisify exec
  const execPromise = (
    name: string,
    cmd: string,
    current: number,
    total: number,
  ): Promise<string> => {
    return new Promise((resolve, reject) => {
      exec(cmd, { maxBuffer: 100 * 1024 * 1024 }, (error, stdout, stderr) => {
        if (error) {
          reject(error)
          return
        }
        if (stderr && printStdErr && !ignoreStdErrs.includes(stderr.trim())) {
          console.error(`Script error output: ${stderr}`)
        }
        let statsString = ""
        if (stderr) {
          const warnings = (stderr.match(/warning: /gi) || []).length
          const bugs = (stderr.match(/bug: /gi) || []).length
          if (warnings > 0 || bugs > 0) {
            statsString = ` [noir warnings: ${warnings}, noir bugs: ${bugs}]`
          }
        }
        console.log(`Successfully compiled ${name}${statsString} (${current}/${total})`)
        resolve(stdout)
      })
    })
  }

  const pool = new PromisePool(concurrency)
  const promises: Promise<void>[] = []

  // Get all circuits that need to be compiled
  const allCircuits = [...STATIC_CIRCUITS, ...generatedCircuits]
  const circuitsToCompile = forceCompilation
    ? allCircuits
    : allCircuits.filter(({ name }) => {
        const outputPath = path.join("target", `${name}.json`)
        return !fs.existsSync(outputPath)
      })

  // Process circuits with controlled concurrency
  const totalCount = circuitsToCompile.length
  let processedCount = 0
  for (const { name } of circuitsToCompile) {
    processedCount++

    const promise = (name: string, counter: number) =>
      pool.add(async () => {
        try {
          console.log(`Compiling ${name}... (${counter}/${totalCount})`)
          await execPromise(name, `${command} ${name}`, counter, totalCount)
        } catch (error: any) {
          console.error(`Error executing script for ${name}: ${error.message}`)
        }
      })
    promises.push(promise(name, processedCount))
  }

  // Wait for all compilations to complete
  await Promise.all(promises)

  if (processedCount > 0) {
    const duration = (Date.now() - startTime) / 1000 // convert to seconds
    const minutes = Math.floor(duration / 60)
    const seconds = Math.floor(duration % 60)

    const skippedCount = allCircuits.length - circuitsToCompile.length
    console.log(`Total circuits: ${allCircuits.length}`)
    console.log(`Circuits compiled: ${processedCount}`)
    if (skippedCount > 0) console.log(`Circuits skipped: ${skippedCount} (already compiled)`)

    if (minutes > 0) {
      console.log(`Total time taken: ${minutes}m ${seconds}s`)
    } else if (seconds > 0) {
      console.log(`Total time taken: ${seconds}s`)
    }
  } else {
    console.log("No circuits to compile")
  }
}

function checkNargoVersion() {
  try {
    // Read package.json to get expected nargo version
    const packageJsonPath = path.resolve(__dirname, "../../../package.json")
    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf8"))
    const expectedNoirVersion = packageJson.dependencies["@noir-lang/noir_js"]
    if (!expectedNoirVersion) {
      throw new Error("Couldn't find noir version in package.json")
    }
    // Get installed version numbers for comparison
    const nargoVersionOutput = execSync("nargo -V").toString().trim()
    const versionMatch = nargoVersionOutput.match(/nargo version = ([^\s\n]+)/)
    const installedNargoVersion = versionMatch ? versionMatch[1] : null
    if (!installedNargoVersion) {
      throw new Error(`Failed to parse nargo version output: ${nargoVersionOutput}`)
    }
    if (installedNargoVersion !== expectedNoirVersion.replace("^", "")) {
      throw new Error(
        `nargo version mismatch. Expected ${expectedNoirVersion} but found ${installedNargoVersion}. Please switch nargo versions using noirup.`,
      )
    }
  } catch (error: any) {
    if (error.message.includes("command not found")) {
      console.error(
        "Error: nargo is not installed. Visit https://noir-lang.org for installation instructions.",
      )
    } else {
      console.error("Error:", error.message)
    }
    process.exit(1)
  }
}

const args = process.argv.slice(2)

if (args.includes("generate")) {
  const unconstrained = args.includes("unconstrained")
  generateDscCircuits({ unconstrained })
  generateIdDataCircuits({ unconstrained })
  generateDataIntegrityCheckCircuits({ unconstrained })
  generateOuterCircuits({ unconstrained })
  generateFaceMatchAndroidCircuits({ unconstrained })
  generateWorkspaceToml()
}

if (args.includes("compile")) {
  // Parse --concurrency argument if provided
  let concurrency = DEFAULT_CONCURRENCY
  const concurrencyArg = args.find((arg) => arg.startsWith("--concurrency="))
  if (concurrencyArg) {
    const value = concurrencyArg.split("=")[1]
    const parsed = parseInt(value, 10)
    if (!isNaN(parsed) && parsed > 0) {
      concurrency = parsed
    } else {
      console.warn(`Invalid --concurrency value. Using default: ${DEFAULT_CONCURRENCY}`)
    }
  }
  const forceCompilation = args.includes("force")
  const printStdErr = args.includes("verbose")
  checkNargoVersion()
  compileCircuitsWithNargo({ forceCompilation, printStdErr, concurrency })
}
