import * as fs from "fs"
import * as path from "path"
import { exec, execSync } from "child_process"
import { compileCircuit } from "../utils"
import {
  CERTIFICATE_REGISTRY_HEIGHT,
  HASH_ALGORITHM_SHA1,
  HASH_ALGORITHM_SHA256,
  HASH_ALGORITHM_SHA384,
  HASH_ALGORITHM_SHA512,
} from "@zkpassport/utils"

// Function to ensure directory exists
function ensureDirectoryExistence(filePath: string) {
  try {
    fs.mkdirSync(path.dirname(filePath), { recursive: true })
  } catch (e) {}
}

const generatedCircuits: {
  name: string
  path: string
}[] = []

function getHashAlgorithmByteSize(hash_algorithm: "sha1" | "sha256" | "sha384" | "sha512") {
  if (hash_algorithm === "sha1") {
    return 20
  } else if (hash_algorithm === "sha256") {
    return 32
  } else if (hash_algorithm === "sha384") {
    return 48
  } else if (hash_algorithm === "sha512") {
    return 64
  }
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
  { name: "compare_citizenship", path: "./src/noir/bin/compare/citizenship" },
  { name: "compare_age", path: "./src/noir/bin/compare/age/standard" },
  { name: "compare_age_evm", path: "./src/noir/bin/compare/age/evm" },
  { name: "compare_expiry", path: "./src/noir/bin/compare/expiry/standard" },
  { name: "compare_expiry_evm", path: "./src/noir/bin/compare/expiry/evm" },
  { name: "compare_birthdate", path: "./src/noir/bin/compare/birthdate/standard" },
  { name: "compare_birthdate_evm", path: "./src/noir/bin/compare/birthdate/evm" },
  { name: "disclose_flags", path: "./src/noir/bin/disclose/flags" },
  { name: "disclose_bytes", path: "./src/noir/bin/disclose/bytes/standard" },
  { name: "disclose_bytes_evm", path: "./src/noir/bin/disclose/bytes/evm" },
  { name: "bind", path: "./src/noir/bin/bind/standard" },
  { name: "bind_evm", path: "./src/noir/bin/bind/evm" },
  { name: "data_check_expiry", path: "./src/noir/bin/data-check/expiry" },
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
]

const LIB_CIRCUITS = [
  "src/noir/lib/bind",
  "src/noir/lib/commitment/common",
  "src/noir/lib/commitment/csc-to-dsc",
  "src/noir/lib/commitment/dsc-to-id",
  "src/noir/lib/commitment/integrity-to-disclosure",
  "src/noir/lib/commitment/scoped-nullifier",
  "src/noir/lib/compare/age",
  "src/noir/lib/compare/citizenship",
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
  hash_algorithm: "sha1" | "sha256" | "sha384" | "sha512",
  unconstrained: boolean = false,
) => `// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use commitment::commit_to_dsc;
use sig_check_ecdsa::verify_${curve_family}_${curve_name};
use utils::{concat_array, split_array};
use sig_check_common::${hash_algorithm}_and_check_data_to_sign;

${unconstrained ? "unconstrained " : ""}fn main(
    certificate_registry_root: pub Field,
    certificate_registry_index: Field,
    certificate_registry_hash_path: [Field; ${CERTIFICATE_REGISTRY_HEIGHT}],
    certificate_tags: Field,
    salt: Field,
    country: str<3>,
    csc_pubkey_x: [u8; ${Math.ceil(bit_size / 8)}],
    csc_pubkey_y: [u8; ${Math.ceil(bit_size / 8)}],
    dsc_signature: [u8; ${Math.ceil(bit_size / 8) * 2}],
    tbs_certificate: [u8; ${tbs_max_len}],
    tbs_certificate_len: u64,
) -> pub Field {
    let (r, s) = split_array(dsc_signature);
    let msg_hash = ${hash_algorithm}_and_check_data_to_sign(tbs_certificate, tbs_certificate_len);
    assert(verify_${curve_family}_${curve_name}(
        csc_pubkey_x,
        csc_pubkey_y,
        r,
        s,
        msg_hash,
    ));
    let comm_out = commit_to_dsc(
        certificate_registry_root,
        certificate_registry_index,
        certificate_registry_hash_path,
        certificate_tags,
        country,
        tbs_certificate,
        salt,
        ${hashAlgorithmToId(hash_algorithm)},
        concat_array(csc_pubkey_x, csc_pubkey_y),
    );
    comm_out
}`

const DSC_RSA_TEMPLATE = (
  rsa_type: "pss" | "pkcs",
  bit_size: number,
  tbs_max_len: number,
  hash_algorithm: "sha1" | "sha256" | "sha384" | "sha512",
  unconstrained: boolean = false,
) => `// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use sig_check_rsa::verify_signature;
use commitment::commit_to_dsc;

${unconstrained ? "unconstrained " : ""}fn main(
    certificate_registry_root: pub Field,
    certificate_registry_index: Field,
    certificate_registry_hash_path: [Field; ${CERTIFICATE_REGISTRY_HEIGHT}],
    certificate_tags: Field,
    salt: Field,
    country: str<3>,
    tbs_certificate: [u8; ${tbs_max_len}],
    tbs_certificate_len: u64,
    csc_pubkey: [u8; ${Math.ceil(bit_size / 8)}],
    csc_pubkey_redc_param: [u8; ${Math.ceil(bit_size / 8) + 1}],
    dsc_signature: [u8; ${Math.ceil(bit_size / 8)}],
    exponent: u32,
) -> pub Field {
    assert(verify_signature::<${Math.ceil(bit_size / 8)}, ${
  rsa_type === "pss" ? 1 : 0
}, ${tbs_max_len}, ${getHashAlgorithmByteSize(hash_algorithm)}>(
        csc_pubkey,
        dsc_signature,
        csc_pubkey_redc_param,
        exponent,
        tbs_certificate,
        tbs_certificate_len,
    ));
    let comm_out = commit_to_dsc(
        certificate_registry_root,
        certificate_registry_index,
        certificate_registry_hash_path,
        certificate_tags,
        country,
        tbs_certificate,
        salt,
        ${hashAlgorithmToId(hash_algorithm)},
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
  hash_algorithm: "sha1" | "sha256" | "sha384" | "sha512",
  unconstrained: boolean = false,
) => `// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use commitment::commit_to_id;
use data_check_tbs_pubkey::verify_ecdsa_pubkey_in_tbs;
use sig_check_ecdsa::verify_${curve_family}_${curve_name};
use utils::split_array;
use sig_check_common::${hash_algorithm}_and_check_data_to_sign;

${unconstrained ? "unconstrained " : ""}fn main(
    comm_in: pub Field,
    salt_in: Field,
    salt_out: Field,
    dg1: [u8; 95],
    dsc_pubkey_x: [u8; ${Math.ceil(bit_size / 8)}],
    dsc_pubkey_y: [u8; ${Math.ceil(bit_size / 8)}],
    sod_signature: [u8; ${Math.ceil(bit_size / 8) * 2}],
    tbs_certificate: [u8; ${tbs_max_len}],
    pubkey_offset_in_tbs: u32,
    signed_attributes: [u8; 200],
    signed_attributes_size: u64,
) -> pub Field {
    let (r, s) = split_array(sod_signature);
    let msg_hash = ${hash_algorithm}_and_check_data_to_sign(signed_attributes, signed_attributes_size);
    verify_ecdsa_pubkey_in_tbs(
        dsc_pubkey_x,
        dsc_pubkey_y,
        tbs_certificate,
        pubkey_offset_in_tbs,
    );
    assert(verify_${curve_family}_${curve_name}(
        dsc_pubkey_x,
        dsc_pubkey_y,
        r,
        s,
        msg_hash,
    ));
    let comm_out = commit_to_id(
        comm_in,
        salt_in,
        salt_out,
        dg1,
        tbs_certificate,
        sod_signature,
        signed_attributes,
        signed_attributes_size as Field,
    );
    comm_out
}
`

const ID_DATA_RSA_TEMPLATE = (
  rsa_type: "pss" | "pkcs",
  bit_size: number,
  tbs_max_len: number,
  hash_algorithm: "sha1" | "sha256" | "sha384" | "sha512",
  unconstrained: boolean = false,
) => `// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use sig_check_rsa::verify_signature;
use data_check_tbs_pubkey::verify_rsa_pubkey_in_tbs;
use commitment::commit_to_id;

${unconstrained ? "unconstrained " : ""}fn main(
    comm_in: pub Field,
    salt_in: Field,
    salt_out: Field,
    dg1: [u8; 95],
    dsc_pubkey: [u8; ${Math.ceil(bit_size / 8)}],
    dsc_pubkey_redc_param: [u8; ${Math.ceil(bit_size / 8) + 1}],
    sod_signature: [u8; ${Math.ceil(bit_size / 8)}],
    tbs_certificate: [u8; ${tbs_max_len}],
    pubkey_offset_in_tbs: u32,
    signed_attributes: [u8; 200],
    signed_attributes_size: u64,
    exponent: u32,
) -> pub Field {
    verify_rsa_pubkey_in_tbs(dsc_pubkey, tbs_certificate, pubkey_offset_in_tbs);
    assert(verify_signature::<${Math.ceil(bit_size / 8)}, ${
  rsa_type === "pss" ? 1 : 0
}, 200, ${getHashAlgorithmByteSize(hash_algorithm)}>(
        dsc_pubkey,
        sod_signature,
        dsc_pubkey_redc_param,
        exponent,
        signed_attributes,
        signed_attributes_size,
    ));
    let comm_out = commit_to_id(
        comm_in,
        salt_in,
        salt_out,
        dg1,
        tbs_certificate,
        sod_signature,
        signed_attributes,
        signed_attributes_size as Field,
    );
    comm_out
}
`

const DATA_INTEGRITY_CHECK_TEMPLATE = (
  signed_attributes_hash_algorithm: "sha1" | "sha256" | "sha384" | "sha512",
  dg_hash_algorithm: "sha1" | "sha256" | "sha384" | "sha512",
  unconstrained: boolean = false,
) => `// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use commitment::commit_to_disclosure;
use data_check_expiry::check_expiry;
use data_check_integrity::{check_dg1_${dg_hash_algorithm}, check_signed_attributes_${signed_attributes_hash_algorithm}};

${unconstrained ? "unconstrained " : ""}fn main(
    current_date: pub str<8>,
    comm_in: pub Field,
    salt_in: Field,
    salt_out: Field,
    dg1: [u8; 95],
    signed_attributes: [u8; 200],
    signed_attributes_size: u32,
    e_content: [u8; 700],
    e_content_size: u32,
    dg1_offset_in_e_content: u32,
    private_nullifier: Field,
) -> pub Field {
    // Check the ID is not expired first
    check_expiry(dg1, current_date.as_bytes());
    // Check the integrity of the data
    check_dg1_${dg_hash_algorithm}(
        dg1,
        e_content,
        dg1_offset_in_e_content,
    );
    check_signed_attributes_${signed_attributes_hash_algorithm}(
        signed_attributes,
        signed_attributes_size,
        e_content,
        e_content_size,
    );
    let comm_out = commit_to_disclosure(
        comm_in,
        salt_in,
        salt_out,
        dg1,
        signed_attributes,
        signed_attributes_size as Field,
        private_nullifier,
    );
    comm_out
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
scoped_nullifier -> The scoped nullifier
csc_to_dsc_proof -> The proof of the CSC to DSC circuit
dsc_to_id_data_proof -> The proof of the DSC to ID Data circuit
integrity_check_proof -> The proof of the integrity check circuit
disclosure_proofs -> The proofs of the disclosure circuits
*/

use common::compute_merkle_root;
use outer_lib::{
    CSCtoDSCProof, DisclosureProof, DSCtoIDDataProof, IntegrityCheckProof,
    prepare_disclosure_inputs, prepare_integrity_check_inputs, poseidon2_hash,
};
use std::verify_proof_with_type;
global PROOF_TYPE_HONK_ZK: u32 = 7;

fn verify_subproofs(
    // Root of the certificate merkle tree
    certificate_registry_root: Field,
    // Root of the circuit registry merkle tree
    circuit_registry_root: Field,
    // Current date as a string, e.g. 20241103
    current_date: str<8>,
    // The commitments over the parameters of the disclosure circuits
    param_commitments: [Field; ${disclosure_proofs_count}],
    // The nullifier service scope (a Pederson hash of the domain)
    service_scope: Field,
    // The service sub-scope
    service_subscope: Field,
    // The scoped nullifier: H(private_nullifier,service_scope,service_subscope)
    scoped_nullifier: Field,
    csc_to_dsc_proof: CSCtoDSCProof,
    dsc_to_id_data_proof: DSCtoIDDataProof,
    integrity_check_proof: IntegrityCheckProof,
    disclosure_proofs: [DisclosureProof; ${disclosure_proofs_count}],
) {
    // Verify that all subproofs vkey hashes exist in the circuit tree
    // This way we know for sure that the proofs were generated with valid circuits
    assert_eq(circuit_registry_root, compute_merkle_root(csc_to_dsc_proof.key_hash, csc_to_dsc_proof.tree_index, csc_to_dsc_proof.tree_hash_path));
    assert_eq(circuit_registry_root, compute_merkle_root(dsc_to_id_data_proof.key_hash, dsc_to_id_data_proof.tree_index, dsc_to_id_data_proof.tree_hash_path));
    assert_eq(circuit_registry_root, compute_merkle_root(integrity_check_proof.key_hash, integrity_check_proof.tree_index, integrity_check_proof.tree_hash_path));
    for i in 0..disclosure_proofs.len() {
        assert_eq(circuit_registry_root, compute_merkle_root(disclosure_proofs[i].key_hash, disclosure_proofs[i].tree_index, disclosure_proofs[i].tree_hash_path));
    }
      
    // Verify that the vkey hashes are correct
    assert_eq(poseidon2_hash(csc_to_dsc_proof.vkey), csc_to_dsc_proof.key_hash);
    assert_eq(poseidon2_hash(dsc_to_id_data_proof.vkey), dsc_to_id_data_proof.key_hash);
    assert_eq(poseidon2_hash(integrity_check_proof.vkey), integrity_check_proof.key_hash);
    for i in 0..disclosure_proofs.len() {
        assert_eq(poseidon2_hash(disclosure_proofs[i].vkey), disclosure_proofs[i].key_hash);
    }

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
    assert_eq(csc_to_dsc_proof.public_inputs[0], dsc_to_id_data_proof.public_inputs[0]);

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
    assert_eq(dsc_to_id_data_proof.public_inputs[1], integrity_check_proof.public_inputs[0]);

    verify_proof_with_type(
        integrity_check_proof.vkey,
        integrity_check_proof.proof,
        prepare_integrity_check_inputs(
            current_date,
            integrity_check_proof.public_inputs[0], // comm_in
            integrity_check_proof.public_inputs[1], // comm_out
        ),
        integrity_check_proof.key_hash,
        PROOF_TYPE_HONK_ZK,
    );

    for i in 0..disclosure_proofs.len() {
        // Commitment out from integrity check circuit == commitment in from disclosure circuit
        assert_eq(integrity_check_proof.public_inputs[1], disclosure_proofs[i].public_inputs[0]);

        verify_proof_with_type(
            disclosure_proofs[i].vkey,
            disclosure_proofs[i].proof,
            prepare_disclosure_inputs(
                disclosure_proofs[i].public_inputs[0], // comm_in
                param_commitments[i],
                service_scope,
                service_subscope,
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
    current_date: pub str<8>,
    service_scope: pub Field,
    service_subscope: pub Field,
    param_commitments: pub [Field; ${disclosure_proofs_count}],
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
        scoped_nullifier,
        csc_to_dsc_proof,
        dsc_to_id_data_proof,
        integrity_check_proof,
        disclosure_proofs,
    );
}`

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
  hash_algorithm: "sha1" | "sha256" | "sha384" | "sha512",
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
  signed_attributes_hash_algorithm: "sha1" | "sha256" | "sha384" | "sha512",
  dg_hash_algorithm: "sha1" | "sha256" | "sha384" | "sha512",
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
    { name: "data_check_expiry", path: "../../../../../lib/data-check/expiry" },
    { name: "commitment", path: "../../../../../lib/commitment/integrity-to-disclosure" },
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

function generateOuterCircuit(disclosure_proofs_count: number, unconstrained: boolean = false) {
  const noirFile = OUTER_CIRCUIT_TEMPLATE(disclosure_proofs_count, unconstrained)
  const name = `outer_count_${disclosure_proofs_count + 3}`
  const nargoFile = NARGO_TEMPLATE(name, [
    { name: "common", path: "../../../../lib/commitment/common" },
    { name: "outer_lib", path: "../../../../lib/outer" },
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
  { type: "ecdsa", family: "nist", curve_name: "p256", bit_size: 256 },
  { type: "ecdsa", family: "nist", curve_name: "p384", bit_size: 384 },
  { type: "ecdsa", family: "nist", curve_name: "p521", bit_size: 521 },
  { type: "ecdsa", family: "brainpool", curve_name: "256r1", bit_size: 256 },
  { type: "ecdsa", family: "brainpool", curve_name: "384r1", bit_size: 384 },
  { type: "ecdsa", family: "brainpool", curve_name: "512r1", bit_size: 512 },
  { type: "ecdsa", family: "brainpool", curve_name: "256t1", bit_size: 256 },
  { type: "ecdsa", family: "brainpool", curve_name: "384t1", bit_size: 384 },
  { type: "ecdsa", family: "brainpool", curve_name: "512t1", bit_size: 512 },
  { type: "rsa", family: "pss", bit_size: 1024 },
  { type: "rsa", family: "pss", bit_size: 2048 },
  { type: "rsa", family: "pss", bit_size: 3072 },
  { type: "rsa", family: "pss", bit_size: 4096 },
  { type: "rsa", family: "pkcs", bit_size: 1024 },
  { type: "rsa", family: "pkcs", bit_size: 2048 },
  { type: "rsa", family: "pkcs", bit_size: 3072 },
  { type: "rsa", family: "pkcs", bit_size: 4096 },
]

const TBS_MAX_LENGTHS = [700, 1000, 1200, 1500, 1600]

const HASH_ALGORITHMS_SUPPORTED = ["sha1", "sha256", "sha384", "sha512"]

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
}

const generateDataIntegrityCheckCircuits = ({
  unconstrained = false,
}: {
  unconstrained: boolean
}) => {
  console.log("Generating data integrity check circuits...")
  HASH_ALGORITHMS_SUPPORTED.forEach((signed_attributes_hash_algorithm) => {
    HASH_ALGORITHMS_SUPPORTED.forEach((dg_hash_algorithm) => {
      generateDataIntegrityCheckCircuit(
        signed_attributes_hash_algorithm as "sha1" | "sha256" | "sha384" | "sha512",
        dg_hash_algorithm as "sha1" | "sha256" | "sha384" | "sha512",
        unconstrained,
      )
    })
  })
}

const generateOuterCircuits = ({ unconstrained = false }: { unconstrained: boolean }) => {
  console.log("Generating outer circuits...")
  for (let i = 1; i <= 9; i++) {
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

function hashAlgorithmToId(hash_algorithm: "sha1" | "sha256" | "sha384" | "sha512") {
  const hashMap: Record<string, number> = {
    sha1: HASH_ALGORITHM_SHA1,
    sha256: HASH_ALGORITHM_SHA256,
    sha384: HASH_ALGORITHM_SHA384,
    sha512: HASH_ALGORITHM_SHA512,
  }
  if (hashMap[hash_algorithm] === undefined) {
    throw new Error(`Unsupported hash algorithm: ${hash_algorithm}`)
  }
  return hashMap[hash_algorithm]
}
