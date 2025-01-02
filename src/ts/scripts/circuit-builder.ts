import * as fs from "fs"
import * as path from "path"
import { compileCircuit } from "zkpassport-utils/utils"
import { exec } from "child_process"

// Function to ensure directory exists
function ensureDirectoryExistence(filePath: string) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true })
}

const generatedCircuits: {
  name: string
  path: string
}[] = []

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
compiler_version = ">=0.36.0"

[dependencies]
${dependencies.map(({ name, path }) => `${name} = { path = "${path}" }`).join("\n")}
`

const WORKSPACE_NARGO_TEMPLATE = (dependencies: string[]) => `[workspace]
members = [
    "src/noir/bin/compare/citizenship",
    "src/noir/bin/compare/age",
    "src/noir/bin/disclose/flags",
    "src/noir/bin/disclose/bytes",
    "src/noir/bin/main/outer",
    "src/noir/bin/data-check/expiry",
    "src/noir/bin/data-check/integrity",
    "src/noir/bin/exclusion-check/country",
    "src/noir/bin/inclusion-check/country",${dependencies
      .map(
        (path) => `
    "${path.replace("./", "")}"`,
      )
      .join(",")}
]
`

const DSC_ECDSA_TEMPLATE = (
  curve_family: string,
  curve_name: string,
  bit_size: number,
  tbs_max_len: number,
  unconstrained: boolean = false,
) => `// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use commitment::commit_to_dsc;
use sig_check_ecdsa::verify_${curve_family}_${curve_name};
use utils::{concat_array, split_array};

${unconstrained ? "unconstrained " : ""}fn main(
    certificate_registry_root: pub Field,
    certificate_registry_index: Field,
    certificate_registry_hash_path: [Field; 14],
    certificate_registry_id: Field,
    salt: Field,
    country: str<3>,
    csc_pubkey_x: [u8; ${Math.ceil(bit_size / 8)}],
    csc_pubkey_y: [u8; ${Math.ceil(bit_size / 8)}],
    dsc_signature: [u8; ${Math.ceil(bit_size / 8) * 2}],
    tbs_certificate: [u8; ${tbs_max_len}],
    tbs_certificate_len: u64,
) -> pub Field {
    let (r, s) = split_array(dsc_signature);
    assert(verify_${curve_family}_${curve_name}(
        csc_pubkey_x,
        csc_pubkey_y,
        r,
        s,
        tbs_certificate,
        tbs_certificate_len,
    ));
    let comm_out = commit_to_dsc(
        certificate_registry_root,
        certificate_registry_index,
        certificate_registry_hash_path,
        certificate_registry_id,
        country,
        tbs_certificate,
        salt,
        concat_array(csc_pubkey_x, csc_pubkey_y),
    );
    comm_out
}`

const DSC_RSA_TEMPLATE = (
  rsa_type: "pss" | "pkcs",
  bit_size: number,
  tbs_max_len: number,
  unconstrained: boolean = false,
) => `// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use sig_check_rsa::verify_signature;
use commitment::commit_to_dsc;

${unconstrained ? "unconstrained " : ""}fn main(
    certificate_registry_root: Field,
    certificate_registry_index: Field,
    certificate_registry_hash_path: [Field; 14],
    certificate_registry_id: Field,
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
}, ${tbs_max_len}>(
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
        certificate_registry_id,
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
  unconstrained: boolean = false,
) => `// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use commitment::commit_to_id;
use data_check_tbs_pubkey::verify_ecdsa_pubkey_in_tbs;
use sig_check_ecdsa::verify_${curve_family}_${curve_name};
use utils::split_array;

${unconstrained ? "unconstrained " : ""}fn main(
    comm_in: pub Field,
    salt: Field,
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
        signed_attributes,
        signed_attributes_size,
    ));
    let comm_out = commit_to_id(
        comm_in,
        salt,
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
  unconstrained: boolean = false,
) => `// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use sig_check_rsa::verify_signature;
use data_check_tbs_pubkey::verify_rsa_pubkey_in_tbs;
use commitment::commit_to_id;

${unconstrained ? "unconstrained " : ""}fn main(
    comm_in: pub Field,
    salt: Field,
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
    assert(verify_signature::<${Math.ceil(bit_size / 8)}, ${rsa_type === "pss" ? 1 : 0}, 200>(
        dsc_pubkey,
        sod_signature,
        dsc_pubkey_redc_param,
        exponent,
        signed_attributes,
        signed_attributes_size,
    ));
    let comm_out = commit_to_id(
        comm_in,
        salt,
        dg1,
        tbs_certificate,
        sod_signature,
        signed_attributes,
        signed_attributes_size as Field,
    );
    comm_out
}
`

function generateDscEcdsaCircuit(
  curve_family: string,
  curve_name: string,
  bit_size: number,
  tbs_max_len: number,
  unconstrained: boolean = false,
) {
  const noirFile = DSC_ECDSA_TEMPLATE(
    curve_family,
    curve_name,
    bit_size,
    tbs_max_len,
    unconstrained,
  )
  const name = `sig_check_dsc_tbs_${tbs_max_len}_ecdsa_${curve_family}_${curve_name}`
  const nargoFile = NARGO_TEMPLATE(name, [
    { name: "sig_check_ecdsa", path: "../../../../../../../lib/sig-check/ecdsa" },
    { name: "utils", path: "../../../../../../../lib/utils" },
    { name: "commitment", path: "../../../../../../../lib/commitment/csc-to-dsc" },
  ])
  const folderPath = `./src/noir/bin/sig-check/dsc/tbs_${tbs_max_len}/ecdsa/${curve_family}/${curve_name}`
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
  unconstrained: boolean = false,
) {
  const noirFile = DSC_RSA_TEMPLATE(rsa_type, bit_size, tbs_max_len, unconstrained)
  const name = `sig_check_dsc_tbs_${tbs_max_len}_rsa_${rsa_type}_${bit_size}`
  const nargoFile = NARGO_TEMPLATE(name, [
    { name: "sig_check_rsa", path: "../../../../../../../lib/sig-check/rsa" },
    { name: "utils", path: "../../../../../../../lib/utils" },
    { name: "commitment", path: "../../../../../../../lib/commitment/csc-to-dsc" },
  ])
  const folderPath = `./src/noir/bin/sig-check/dsc/tbs_${tbs_max_len}/rsa/${rsa_type}/${bit_size}`
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
  unconstrained: boolean = false,
) {
  const noirFile = ID_DATA_ECDSA_TEMPLATE(
    curve_family,
    curve_name,
    bit_size,
    tbs_max_len,
    unconstrained,
  )
  const name = `sig_check_id_data_tbs_${tbs_max_len}_ecdsa_${curve_family}_${curve_name}`
  const nargoFile = NARGO_TEMPLATE(name, [
    { name: "sig_check_ecdsa", path: "../../../../../../../lib/sig-check/ecdsa" },
    { name: "utils", path: "../../../../../../../lib/utils" },
    { name: "data_check_tbs_pubkey", path: "../../../../../../../lib/data-check/tbs-pubkey" },
    { name: "commitment", path: "../../../../../../../lib/commitment/dsc-to-id" },
  ])
  const folderPath = `./src/noir/bin/sig-check/id-data/tbs_${tbs_max_len}/ecdsa/${curve_family}/${curve_name}`
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
  unconstrained: boolean = false,
) {
  const noirFile = ID_DATA_RSA_TEMPLATE(rsa_type, bit_size, tbs_max_len, unconstrained)
  const name = `sig_check_id_data_tbs_${tbs_max_len}_rsa_${rsa_type}_${bit_size}`
  const nargoFile = NARGO_TEMPLATE(name, [
    { name: "sig_check_rsa", path: "../../../../../../../lib/sig-check/rsa" },
    { name: "utils", path: "../../../../../../../lib/utils" },
    { name: "data_check_tbs_pubkey", path: "../../../../../../../lib/data-check/tbs-pubkey" },
    { name: "commitment", path: "../../../../../../../lib/commitment/dsc-to-id" },
  ])
  const folderPath = `./src/noir/bin/sig-check/id-data/tbs_${tbs_max_len}/rsa/${rsa_type}/${bit_size}`
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

const TBS_MAX_LENGTHS = [700, 1000, 1200, 1500]

const generateDscCircuits = ({ unconstrained = false }: { unconstrained: boolean }) => {
  console.log("Generating DSC circuits...")
  SIGNATURE_ALGORITHMS_SUPPORTED.forEach(({ type, family, curve_name, bit_size }) => {
    TBS_MAX_LENGTHS.forEach((tbs_max_len) => {
      if (type === "ecdsa") {
        generateDscEcdsaCircuit(family, curve_name!, bit_size, tbs_max_len, unconstrained)
      } else {
        generateDscRsaCircuit(family as "pss" | "pkcs", bit_size, tbs_max_len, unconstrained)
      }
    })
  })
}

const generateIdDataCircuits = ({ unconstrained = false }: { unconstrained: boolean }) => {
  console.log("Generating ID data circuits...")
  SIGNATURE_ALGORITHMS_SUPPORTED.forEach(({ type, family, curve_name, bit_size }) => {
    TBS_MAX_LENGTHS.forEach((tbs_max_len) => {
      if (type === "ecdsa") {
        generateIdDataEcdsaCircuit(family, curve_name!, bit_size, tbs_max_len, unconstrained)
      } else {
        generateIdDataRsaCircuit(family as "pss" | "pkcs", bit_size, tbs_max_len, unconstrained)
      }
    })
  })
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

const compileCircuitsWithNargo = async (getGateCount: boolean = false) => {
  const command = getGateCount ? "bash scripts/info.sh" : "nargo compile --force --package"
  generatedCircuits.forEach(async ({ name }) => {
    console.log(`Compiling ${name}`)
    exec(`${command} ${name}`, (error, stdout, stderr) => {
      if (error) {
        console.error(`Error executing script: ${error.message}`)
        return
      }
      if (stderr) {
        console.error(`Script error output: ${stderr}`)
        return
      }
      console.log(`Script output: ${stdout}`)
    })
  })
}

const args = process.argv.slice(2)
const unconstrained = args.includes("unconstrained")

generateDscCircuits({ unconstrained: unconstrained })
generateIdDataCircuits({ unconstrained: unconstrained })
generateWorkspaceToml()
// This works but use at your own risk (this will be very demanding of your machine)
// compileCircuitsWithNargo()
