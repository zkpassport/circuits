import * as fs from "fs"
import * as path from "path"
import { exec, execSync } from "child_process"
import { compileCircuit } from "../utils"

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

function getHashAlgorithmByteSize(hash_algorithm: "sha256" | "sha384" | "sha512") {
  if (hash_algorithm === "sha256") {
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
  { name: "compare_age", path: "./src/noir/bin/compare/age" },
  { name: "compare_expiry", path: "./src/noir/bin/compare/expiry" },
  { name: "compare_birthdate", path: "./src/noir/bin/compare/birthdate" },
  { name: "disclose_flags", path: "./src/noir/bin/disclose/flags" },
  { name: "disclose_bytes", path: "./src/noir/bin/disclose/bytes" },
  { name: "data_check_expiry", path: "./src/noir/bin/data-check/expiry" },
  {
    name: "exclusion_check_issuing_country",
    path: "./src/noir/bin/exclusion-check/issuing-country",
  },
  {
    name: "inclusion_check_issuing_country",
    path: "./src/noir/bin/inclusion-check/issuing-country",
  },
  {
    name: "exclusion_check_nationality",
    path: "./src/noir/bin/exclusion-check/nationality",
  },
  {
    name: "inclusion_check_nationality",
    path: "./src/noir/bin/inclusion-check/nationality",
  },
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
  .join(",")}
]
`

const DSC_ECDSA_TEMPLATE = (
  curve_family: string,
  curve_name: string,
  bit_size: number,
  tbs_max_len: number,
  hash_algorithm: "sha256" | "sha384" | "sha512",
  unconstrained: boolean = false,
) => `// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use commitment::commit_to_dsc;
use sig_check_ecdsa::verify_${curve_family}_${curve_name};
use utils::{concat_array, split_array};
use sig_check_common::${hash_algorithm}_and_check_data_to_sign;

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
  hash_algorithm: "sha256" | "sha384" | "sha512",
  unconstrained: boolean = false,
) => `// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use sig_check_rsa::verify_signature;
use commitment::commit_to_dsc;

${unconstrained ? "unconstrained " : ""}fn main(
    certificate_registry_root: pub Field,
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
  hash_algorithm: "sha256" | "sha384" | "sha512",
  unconstrained: boolean = false,
) => `// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use commitment::commit_to_id;
use data_check_tbs_pubkey::verify_ecdsa_pubkey_in_tbs;
use sig_check_ecdsa::verify_${curve_family}_${curve_name};
use utils::split_array;
use sig_check_common::${hash_algorithm}_and_check_data_to_sign;

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
  hash_algorithm: "sha256" | "sha384" | "sha512",
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

const DATA_INTEGRITY_CHECK_TEMPLATE = (
  hash_algorithm: "sha256" | "sha384" | "sha512",
  unconstrained: boolean = false,
) => `// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use commitment::commit_to_disclosure;
use data_check_expiry::check_expiry;
use data_check_integrity::check_integrity_of_data_${hash_algorithm};

${unconstrained ? "unconstrained " : ""}fn main(
    current_date: pub str<8>,
    comm_in: pub Field,
    salt: Field,
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
    check_integrity_of_data_${hash_algorithm}(
        dg1,
        signed_attributes,
        signed_attributes_size,
        e_content,
        e_content_size,
        dg1_offset_in_e_content,
    );
    let comm_out = commit_to_disclosure(
        comm_in,
        salt,
        dg1,
        signed_attributes,
        signed_attributes_size as Field,
        private_nullifier,
    );
    comm_out
}
`

function generateDscEcdsaCircuit(
  curve_family: string,
  curve_name: string,
  bit_size: number,
  tbs_max_len: number,
  hash_algorithm: "sha256" | "sha384" | "sha512",
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
  hash_algorithm: "sha256" | "sha384" | "sha512",
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
  hash_algorithm: "sha256" | "sha384" | "sha512",
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
  hash_algorithm: "sha256" | "sha384" | "sha512",
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
  hash_algorithm: "sha256" | "sha384" | "sha512",
  unconstrained: boolean = false,
) {
  const noirFile = DATA_INTEGRITY_CHECK_TEMPLATE(hash_algorithm, unconstrained)
  const name = `data_check_integrity_${hash_algorithm}`
  const nargoFile = NARGO_TEMPLATE(name, [
    { name: "data_check_integrity", path: "../../../../lib/data-check/integrity" },
    { name: "data_check_expiry", path: "../../../../lib/data-check/expiry" },
    { name: "commitment", path: "../../../../lib/commitment/integrity-to-disclosure" },
  ])
  const folderPath = `./src/noir/bin/data-check/integrity/${hash_algorithm}`
  const noirFilePath = `${folderPath}/src/main.nr`
  const nargoFilePath = `${folderPath}/Nargo.toml`
  ensureDirectoryExistence(noirFilePath)
  fs.writeFileSync(noirFilePath, noirFile)
  ensureDirectoryExistence(nargoFilePath)
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

const HASH_ALGORITHMS_SUPPORTED = ["sha256", "sha384", "sha512"]

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
            hash_algorithm as "sha256" | "sha384" | "sha512",
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
            hash_algorithm as "sha256" | "sha384" | "sha512",
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
            hash_algorithm as "sha256" | "sha384" | "sha512",
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
            hash_algorithm as "sha256" | "sha384" | "sha512",
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
  HASH_ALGORITHMS_SUPPORTED.forEach((hash_algorithm) => {
    generateDataIntegrityCheckCircuit(
      hash_algorithm as "sha256" | "sha384" | "sha512",
      unconstrained,
    )
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

// Maximum number of concurrent circuit compilations via `nargo compile`
const MAX_CONCURRENT_COMPILATIONS = 10

// Promise pool for controlled concurrency
class PromisePool {
  private queue: (() => Promise<void>)[] = []
  private activePromises = 0

  constructor(private maxConcurrent: number) {}

  async add(fn: () => Promise<void>) {
    if (this.activePromises >= this.maxConcurrent) {
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

const compileCircuitsWithNargo = async ({
  forceCompilation = false,
  getGateCount = false,
  printStdErr = false,
}: {
  forceCompilation?: boolean
  getGateCount?: boolean
  printStdErr?: boolean
} = {}) => {
  const startTime = Date.now()
  const command = getGateCount ? "bash scripts/info.sh" : "nargo compile --force --package"

  // Helper function to promisify exec
  const execPromise = (name: string, cmd: string): Promise<string> => {
    return new Promise((resolve, reject) => {
      exec(cmd, { maxBuffer: 100 * 1024 * 1024 }, (error, stdout, stderr) => {
        if (error) {
          reject(error)
          return
        }
        if (stderr && printStdErr) {
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
        console.log(`Successfully compiled ${name}${statsString}`)
        resolve(stdout)
      })
    })
  }

  const pool = new PromisePool(MAX_CONCURRENT_COMPILATIONS)
  const promises: Promise<void>[] = []

  // Process circuits with controlled concurrency
  for (const { name } of [...STATIC_CIRCUITS, ...generatedCircuits]) {
    // Check if compilation output already exists
    const outputPath = path.join("target", `${name}.json`)
    if (fs.existsSync(outputPath) && !forceCompilation) {
      console.log(`Skipping ${name} - compilation output already exists`)
      continue
    }

    const promise = pool.add(async () => {
      try {
        console.log(`Compiling ${name}...`)
        await execPromise(name, `${command} ${name}`)
      } catch (error: any) {
        console.error(`Error executing script for ${name}: ${error.message}`)
      }
    })
    promises.push(promise)
  }

  // Wait for all compilations to complete
  await Promise.all(promises)

  const duration = (Date.now() - startTime) / 1000 // convert to seconds
  const minutes = Math.floor(duration / 60)
  const seconds = Math.floor(duration % 60)

  if (minutes > 0) {
    console.log(`Total time taken: ${minutes}m ${seconds}s`)
  } else if (seconds > 0) {
    console.log(`Total time taken: ${seconds}s`)
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
    if (installedNargoVersion !== expectedNoirVersion) {
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
const compile = args.includes("compile")
const generate = args.includes("generate")

if (generate) {
  const unconstrained = args.includes("unconstrained")
  generateDscCircuits({ unconstrained })
  generateIdDataCircuits({ unconstrained })
  generateDataIntegrityCheckCircuits({ unconstrained })
  generateWorkspaceToml()
}

if (compile) {
  const forceCompilation = args.includes("force-compilation")
  const printStdErr = args.includes("print-stderr")
  checkNargoVersion()
  compileCircuitsWithNargo({ forceCompilation, printStdErr })
}
