import { compile_program, createFileManager } from "@noir-lang/noir_wasm"
import { CompiledCircuit } from "@noir-lang/types"
import { AsnSerializer } from "@peculiar/asn1-schema"
import { PackagedCircuit } from "@zkpassport/utils"
import { readFile } from "fs/promises"
import path from "path"
import { promisify } from "util"
import { gzip } from "zlib"
import { decompressSync as gunzip } from "fflate"
import { Barretenberg } from "@aztec/bb.js"

export const gzipAsync = promisify(gzip)

/**
 * Loads a circuit manifest from a JSON file.
 * @param filename - The path to the JSON file.
 * @returns The compiled circuit.
 */
export async function loadCircuitManifest(filename: string): Promise<CompiledCircuit> {
  try {
    return JSON.parse(await readFile(filename, "utf-8"))
  } catch (error) {
    throw new Error(`${filename} is not valid JSON`)
  }
}

export async function loadPackagedCircuit(
  circuitName: string,
  basePath = "../../target/packaged",
): Promise<PackagedCircuit> {
  const circuitPath = path.join(__dirname, basePath, `${circuitName}.json`)
  try {
    return JSON.parse(await readFile(circuitPath, "utf-8")) as PackagedCircuit
  } catch (error) {
    throw new Error(`${circuitPath} is not valid JSON`)
  }
}

/**
 * Compiles a circuit from the specified path.
 * @param path - The path to the circuit file.
 * @returns The compiled circuit.
 */
export async function compileCircuit(path: string): Promise<CompiledCircuit> {
  const fm = createFileManager(path)
  const myCompiledCode = await compile_program(fm)
  return myCompiledCode.program
}

export function serializeAsn(obj: any): ArrayBuffer {
  return AsnSerializer.serialize(obj)
}

export function createUTCDate(year: number, month: number, day: number): Date {
  return new Date(Date.UTC(year, month, day))
}

export function snakeToCamel(str: string): string {
  return str.replace(/_([a-z0-9])/g, (_, letter) => letter.toUpperCase())
}

export function snakeToPascal(str: string): string {
  return str
    .replace(/_([a-z0-9])/g, (_, letter) => letter.toUpperCase())
    .replace(/^([a-z])/, (_, letter) => letter.toUpperCase())
}

export function camelToSnake(str: string): string {
  return str.replace(/([A-Z0-9])/g, "_$1").toLowerCase()
}

export function pascalToSnake(str: string): string {
  return str.replace(/([A-Z0-9])/g, "_$1").toLowerCase()
}

// Converts bytecode from a base64 string to a Uint8Array
function acirToUint8Array(base64EncodedBytecode: string): Uint8Array {
  const compressedByteCode = base64Decode(base64EncodedBytecode)
  return gunzip(compressedByteCode)
}

// Since this is a simple function, we can use feature detection to
// see if we are in the nodeJs environment or the browser environment.
function base64Decode(input: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    // Node.js environment
    const b = Buffer.from(input, "base64")
    return new Uint8Array(b.buffer, b.byteOffset, b.byteLength)
  } else if (typeof atob === "function") {
    // Browser environment
    return Uint8Array.from(atob(input), (c) => c.charCodeAt(0))
  } else {
    throw new Error("No implementation found for base64 decoding.")
  }
}

export async function initBarretenberg() {
  const barretenberg = await Barretenberg.new({
    threads: 8,
  })

  return barretenberg
}

export async function destroyBarretenberg(barretenberg: Barretenberg) {
  await barretenberg.destroy()
}

export async function getGateCount(
  barretenberg: Barretenberg,
  circuitBytecode: string,
  recursive = true,
) {
  const constraintSystemBuf = acirToUint8Array(circuitBytecode)
  const [gateCount] = await barretenberg.acirGetCircuitSizes(constraintSystemBuf, recursive, true)
  return gateCount
}
