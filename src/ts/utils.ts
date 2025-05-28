import { compile_program, createFileManager } from "@noir-lang/noir_wasm"
import { CompiledCircuit } from "@noir-lang/types"
import { AsnSerializer } from "@peculiar/asn1-schema"
import { PackagedCircuit } from "@zkpassport/utils"
import { readFile } from "fs/promises"
import path from "path"
import { promisify } from "util"
import { gzip } from "zlib"

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
