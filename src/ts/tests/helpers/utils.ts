import { readFile } from "fs/promises"
import { CompiledCircuit, type Field } from "@noir-lang/types"
import { createFileManager, compile_program } from "@noir-lang/noir_wasm"
import path from "path"

/**
 * Convert a little-endian buffer into a BigInt.
 * @param buf - The little-endian buffer to convert.
 * @returns A BigInt with the little-endian representation of buf.
 */
export function toBigIntLE(buf: Buffer): bigint {
  const reversed = buf
  reversed.reverse()
  const hex = reversed.toString("hex")
  if (hex.length === 0) {
    return BigInt(0)
  }
  return BigInt(`0x${hex}`)
}

/**
 * Convert a big-endian buffer into a BigInt.
 * @param buf - The big-endian buffer to convert.
 * @returns A BigInt with the big-endian representation of buf.
 */
export function toBigIntBE(buf: Buffer): bigint {
  const hex = buf.toString("hex")
  if (hex.length === 0) {
    return BigInt(0)
  }
  return BigInt(`0x${hex}`)
}

/**
 * Convert a BigInt to a little-endian buffer.
 * @param num - The BigInt to convert.
 * @param width - The number of bytes that the resulting buffer should be.
 * @returns A little-endian buffer representation of num.
 */
export function toBufferLE(num: bigint, width: number): Buffer {
  if (num < BigInt(0)) {
    throw new Error(`Cannot convert negative bigint ${num.toString()} to buffer with toBufferLE.`)
  }
  const hex = num.toString(16)
  const buffer = Buffer.from(hex.padStart(width * 2, "0").slice(0, width * 2), "hex")
  buffer.reverse()
  return buffer
}

/**
 * Convert a BigInt to a big-endian buffer.
 * @param num - The BigInt to convert.
 * @param width - The number of bytes that the resulting buffer should be.
 * @returns A big-endian buffer representation of num.
 */
export function toBufferBE(num: bigint, width: number): Buffer {
  if (num < BigInt(0)) {
    throw new Error(`Cannot convert negative bigint ${num.toString()} to buffer with toBufferBE.`)
  }
  const hex = num.toString(16)
  const buffer = Buffer.from(hex.padStart(width * 2, "0").slice(0, width * 2), "hex")
  if (buffer.length > width) {
    throw new Error(`Number ${num.toString(16)} does not fit in ${width}`)
  }
  return buffer
}

/**
 * Converts a BigInt to its hex representation.
 * @param num - The BigInt to convert.
 * @param padTo32 - Whether to pad the resulting string to 32 bytes.
 * @returns An even-length 0x-prefixed string.
 */
export function toHex(num: bigint, padTo32 = false): `0x${string}` {
  const str = num.toString(16)
  const targetLen = str.length % 2 === 0 ? str.length : str.length + 1
  const paddedStr = str.padStart(padTo32 ? 64 : targetLen, "0")
  return `0x${paddedStr}`
}

/**
 * Converts a hex string to a buffer. Throws if input is not a valid hex string.
 * @param value - The hex string to convert. May be 0x prefixed or not.
 * @returns A buffer.
 */
export function fromHex(value: string): Buffer {
  const hexRegex = /^(0x)?[0-9a-fA-F]*$/
  if (!hexRegex.test(value) || value.length % 2 !== 0) {
    throw new Error(`Invalid hex string: ${value}`)
  }
  return Buffer.from(value.replace(/^0x/i, ""), "hex")
}

/**
 * Strips the '0x' prefix from a hexadecimal string.
 * @param input - The input string.
 * @returns The input string without the '0x' prefix.
 */
export function strip0x(input: string): string {
  return input.startsWith("0x") ? input.slice(2) : input
}

/**
 * Loads a circuit from a specified file name, resolving it to a full path if necessary.
 * @param fileName - The name or full path of the circuit file.
 * @returns The loaded circuit manifest.
 */
export async function loadCircuit(fileName: string) {
  // Check if the input is a full path or just a base name
  const isFullPath = path.isAbsolute(fileName) || fileName.includes("/")
  const circuitPath = isFullPath ? fileName : path.resolve(`target/${fileName}.json`)

  return await loadCircuitManifest(circuitPath)
}

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

export function fromBytesToBigInt(bytes: number[]): bigint {
  return BigInt("0x" + Buffer.from(bytes).toString("hex"))
}

export function fromArrayBufferToBigInt(buffer: ArrayBuffer): bigint {
  return BigInt("0x" + Buffer.from(buffer).toString("hex"))
}

export function padArrayWithZeros(array: Field[], length: number): Field[]
export function padArrayWithZeros(array: number[], length: number): number[]
export function padArrayWithZeros(array: Buffer, length: number): Buffer
export function padArrayWithZeros(array: any, length: number): any {
  if (Array.isArray(array)) {
    return array.concat(Array(length - array.length).fill(0))
  } else if (Buffer.isBuffer(array)) {
    const zeros = Buffer.alloc(length - array.length)
    return Buffer.concat([array, zeros])
  }
  throw new Error("Input must be an array or a Buffer.")
}
