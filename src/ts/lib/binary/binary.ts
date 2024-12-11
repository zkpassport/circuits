import { inspect } from "util"

declare global {
  interface BigIntConstructor {
    (value: Binary): bigint
  }
}

export type BinaryInput =
  | bigint
  | Buffer
  | Uint8Array
  | number[]
  | string
  | number
  | ArrayBufferLike
export type HexString = string & { readonly __hex: unique symbol }

export class Binary {
  private readonly bytes: Uint8Array

  constructor(data: BinaryInput) {
    this.bytes = Binary.convertToBytes(data)
  }

  private static convertToBytes(data: BinaryInput): Uint8Array {
    if (typeof data === "bigint" || typeof data === "number") {
      const hex = data.toString(16)
      const paddedHex = hex.padStart(Math.ceil(hex.length / 2) * 2, "0")
      return new Uint8Array(paddedHex.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || [])
    }

    if (data instanceof Uint8Array) {
      return new Uint8Array(data)
    }

    if (Buffer.isBuffer(data)) {
      return new Uint8Array(data)
    }

    if (Array.isArray(data)) {
      if (!data.every((n) => typeof n === "number" && n >= 0 && n <= 255)) {
        throw new Error("Invalid byte array: values must be between 0 and 255")
      }
      return new Uint8Array(data)
    }

    if (data instanceof ArrayBuffer) {
      return new Uint8Array(data)
    }

    if (typeof data === "string") {
      if (Binary.isHexString(data)) {
        const hex = data.startsWith("0x") ? data.slice(2) : data
        const paddedHex = hex.padStart(Math.ceil(hex.length / 2) * 2, "0")
        return new Uint8Array(paddedHex.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || [])
      }

      try {
        // Try parsing as numeric string first
        const bigInt = BigInt(data)
        return Binary.convertToBytes(bigInt)
      } catch {
        // Fall back to ASCII if not numeric
        return new Uint8Array(Buffer.from(data, "ascii"))
      }
    }

    throw new Error("Unsupported data type")
  }

  private static isHexString(value: string): value is HexString {
    const hex = value.startsWith("0x") ? value.slice(2) : value
    return /^[0-9a-fA-F]*$/.test(hex)
  }

  // Factory methods
  static from(data: BinaryInput): Binary {
    return new Binary(data)
  }

  static fromHex(hex: string): Binary {
    if (!Binary.isHexString(hex)) {
      throw new Error("Invalid hex string")
    }
    return new Binary(hex.startsWith("0x") ? hex : "0x" + hex)
  }

  static fromBuffer(buffer: Buffer): Binary {
    return new Binary(buffer)
  }

  static fromBase64(base64: string): Binary {
    const binary = atob(base64)
    return new Binary(Uint8Array.from(binary, (c) => c.charCodeAt(0)))
  }

  static empty(): Binary {
    return new Binary(new Uint8Array(0))
  }

  static zero(length: number): Binary {
    return new Binary(new Uint8Array(length))
  }

  // Conversion methods
  toBigInt(): bigint {
    return BigInt("0x" + this.toHex().slice(2))
  }

  toUInt8Array(): Uint8Array {
    return new Uint8Array(this.bytes)
  }

  toNumberArray(): number[] {
    return Array.from(this.bytes)
  }

  toHex(): HexString | string {
    return ("0x" +
      Array.from(this.bytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("")) as HexString
  }

  toBuffer(): Buffer {
    return Buffer.from(this.bytes)
  }

  toString(encoding: BufferEncoding = "hex"): string {
    if (encoding === "hex") {
      return this.toHex().slice(2)
    }
    return Buffer.from(this.bytes).toString(encoding)
  }

  toBase64(): string {
    return btoa(String.fromCharCode(...this.bytes))
  }

  toJSON(): string {
    return this.toHex()
  }

  [inspect.custom](): string {
    return `Binary(${this.toHex()})`
  }

  [Symbol.toPrimitive](hint: string): string | number | bigint {
    switch (hint) {
      case "number":
        return Number(this.toBigInt())
      case "string":
        return `Binary(${this.toHex()})`
      default:
        return this.toBigInt()
    }
  }

  valueOf(): bigint {
    return this.toBigInt()
  }

  get length(): number {
    return this.bytes.length
  }

  // Iterator
  *[Symbol.iterator](): Iterator<number> {
    yield* this.bytes
  }

  // Utility methods
  equals(other: Binary): boolean {
    if (this.length !== other.length) return false
    return this.bytes.every((byte, i) => byte === other.bytes[i])
  }

  slice(start?: number, end?: number): Binary {
    return new Binary(this.bytes.slice(start, end))
  }

  // concat(other: Binary): Binary {
  //   const result = new Uint8Array(this.length + other.length)
  //   result.set(this.bytes)
  //   result.set(other.bytes, this.length)
  //   return new Binary(result)
  // }
  concat(other: Binary): Binary {
    return new Binary([...this.toNumberArray(), ...other.toNumberArray()])
  }

  // Add operator overload
  [Symbol.for("+")](other: Binary): Binary {
    return this.concat(other)
  }

  compare(other: Binary): number {
    const minLength = Math.min(this.length, other.length)
    for (let i = 0; i < minLength; i++) {
      const diff = this.bytes[i] - other.bytes[i]
      if (diff !== 0) return diff
    }
    return this.length - other.length
  }

  // Bitwise operations
  xor(other: Binary): Binary {
    if (this.length !== other.length) {
      throw new Error("Binary instances must be of equal length for XOR operation")
    }
    const result = new Uint8Array(this.length)
    for (let i = 0; i < this.length; i++) {
      result[i] = this.bytes[i] ^ other.bytes[i]
    }
    return new Binary(result)
  }

  and(other: Binary): Binary {
    if (this.length !== other.length) {
      throw new Error("Binary instances must be of equal length for AND operation")
    }
    const result = new Uint8Array(this.length)
    for (let i = 0; i < this.length; i++) {
      result[i] = this.bytes[i] & other.bytes[i]
    }
    return new Binary(result)
  }

  or(other: Binary): Binary {
    if (this.length !== other.length) {
      throw new Error("Binary instances must be of equal length for OR operation")
    }
    const result = new Uint8Array(this.length)
    for (let i = 0; i < this.length; i++) {
      result[i] = this.bytes[i] | other.bytes[i]
    }
    return new Binary(result)
  }

  not(): Binary {
    const result = new Uint8Array(this.length)
    for (let i = 0; i < this.length; i++) {
      result[i] = ~this.bytes[i] & 0xff
    }
    return new Binary(result)
  }

  // Padding methods
  padStart(length: number, fillByte: number = 0): Binary {
    if (this.length >= length) return this
    const result = new Uint8Array(length)
    result.fill(fillByte, 0, length - this.length)
    result.set(this.bytes, length - this.length)
    return new Binary(result)
  }

  padEnd(length: number, fillByte: number = 0): Binary {
    if (this.length >= length) return this
    const result = new Uint8Array(length)
    result.set(this.bytes)
    result.fill(fillByte, this.length)
    return new Binary(result)
  }
}
