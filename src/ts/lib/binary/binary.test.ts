import { describe, it, expect } from "bun:test"
import { Binary, HexString } from "./binary"

describe("Binary", () => {
  // Constructor and factory methods
  describe("construction", () => {
    it("should create from BigInt", () => {
      const value = BigInt(123456789)
      const binary = new Binary(value)
      expect(binary.toBigInt()).toBe(value)
    })

    it("should create from Uint8Array", () => {
      const value = new Uint8Array([1, 2, 3, 4, 5])
      const binary = new Binary(value)
      expect(binary.toUInt8Array()).toEqual(value)
    })

    it("should create from number[]", () => {
      const value = [10, 20, 30, 40, 50]
      const binary = new Binary(value)
      expect(binary.toNumberArray()).toEqual(value)
    })

    it("should create from hex string", () => {
      const value = "0xdeadbeef" as HexString
      const binary = new Binary(value)
      expect(binary.toHex()).toBe(value)
    })

    it("should create empty binary", () => {
      const binary = Binary.empty()
      expect(binary.length).toBe(0)
    })

    it("should create zero-filled binary", () => {
      const binary = Binary.zero(5)
      expect(binary.length).toBe(5)
      expect(binary.toNumberArray()).toEqual([0, 0, 0, 0, 0])
    })

    it("should throw for invalid number array values", () => {
      expect(() => new Binary([256])).toThrow("Invalid byte array")
      expect(() => new Binary([-1])).toThrow("Invalid byte array")
    })

    it("should throw for unsupported types", () => {
      expect(() => new Binary({} as any)).toThrow("Unsupported data type")
    })
  })

  // Conversion methods
  describe("conversions", () => {
    const testValue = new Binary([0xde, 0xad, 0xbe, 0xef])

    it("should convert to BigInt", () => {
      expect(testValue.toBigInt()).toBe(BigInt("0xdeadbeef"))
    })

    it("should convert to Uint8Array", () => {
      expect(testValue.toUInt8Array()).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))
    })

    it("should convert to number[]", () => {
      expect(testValue.toNumberArray()).toEqual([0xde, 0xad, 0xbe, 0xef])
    })

    it("should convert to hex string", () => {
      expect(testValue.toHex()).toBe("0xdeadbeef" as HexString)
    })

    it("should convert to Buffer", () => {
      expect(testValue.toBuffer()).toEqual(Buffer.from([0xde, 0xad, 0xbe, 0xef]))
    })

    it("should convert to and from base64", () => {
      const original = new Binary("Hello, World!")
      const base64 = original.toBase64()
      expect(base64).toBe("SGVsbG8sIFdvcmxkIQ==")
      const decoded = Binary.fromBase64(base64)
      expect(decoded.equals(original)).toBe(true)
    })

    it("should handle different string encodings", () => {
      const ascii = new Binary("Hello")
      expect(ascii.toString("utf8")).toBe("Hello")
      expect(ascii.toString("hex")).toBe("48656c6c6f")
    })
  })

  // Standard interfaces
  describe("standard interfaces", () => {
    const binary = new Binary([1, 2, 3])

    it("should implement JSON serialization", () => {
      expect(JSON.stringify({ foo: binary })).toBe('{"foo":"0x010203"}')
    })

    it("should implement custom inspection", () => {
      expect(String(binary)).toBe("Binary(0x010203)")
    })

    it("should implement primitive conversion", () => {
      expect(Number(binary)).toBe(66051) // 0x010203 in decimal
      expect(String(binary)).toBe("Binary(0x010203)")
      expect(BigInt(binary)).toBe(BigInt("0x010203"))
    })

    it("should be iterable", () => {
      expect([...binary]).toEqual([1, 2, 3])
    })
  })

  // Utility methods
  describe("utility methods", () => {
    it("should compare binaries", () => {
      const a = new Binary([1, 2, 3])
      const b = new Binary([1, 2, 4])
      const c = new Binary([1, 2, 3])

      expect(a.compare(b)).toBeLessThan(0)
      expect(b.compare(a)).toBeGreaterThan(0)
      expect(a.compare(c)).toBe(0)
    })

    it("should check equality", () => {
      const a = new Binary([1, 2, 3])
      const b = new Binary([1, 2, 3])
      const c = new Binary([1, 2, 4])

      expect(a.equals(b)).toBe(true)
      expect(a.equals(c)).toBe(false)
    })

    it("should slice correctly", () => {
      const binary = new Binary([1, 2, 3, 4, 5])
      expect(binary.slice(1, 4).toNumberArray()).toEqual([2, 3, 4])
      expect(binary.slice(2).toNumberArray()).toEqual([3, 4, 5])
      expect(binary.slice(0, -1).toNumberArray()).toEqual([1, 2, 3, 4])
    })

    it("should concatenate binaries", () => {
      const a = new Binary([1, 2])
      const b = new Binary([3, 4])
      expect(a.concat(b).toNumberArray()).toEqual([1, 2, 3, 4])
    })
  })

  // Bitwise operations
  describe("bitwise operations", () => {
    it("should perform XOR operation", () => {
      const a = new Binary([0xff, 0x00])
      const b = new Binary([0x0f, 0xf0])
      expect(a.xor(b).toNumberArray()).toEqual([0xf0, 0xf0])
    })

    it("should perform AND operation", () => {
      const a = new Binary([0xff, 0x00])
      const b = new Binary([0x0f, 0xf0])
      expect(a.and(b).toNumberArray()).toEqual([0x0f, 0x00])
    })

    it("should perform OR operation", () => {
      const a = new Binary([0xff, 0x00])
      const b = new Binary([0x0f, 0xf0])
      expect(a.or(b).toNumberArray()).toEqual([0xff, 0xf0])
    })

    it("should perform NOT operation", () => {
      const binary = new Binary([0x0f, 0xf0])
      expect(binary.not().toNumberArray()).toEqual([0xf0, 0x0f])
    })

    it("should throw for mismatched lengths in bitwise operations", () => {
      const a = new Binary([0xff])
      const b = new Binary([0xff, 0x00])
      expect(() => a.xor(b)).toThrow("must be of equal length")
      expect(() => a.and(b)).toThrow("must be of equal length")
      expect(() => a.or(b)).toThrow("must be of equal length")
    })
  })

  // Padding methods
  describe("padding methods", () => {
    it("should pad start correctly", () => {
      const binary = new Binary([0xff])
      expect(binary.padStart(3).toNumberArray()).toEqual([0x00, 0x00, 0xff])
      expect(binary.padStart(3, 0xff).toNumberArray()).toEqual([0xff, 0xff, 0xff])
    })

    it("should pad end correctly", () => {
      const binary = new Binary([0xff])
      expect(binary.padEnd(3).toNumberArray()).toEqual([0xff, 0x00, 0x00])
      expect(binary.padEnd(3, 0xff).toNumberArray()).toEqual([0xff, 0xff, 0xff])
    })

    it("should return same binary if padding length is less than current length", () => {
      const binary = new Binary([0xff, 0xff])
      expect(binary.padStart(1).toNumberArray()).toEqual([0xff, 0xff])
      expect(binary.padEnd(1).toNumberArray()).toEqual([0xff, 0xff])
    })
  })
})
