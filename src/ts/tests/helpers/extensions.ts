import { type Field } from "@noir-lang/types"
import { bytesToBigInt, bigIntToFields } from "./conversion"

declare global {
  interface BigInt {
    toField(): Field
    toFieldArray(): Array<Field>
  }
  interface Buffer {
    toField(): string
    toFieldArray(): Array<Field>
  }
  interface Array<T> {
    toField(): string
  }
}

BigInt.prototype.toField = function (): Field {
  return "0x" + this.toString(16)
}
BigInt.prototype.toFieldArray = function (): Array<Field> {
  return Array.from(this.toString(16).match(/.{1,2}/g) || []).map(
    (byte) => parseInt(byte as string, 16) as Field,
  )
}
Buffer.prototype.toField = function (): string {
  return "0x" + this.toString("hex")
}
Buffer.prototype.toFieldArray = function (): Array<Field> {
  return Array.from(this)
}
Array.prototype.toField = function (): string {
  if (!this.every((item) => typeof item === "number")) {
    throw new Error("toField is only applicable to Array<number>")
  }
  for (const num of this) {
    if (num < 0 || num > 255) {
      throw new Error("Array elements must be in the byte range (0-255)")
    }
  }
  return this.map((num) => num.toString(16).padStart(2, "0")).join("")
}
