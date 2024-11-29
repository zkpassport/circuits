import { Field } from "@noir-lang/types"

export function bigIntToFields(bigIntValue: BigInt): Array<Field> {
  const modulusBytes: number[] = Array.from(bigIntValue.toString(16).match(/.{1,2}/g) || []).map(
    (byte) => parseInt(byte, 16),
  )
  return modulusBytes.map((byte) => byte as Field)
}

export function bigIntToField(bigIntValue: BigInt): Field {
  return bigIntValue.toString() as Field
}

export function uint8ArrayToBigInt(uint8Array: Uint8Array): bigint {
  return BigInt(
    `0x${Array.from(uint8Array)
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("")}`,
  )
}

export function bignumFromString(bignumStr: string): bigint {
  if (bignumStr.startsWith("0x")) {
    return BigInt(bignumStr)
  } else if (/[a-fA-F]/.test(bignumStr)) {
    return BigInt(`0x${bignumStr}`)
  } else {
    return BigInt(bignumStr)
  }
}

export function hexToBytes(hex: string) {
  const hexWithoutPrefix = hex.startsWith("0x") ? hex.slice(2) : hex
  return hexWithoutPrefix.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16))
}

export function bytesToBigInt(bytes: number[]) {
  return BigInt(`0x${bytes.map((byte) => byte.toString(16).padStart(2, "0")).join("")}`)
}

export function padHexToEven(hex: string) {
  return hex.length % 2 === 0 ? hex : `0${hex}`
}
