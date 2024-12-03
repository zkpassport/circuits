const BARRETT_REDUCTION_OVERFLOW_BITS = 4n

function getMinNumberOfBits(num: bigint): number {
  return num.toString(2).length
}

function hexToBytes(hex: string): number[] {
  const hexWithoutPrefix = hex.startsWith("0x") ? hex.slice(2) : hex
  return hexWithoutPrefix.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16))
}

function bytesToBigInt(bytes: number[]): bigint {
  return BigInt(`0x${bytes.map((byte) => byte.toString(16).padStart(2, "0")).join("")}`)
}

function padHexToEven(hex: string): string {
  return hex.length % 2 === 0 ? hex : `0${hex}`
}

/**
 * Compute the reduction parameter used in Barrett reduction
 * redc param = 2 * ceil(log2(modulus)) / modulus
 */
function computeBarrettReductionParameter(modulus: bigint): bigint {
  const k = modulus.toString(2).length
  // Add overflow bits
  const multiplicand = 1n << BigInt(k * 2 + Number(BARRETT_REDUCTION_OVERFLOW_BITS))
  return multiplicand / modulus
}

/**
 * Split a BigInt into an array of 120-bit slices
 */
function splitInto120BitLimbs(input: bigint, numBits: number): bigint[] {
  const numLimbs = Math.floor(numBits / 120) + (numBits % 120 !== 0 ? 1 : 0)
  const mask = (1n << 120n) - 1n
  const result: bigint[] = []

  for (let i = 0; i < numLimbs; i++) {
    const slice = input & mask
    input = input >> 120n
    result.push(slice)
  }
  return result
}

/**
 * Compute an array of 120-bit limbs that represents a Barrett reduction parameter
 */
export function redcLimbs(bn: bigint, numBits: number): number[] {
  const redcParam = computeBarrettReductionParameter(bn)
  const limbs = splitInto120BitLimbs(redcParam, numBits)
  const totalBytes = numBits / 8 + (numBits % 8 !== 0 ? 1 : 0)
  return limbs
    .reverse()
    .map((limb, i) => {
      const hex = limb.toString(16)
      const paddedHex = i === 0 ? hex.padStart(totalBytes % 15, "0") : hex.padStart(30, "0")
      return hexToBytes(padHexToEven(paddedHex))
    })
    .flat()
}

export function redcLimbsFromBytes(bytes: number[] | Buffer): number[] {
  let bn: bigint
  if (Buffer.isBuffer(bytes)) {
    bn = bytesToBigInt(Array.from(bytes))
  } else {
    bn = bytesToBigInt(bytes)
  }
  return redcLimbs(bn, getMinNumberOfBits(bn))
}
