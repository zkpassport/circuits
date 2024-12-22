interface DisclosedDataRaw {
  issuingCountry: Uint8Array // 3 bytes
  nationality: Uint8Array // 3 bytes
  documentType: Uint8Array // 2 bytes
  documentNumber: Uint8Array // 9 bytes
  dateOfExpiry: Uint8Array // 6 bytes
  dateOfBirth: Uint8Array // 6 bytes
  name: Uint8Array // 39 bytes
  gender: Uint8Array // 1 byte
}

interface ProofData {
  publicInputs: string[]
  proof: Uint8Array | string
}

function stripChevrons(str: string): string {
  return str.replace(/^<+|<+$/g, "").replace(/</g, " ")
}

export class DisclosedData {
  readonly issuingCountry: string // 3-letter country code
  readonly nationality: string // 3-letter country code
  readonly documentType: string // 2-letter document type
  readonly documentNumber: string // Document number
  readonly dateOfExpiry: Date // Expiry date
  readonly dateOfBirth: Date // Birth date
  readonly name: string // Full name
  readonly gender: string // Gender

  constructor(data: {
    issuingCountry: string
    nationality: string
    documentType: string
    documentNumber: string
    dateOfExpiry: Date
    dateOfBirth: Date
    name: string
    gender: string
  }) {
    this.issuingCountry = data.issuingCountry
    this.nationality = data.nationality
    this.documentType = data.documentType
    this.documentNumber = data.documentNumber
    this.dateOfExpiry = data.dateOfExpiry
    this.dateOfBirth = data.dateOfBirth
    this.name = data.name
    this.gender = data.gender
  }

  static fromProof(proof: ProofData): DisclosedData {
    const disclosedBytes = proof.publicInputs.slice(3, 93).map((hex) => parseInt(hex, 16))

    const raw: DisclosedDataRaw = {
      issuingCountry: new Uint8Array(disclosedBytes.slice(0, 3)),
      nationality: new Uint8Array(disclosedBytes.slice(3, 6)),
      documentType: new Uint8Array(disclosedBytes.slice(6, 8)),
      documentNumber: new Uint8Array(disclosedBytes.slice(8, 17)),
      dateOfExpiry: new Uint8Array(disclosedBytes.slice(17, 23)),
      dateOfBirth: new Uint8Array(disclosedBytes.slice(23, 29)),
      name: new Uint8Array(disclosedBytes.slice(29, 68)),
      gender: new Uint8Array(disclosedBytes.slice(68, 69)),
    }

    const decoder = new TextDecoder()
    const decode = (arr: Uint8Array) => decoder.decode(arr).replace(/\0/g, "")

    return new DisclosedData({
      issuingCountry: decode(raw.issuingCountry),
      nationality: decode(raw.nationality),
      documentType: stripChevrons(decode(raw.documentType)),
      documentNumber: stripChevrons(decode(raw.documentNumber)),
      dateOfExpiry: parseDate(raw.dateOfExpiry),
      dateOfBirth: parseDate(raw.dateOfBirth),
      name: stripChevrons(decode(raw.name)),
      gender: decode(raw.gender),
    })
  }
}

function parseDate(bytes: Uint8Array): Date {
  const str = new TextDecoder().decode(bytes).replace(/\0/g, "")
  // Format: YYMMDD
  const year = parseInt(str.substring(0, 2))
  const month = parseInt(str.substring(2, 4)) - 1 // JS months are 0-based (yes, that's retarded)
  const day = parseInt(str.substring(4, 6))
  // Assume current century (e.g. 20YY) for dates unless that would make it more than 10 years in the future
  const currentYear = new Date().getFullYear()
  const currentCentury = Math.floor(currentYear / 100) * 100
  const previousCentury = currentCentury - 100
  const fullYear =
    year + (year + currentCentury > currentYear + 10 ? previousCentury : currentCentury)
  return new Date(fullYear, month, day)
}

function formatDateToBytes(date: Date): Uint8Array {
  const year = date.getFullYear() % 100 // Get last 2 digits
  const month = date.getMonth() + 1 // JS months are 0-based
  const day = date.getDate()

  const str = `${year.toString().padStart(2, "0")}${month.toString().padStart(2, "0")}${day
    .toString()
    .padStart(2, "0")}`
  return new TextEncoder().encode(str)
}

export function createDisclosedDataRaw(data: {
  issuingCountry: Uint8Array | string
  nationality: Uint8Array | string
  documentType: Uint8Array | string
  documentNumber: Uint8Array | string
  dateOfExpiry: Uint8Array | string | Date
  dateOfBirth: Uint8Array | string | Date
  name: Uint8Array | string
  gender: Uint8Array | string
}): DisclosedDataRaw {
  const encoder = new TextEncoder()

  function padArray(arr: Uint8Array, length: number): Uint8Array {
    if (arr.length === length) return arr
    const result = new Uint8Array(length)
    result.set(arr.slice(0, length))
    return result
  }

  function processInput(input: Uint8Array | string | Date, length: number): Uint8Array {
    if (input instanceof Date) {
      return padArray(formatDateToBytes(input), length)
    }
    const arr = typeof input === "string" ? encoder.encode(input) : input
    return padArray(arr, length)
  }

  return {
    issuingCountry: processInput(data.issuingCountry, 3),
    nationality: processInput(data.nationality, 3),
    documentType: processInput(data.documentType, 2),
    documentNumber: processInput(data.documentNumber, 9),
    dateOfExpiry: processInput(data.dateOfExpiry, 6),
    dateOfBirth: processInput(data.dateOfBirth, 6),
    name: processInput(data.name, 39),
    gender: processInput(data.gender, 1),
  }
}
