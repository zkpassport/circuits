import { InputMap } from "@noir-lang/noir_js"
import {
  Binary,
  getDiscloseCircuitInputs,
  getDSCCircuitInputs,
  getIDDataCircuitInputs,
  getIntegrityCheckCircuitInputs,
  getNowTimestamp,
  PassportReader,
  type PackagedCertificate,
  type PassportViewModel,
  type Query,
} from "@zkpassport/utils"
import fs from "fs/promises"
import path from "path"

type CircuitType = "dsc" | "id" | "integrity" | "disclose"

export class TestHelper {
  private passportReader = new PassportReader()
  public passport!: PassportViewModel
  private certificates!: PackagedCertificate[]

  setCertificates(certificates: PackagedCertificate[]) {
    this.certificates = certificates
  }

  async generateCircuitInputs(
    circuitType: CircuitType,
    nowTimestamp: number = getNowTimestamp(),
  ): Promise<InputMap> {
    switch (circuitType) {
      case "dsc": {
        const inputs = await getDSCCircuitInputs(this.passport as any, 1n, this.certificates)
        if (!inputs) throw new Error("Unable to generate DSC circuit inputs")
        return inputs
      }
      case "id": {
        const inputs = await getIDDataCircuitInputs(this.passport as any, 1n, 2n)
        if (!inputs) throw new Error("Unable to generate ID data circuit inputs")
        return inputs
      }
      case "integrity": {
        const inputs = await getIntegrityCheckCircuitInputs(
          this.passport as any,
          2n,
          3n,
          nowTimestamp,
        )
        if (!inputs) throw new Error("Unable to generate integrity check circuit inputs")
        return inputs
      }
      case "disclose": {
        const query: Query = {
          fullname: { disclose: true },
          nationality: { disclose: true },
          birthdate: { disclose: true },
        }
        const inputs = await getDiscloseCircuitInputs(this.passport as any, query, 3n)
        if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
        return inputs
      }
    }
  }

  public async loadPassportDataFromFile(dg1FileName: string, sodFileName: string): Promise<void> {
    const FIXTURES_PATH = "src/ts/tests/fixtures"
    if (!fs || !path) {
      throw new Error("File system operations are only available in Node.js environment")
    }
    const dg1 = Binary.from(await fs.readFile(path.resolve(FIXTURES_PATH, dg1FileName)))
    const sod = Binary.from(await fs.readFile(path.resolve(FIXTURES_PATH, sodFileName)))
    this.passportReader.loadPassport(dg1, sod)
    this.passport = this.passportReader.getPassportViewModel() as any
  }

  public async loadPassport(dg1: Binary, sod: Binary): Promise<void> {
    this.passportReader.loadPassport(dg1, sod)
    this.passport = this.passportReader.getPassportViewModel() as any
  }
}

export function utcDateToUnixTimestamp(year: number, month: number, day: number) {
  return Math.floor(Date.UTC(year, month - 1, day) / 1000)
}
