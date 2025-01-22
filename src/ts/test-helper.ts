import fs from "fs/promises"
import path from "path"
import {
  Binary,
  PassportReader,
  type CSCMasterlist,
  type PassportViewModel,
  type Query,
  getDiscloseCircuitInputs,
  getDSCCircuitInputs,
  getIDDataCircuitInputs,
  getIntegrityCheckCircuitInputs,
} from "@zkpassport/utils"
import { InputMap } from "@noir-lang/noir_js"

type CircuitType = "dsc" | "id" | "integrity" | "disclose"

export class TestHelper {
  private passportReader = new PassportReader()
  public passport!: PassportViewModel
  private masterlist!: CSCMasterlist

  setMasterlist(masterlist: CSCMasterlist) {
    this.masterlist = masterlist
  }

  async generateCircuitInputs(circuitType: CircuitType): Promise<InputMap> {
    switch (circuitType) {
      case "dsc": {
        const inputs = await getDSCCircuitInputs(
          this.passport as any,
          0n,
          undefined,
          this.masterlist,
        )
        if (!inputs) throw new Error("Unable to generate DSC circuit inputs")
        return inputs
      }
      case "id": {
        const inputs = await getIDDataCircuitInputs(this.passport as any, 0n)
        if (!inputs) throw new Error("Unable to generate ID data circuit inputs")
        return inputs
      }
      case "integrity": {
        const inputs = await getIntegrityCheckCircuitInputs(this.passport as any, 0n)
        if (!inputs) throw new Error("Unable to generate integrity check circuit inputs")
        return inputs
      }
      case "disclose": {
        const query: Query = {
          fullname: { disclose: true },
          nationality: { disclose: true },
          birthdate: { disclose: true },
        }
        const inputs = await getDiscloseCircuitInputs(this.passport as any, query, 0n)
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
