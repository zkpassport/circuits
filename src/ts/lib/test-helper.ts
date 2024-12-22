import { Binary } from "@/lib/binary"
import { PassportReader } from "@/lib/passport-reader"
import { CSCMasterlist, PassportViewModel, Query } from "@/types"
import { readFile } from "fs/promises"
import path from "path"
import {
  getDiscloseCircuitInputs,
  getDSCCircuitInputs,
  getIDDataCircuitInputs,
  getIntegrityCheckCircuitInputs,
} from "./circuit-matcher"
import { InputMap } from "@noir-lang/noir_js"

type CircuitType = "dsc" | "id" | "integrity" | "disclose"

export class TestHelper {
  private passportReader = new PassportReader()
  public passport!: PassportViewModel
  private masterlist!: CSCMasterlist
  private maxTbsLength!: number

  setMasterlist(masterlist: CSCMasterlist) {
    this.masterlist = masterlist
  }

  setMaxTbsLength(maxTbsLength: number) {
    this.maxTbsLength = maxTbsLength
  }

  async generateCircuitInputs(circuitType: CircuitType): Promise<InputMap> {
    switch (circuitType) {
      case "dsc": {
        const inputs = await getDSCCircuitInputs(this.passport, this.maxTbsLength, this.masterlist)
        if (!inputs) throw new Error("Unable to generate DSC circuit inputs")
        return {
          ...inputs,
          salt: 0,
        }
      }
      case "id": {
        const inputs = await getIDDataCircuitInputs(this.passport, this.maxTbsLength)
        if (!inputs) throw new Error("Unable to generate ID data circuit inputs")
        return {
          ...inputs,
          salt: 0,
        }
      }
      case "integrity": {
        const inputs = await getIntegrityCheckCircuitInputs(this.passport, this.maxTbsLength)
        if (!inputs) throw new Error("Unable to generate integrity check circuit inputs")
        return {
          ...inputs,
          salt: 0,
        }
      }
      case "disclose": {
        const query: Query = {
          fullname: { disclose: true },
          nationality: { disclose: true },
          birthdate: { disclose: true },
        }
        const inputs = await getDiscloseCircuitInputs(this.passport, query)
        if (!inputs) throw new Error("Unable to generate disclose circuit inputs")
        return {
          ...inputs,
          salt: 0,
        }
      }
    }
  }

  public async loadPassportDataFromFile(dg1FileName: string, sodFileName: string): Promise<void> {
    const FIXTURES_PATH = "src/ts/tests/fixtures"
    const dg1 = Binary.from(await readFile(path.resolve(FIXTURES_PATH, dg1FileName)))
    const sod = Binary.from(await readFile(path.resolve(FIXTURES_PATH, sodFileName)))
    this.passportReader.loadPassport(dg1, sod)
    this.passport = this.passportReader.getPassportViewModel()
  }

  public async loadPassport(dg1: Binary, sod: Binary): Promise<void> {
    this.passportReader.loadPassport(dg1, sod)
    this.passport = this.passportReader.getPassportViewModel()
  }
}
