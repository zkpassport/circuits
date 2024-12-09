import { Binary } from "@/lib/binary"
import { PassportReader } from "@/lib/passport-reader/passport-reader"
import { PassportViewModel, Query } from "@/types"
import { readFile } from "fs/promises"
import path from "path"
import {
  getDiscloseCircuitInputs,
  getDSCCircuitInputs,
  getIDDataCircuitInputs,
  getIntegrityCheckCircuitInputs,
} from "./circuit-matcher"

const FIXTURES_PATH = "src/ts/tests/fixtures"

type CircuitType = "dsc" | "id" | "integrity" | "disclose"

interface CircuitInputs {
  dsc: any
  id: any
  integrity: any
  disclose: any
}

export class TestHelper {
  private passportReader = new PassportReader()
  private passport: PassportViewModel

  constructor() {}

  async generateCircuitInputs<T extends CircuitType>(circuitType: T): Promise<CircuitInputs[T]> {
    switch (circuitType) {
      case "dsc": {
        const inputs = await getDSCCircuitInputs(this.passport)
        return {
          ...inputs,
          salt: 0,
        }
      }
      case "id": {
        const inputs = await getIDDataCircuitInputs(this.passport)
        return {
          ...inputs,
          salt: 0,
        }
      }
      case "integrity": {
        const inputs = await getIntegrityCheckCircuitInputs(this.passport)
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
        return {
          ...inputs,
          salt: 0,
        }
      }
    }
  }

  public async loadPassportDataFromFile(dg1FileName: string, sodFileName: string): Promise<void> {
    const dg1 = Binary.from(await readFile(path.resolve(FIXTURES_PATH, dg1FileName)))
    const sod = Binary.from(await readFile(path.resolve(FIXTURES_PATH, sodFileName)))
    this.passportReader.loadPassport(dg1, sod)
    this.passport = this.passportReader.getPassportViewModel()
  }
}
