import { InputMap } from "@noir-lang/noir_js"
import { TestHelper } from "../test-helper"

export class BenchmarkHelper extends TestHelper {
  private targetTbsSize: number

  constructor(targetTbsSize: number) {
    super()
    this.targetTbsSize = targetTbsSize
  }

  async generateCircuitInputs(circuitType: "id"): Promise<InputMap> {
    // Get the original inputs
    const originalInputs = await super.generateCircuitInputs(circuitType)
    
    // Check if we need to pad the TBS certificate
    if (originalInputs.tbs_certificate && Array.isArray(originalInputs.tbs_certificate)) {
      const currentSize = originalInputs.tbs_certificate.length
      
      if (currentSize < this.targetTbsSize) {
        // Pad with zeros to reach target size
        const paddedCertificate = [
          ...originalInputs.tbs_certificate,
          ...new Array(this.targetTbsSize - currentSize).fill("0x00")
        ]
        
        // Return modified inputs with padded certificate
        return {
          ...originalInputs,
          tbs_certificate: paddedCertificate,
          // tbs_certificate_len remains the original length
        }
      }
    }
    
    return originalInputs
  }
}