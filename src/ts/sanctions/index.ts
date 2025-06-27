import { SMT } from "@zkpassport/utils"
import { poseidon2 } from "./hash"
import nameAndDobSMTJson from "./outputs/nameAndDobSMT.json"
import nameAndYobSMTJson from "./outputs/nameAndYobSMT.json"
import passportNoAndNationalitySMTJson from "./outputs/passportNoAndNationalitySMT.json"

/**
 * Data class containing the SanctionsSparseMerkleTrees
 */
export class SanctionsSparseMerkleTrees {

    constructor(
        public passportNoAndNationalitySMT: SMT,
        public nameAndDobSMT: SMT,
        public nameAndYobSMT: SMT
    ) {}

    /**
     * Initialize the SanctionsSparseMerkleTrees
     * @returns SanctionsSparseMerkleTrees
     */
    static init() {
        const passportNoAndNationalitySMT = new SMT(poseidon2, /*bigNumbers=*/ true)
        const nameAndDobSMT = new SMT(poseidon2, /*bigNumbers=*/ true)
        const nameAndYobSMT = new SMT(poseidon2, /*bigNumbers=*/ true)
        passportNoAndNationalitySMT.import(passportNoAndNationalitySMTJson)
        nameAndYobSMT.import(nameAndYobSMTJson)
        nameAndDobSMT.import(nameAndDobSMTJson)

        return new SanctionsSparseMerkleTrees(passportNoAndNationalitySMT, nameAndDobSMT, nameAndYobSMT)
    }
}