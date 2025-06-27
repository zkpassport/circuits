
import { poseidon2, SMT } from "@zkpassport/utils"
import nameAndDobJson from "../outputs/NEW_nameAndDobSMT.json"
import nameAndYobJson from "../outputs/NEW_nameAndYobSMT.json"
import passportNoAndCountryJson from "../outputs/NEW_passportNoAndCountrySMT.json"
import { hashNameAndDob, hashNameAndYob, hashPassportNoAndCountry, nameToMRZ, passportNoAndCountry, passportToMRZ } from "../trees/generate_trees"
import { SanctionsNames, SanctionsPassport, PassportMRZData } from "../trees/types"

/**
 * Generate test data within exclusion-check/sanctions/src/lib.nr
 */
async function testNonMembershipFullSets() {
    const passportNoAndCountrySMT = new SMT(poseidon2, /*bigNumbers=*/ true)
    passportNoAndCountrySMT.import(JSON.stringify(passportNoAndCountryJson));

    const nameAndDobSMT = new SMT(poseidon2, /*bigNumbers=*/ true)
    nameAndDobSMT.import(JSON.stringify(nameAndDobJson));

    const nameAndYobSMT = new SMT(poseidon2, /*bigNumbers=*/ true)
    nameAndYobSMT.import(JSON.stringify(nameAndYobJson));

    // non inclusion proof of arb value
    console.log(await passportNoAndCountrySMT.createProof(1n));

    const passportNo = "123456789";
    const country = "United Kingdom";
    const passport: SanctionsPassport = {
        Pass_No: passportNo,
        Pass_Country: country,
    }
    const passportToMRZ = passportNoAndCountry(passport);

    const mrz = nameToMRZ([{
        First_Name: "John",
        Last_Name: "Doe",
        day: "12",
        month: "jan",
        year: "1990",
    } as SanctionsNames])

    const hash = await hashPassportNoAndCountry([passportToMRZ as PassportMRZData]);

    const nonPassportProof = passportNoAndCountrySMT.createProof(hash[0]);
    console.log("non passport proof", nonPassportProof);

    const nameAndDobHash = await hashNameAndDob([mrz[0]]);
    const nameAndYobHash = await hashNameAndYob([mrz[0]]);

    const nonNameAndDobProof = nameAndDobSMT.createProof(nameAndDobHash[0]);
    console.log("non name and dob proof", nonNameAndDobProof);

    const nonNameAndYobProof = nameAndYobSMT.createProof(nameAndYobHash[0]);
    console.log("non name and yob proof", nonNameAndYobProof);
}

testNonMembershipFullSets();