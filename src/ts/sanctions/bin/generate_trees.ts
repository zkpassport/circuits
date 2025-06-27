import {SMT, poseidon2} from "@zkpassport/utils/merkle-tree"
import fs from "fs"
import NAMES_Sanctions_LIST from "../inputs/names.json"
import PASSPORTS_Sanctions_LIST from "../inputs/passports.json"
import { hashNameAndDob, hashNameAndYob, hashPassportNoAndCountry, nameToMRZ, passportToMRZ } from "../trees/generate_trees";
import { SanctionsNames, SanctionsPassport } from "../trees/types";


/**
 * Steps:
 * 1. Parse the Sanctions list into MRZ format
 * 2. Hash the MRZ data
 * 3. Generate the leaves for the SMT
 * 4. Add the leaves to the SMT
 * 5. Export the SMT
 */
async function generateSanctionsTrees() {
    console.log("Parsing Data: Starting");
    console.log("Parsing Data: Converted Sanctions list into MRZ format");
    const mrz = nameToMRZ(NAMES_Sanctions_LIST as SanctionsNames[])
    const passportMRZ = passportToMRZ(PASSPORTS_Sanctions_LIST as SanctionsPassport[])

    console.log("Parsing Data: Generating leaves (hashing MRZ data)")
    const nameAndDobHashed = await hashNameAndDob(mrz);
    const nameAndYobHashed = await hashNameAndYob(mrz);
    const passportNoAndCountryHashed = await hashPassportNoAndCountry(passportMRZ);

    console.log("Parsing Data: Complete");

    const nameAndDobSMT = new SMT(poseidon2, /*bigNumbers=*/ true)
    const nameAndYobSMT = new SMT(poseidon2, /*bigNumbers=*/ true)
    const passportNoAndCountrySMT = new SMT(poseidon2, /*bigNumbers=*/ true)

    console.log("Generate Trees: Starting");
    console.log("Generate Trees: Adding name and yob leaves");
    // TODO: more efficient way to do this? batch adding?
    for (const item of nameAndDobHashed) {
        try {
            await nameAndDobSMT.add(item, BigInt(1));
        } catch (error) {
            console.log(error);
        }
    }

    console.log("Generate Trees: Adding name and yob leaves");
    for (const item of nameAndYobHashed) {
        try {
            await nameAndYobSMT.add(item, BigInt(1));
        } catch (error) {
            console.log(error);
        }
    }

    console.log("Generate Trees: Adding passport no and country leaves");
    for (const item of passportNoAndCountryHashed) {
        try {
            await passportNoAndCountrySMT.add(item, BigInt(1));
        } catch (error) {
            console.log(error);
        }
    }

    console.log("Generate Trees: Complete");

    const nameAndDobAsJson = nameAndDobSMT.export();
    const nameAndYobAsJson = nameAndYobSMT.export();
    const passportNoAndCountryAsJson = passportNoAndCountrySMT.export();

    console.log("Exporting Trees: Starting");

    fs.writeFileSync("NEW_nameAndDobSMT.json", nameAndDobAsJson);
    fs.writeFileSync("NEW_nameAndYobSMT.json", nameAndYobAsJson);
    fs.writeFileSync("NEW_passportNoAndCountrySMT.json", passportNoAndCountryAsJson);

    console.log("Exporting Trees: Complete");
}


generateSanctionsTrees();
