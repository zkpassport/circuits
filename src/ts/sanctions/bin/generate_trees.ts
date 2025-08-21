import {poseidon2, AsyncOrderedMT} from "@zkpassport/utils/merkle-tree"
import fs from "fs"
import NAMES_Sanctions_LIST from "../inputs/names.json"
import PASSPORTS_Sanctions_LIST from "../inputs/passports.json"
import { hashNameAndDob, hashNameAndYob, hashPassportNoAndCountry, nameToMRZ, passportToMRZ } from "../trees/generate_trees";
import { SanctionsNames, SanctionsPassport } from "../trees/types";
import path from "path";

const TREE_DEPTH = 13;
const SINGLE_TREE_DEPTH = 14;

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
    console.log("data lengths", nameAndDobHashed.length, nameAndYobHashed.length, passportNoAndCountryHashed.length);
    console.log("data lengths log 2", Math.log2(nameAndDobHashed.length), Math.log2(nameAndYobHashed.length), Math.log2(passportNoAndCountryHashed.length));
    console.log("combined log 2", Math.log2(nameAndDobHashed.length + nameAndYobHashed.length + passportNoAndCountryHashed.length));

    console.log("Parsing Data: Complete");
    const singleTree = await AsyncOrderedMT.create(SINGLE_TREE_DEPTH, poseidon2)
    const singleTreeData = nameAndDobHashed.concat(nameAndYobHashed, passportNoAndCountryHashed)

    console.log("Generate Tree: Starting");

    await singleTree.initializeAndSort(singleTreeData);

    console.log("Generate Trees: Complete");

    console.log("Generate Trees: Serialized");
    const singleTreeSerialized = singleTree.serialize();

    console.log("Exporting Trees: Starting");

    // Write into outputs/
    fs.writeFileSync(path.join(__dirname, "../outputs/Ordered_singleTree.json"), JSON.stringify(singleTreeSerialized, null, 2));

    console.log("Exporting Trees: Complete");
}


generateSanctionsTrees();
