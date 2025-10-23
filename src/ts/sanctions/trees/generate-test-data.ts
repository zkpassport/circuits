import { poseidon2, AsyncOrderedMT } from "@zkpassport/utils/merkle-tree"
import allSanctionsTree from "../output/all_sanctions_tree.json"
import { hashName, hashNameAndDob, hashNameAndYob, hashPassportNoAndCountry, nameToMRZ, passportNoAndCountry, passportToMRZ } from "./utils"
import { SanctionsEntry, PassportMRZData } from "../types"

/**
 * Generate test data within exclusion-check/sanctions/src/lib.nr
 */
async function testNonMembershipFullSets() {
    console.log("test: test_ordered_mt_non_membership")
    const singleTree = await AsyncOrderedMT.fromSerialized(allSanctionsTree as string[][], poseidon2)
    console.log("singleTree root hex", `0x${singleTree.root.toString(16).padStart(64, "0")}`);
    console.log("singleTree root decimal", singleTree.root);
    // non inclusion proof of arb value
    const singleTreeNonMembershipProof = await singleTree.createNonMembershipProof(1n);
    console.log("singleTreeNonMembershipProof", singleTreeNonMembershipProof);
    console.log("left sibling path", singleTreeNonMembershipProof.left?.proof.siblings);
    console.log("right sibling path", singleTreeNonMembershipProof.right?.proof.siblings);

    await AsyncOrderedMT.verifyNonMembershipProof(singleTreeNonMembershipProof, poseidon2)

    console.log("test: non_inclusion_of_dg1");

    const sanctionEntry: Partial<SanctionsEntry> = {
        name: "John Doe",
        first_name: ["John"],
        last_name: ["Doe"],
        countries: ["GB"],
        nationality: ["GB"],
        passports: ["123456789"],
        has_passport: true,
        birth_date: "1990-01-12"
    }

    const passportToMRZ = passportNoAndCountry(sanctionEntry as SanctionsEntry);

    const mrz = nameToMRZ([sanctionEntry as SanctionsEntry])

    const nameHash = await hashName([mrz[0]]);

    const nonNameProof = singleTree.createNonMembershipProof(nameHash[0])
    console.log("target hex", `0x${nameHash[0].toString(16).padStart(64, "0")}`);
    console.log("non name proof", nonNameProof);
    console.log("left sibling path", nonNameProof.left?.proof.siblings);
    console.log("right sibling path", nonNameProof.right?.proof.siblings);

    const passportNoHash = await hashPassportNoAndCountry([passportToMRZ as PassportMRZData]);

    const nonPassportProof = singleTree.createNonMembershipProof(passportNoHash[0]);
    console.log("target hex", `0x${passportNoHash[0].toString(16).padStart(64, "0")}`);
    console.log("non passport proof", nonPassportProof);
    console.log("left sibling path", nonPassportProof.left?.proof.siblings);
    console.log("right sibling path", nonPassportProof.right?.proof.siblings);

    const nameAndDobHash = await hashNameAndDob([mrz[0]]);
    const nameAndYobHash = await hashNameAndYob([mrz[0]]);

    const nonNameAndDobProof = singleTree.createNonMembershipProof(nameAndDobHash[0]);
    console.log("target hex", `0x${nameAndDobHash[0].toString(16).padStart(64, "0")}`);
    console.log("non name and dob proof", nonNameAndDobProof);
    console.log("left sibling path", nonNameAndDobProof.left?.proof.siblings);
    console.log("right sibling path", nonNameAndDobProof.right?.proof.siblings);

    const nonNameAndYobProof = singleTree.createNonMembershipProof(nameAndYobHash[0]);
    console.log("target hex", `0x${nameAndYobHash[0].toString(16).padStart(64, "0")}`);
    console.log("non name and yob proof", nonNameAndYobProof);
    console.log("left sibling path", nonNameAndYobProof.left?.proof.siblings);
    console.log("right sibling path", nonNameAndYobProof.right?.proof.siblings);
}

testNonMembershipFullSets();