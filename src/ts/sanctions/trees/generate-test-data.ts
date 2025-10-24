import { poseidon2, AsyncOrderedMT } from "@zkpassport/utils/merkle-tree"
import allSanctionsTree from "../output/all_sanctions_tree.json"
import { hashName, hashNameAndDob, hashNameAndYob, hashPassportNoAndCountry, nameToMRZ, passportNoAndCountry, passportToMRZ } from "./utils"
import { SanctionsEntry, PassportMRZData } from "../types"

async function initalizeTree() {
    const singleTree = await AsyncOrderedMT.fromSerialized(allSanctionsTree as string[][], poseidon2)
    return singleTree
}

/**
 * This file generate the necessary test data for src/noir/lib/exclusion-check/sanctions/src/lib.nr
 */

async function generateSimpleTest(singleTree: AsyncOrderedMT) {
    console.log("test: test_ordered_mt_non_membership")
    console.log("singleTree root hex", `0x${singleTree.root.toString(16).padStart(64, "0")}`);
    console.log("singleTree root decimal", singleTree.root);
    // non inclusion proof of arb value
    const singleTreeNonMembershipProof = await singleTree.createNonMembershipProof(1n);
    console.log("singleTreeNonMembershipProof", singleTreeNonMembershipProof);
    console.log("left sibling path", singleTreeNonMembershipProof.left?.proof.siblings);
    console.log("right sibling path", singleTreeNonMembershipProof.right?.proof.siblings);

    await AsyncOrderedMT.verifyNonMembershipProof(singleTreeNonMembershipProof, poseidon2)
}

async function generateMerkleProof(singleTree: AsyncOrderedMT, sanctionEntry: SanctionsEntry) {
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

async function generateMultipleMerkleProofs(singleTree: AsyncOrderedMT, sanctionEntry: SanctionsEntry) {
    const passportToMRZ = passportNoAndCountry(sanctionEntry as SanctionsEntry);

    const mrz = nameToMRZ([sanctionEntry as SanctionsEntry])

    const nameHashes = await hashName(mrz);
    console.log(mrz)

    const nonNameProofs = nameHashes.map(nameHash => singleTree.createNonMembershipProof(nameHash));
    console.log("target hex", nameHashes.map(nameHash => `0x${nameHash.toString(16).padStart(64, "0")}`));
    nonNameProofs.forEach(proof => {
        console.log("non name proof", proof);
    });

    const passportNoHash = await hashPassportNoAndCountry([passportToMRZ as PassportMRZData]);

    const nonPassportProof = singleTree.createNonMembershipProof(passportNoHash[0]);
    console.log("target hex", `0x${passportNoHash[0].toString(16).padStart(64, "0")}`);
    console.log("non passport proof", nonPassportProof);
    console.log("left sibling path", nonPassportProof.left?.proof.siblings);
    console.log("right sibling path", nonPassportProof.right?.proof.siblings);

    const nameAndDobHashes = await hashNameAndDob(mrz);
    const nameAndYobHashes = await hashNameAndYob(mrz);

    const nonNameAndDobProofs = nameAndDobHashes.map(nameAndDobHash => singleTree.createNonMembershipProof(nameAndDobHash));
    console.log("target hex", nameAndDobHashes.map(nameAndDobHash => `0x${nameAndDobHash.toString(16).padStart(64, "0")}`));
    nonNameAndDobProofs.forEach(proof => {
        console.log("non name and dob proof", proof);
    });

    const nonNameAndYobProofs = nameAndYobHashes.map(nameAndYobHash => singleTree.createNonMembershipProof(nameAndYobHash));
    console.log("target hex", nameAndYobHashes.map(nameAndYobHash => `0x${nameAndYobHash.toString(16).padStart(64, "0")}`));
    nonNameAndYobProofs.forEach(proof => {
        console.log("non name and yob proof", proof);
    });
}

async function generateNonMembershipTest(singleTree: AsyncOrderedMT) {
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
    
    await generateMerkleProof(singleTree, sanctionEntry as SanctionsEntry)
}

// Should fail as the name is in the tree
async function generateMembershipTest(singleTree: AsyncOrderedMT) {
    const sanctionEntry: Partial<SanctionsEntry> = {
        name: "Michael Davis",
        first_name: ["Michael"],
        last_name: ["Davis"],
        countries: ["DE"],
        nationality: ["DE"],
        passports: ["123456789"],
        has_passport: true,
        birth_date: "1980-04-16"
    }
    
    const passportToMRZ = passportNoAndCountry(sanctionEntry as SanctionsEntry);

    const mrz = nameToMRZ([sanctionEntry as SanctionsEntry])

    const nameHash = await hashName([mrz[0]]);

    const nonNameProof = singleTree.createMembershipProof(nameHash[0])
    console.log("target hex", `0x${nameHash[0].toString(16).padStart(64, "0")}`);
    console.log("non name proof", nonNameProof);
}

async function generateGermanNonMembershipTest(singleTree: AsyncOrderedMT) {
    const sanctionEntry: Partial<SanctionsEntry> = {
        name: "Johannes Mueller",
        first_name: ["Johannes"],
        last_name: ["Mueller"],
        countries: ["DE"],
        nationality: ["DE"],
        passports: ["123456789"],
        has_passport: true,
        birth_date: "1986-02-26"
    }
    
    await generateMerkleProof(singleTree, sanctionEntry as SanctionsEntry)
}

async function generateMultipleMerkleProofsTest(singleTree: AsyncOrderedMT) {
    const sanctionEntry: Partial<SanctionsEntry> = {
        name: "Jean-Pierre Dupont",
        first_name: ["Jean-Pierre-Martin", "Jean-Pierre", "Jean"],
        last_name: ["Dupont"],
        countries: ["FR"],
        nationality: ["FR"],
        passports: ["123456789"],
        has_passport: true,
        birth_date: "1995-05-03"
    }

    await generateMultipleMerkleProofs(singleTree, sanctionEntry as SanctionsEntry)
}

async function main() {
    const singleTree = await initalizeTree();
    // await generateSimpleTest(singleTree)
    // await generateNonMembershipTest(singleTree)
    // await generateGermanNonMembershipTest(singleTree)
    // await generateMembershipTest(singleTree)
    await generateMultipleMerkleProofsTest(singleTree)
}

main()