import {poseidon2, AsyncOrderedMT} from "@zkpassport/utils/merkle-tree"
import fs from "fs"
import { hashName, hashNameAndDob, hashNameAndYob, hashPassportNoAndCountry, nameToMRZ, passportToMRZ } from "./utils";
import { SanctionsEntry } from "../types";
import path from "path";
import { exec } from "child_process"

const OPEN_SANCTIONS_DATASETS_URL = `https://data.opensanctions.org/datasets`

const sanctionsListNames = ["ch_seco_sanctions", "eu_fsf", "gb_fcdo_sanctions", "us_ofac_sdn"];

// Currently, the max is really close to 17, so we use 18 as it may soon rise above 17
const TREE_DEPTH = 18;

async function getSanctionsListEntities(datasetName: string) {
    const today = new Date().toISOString().split('T')[0].replace(/-/g, '');
    const response = await fetch(`${OPEN_SANCTIONS_DATASETS_URL}/${today}/${datasetName}/entities.ftm.json`);
    const data = await response.text();
    console.log("Downloaded", datasetName, "entities.ftm.json successfully");
    return {entities: data, datasetName: datasetName};
}

async function generateSanctionsTreesForList(sanctionsList: SanctionsEntry[]) {
    console.log("Parsing Data: Starting");
    console.log("Parsing Data: Converted Sanctions list into MRZ format");
    const mrz = nameToMRZ(sanctionsList);
    const passportMRZ = passportToMRZ(sanctionsList);
    console.log("mrz length", mrz.length);
    console.log("Parsing Data: Generating leaves (hashing MRZ data)")
    const nameHashed = await hashName(mrz);
    const nameAndDobHashed = await hashNameAndDob(mrz);
    const nameAndYobHashed = await hashNameAndYob(mrz);
    const passportNoAndCountryHashed = await hashPassportNoAndCountry(passportMRZ);
    console.log("data lengths", nameHashed.length, nameAndDobHashed.length, nameAndYobHashed.length, passportNoAndCountryHashed.length);
    console.log("data lengths log 2", Math.log2(nameHashed.length), Math.log2(nameAndDobHashed.length), Math.log2(nameAndYobHashed.length), Math.log2(passportNoAndCountryHashed.length));
    console.log("combined log 2", Math.log2(nameHashed.length + nameAndDobHashed.length + nameAndYobHashed.length + passportNoAndCountryHashed.length));

    console.log("Parsing Data: Complete");
    const singleTree = await AsyncOrderedMT.create(TREE_DEPTH, poseidon2)
    const singleTreeData = nameHashed.concat(nameAndDobHashed, nameAndYobHashed, passportNoAndCountryHashed)

    console.log("Generate Tree: Starting");

    await singleTree.initializeAndSort(singleTreeData);

    console.log("Generate Trees: Complete");

    console.log("Generate Trees: Serialized");
    const singleTreeSerialized = singleTree.serialize();

    console.log("Exporting Trees: Starting");

    return singleTreeSerialized;
}

/**
 * Steps:
 * 1. Parse the Sanctions list into MRZ format
 * 2. Hash the MRZ data
 * 3. Generate the leaves for the SMT
 * 4. Add the leaves to the SMT
 * 5. Export the SMT
 */
async function generateSanctionsTrees() {
    const openSanctionsResults = await Promise.all(sanctionsListNames.map(getSanctionsListEntities));

    // Clear the input directory
    fs.rmSync(path.join(__dirname, `../input`), { recursive: true, force: true });
    // Clear the temp directory
    fs.rmSync(path.join(__dirname, `../temp`), { recursive: true, force: true });

    // Check if the input directory exists
    if (!fs.existsSync(path.join(__dirname, `../input`))) {
        fs.mkdirSync(path.join(__dirname, `../input`), { recursive: true });
    }
    // Check if the temp directory exists
    if (!fs.existsSync(path.join(__dirname, `../temp`))) {
        fs.mkdirSync(path.join(__dirname, `../temp`), { recursive: true });
    }
    // Check if the output directory exists
    if (!fs.existsSync(path.join(__dirname, `../output`))) {
        fs.mkdirSync(path.join(__dirname, `../output`), { recursive: true });
    }
    
    const pythonScript = path.join(__dirname, "../scripts/parse_opensanctions.py");
    for (const {entities, datasetName} of openSanctionsResults) {
        // The Python script expects the entities as a single file, so we need to write them to a file
        const entitiesFile = path.join(__dirname, `../temp/${datasetName}_entities.ftm.json`);
        fs.writeFileSync(entitiesFile, entities);
        // Run the python script to parse the entities
        const cmd = await exec(`python ${pythonScript} ${entitiesFile} --output-dir ${path.join(__dirname, `../input/${datasetName}`)}`)
        const promise = new Promise((resolve, reject) => {
            cmd.once("close", (code) => {
                if (code !== 0) {
                    reject(new Error("Error running python script: " + code));
                }
                resolve(true);
            });
            cmd.once("error", (error) => {
                reject(new Error("Error running python script: " + error));
            });
        });
        await promise.then(() => {
            // Delete the entities file
            console.log(`${datasetName} parsed successfully by the python script`);
        }).catch((error) => {
            console.error("Error parsing ", datasetName, " with the python script: ", error);
        });
        fs.unlinkSync(entitiesFile);
    }

    const sanctionsLists = openSanctionsResults.map(({datasetName}) => JSON.parse(fs.readFileSync(path.join(__dirname, `../input/${datasetName}/persons_with_passports.json`), 'utf8')));

    // Generate the tree for each sanctions list
    console.log("Generating Trees for each sanctions list");
    for (const sanctionsList of sanctionsLists) {
        const datasetName = sanctionsList[0].datasets[0];
        console.log("Generating Trees for dataset: ", datasetName);
        try {
            const singleTreeSerialized = await generateSanctionsTreesForList(sanctionsList);
            fs.writeFileSync(path.join(__dirname, `../output/${datasetName}_tree.json`), JSON.stringify(singleTreeSerialized, null, 2));
            console.log("Trees generated for dataset: ", datasetName);
        } catch (error) {
            console.error("Error generating trees for dataset: ", datasetName, error);
        }
    }

    // Generate the tree for all sanctions lists
    console.log("Generating Tree for all sanctions lists combined");
    try {
        const singleTreeSerialized = await generateSanctionsTreesForList(sanctionsLists.flat());
        fs.writeFileSync(path.join(__dirname, `../output/all_sanctions_tree.json`), JSON.stringify(singleTreeSerialized, null, 2));
        console.log("Tree generated for all sanctions lists");
    } catch (error) {
        console.error("Error generating tree for all sanctions lists", error);
    }
}


generateSanctionsTrees();