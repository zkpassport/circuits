import {SMT, poseidon2} from "@zkpassport/utils/merkle-tree"
import fs from "fs"
import countries from "i18n-iso-countries";
import en from "i18n-iso-countries/langs/en.json";
import NAMES_OFAC_LIST from "./inputs/names.json"
import PASSPORTS_OFAC_LIST from "./inputs/passports.json"

import { Barretenberg, Fr } from "@aztec/bb.js";

countries.registerLocale(en);

type OFACNames = {
    First_Name: string
    Last_Name: string
    day: string | null
    month: string | null
    year: string
}

type OFACPassport = {
    Pass_No: string
    Pass_Country: string
}

type MRZData = {
    name: string,
    nameMRZ: bigint[],
    dob: string | null,
    dobMRZ: bigint[] | null,
    year: string | null,
    yearMRZ: bigint[] | null,
}

type PassportMRZData = {
    passportNo: string,
    passportNoMRZ: bigint[],
    passportCountry: string,
    passportCountryMRZ: bigint[],
}

// Name and DOB

function processDob(day: string, month: string, year: string): {
    dob: string,
    dobMRZ: bigint[],
    year: string,
    yearMRZ: bigint[],
} {
    // YYMMDD
    const monthMap: { [key: string]: string } = {
      jan: '01',
      feb: '02',
      mar: '03',
      apr: '04',
      may: '05',
      jun: '06',
      jul: '07',
      aug: '08',
      sep: '09',
      oct: '10',
      nov: '11',
      dec: '12',
    };
  
    month = monthMap[month.toLowerCase()];
    year = year.slice(-2);
    const dob =year + month + day;
    const dobMRZ = stringToAsciiBigIntArray(dob);
    const yearMRZ = stringToAsciiBigIntArray(year);
    return {
        dob,
        dobMRZ,
        year,
        yearMRZ
    }
  }

  function processName(firstName: string, lastName: string): {
    nameMRZ: bigint[],
    name: string,
  } {
    // LASTNAME<<FIRSTNAME<MIDDLENAME<<<... (6-44)
    firstName = firstName.replace(/'/g, '');
    firstName = firstName.replace(/\./g, '');
    firstName = firstName.replace(/[- ]/g, '<');
    lastName = lastName.replace(/'/g, '');
    lastName = lastName.replace(/[- ]/g, '<');
    lastName = lastName.replace(/\./g, '');
    // Removed apostrophes from the first name, eg O'Neil -> ONeil
    // Replace spaces and hyphens with '<' in the first name, eg John Doe -> John<Doe
    // TODO : Handle special cases like malaysia : no two filler characters like << for surname and givenname
    // TODO : Verify rules for . in names. eg : J. Doe (Done same as apostrophe for now)
  
    let name = lastName + '<<' + firstName;
    if (name.length > 39) {
      name = name.substring(0, 39);
    } else {
      while (name.length < 39) {
        name += '<';
      }
    }

    let nameMRZ = stringToAsciiBigIntArray(name);
    return {nameMRZ, name};
  }

export function stringToAsciiBigIntArray(str: string): bigint[] {
    let asciiBigIntArray = [];
    for (let i = 0; i < str.length; i++) {
        asciiBigIntArray.push(BigInt(str.charCodeAt(i)));
    }
    return asciiBigIntArray;
}


function nameToMRZ(ofacList: OFACNames[]): MRZData[] {
    const processedList: MRZData[] = [];

    for (const item of ofacList) {
        // todo: fix what has it and what does not
        let processedDob: string | null = null;
        let processedYear: string | null = null;
        let processedYearMRZ: bigint[] | null = null;
        let processedDobMRZ: bigint[] | null = null;

        if (item.day && item.month) {
            const {dob, dobMRZ, year, yearMRZ} = processDob(item.day, item.month, item.year);
            processedDob = dob;
            processedDobMRZ = dobMRZ;
            processedYear = year;
            processedYearMRZ = yearMRZ;
        }
        const {nameMRZ, name} = processName(item.First_Name, item.Last_Name);

        processedList.push({
            name,
            nameMRZ,
            dob: processedDob,
            dobMRZ: processedDobMRZ,
            year: processedYear,
            yearMRZ: processedYearMRZ,
        })
    }

    return processedList;
}

// passports

// this is a temporary workaround for some of the country name,
// will be removed once we parse the OFAC list better, starting from the XML file.
// c.t. self/common/src/utils/trees.ts
const normalizeCountryName = (country: string): string => {
    const mapping: Record<string, string> = {
      "palestinian": "Palestine",
      "korea, north": "North Korea",
      "korea, south": "Korea, Republic of",
      "united kingdom": "United Kingdom",
      "syria": "Syrian Arab Republic",
      "burma": "Myanmar",
      "cabo verde": "Cape Verde",
      "congo, democratic republic of the": "Democratic Republic of the Congo",
      "macau": "Macao",
    };
    return mapping[country.toLowerCase()] || country;
  };

function passportNoAndCountry(passportList: OFACPassport): PassportMRZData | null {
    let passportNo = passportList.Pass_No;
    const passportCountry = passportList.Pass_Country;

    const countryCode = countries.getAlpha3Code(normalizeCountryName(passportCountry), "en");
    if (!countryCode) {
        console.log('Error getting country code', passportCountry);
        return null;
    }

    if (passportNo.length > 9) {
        console.log('passport number length is greater than 9:', passportNo);
    } else if (passportNo.length < 9) {
        while (passportNo.length != 9) {
            passportNo += '<';
        }
    }

    return {
        passportNo,
        passportNoMRZ: stringToAsciiBigIntArray(passportNo),
        passportCountry,
        passportCountryMRZ: stringToAsciiBigIntArray(countryCode),
    }
}

function passportToMRZ(passportList: OFACPassport[]): PassportMRZData[] {
    const processedList: PassportMRZData[] = [];

    for (const item of passportList) {
        const passportMRZ = passportNoAndCountry(item);
        if (passportMRZ) {
            processedList.push(passportMRZ);
        }
    }

    return processedList;
}

async function hashNameAndDob(mrz: MRZData[]): Promise<bigint[]> {
    const hashedList: bigint[] = [];
    for (const item of mrz) {
        const name = item.nameMRZ;
        const dob = item.dobMRZ;

        if (name && dob) {
            const nameAndDobBytes = [...name, ...dob];
            hashedList.push(await poseidon2(nameAndDobBytes));
        }
    }
    return hashedList;
}

async function hashNameAndYob(mrz: MRZData[]): Promise<bigint[]> {
    const hashedList: bigint[] = [];
    for (const item of mrz) {
        const name = item.nameMRZ;
        const year = item.yearMRZ;

        if (name && year) {
            const nameAndYobBytes = [...name, ...year];
            hashedList.push(await poseidon2(nameAndYobBytes));
        }
    }
    return hashedList;
}

async function hashPassportNoAndCountry(passportList: PassportMRZData[]): Promise<bigint[]> {
    const hashedList: bigint[] = [];
    for (const item of passportList) {
        const passportNo = item.passportNoMRZ;
        const passportCountry = item.passportCountryMRZ;

        if (passportNo && passportCountry) {
            const passportNoAndCountryBytes = [...passportNo, ...passportCountry];
            hashedList.push(await poseidon2(passportNoAndCountryBytes));
        }
    }
    return hashedList;
}

// Make merkle tree from OFAC list
async function main() {
    // const smt = new SMT(poseidon2, /*bigNumbers=*/ true)

    const mrz = nameToMRZ(NAMES_OFAC_LIST as OFACNames[])

    const passportMRZ = passportToMRZ(PASSPORTS_OFAC_LIST as OFACPassport[])
    console.log(passportMRZ)

    console.log("Converted OFAC list into MRZ format");

    console.log("Making merkle leaves");
    const nameAndDobHashed = await hashNameAndDob(mrz);
    console.log("name and dob hashed");
    const nameAndYobHashed = await hashNameAndYob(mrz);
    console.log("name and yob hashed");
    const passportNoAndCountryHashed = await hashPassportNoAndCountry(passportMRZ);
    console.log("passport no and country hashed");

    console.log("Made merkle leaves");

    const nameAndDobSMT = new SMT(poseidon2, /*bigNumbers=*/ true)
    const nameAndYobSMT = new SMT(poseidon2, /*bigNumbers=*/ true)
    const passportNoAndCountrySMT = new SMT(poseidon2, /*bigNumbers=*/ true)

    console.log("Adding leaves to merkle trees");
    console.log("adding name and dob leaves");
    // TODO: more efficient way to do this? batch adding?
    for (const item of nameAndDobHashed) {
        try {
            await nameAndDobSMT.add(item, BigInt(1));
        } catch (error) {
            console.log(error);
        }
    }

    console.log("adding name and yob leaves");

    for (const item of nameAndYobHashed) {
        try {
            await nameAndYobSMT.add(item, BigInt(1));
        } catch (error) {
            console.log(error);
        }
    }

    console.log("adding passport no and country leaves");

    for (const item of passportNoAndCountryHashed) {
        try {
            await passportNoAndCountrySMT.add(item, BigInt(1));
        } catch (error) {
            console.log(error);
        }
    }

    console.log("Merkle trees created");

    const nameAndDobAsJson = nameAndDobSMT.export();
    const nameAndYobAsJson = nameAndYobSMT.export();
    const passportNoAndCountryAsJson = passportNoAndCountrySMT.export();

    console.log("Merkle trees exported");

    fs.writeFileSync("NEW_nameAndDobSMT.json", nameAndDobAsJson);
    fs.writeFileSync("NEW_nameAndYobSMT.json", nameAndYobAsJson);
    fs.writeFileSync("NEW_passportNoAndCountrySMT.json", passportNoAndCountryAsJson);
}


// main();

import nameAndDobJson from "./outputs/NEW_nameAndDobSMT.json"
import nameAndYobJson from "./outputs/NEW_nameAndYobSMT.json"
import passportNoAndCountryJson from "./outputs/NEW_passportNoAndCountrySMT.json"

const TREE_DEPTH = 256;
function generateSMTProof(smt: SMT, leaf: bigint) {
    const proof = smt.createProof(leaf);
    const depth = proof.siblings.length;
    console.log(proof);

    let closestLeaf;
    if (!proof.matchingEntry) {
        if (!proof.entry[1]) {
            // non membership proof
            closestLeaf = BigInt(0);
        } else {
            closestLeaf = BigInt(proof.entry[0]);
        }
    } else {
        closestLeaf = BigInt(proof.matchingEntry[0]); // actual closes
    }

    proof.siblings.reverse();
    while (proof.siblings.length < TREE_DEPTH) proof.siblings.push(BigInt(0));

    return {
        root: proof.root,
        depth,
        closestLeaf,
        siblings: proof.siblings,
    }
}

// function makeTestData() {
//     const treeDepth = 256;
//     const nameAndDobSMT = new SMT(poseidon2, /*bigNumbers=*/ true)
//     nameAndDobSMT.import(JSON.stringify(nameAndDobJson));

//     // Get a merkle root for a known key
//     const proof = generateSMTProof(nameAndDobSMT, 12045524646828408848970088604958965805056114143397058268067009836652442217643n);
//     console.log(proof);
// }

// makeTestData();

// async function testSparse() {
    // const smt = new SMT(poseidon2, /*bigNumbers=*/ true)
    // await smt.add(0n, 1n);
    // await smt.add(1n, 1n);
    // await smt.add(3n, 1n);

    // console.log(await smt.createProof(3n));


    // const smt = new SMT(poseidon2, /*bigNumbers=*/ true)

    // await smt.add(0n, 1n);
    // await smt.add(1n, 1n);
    // await smt.add(3n, 1n);
    // await smt.add(7n, 1n);

    // console.log(await smt.createProof(5n));

    // console.log(await smt.createProof(3n));
    // console.log(await smt.createProof(7n));
    
    // const sevenProof = await smt.createProof(7n);
    // console.log("original seven proof", sevenProof);
    // console.log("verified original proof", await smt.verifyProof(sevenProof));
    // const threeProof = await smt.createProof(3n);
    // console.log("original 3 proof", threeProof);
    // console.log("verified original three proof", await smt.verifyProof(threeProof));
    // threeProof.matchingEntry = threeProof.entry;
    // threeProof.entry = [7n];
    // console.log("modified seven proof", threeProof);

    // console.log("verified modified proof", await smt.verifyProof(threeProof));
    // console.log(threeProof.siblings.map(sibling => [sibling, sibling.toString(16)]));

    // console.log("H(1,1,1) = ", (await poseidon2([1n, 1n, 0n])).toString(16));
    // const nineProof = await smt.createProof(9n);
    // console.log("nine proof", nineProof);
    // console.log("verified nine proof", await smt.verifyProof(nineProof));

    // const sevenProof = await smt.createProof(7n);
    // console.log("seven proof", sevenProof);
    // console.log("verified seven proof", await smt.verifyProof(sevenProof));

    // // alter the 5 proof
    // sevenProof.matchingEntry = sevenProof.entry;
    // sevenProof.entry = [3n];
    // console.log("modified seven proof", sevenProof);
    // console.log("verified modified proof", await smt.verifyProof(sevenProof));


    // console.log(
    //     "\n\n\n inserting 3"
    // )
    // await smt.add(5n, 1n);
    // console.log(
    //     "\n\n\n done 3"
    // )
    // console.log("H(1,1,1) = ", await poseidon2([1n, 1n, 1n]));
    // console.log("H(5,1,1) = ", await poseidon2([5n, 1n, 1n]));
    // console.log(await smt.createProof(1n));
    // console.log(await smt.createProof(5n));
    // console.log(await smt.createProof(2n));
    // console.log(await smt.createProof(4n));

// }

// testSparse();

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
    const passport: OFACPassport = {
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
    } as OFACNames])

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