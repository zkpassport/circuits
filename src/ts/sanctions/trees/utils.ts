import { countryCodeAlpha2ToAlpha3, poseidon2 } from "@zkpassport/utils";
import { MRZData, SanctionsEntry, PassportMRZData } from "../types";
import countries from "i18n-iso-countries";
import en from "i18n-iso-countries/langs/en.json";

countries.registerLocale(en);

export function processDob(birth_date: string): {
    dob: string | null,
    dobMRZ: bigint[] | null,
    year: string,
    yearMRZ: bigint[],
} {
    // Only the year is provided
    if (birth_date.length === 4) {
        return {
            dob: null,
            dobMRZ: null,
            year: birth_date,
            yearMRZ: stringToAsciiBigIntArray(birth_date),
        }
    }

    // YYYY-MM-DD
    const [year, month, day] = birth_date.split('-');
  
    // The day or month is not provided, so we only get the year
    if (month === undefined || day === undefined) {
        return {
            dob: null,
            dobMRZ: null,
            year: birth_date.split('-')[0],
            yearMRZ: stringToAsciiBigIntArray(birth_date.split('-')[0]),
        }
    }

    const monthNumber = parseInt(month);
    const dob = year.slice(-2) + monthNumber.toString().padStart(2, '0') + day.padStart(2, '0');
    const dobMRZ = stringToAsciiBigIntArray(dob);
    const yearMRZ = stringToAsciiBigIntArray(year);
    return {
        dob,
        dobMRZ,
        year,
        yearMRZ
    }
  }

  export function processName(firstNames: string[], lastNames: string[]): {
    nameMRZ: bigint[][],
    name: string[],
  } {
    // LASTNAME<<FIRSTNAME<MIDDLENAME<<<... (6-44)
    firstNames = firstNames.map(name => name.replace(/'/g, ''));
    firstNames = firstNames.map(name => name.replace(/\./g, ''));
    firstNames = firstNames.map(name => name.replace(/[- ]/g, '<'));
    lastNames = lastNames.map(name => name.replace(/'/g, ''));
    lastNames = lastNames.map(name => name.replace(/[- ]/g, '<'));
    lastNames = lastNames.map(name => name.replace(/\./g, ''));

    let names: string[] = [];
    let namesMRZ: bigint[][] = [];
    for (const firstName of firstNames) {
        for (const lastName of lastNames) {
            let parsedName = lastName + '<<' + firstName;
            if (parsedName.length > 39) {
                parsedName = parsedName.substring(0, 39);
            } else {
                while (parsedName.length < 39) {
                    parsedName += '<';
                }
            }
            names.push(parsedName.toUpperCase());
            namesMRZ.push(stringToAsciiBigIntArray(parsedName.toUpperCase()));
        }
    }
  
    return {nameMRZ: namesMRZ, name: names};
  }

export function stringToAsciiBigIntArray(str: string): bigint[] {
    let asciiBigIntArray = [];
    for (let i = 0; i < str.length; i++) {
        asciiBigIntArray.push(BigInt(str.charCodeAt(i)));
    }
    return asciiBigIntArray;
}


export function nameToMRZ(sanctionsList: SanctionsEntry[]): MRZData[] {
    const processedList: MRZData[] = [];

    for (const item of sanctionsList) {
        // todo: fix what has it and what does not
        let processedDob: string | null = null;
        let processedYear: string | null = null;
        let processedYearMRZ: bigint[] | null = null;
        let processedDobMRZ: bigint[] | null = null;

        if (item.birth_date) {
            const {dob, dobMRZ, year, yearMRZ} = processDob(item.birth_date);
            processedDob = dob;
            processedDobMRZ = dobMRZ;
            processedYear = year.slice(-2);
            processedYearMRZ = yearMRZ;
        }
        const {nameMRZ, name} = processName(item.first_name, item.last_name);

        for (let i = 0; i < nameMRZ.length; i++) {
            processedList.push({
                name: name[i],
                nameMRZ: nameMRZ[i],
                dob: processedDob,
                dobMRZ: processedDobMRZ,
                year: processedYear,
                yearMRZ: processedYearMRZ,
            })
        }
    }

    return processedList;
}

export function passportNoAndCountry(sanctionsEntry: SanctionsEntry): PassportMRZData | null {
    if (!sanctionsEntry.has_passport || sanctionsEntry.passports.length === 0 || (sanctionsEntry.nationality.length === 0 && sanctionsEntry.countries.length === 0)) {
        return null;
    }

    let passportNo = sanctionsEntry.passports[0];
    const passportCountryAlpha2Code = sanctionsEntry.nationality.length > 0 ? sanctionsEntry.nationality[0] : sanctionsEntry.countries[0];

    const passportCountry = passportCountryAlpha2Code && passportCountryAlpha2Code.length === 2 ? countryCodeAlpha2ToAlpha3(passportCountryAlpha2Code) : passportCountryAlpha2Code;
    if (!passportCountry) {
        return null;
    }

    if (passportNo.length < 9) {
        while (passportNo.length != 9) {
            passportNo += '<';
        }
    }

    return {
        passportNo,
        passportNoMRZ: stringToAsciiBigIntArray(passportNo),
        passportCountry,
        passportCountryMRZ: stringToAsciiBigIntArray(passportCountry),
    }
}

export function passportToMRZ(sanctionsList: SanctionsEntry[]): PassportMRZData[] {
    const processedList: PassportMRZData[] = [];

    for (const item of sanctionsList) {
        const passportMRZ = passportNoAndCountry(item);
        if (passportMRZ) {
            processedList.push(passportMRZ);
        }
    }

    return processedList;
}

export async function hashName(mrz: MRZData[]): Promise<bigint[]> {
    const hashedList: bigint[] = [];
    const itemEncountered: Set<string> = new Set();
    for (const item of mrz) {
        const name = item.nameMRZ;
        if (name && !itemEncountered.has(name.toString())) {
            itemEncountered.add(name.toString());
            hashedList.push(await poseidon2(name));
        }
    }
    return hashedList;
}

export async function hashNameAndDob(mrz: MRZData[]): Promise<bigint[]> {
    const hashedList: bigint[] = [];
    const itemEncountered: Set<string> = new Set();
    for (const item of mrz) {
        const name = item.nameMRZ;
        const dob = item.dobMRZ;

        if (name && dob && !itemEncountered.has(name.toString() + dob.toString())) {
            itemEncountered.add(name.toString() + dob.toString());
            const nameAndDobBytes = [...name, ...dob];
            hashedList.push(await poseidon2(nameAndDobBytes));
        }
    }
    return hashedList;
}

export async function hashNameAndYob(mrz: MRZData[]): Promise<bigint[]> {
    const hashedList: bigint[] = [];
    const itemEncountered: Set<string> = new Set();
    for (const item of mrz) {
        const name = item.nameMRZ;
        const year = item.yearMRZ?.slice(-2);

        if (name && year && !itemEncountered.has(name.toString() + year.toString())) {
            itemEncountered.add(name.toString() + year.toString());
            const nameAndYobBytes = [...name, ...year];
            hashedList.push(await poseidon2(nameAndYobBytes));
        }
    }
    return hashedList;
}

export async function hashPassportNoAndCountry(passportList: PassportMRZData[]): Promise<bigint[]> {
    const hashedList: bigint[] = [];
    const itemEncountered: Set<string> = new Set();
    for (const item of passportList) {
        const passportNo = item.passportNoMRZ;
        const passportCountry = item.passportCountryMRZ;

        if (passportNo && passportCountry && !itemEncountered.has(passportNo.toString() + passportCountry.toString())) {
            itemEncountered.add(passportNo.toString() + passportCountry.toString());
            const passportNoAndCountryBytes = [...passportNo, ...passportCountry];
            hashedList.push(await poseidon2(passportNoAndCountryBytes));
        }
    }
    return hashedList;
}