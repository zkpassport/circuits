import { poseidon2 } from "@zkpassport/utils";
import { MRZData, OFACNames, OFACPassport, PassportMRZData } from "./types";
import countries from "i18n-iso-countries";
import en from "i18n-iso-countries/langs/en.json";

countries.registerLocale(en);

export function processDob(day: string, month: string, year: string): {
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

  export function processName(firstName: string, lastName: string): {
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


export function nameToMRZ(sanctionsList: OFACNames[]): MRZData[] {
    const processedList: MRZData[] = [];

    for (const item of sanctionsList) {
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

export function passportNoAndCountry(passportList: OFACPassport): PassportMRZData | null {
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

export function passportToMRZ(passportList: OFACPassport[]): PassportMRZData[] {
    const processedList: PassportMRZData[] = [];

    for (const item of passportList) {
        const passportMRZ = passportNoAndCountry(item);
        if (passportMRZ) {
            processedList.push(passportMRZ);
        }
    }

    return processedList;
}

export async function hashNameAndDob(mrz: MRZData[]): Promise<bigint[]> {
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

export async function hashNameAndYob(mrz: MRZData[]): Promise<bigint[]> {
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

export async function hashPassportNoAndCountry(passportList: PassportMRZData[]): Promise<bigint[]> {
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