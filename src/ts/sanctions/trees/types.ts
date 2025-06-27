export type SanctionsNames = {
    First_Name: string
    Last_Name: string
    day: string | null
    month: string | null
    year: string
}

export type SanctionsPassport = {
    Pass_No: string
    Pass_Country: string
}

export type MRZData = {
    name: string,
    nameMRZ: bigint[],
    dob: string | null,
    dobMRZ: bigint[] | null,
    year: string | null,
    yearMRZ: bigint[] | null,
}

export type PassportMRZData = {
    passportNo: string,
    passportNoMRZ: bigint[],
    passportCountry: string,
    passportCountryMRZ: bigint[],
}