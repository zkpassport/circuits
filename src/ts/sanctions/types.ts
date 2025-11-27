import { ExtendedAlpha2Code, SanctionsAlpha2Code, SanctionsCountries } from "@zkpassport/utils"
import { Alpha2Code } from "i18n-iso-countries"

export type SanctionsStatus = "sanctioned" | "debarred" | "wanted" | "crime-related" | "pep" | "person-of-interest" | "interpol-notice" | "disqualified"
export type SanctionsDataset = "gb_fcdo_sanctions" | "us_ofac_sdn" | "ch_seco_sanctions" | "eu_sanctions_map" | "eu_fsf" | "eu_esma_sanctions"

export type SanctionsEntry = {
  id: string
  name: string
  is_latin_name: boolean
  first_name: string[]
  middle_name: string[]
  second_name: string[]
  last_name: string[]
  all_names: string[]
  aliases: string[]
  birth_date: string // YYYY-MM-DD or YYYY
  passports: string[]
  nationality: Alpha2Code[]
  has_passport: boolean
  status: SanctionsStatus[]
  countries: Alpha2Code[]
  datasets: SanctionsDataset[]
}

export type MRZData = {
  name: string
  nameMRZ: bigint[]
  dob: string | null
  dobMRZ: bigint[] | null
  year: string | null
  yearMRZ: bigint[] | null
}

export type PassportMRZData = {
  passportNo: string
  passportNoMRZ: bigint[]
  passportCountry: string
  passportCountryMRZ: bigint[]
}
