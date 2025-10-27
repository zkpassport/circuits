#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0
"""
Parse OpenSanctions entities.ftm.json file to extract persons with passport information.
Follow-the-Money (FTM) format parser.
"""

import json
import csv
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import sys
import os
import unicodedata

# Global tracking for entities without Latin names
entities_without_latin_names = []

def is_latin(text: str) -> bool:
    """
    Check if a string contains primarily Latin characters.
    Returns True if the text is mostly Latin alphabet (including accented characters).
    """
    if not text:
        return False
    
    latin_count = 0
    total_alpha = 0
    
    for char in text:
        if char.isalpha():
            total_alpha += 1
            # Check if character is in Latin Unicode blocks
            # This includes basic Latin (A-Z), Latin-1 Supplement (À-ÿ), Latin Extended-A, etc.
            char_name = unicodedata.name(char, '')
            if 'LATIN' in char_name or char in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz':
                latin_count += 1
    
    # Consider it Latin if more than 50% of alphabetic characters are Latin
    if total_alpha == 0:
        return False
    return (latin_count / total_alpha) > 0.5

# Removed select_latin_name function as we now create entries for all Latin names

# ICAO Doc 9303 compliant transliteration tables
# Latin character transliteration based on ICAO standards
LATIN_TRANSLITERATION = {
    "\u0027": "",                      # ' (apostrophe)
    "\u00C0": "A",                     # À
    "\u00C1": "A",                     # Á
    "\u00C2": "A",                     # Â
    "\u00C3": "A",                     # Ã
    "\u00C4": "AE",                    # Ä (or A)
    "\u00C5": "AA",                    # Å (or A)
    "\u00C6": "AE",                    # Æ
    "\u00C7": "C",                     # Ç
    "\u00C8": "E",                     # È
    "\u00C9": "E",                     # É
    "\u00CA": "E",                     # Ê
    "\u00CB": "E",                     # Ë
    "\u00CC": "I",                     # Ì
    "\u00CD": "I",                     # Í
    "\u00CE": "I",                     # Î
    "\u00CF": "I",                     # Ï
    "\u00D0": "D",                     # Ð
    "\u00D1": "N",                     # Ñ (or NXX)
    "\u00D2": "O",                     # Ò
    "\u00D3": "O",                     # Ó
    "\u00D4": "O",                     # Ô
    "\u00D5": "O",                     # Õ
    "\u00D6": "OE",                    # Ö (or O)
    "\u00D8": "OE",                    # Ø
    "\u00D9": "U",                     # Ù
    "\u00DA": "U",                     # Ú
    "\u00DB": "U",                     # Û
    "\u00DC": "UE",                    # Ü (or UXX or U)
    "\u00DD": "Y",                     # Ý
    "\u00DE": "TH",                    # Þ
    "\u00DF": "SS",                    # ß (eszett)
    "\u0100": "A",                     # Ā
    "\u0102": "A",                     # Ă
    "\u0104": "A",                     # Ą
    "\u0106": "C",                     # Ć
    "\u0108": "C",                     # Ĉ
    "\u010A": "C",                     # Ċ
    "\u010C": "C",                     # Č
    "\u010E": "D",                     # Ď
    "\u0110": "D",                     # Đ
    "\u0112": "E",                     # Ē
    "\u0114": "E",                     # Ĕ
    "\u0116": "E",                     # Ė
    "\u0118": "E",                     # Ę
    "\u011A": "E",                     # Ě
    "\u011C": "G",                     # Ĝ
    "\u011E": "G",                     # Ğ
    "\u0120": "G",                     # Ġ
    "\u0122": "G",                     # Ģ
    "\u0124": "H",                     # Ĥ
    "\u0126": "H",                     # Ħ
    "\u0128": "I",                     # Ĩ
    "\u012A": "I",                     # Ī
    "\u012C": "I",                     # Ĭ
    "\u012E": "I",                     # Į
    "\u0130": "I",                     # İ
    "\u0131": "I",                     # ı
    "\u0132": "IJ",                    # Ĳ
    "\u0134": "J",                     # Ĵ
    "\u0136": "K",                     # Ķ
    "\u0139": "L",                     # Ĺ
    "\u013B": "L",                     # Ļ
    "\u013D": "L",                     # Ľ
    "\u013F": "L",                     # Ŀ
    "\u0141": "L",                     # Ł
    "\u0143": "N",                     # Ń
    "\u0145": "N",                     # Ņ
    "\u0147": "N",                     # Ň
    "\u014A": "N",                     # Ŋ
    "\u014C": "O",                     # Ō
    "\u014E": "O",                     # Ŏ
    "\u0150": "O",                     # Ő
    "\u0152": "OE",                    # Œ
    "\u0154": "R",                     # Ŕ
    "\u0156": "R",                     # Ŗ
    "\u0158": "R",                     # Ř
    "\u015A": "S",                     # Ś
    "\u015C": "S",                     # Ŝ
    "\u015E": "S",                     # Ş
    "\u0160": "S",                     # Š
    "\u0162": "T",                     # Ţ
    "\u0164": "T",                     # Ť
    "\u0166": "T",                     # Ŧ
    "\u0168": "U",                     # Ũ
    "\u016A": "U",                     # Ū
    "\u016C": "U",                     # Ŭ
    "\u016E": "U",                     # Ů
    "\u0170": "U",                     # Ű
    "\u0172": "U",                     # Ų
    "\u0174": "W",                     # Ŵ
    "\u0176": "Y",                     # Ŷ
    "\u0178": "Y",                     # Ÿ
    "\u0179": "Z",                     # Ź
    "\u017B": "Z",                     # Ż
    "\u017D": "Z",                     # Ž
    "\u1E9E": "SS",                    # ẞ
}

# Cyrillic to Latin transliteration based on ICAO Doc 9303
CYRILLIC_TRANSLITERATION = {
    "\u0401": "E",      # Ё (except Belorussian = IO)
    "\u0402": "D",      # Ђ
    "\u0404": "IE",     # Є (except if Ukrainian first character, then = YE)
    "\u0405": "DZ",     # Ѕ
    "\u0406": "I",      # І
    "\u0407": "I",      # Ї (except if Ukrainian first character, then = YI)
    "\u0408": "J",      # Ј
    "\u0409": "LJ",     # Љ
    "\u040A": "NJ",     # Њ
    "\u040C": "K",      # Ќ (except Macedonian = KJ)
    "\u040E": "U",      # Ў
    "\u040F": "DZ",     # Џ (except Macedonian = DJ)
    "\u0410": "A",      # А
    "\u0411": "B",      # Б
    "\u0412": "V",      # В
    "\u0413": "G",      # Г (except Belorussian, Serbian, Ukrainian = H)
    "\u0414": "D",      # Д
    "\u0415": "E",      # Е
    "\u0416": "ZH",     # Ж (except Serbian = Z)
    "\u0417": "Z",      # З
    "\u0418": "I",      # И (except Ukrainian = Y)
    "\u0419": "I",      # Й (except if Ukrainian first character, then = Y)
    "\u041A": "K",      # К
    "\u041B": "L",      # Л
    "\u041C": "M",      # М
    "\u041D": "N",      # Н
    "\u041E": "O",      # О
    "\u041F": "P",      # П
    "\u0420": "R",      # Р
    "\u0421": "S",      # С
    "\u0422": "T",      # Т
    "\u0423": "U",      # У
    "\u0424": "F",      # Ф
    "\u0425": "KH",     # Х (except Serbian, Macedonian = H)
    "\u0426": "TS",     # Ц (except Serbian, Macedonian = C)
    "\u0427": "CH",     # Ч (except Serbian = C)
    "\u0428": "SH",     # Ш (except Serbian = S)
    "\u0429": "SHCH",   # Щ (except Bulgarian = SHT)
    "\u042A": "IE",     # Ъ
    "\u042B": "Y",      # Ы
    "\u042D": "E",      # Э
    "\u042E": "IU",     # Ю (except if Ukrainian first character, then = YU)
    "\u042F": "IA",     # Я (except if Ukrainian first character, then = YA)
    "\u046A": "U",      # Ѫ
    "\u0474": "Y",      # Ѵ
    "\u0490": "G",      # Ґ
    "\u0492": "G",      # Ғ (except Macedonian = GJ)
    "\u04BA": "C",      # Һ
}

# Arabic to Latin transliteration based on ICAO Doc 9303
ARABIC_TRANSLITERATION = {
    "\u0621": "XE",     # ء hamza
    "\u0622": "XAA",    # آ alef with madda above
    "\u0623": "XAE",    # أ alef with hamza above
    "\u0624": "U",      # ؤ waw with hamza above
    "\u0625": "I",      # إ alef with hamza below
    "\u0626": "XI",     # ئ yeh with hamza above
    "\u0627": "A",      # ا alef
    "\u0628": "B",      # ب beh
    "\u0629": "XTA",    # ة teh marbuta (XAH at end of name)
    "\u062A": "T",      # ت teh
    "\u062B": "XTH",    # ث theh
    "\u062C": "J",      # ج jeem
    "\u062D": "XH",     # ح hah
    "\u062E": "XKH",    # خ khah
    "\u062F": "D",      # د dal
    "\u0630": "XDH",    # ذ thal
    "\u0631": "R",      # ر reh
    "\u0632": "Z",      # ز zain
    "\u0633": "S",      # س seen
    "\u0634": "XSH",    # ش sheen
    "\u0635": "XSS",    # ص sad
    "\u0636": "XDZ",    # ض dad
    "\u0637": "XTT",    # ط tah
    "\u0638": "XZZ",    # ظ zah
    "\u0639": "E",      # ع ain
    "\u063A": "G",      # غ ghain
    "\u0641": "F",      # ف feh
    "\u0642": "Q",      # ق qaf
    "\u0643": "K",      # ك kaf
    "\u0644": "L",      # ل lam
    "\u0645": "M",      # م meem
    "\u0646": "N",      # ن noon
    "\u0647": "H",      # ه heh
    "\u0648": "W",      # و waw
    "\u0649": "XAY",    # ى alef maksura
    "\u064A": "Y",      # ي yeh
    "\u0671": "XXA",    # ٱ alef wasla
    "\u0679": "XXT",    # ٹ tteh
    "\u067C": "XRT",    # ټ teh with ring
    "\u067E": "P",      # پ peh
    "\u0681": "XKE",    # ځ hah with hamza above
    "\u0685": "XXH",    # څ hah with 3 dots above
    "\u0686": "XC",     # چ tcheh
    "\u0688": "XXD",    # ڈ ddal
    "\u0689": "XDR",    # ډ dal with ring
    "\u0691": "XXR",    # ڑ rreh
    "\u0693": "XRR",    # ړ reh with ring
    "\u0696": "XRX",    # ږ reh with dot below and dot above
    "\u0698": "XJ",     # ژ jeh
    "\u069A": "XXS",    # ښ seen with dot below and dot above
    "\u06A9": "XKK",    # ک keheh
    "\u06AB": "XXK",    # ګ kaf with ring
    "\u06AD": "XNG",    # ڭ ng
    "\u06AF": "XGG",    # گ gaf
    "\u06BA": "XNN",    # ں noon ghunna
    "\u06BC": "XXN",    # ڼ noon with ring
    "\u06BE": "XDO",    # ھ heh doachashmee
    "\u06C0": "XYH",    # ۀ heh with yeh above
    "\u06C1": "XXG",    # ہ heh goal
    "\u06C2": "XGE",    # ۂ heh goal with hamza above
    "\u06C3": "XTG",    # ۃ teh marbuta goal
    "\u06CC": "XYA",    # ى farsi yeh
    "\u06CD": "XXY",    # ۍ yeh with tail
    "\u06D0": "Y",      # ې yeh
    "\u06D2": "XYB",    # ے yeh barree
    "\u06D3": "XBE",    # ۓ yeh barree with hamza above
}

def is_cyrillic(text: str) -> bool:
    """Check if text contains any Cyrillic characters."""
    if not text:
        return False
    
    cyrillic_count = 0
    total_alpha = 0
    
    for char in text:
        if char.isalpha():
            total_alpha += 1
            # Cyrillic Unicode block: U+0400–U+04FF
            if '\u0400' <= char <= '\u04FF':
                cyrillic_count += 1
    
    if total_alpha == 0:
        return False
    return cyrillic_count > 0

def is_arabic(text: str) -> bool:
    """Check if text contains any Arabic characters."""
    if not text:
        return False
    
    arabic_count = 0
    total_alpha = 0
    
    for char in text:
        if char.isalpha():
            total_alpha += 1
            # Arabic Unicode block: U+0600–U+06FF
            if '\u0600' <= char <= '\u06FF':
                arabic_count += 1
    
    if total_alpha == 0:
        return False
    return arabic_count > 0

def transliterate_cyrillic(text: str) -> str:
    """Transliterate Cyrillic text to Latin using ICAO standards."""
    if not text:
        return text
    
    result = text
    for char, replacement in CYRILLIC_TRANSLITERATION.items():
        result = result.replace(char, replacement)
        # Also handle lowercase
        result = result.replace(char.lower(), replacement.lower())
    
    return result

def transliterate_arabic(text: str) -> str:
    """Transliterate Arabic text to Latin using ICAO standards."""
    if not text:
        return text
    
    result = text
    for char, replacement in ARABIC_TRANSLITERATION.items():
        result = result.replace(char, replacement)
    
    # TODO(md): make more robust
    # Handle teh marbuta at end of name components
    # This is a simplified approach - ideally would parse name components
    result = result.replace("XTA ", "XAH ").replace("XTA-", "XAH-")
    if result.endswith("XTA"):
        result = result[:-3] + "XAH"
    
    return result

def clean_name_for_mrz(name: str) -> str:
    """
    Clean name for MRZ compatibility using ICAO transliteration standards.
    - Transliterates special Latin characters to ASCII equivalents
    - Removes apostrophes and quotes
    - Converts to uppercase for MRZ format
    """
    if not name:
        return name
    
    # Apply transliteration for special characters
    cleaned = name
    for char, replacement in LATIN_TRANSLITERATION.items():
        cleaned = cleaned.replace(char, replacement)
    
    # Also remove various types of apostrophes and quotes not in the main transliteration
    # Including: ' ' ` ´ ʼ ʻ ʽ ʾ ʿ ˈ ˊ ˋ " " "
    cleaned = cleaned.replace("'", "").replace("'", "").replace("`", "").replace("´", "")
    cleaned = cleaned.replace("ʼ", "").replace("ʻ", "").replace("ʽ", "")
    cleaned = cleaned.replace("ʾ", "").replace("ʿ", "").replace("ˈ", "").replace("ˊ", "").replace("ˋ", "")
    cleaned = cleaned.replace('"', "").replace('"', "").replace('"', "")
    
    # Remove any double spaces that might result
    cleaned = " ".join(cleaned.split())
    
    # Convert to uppercase for MRZ format
    cleaned = cleaned.upper()
    
    return cleaned

def extract_person_data(entity: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract person data from an FTM entity.
    Returns a list of person dictionaries, one for each Latin name variant.
    
    Args:
        entity: FTM entity dictionary
        
    Returns:
        List of dictionaries with person data (empty list if not a person)
    """
    # Check if this is a Person entity
    schema = entity.get('schema')
    if schema != 'Person':
        return []
    
    properties = entity.get('properties', {})
    
    # Extract all names from various fields
    names = properties.get('name', [])
    
    # Also construct names from firstName, middleName, secondName | lastName if available
    first_names = properties.get('firstName', [])
    middle_names = properties.get('middleName', [])
    second_names = properties.get('secondName', [])
    last_names = properties.get('lastName', [])
    
    # Generate combinations from name parts
    if first_names or second_names or last_names:
        for first in first_names or ['']:
            for middle in middle_names or ['']:
                for second in second_names or ['']:
                    for last in last_names or ['']:
                        parts = [p for p in [first, middle, second, last] if p]
                        if parts:
                            full_name = ' '.join(parts)
                            if full_name not in names:
                                names.append(full_name)
    
    if not names:
        return []
    
    # First pass: find existing Latin names and clean them
    latin_names = []
    non_latin_names = []
    
    for name in names:
        if is_latin(name):
            # Clean the Latin name for MRZ compatibility
            cleaned_name = clean_name_for_mrz(name)
            latin_names.append(cleaned_name)
        else:
            non_latin_names.append(name)
    
    # If no Latin names found, transliterate non-Latin names
    if not latin_names and non_latin_names:
        entities_without_latin_names.append({
            'id': entity.get('id'),
            'primary_name': names[0],
            'all_names': names
        })
        
        # Transliterate non-Latin names to create Latin versions
        for name in non_latin_names:
            transliterated = None
            
            if is_cyrillic(name):
                transliterated = transliterate_cyrillic(name)
            elif is_arabic(name):
                transliterated = transliterate_arabic(name)
            else:
                # For other scripts, just clean and uppercase
                transliterated = name
            
            if transliterated:
                # Clean the transliterated name
                cleaned = clean_name_for_mrz(transliterated)
                if cleaned and cleaned not in latin_names:
                    latin_names.append(cleaned)
    
    # If still no names, use the first name as fallback
    if not latin_names and names:
        latin_names = [clean_name_for_mrz(names[0])]
    
    # Extract aliases (could be in 'alias' or 'weakAlias' properties)
    aliases = []
    if 'alias' in properties:
        aliases.extend(properties['alias'])
    if 'weakAlias' in properties:
        aliases.extend(properties['weakAlias'])
    # Remove duplicates and any names that are in the main names list
    aliases = list(set(aliases) - set(names))
    
    # Extract birth date
    birth_dates = properties.get('birthDate', [])
    birth_date = birth_dates[0] if birth_dates else None
    
    # Extract passport numbers
    passports = properties.get('passportNumber', [])
    
    # Extract topics/status (what the person "is")
    topics = properties.get('topics', [])
    
    # Build status list based on topics and other indicators
    status_list = []
    if 'sanction' in topics:
        status_list.append('sanctioned')
    if 'debarment' in topics:
        status_list.append('debarred')
    if 'wanted' in topics:
        status_list.append('wanted')
    if 'crime' in topics:
        status_list.append('crime-related')
    if 'pep' in topics:
        status_list.append('pep')
    if 'poi' in topics:
        status_list.append('person-of-interest')
    
    # Check datasets for additional status indicators
    datasets = entity.get('datasets', [])
    if any('interpol' in ds.lower() for ds in datasets):
        if 'interpol-wanted' not in status_list and 'wanted' not in status_list:
            status_list.append('interpol-notice')
    if any('pep' in ds.lower() for ds in datasets):
        if 'pep' not in status_list:
            status_list.append('pep')
    if any('disqualified' in ds.lower() for ds in datasets):
        status_list.append('disqualified')
    
    # Extract countries (from country, nationality, birthPlace)
    countries = set()
    
    # Add countries from 'country' property
    if 'country' in properties:
        countries.update(c.upper() for c in properties['country'])
    
    # Add countries from 'nationality' property
    if 'nationality' in properties:
        countries.update(c.upper() for c in properties['nationality'])
    
    # Add countries from birthPlace (extract country codes if present)
    if 'birthPlace' in properties:
        # birthPlace might contain country codes or full place names
        for place in properties['birthPlace']:
            # Check if it's a country code (2-3 letters)
            if isinstance(place, str) and len(place) in [2, 3] and place.isalpha():
                countries.add(place.upper())
    
    # Add countries from address if present
    if 'address' in properties:
        for addr in properties['address']:
            # Look for country codes at the end of addresses
            if isinstance(addr, str):
                parts = addr.split(',')
                if parts:
                    last_part = parts[-1].strip()
                    if len(last_part) in [2, 3] and last_part.isalpha():
                        countries.add(last_part.upper())
    
    countries = list(countries)
    
    # Process individual name fields with transliteration
    processed_first_names = []
    processed_middle_names = []
    processed_second_names = []
    processed_last_names = []

    # Helper function to process name field
    def process_name_field(names_list: List[str]) -> List[str]:
        """Process a list of name variants, applying Latin checks and transliteration."""
        if not names_list:
            return []
        
        processed = []
        for name in names_list:
            if is_latin(name):
                processed.append(clean_name_for_mrz(name))
            else:
                # Only transliterate if no Latin version exists in the list
                has_latin = any(is_latin(n) for n in names_list)
                if not has_latin:
                    transliterated = None
                    if is_cyrillic(name):
                        transliterated = transliterate_cyrillic(name)
                    elif is_arabic(name):
                        transliterated = transliterate_arabic(name)
                    else:
                        transliterated = name
                    
                    if transliterated:
                        processed.append(clean_name_for_mrz(transliterated))
        
        return list(set(processed))  # Remove duplicates
    
    # Process each name field
    processed_first_names = process_name_field(first_names)
    processed_middle_names = process_name_field(middle_names)
    processed_second_names = process_name_field(second_names)
    processed_last_names = process_name_field(last_names)
    
    # Extract nationality
    nationalities = [c.upper() for c in properties.get('nationality', [])]
    
    # Create an entry for each Latin name
    person_entries = []
    
    for name in latin_names:
        person_entry = {
            'id': entity.get('id'),
            'name': name,
            'is_latin_name': is_latin(name),
            'first_name': processed_first_names,
            'middle_name': processed_middle_names,
            'second_name': processed_second_names,
            'last_name': processed_last_names,
            #'all_names': names,
            'aliases': aliases,
            'birth_date': birth_date,
            'passports': passports,
            'nationality': nationalities,
            'has_passport': len(passports) > 0,
            'status': status_list,
            'countries': countries,
            'datasets': datasets
        }
        person_entries.append(person_entry)
    
    return person_entries


def parse_opensanctions_file(file_path: str) -> List[Dict[str, Any]]:
    """
    Parse the OpenSanctions FTM JSON file and extract person data.
    
    Args:
        file_path: Path to entities.ftm.json file
        
    Returns:
        List of person dictionaries
    """
    global entities_without_latin_names
    entities_without_latin_names = []  # Reset the counter
    persons = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            # The file might be in different formats:
            # 1. Array of entities
            # 2. Newline-delimited JSON (each line is an entity)
            # 3. Single object with entities
            
            content = f.read().strip()
            
            # Try to parse as regular JSON array first
            try:
                data = json.loads(content)
                if isinstance(data, list):
                    entities = data
                elif isinstance(data, dict):
                    # Might be wrapped in an object
                    entities = data.get('entities', [data])
                else:
                    entities = []
            except json.JSONDecodeError:
                # Try newline-delimited JSON
                entities = []
                for line in content.split('\n'):
                    if line.strip():
                        try:
                            entity = json.loads(line)
                            entities.append(entity)
                        except json.JSONDecodeError:
                            continue
            
            # Process each entity
            for entity in entities:
                person_entries = extract_person_data(entity)
                for person_data in person_entries:
                    #print(person_data)
                    persons.append(person_data)
                    
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)
    
    return persons


def save_to_csv(persons: List[Dict[str, Any]], output_file: str = 'persons_with_passports.csv'):
    """
    Save person data to CSV file.
    
    Args:
        persons: List of person dictionaries
        output_file: Output CSV file path
    """
    if not persons:
        print("No persons found in the dataset.")
        return
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['id', 'name', 'is_latin_name', 'first_name', 'middle_name', 'second_name', 'last_name', 
                      'aliases', 'birth_date', 'passports', 'nationality', 'has_passport', 
                      'status', 'countries', 'datasets']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        
        writer.writeheader()
        for person in persons:
            # Convert lists to semicolon-separated strings for CSV
            row = person.copy()
            # Remove all_names field from CSV output
            #row.pop('all_names', None)
            row['first_name'] = '; '.join(row.get('first_name', [])) if row.get('first_name') else ''
            row['middle_name'] = '; '.join(row.get('middle_name', [])) if row.get('middle_name') else ''
            row['second_name'] = '; '.join(row.get('second_name', [])) if row.get('second_name') else ''
            row['last_name'] = '; '.join(row.get('last_name', [])) if row.get('last_name') else ''
            row['aliases'] = '; '.join(row['aliases']) if row['aliases'] else ''
            row['passports'] = '; '.join(row['passports']) if row['passports'] else ''
            row['nationality'] = '; '.join(row.get('nationality', [])) if row.get('nationality') else ''
            row['status'] = '; '.join(row.get('status', [])) if row.get('status') else ''
            row['countries'] = '; '.join(row.get('countries', [])) if row.get('countries') else ''
            row['datasets'] = '; '.join(row.get('datasets', [])) if row.get('datasets') else ''
            writer.writerow(row)
    
    print(f"Data saved to {output_file}")


def save_to_json(persons: List[Dict[str, Any]], output_file: str = 'persons_with_passports.json'):
    """
    Save person data to JSON file.
    
    Args:
        persons: List of person dictionaries
        output_file: Output JSON file path
    """
    if not persons:
        print("No persons found in the dataset.")
        return
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(persons, f, indent=2, ensure_ascii=False)
    
    print(f"Data saved to {output_file}")
    
    # Also save non-Latin names report if any exist
    global entities_without_latin_names
    if entities_without_latin_names:
        report_file = output_file.replace('.json', '_non_latin_names.json')
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(entities_without_latin_names, f, indent=2, ensure_ascii=False)
        print(f"Non-Latin names report saved to {report_file}")


def print_statistics(persons: List[Dict[str, Any]]):
    """
    Print statistics about the extracted data.
    
    Args:
        persons: List of person dictionaries
    """
    global entities_without_latin_names
    
    total_persons = len(persons)
    persons_with_passports = sum(1 for p in persons if p['has_passport'])
    persons_with_aliases = sum(1 for p in persons if p['aliases'])
    persons_with_birth_date = sum(1 for p in persons if p['birth_date'])
    persons_with_countries = sum(1 for p in persons if p.get('countries'))
    persons_with_latin_names = sum(1 for p in persons if p.get('is_latin_name', False))
    persons_with_last_name = sum(1 for p in persons if p.get('last_name'))
    persons_without_last_name = total_persons - persons_with_last_name
    persons_with_second_name = sum(1 for p in persons if p.get('second_name'))
    persons_without_second_name = total_persons - persons_with_second_name
    persons_without_latin_names = total_persons - persons_with_latin_names
    
    # Count persons by status
    status_counts = {}
    for person in persons:
        for status in person.get('status', []):
            status_counts[status] = status_counts.get(status, 0) + 1
    
    # Count unique entities
    unique_entities = len(set(p['id'] for p in persons))
    
    print("\n" + "="*50)
    print("STATISTICS")
    print("="*50)
    print(f"Total entries: {total_persons:,}")
    print(f"Unique entities: {unique_entities:,}")
    print(f"Entries with Latin names: {persons_with_latin_names:,} ({persons_with_latin_names/total_persons*100:.1f}%)")
    print(f"Entries WITHOUT Latin names: {persons_without_latin_names:,} ({persons_without_latin_names/total_persons*100:.1f}%)")
    print(f"Entities without any Latin names: {len(entities_without_latin_names):,}")
    print(f"Persons with passports: {persons_with_passports:,} ({persons_with_passports/total_persons*100:.1f}%)")
    print(f"Persons with aliases: {persons_with_aliases:,} ({persons_with_aliases/total_persons*100:.1f}%)")
    print(f"Persons with birth date: {persons_with_birth_date:,} ({persons_with_birth_date/total_persons*100:.1f}%)")
    print(f"Persons with countries: {persons_with_countries:,} ({persons_with_countries/total_persons*100:.1f}%)")
    print(f"Persons with last name: {persons_with_last_name:,} ({persons_with_last_name/total_persons*100:.1f}%)")
    print(f"Persons without last name: {persons_without_last_name:,} ({persons_without_last_name/total_persons*100:.1f}%)")
    print(f"Persons with second name: {persons_with_second_name:,} ({persons_with_second_name/total_persons*100:.1f}%)")
    print(f"Persons without second name: {persons_without_second_name:,} ({persons_without_second_name/total_persons*100:.1f}%)")
    
    # Show status breakdown
    if status_counts:
        print("\nStatus breakdown:")
        for status, count in sorted(status_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {status}: {count:,} ({count/total_persons*100:.1f}%)")
    
    # Show examples of entities without Latin names
    if entities_without_latin_names:
        print("\n" + "="*50)
        print(f"ENTITIES WITHOUT LATIN NAMES (first 10 of {len(entities_without_latin_names)})")
        print("="*50)
        for i, entity in enumerate(entities_without_latin_names[:10], 1):
            print(f"\n{i}. ID: {entity['id']}")
            print(f"   Selected name: {entity['name']}")
            #print(f"   All variants: {' | '.join(entity['all_names'][:3])}")
            #if len(entity['all_names']) > 3:
            #    print(f"   ... and {len(entity['all_names']) - 3} more variants")
    
    # Show some examples
    if persons_with_passports > 0:
        print("\n" + "="*50)
        print("SAMPLE PERSONS WITH PASSPORTS (first 5)")
        print("="*50)
        
        sample_persons = [p for p in persons if p['has_passport']][:5]
        for i, person in enumerate(sample_persons, 1):
            print(f"\n{i}. {person['name']}")
            if person['aliases']:
                print(f"   Aliases: {', '.join(person['aliases'][:3])}")
            if person['birth_date']:
                print(f"   Birth Date: {person['birth_date']}")
            print(f"   Passports: {', '.join(person['passports'])}")
            if person.get('status'):
                print(f"   Status: {', '.join(person['status'])}")
            if person.get('countries'):
                print(f"   Countries: {', '.join(person['countries'])}")
            if person.get('datasets'):
                print(f"   Datasets: {', '.join(person['datasets'][:3])}")


def main():
    """Main function to run the parser."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Parse OpenSanctions FTM JSON file to extract persons with passport information.'
    )
    parser.add_argument(
        'input_file',
        nargs='?',
        default='entities.ftm.json',
        help='Path to entities.ftm.json file (default: entities.ftm.json)'
    )
    parser.add_argument(
        '--output-format',
        choices=['csv', 'json', 'both'],
        default='both',
        help='Output format (default: both)'
    )
    parser.add_argument(
        '--output-dir',
        default='output',
        help='Output directory (default: output)'
    )
    parser.add_argument(
        '--output-prefix',
        default='persons_with_passports',
        help='Output file prefix (default: persons_with_passports)'
    )
    parser.add_argument(
        '--filter-passports',
        action='store_true',
        help='Only include persons who have passports'
    )
    
    args = parser.parse_args()
    
    print(f"Parsing file: {args.input_file}")
    print("This may take a moment for large files...")
    
    # Parse the file
    persons = parse_opensanctions_file(args.input_file)
    
    # Filter if requested
    if args.filter_passports:
        persons = [p for p in persons if p['has_passport']]
        print(f"Filtered to persons with passports only")
    
    # Print statistics
    print_statistics(persons)

    os.makedirs(args.output_dir, exist_ok=True)
    
    # Save to files
    if args.output_format in ['csv', 'both']:
        save_to_csv(persons, f"{args.output_dir}/{args.output_prefix}.csv")
    
    if args.output_format in ['json', 'both']:
        save_to_json(persons, f"{args.output_dir}/{args.output_prefix}.json")
    
    print("\nDone!")


if __name__ == "__main__":
    main()