struct Date {
    day: u8,
    month: u8,
    year: u16,
}

fn get_number_from_utf8_code(code: u8) -> u8 {
    assert(code >= 48 & code <= 57);
    code - 48
}

impl Date {
    pub fn new(day: u8, month: u8, year: u16) -> Self {
        Self {
            day: day,
            month: month,
            year: year,
        }
    }

    pub fn from_bytes_short_year(date: [u8; 6], current_year: [u8; 2]) -> Self {
        let firstYearDigit = get_number_from_utf8_code(date[0]);
        let secondYearDigit = get_number_from_utf8_code(date[1]);

        let mut year: u16 = firstYearDigit as u16 * 10 + secondYearDigit as u16;

        let firstMonthDigit = get_number_from_utf8_code(date[2]);
        let secondMonthDigit = get_number_from_utf8_code(date[3]);

        let month = firstMonthDigit * 10 + secondMonthDigit;

        let firstDayDigit = get_number_from_utf8_code(date[4]);
        let secondDayDigit = get_number_from_utf8_code(date[5]);

        let day = firstDayDigit * 10 + secondDayDigit;

        let currentYearFirstDigit = get_number_from_utf8_code(current_year[0]);
        let currentYearSecondDigit = get_number_from_utf8_code(current_year[1]);

        let mut currentYear: u16 = currentYearFirstDigit as u16 * 10 + currentYearSecondDigit as u16;

        // This way we have a smooth 100 years period according to the current year
        // If the current year is 2023, then 24 will be interpreted as 1924
        // while 22 will be interpreted as 2022
        // A bit problematic for people over 100 years old
        if year <= currentYear {
            year += 2000;
        } else {
            year += 1900;
        }

        Self {
            day: day,
            month: month,
            year: year,
        }
    }

    pub fn from_bytes_long_year(date: [u8; 8]) -> Self {
        let firstYearDigit = get_number_from_utf8_code(date[0]);
        let secondYearDigit = get_number_from_utf8_code(date[1]);
        let thirdYearDigit = get_number_from_utf8_code(date[2]);
        let fourthYearDigit = get_number_from_utf8_code(date[3]);

        let year: u16 = firstYearDigit as u16 * 1000 + secondYearDigit as u16 * 100 + thirdYearDigit as u16 * 10 + fourthYearDigit as u16;

        let firstMonthDigit = get_number_from_utf8_code(date[4]);
        let secondMonthDigit = get_number_from_utf8_code(date[5]);

        let month = firstMonthDigit * 10 + secondMonthDigit;

        let firstDayDigit = get_number_from_utf8_code(date[6]);
        let secondDayDigit = get_number_from_utf8_code(date[7]);

        let day = firstDayDigit * 10 + secondDayDigit;

        Self {
            day: day,
            month: month,
            year: year,
        }
    }

    pub fn from_str_short_year(date: str<6>, current_year: str<2>) -> Self {
        let date_bytes = date.as_bytes();
        Date::from_bytes_short_year(date_bytes, current_year.as_bytes())
    }
    
    pub fn from_str_long_year(date: str<8>) -> Self {
        let date_bytes = date.as_bytes();
        Date::from_bytes_long_year(date_bytes)
    }

    fn get_duration_in_days(self: Self, other: Self) -> u16 {
        let totalDuration: i16 = (self.year as i16 - other.year as i16) * 365
        + (self.month as i16 - other.month as i16) * 30
        + (self.day as i16 - other.day as i16);

        if totalDuration < 0 {
            -1 * totalDuration
        }

        totalDuration as u16
    }
}
