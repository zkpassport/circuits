struct Date {
    day: u8,
    month: u8,
    year: u16,
}

fn get_number_from_utf8_code(code: u8) -> u8 {
    assert(code >= 48 & code <= 57);
    code - 48
}

fn number_to_utf8_code(number: u8) -> u8 {
    assert(number >= 0 & number <= 9);
    number + 48
}

impl Date {
    pub fn new(year: u16, month: u8, day: u8) -> Self {
        Self {
            day: day,
            month: month,
            year: year,
        }
    }

    pub fn from_bytes_short_year(date: [u8; 6], threshold_year: [u8; 2]) -> Self {
        let firstYearDigit = get_number_from_utf8_code(date[0]);
        let secondYearDigit = get_number_from_utf8_code(date[1]);

        let mut year: u16 = firstYearDigit as u16 * 10 + secondYearDigit as u16;

        let firstMonthDigit = get_number_from_utf8_code(date[2]);
        let secondMonthDigit = get_number_from_utf8_code(date[3]);

        let month = firstMonthDigit * 10 + secondMonthDigit;

        let firstDayDigit = get_number_from_utf8_code(date[4]);
        let secondDayDigit = get_number_from_utf8_code(date[5]);

        let day = firstDayDigit * 10 + secondDayDigit;

        let currentYearFirstDigit = get_number_from_utf8_code(threshold_year[0]);
        let currentYearSecondDigit = get_number_from_utf8_code(threshold_year[1]);

        let mut currentYear: u16 = currentYearFirstDigit as u16 * 10 + currentYearSecondDigit as u16;

        // This way we have a smooth 100 years period according to a threshold year
        // Taking the current year as threshold year (for birthdates for example)
        // if the current year is 2023, then 24 will be interpreted as 1924
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

    pub fn from_str_short_year(date: str<6>, threshold_year: str<2>) -> Self {
        let date_bytes = date.as_bytes();
        Date::from_bytes_short_year(date_bytes, threshold_year.as_bytes())
    }
    
    pub fn from_str_long_year(date: str<8>) -> Self {
        let date_bytes = date.as_bytes();
        Date::from_bytes_long_year(date_bytes)
    }

    fn get_duration_in_days(self: Self, other: Self, absolute: bool) -> i32 {
        let totalDuration: i32 = (self.year as i32 - other.year as i32) * 365
        + (self.month as i32 - other.month as i32) * 30
        + (self.day as i32 - other.day as i32);

        if totalDuration < 0 & absolute {
            -1 * totalDuration
        }

        totalDuration
    }

    fn gt(self: Self, other: Self) -> bool {
        self.get_duration_in_days(other, false) > 0
    }

    fn lt(self: Self, other: Self) -> bool {
        self.get_duration_in_days(other, false) < 0
    }

    fn eq(self: Self, other: Self) -> bool {
        self.get_duration_in_days(other, false) == 0
    }

    fn ne(self: Self, other: Self) -> bool {
        self.get_duration_in_days(other, false) != 0
    }

    fn gte(self: Self, other: Self) -> bool {
        self.get_duration_in_days(other, false) >= 0
    }

    fn lte(self: Self, other: Self) -> bool {
        self.get_duration_in_days(other, false) <= 0
    }

    fn println(self: Self) {
        println(self);
    }

    fn to_bytes(self: Self) -> [u8; 8] {
        let mut date: [u8; 8] = [0; 8];

        let firstYearDigit = self.year / 1000;
        let secondYearDigit = (self.year - firstYearDigit * 1000) / 100;
        let thirdYearDigit = (self.year - firstYearDigit * 1000 - secondYearDigit * 100) / 10;
        let fourthYearDigit = self.year - firstYearDigit * 1000 - secondYearDigit * 100 - thirdYearDigit * 10;

        date[0] = number_to_utf8_code(firstYearDigit as u8);
        date[1] = number_to_utf8_code(secondYearDigit as u8);
        date[2] = number_to_utf8_code(thirdYearDigit as u8);
        date[3] = number_to_utf8_code(fourthYearDigit as u8);

        let firstMonthDigit = self.month / 10;
        let secondMonthDigit = self.month - firstMonthDigit * 10;

        date[4] = number_to_utf8_code(firstMonthDigit as u8);
        date[5] = number_to_utf8_code(secondMonthDigit as u8);

        let firstDayDigit = self.day / 10;
        let secondDayDigit = self.day - firstDayDigit * 10;

        date[6] = number_to_utf8_code(firstDayDigit as u8);
        date[7] = number_to_utf8_code(secondDayDigit as u8);

        date
    }
}
