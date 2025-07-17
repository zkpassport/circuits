from datetime import datetime, timedelta, timezone

START_YEAR = 1970
END_YEAR = 2025

def format_date_str(dt: datetime) -> str:
    return dt.strftime("%Y%m%d")

def generate_test_for_year(year: int):
    start = datetime(year, 1, 1, tzinfo=timezone.utc)
    end = datetime(year + 1, 1, 1, tzinfo=timezone.utc)

    print(f"#[test]")
    print(f"fn test_timestamp_to_date_for_{year}() {{")

    current = start
    while current < end and current.year == year:
        timestamp = int(current.timestamp())
        expected = format_date_str(current)
        print(f'    assert(timestamp_to_date_string({timestamp}) == "{expected}");')
        current += timedelta(days=1)

    print("}\n")

def main():
    print("// Auto-generated test functions for timestamp_to_date_string")
    print("// One function per year from 1970 to 2025 (inclusive)")

    for year in range(START_YEAR, END_YEAR + 1):
        generate_test_for_year(year)

if __name__ == "__main__":
    main()
