from datetime import datetime, timedelta, timezone

START_DATE = datetime(1970, 1, 1, tzinfo=timezone.utc)
END_DATE = datetime(2025, 7, 17, tzinfo=timezone.utc)

def format_date_str(dt: datetime) -> str:
    return dt.strftime("%Y%m%d")

def main():
    current_date = START_DATE

    print("// Auto-generated test for timestamp_to_date_string")
    print("// Covers 1970-01-01 to 2025-07-17 inclusive")
    print()
    print("#[test]")
    print("fn test_timestamp_to_date_many_dates() {")

    while current_date <= END_DATE:
        timestamp = int(current_date.timestamp())  # Always UTC
        expected = format_date_str(current_date)
        print(f'    assert(timestamp_to_date_string({timestamp}) == "{expected}");')
        current_date += timedelta(days=1)

    print("}")

if __name__ == "__main__":
    main()
