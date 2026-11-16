use crate::{
    AADHAAR_DELIMITER_COUNT, AADHAAR_MAX_DATA_LENGTH, calculate_aadhaar_private_nullifier,
    commit_to_disclosure_aadhaar, mrz_check_digit, parse_aadhaar_data,
};
use utils::{
    get_dob_from_mrz, get_document_number_from_mrz, get_expiry_date_from_mrz,
    get_issuing_country_from_mrz, get_name_from_mrz, get_nationality_from_mrz, is_id_card,
};

struct QrBuilder {
    data: [u8; AADHAAR_MAX_DATA_LENGTH],
    length: u32,
}

impl QrBuilder {
    fn new() -> Self {
        QrBuilder { data: [0; AADHAAR_MAX_DATA_LENGTH], length: 0 }
    }

    fn bytes<let N: u32>(mut self, bytes: [u8; N]) -> Self {
        for i in 0..N {
            self.data[self.length + i] = bytes[i];
        }
        self.length += N;
        self
    }

    fn field<let N: u32>(self, value: str<N>) -> Self {
        self.bytes(value.as_bytes()).bytes([255])
    }

    fn delimiters(self, count: u32) -> [u32; AADHAAR_DELIMITER_COUNT] {
        let mut indices: [u32; AADHAAR_DELIMITER_COUNT] = [0; AADHAAR_DELIMITER_COUNT];
        let mut found = 0;
        for i in 0..AADHAAR_MAX_DATA_LENGTH {
            if (found < count) & (self.data[i] == 255) {
                indices[found] = i;
                found += 1;
            }
        }
        indices
    }
}

global PHOTO: [u8; 6] = [0xFF, 0x4F, 0xFF, 0x51, 0x00, 0x2F];

fn address(builder: QrBuilder) -> QrBuilder {
    builder
        .field("S/O Ram Kumar")
        .field("Bengaluru")
        .field("Near Temple")
        .field("12")
        .field("Indiranagar")
        .field("560038")
        .field("Indiranagar")
        .field("Karnataka")
        .field("100 Feet Road")
        .field("Bengaluru East")
        .field("Bengaluru")
}

fn sample_v2() -> QrBuilder {
    let builder = QrBuilder::new()
        .field("V2")
        .field("2")
        .field("123420260315123045678")
        .field("Rahul Kumar Sharma")
        .field("15-08-1990")
        .field("M");
    address(builder).field("5678").bytes(PHOTO)
}

fn assert_bytes_eq<let N: u32, let M: u32>(actual: [u8; N], expected: str<M>) {
    let expected = expected.as_bytes();
    for i in 0..N {
        assert_eq(actual[i], if i < M { expected[i] } else { 60 });
    }
}

#[test]
fn test_check_digit() {
    // ICAO 9303 specimen: L898902C3 -> 6, 740812 -> 2, 120415 -> 9
    assert_eq(mrz_check_digit("L898902C3".as_bytes()), 54);
    assert_eq(mrz_check_digit("740812".as_bytes()), 50);
    assert_eq(mrz_check_digit("120415".as_bytes()), 57);
}

#[test]
fn test_parse_v2() {
    let qr = sample_v2();
    let aadhaar = parse_aadhaar_data(qr.data, qr.length, qr.delimiters(18));
    let dg1 = aadhaar.dg1;

    assert(!is_id_card(dg1));
    assert_eq(dg1[5], 73);
    assert_eq(dg1[6], 68);
    assert_bytes_eq(get_issuing_country_from_mrz(dg1), "IND");
    assert_bytes_eq(get_nationality_from_mrz(dg1), "XXX");
    assert_bytes_eq(get_name_from_mrz(dg1), "RAHUL<KUMAR<SHARMA");
    assert_bytes_eq(get_document_number_from_mrz(dg1), "XXXXX1234");
    assert_bytes_eq(get_dob_from_mrz(dg1), "900815");
    assert_bytes_eq(get_expiry_date_from_mrz(dg1), "360315");
    assert_eq(dg1[5 + 64], 77);
    assert_eq(aadhaar.photo_hash, sha256::sha256_var(PHOTO, 6));
    // 2026-03-15T00:00:00Z
    assert_eq(aadhaar.signed_on, 1773532800);
}

#[test]
fn test_parse_v1_with_trailing_hashes() {
    let builder = QrBuilder::new()
        .field("3")
        .field("987620191231235959999")
        .field("Priya")
        .field("01-01-2000")
        .field("F");
    let qr = address(builder).bytes(PHOTO).bytes([7; 64]);
    let aadhaar = parse_aadhaar_data(qr.data, qr.length, qr.delimiters(16));
    let dg1 = aadhaar.dg1;

    assert_bytes_eq(get_name_from_mrz(dg1), "PRIYA");
    assert_bytes_eq(get_document_number_from_mrz(dg1), "XXXXX9876");
    assert_bytes_eq(get_dob_from_mrz(dg1), "000101");
    assert_bytes_eq(get_expiry_date_from_mrz(dg1), "291231");
    // 2019-12-31T00:00:00Z
    assert_eq(aadhaar.signed_on, 1577750400);
    assert_eq(dg1[5 + 64], 70);
    assert_eq(aadhaar.photo_hash, sha256::sha256_var(PHOTO, 6));
}

#[test]
fn test_name_punctuation() {
    let builder = QrBuilder::new()
        .field("V2")
        .field("0")
        .field("123420260315123045678")
        .field(" S. R. O'Neil-Kumar")
        .field("15-08-1990")
        .field("T");
    let qr = address(builder).field("5678").bytes(PHOTO);
    let dg1 = parse_aadhaar_data(qr.data, qr.length, qr.delimiters(18)).dg1;
    assert_bytes_eq(get_name_from_mrz(dg1), "S<R<ONEIL<KUMAR");
    assert_eq(dg1[5 + 64], 60);
}

#[test(should_fail_with = "Delimiter index mismatch")]
fn test_skipped_delimiter() {
    let qr = sample_v2();
    let mut delimiters = qr.delimiters(18);
    // Claim the name starts one field later, where the date of birth is
    delimiters[3] = delimiters[4];
    let _ = parse_aadhaar_data(qr.data, qr.length, delimiters);
}

#[test(should_fail_with = "Unsupported Aadhaar QR version")]
fn test_unknown_version() {
    let qr = QrBuilder::new().field("V9").field("0");
    let _ = parse_aadhaar_data(qr.data, qr.length, qr.delimiters(18));
}

#[test]
fn test_nullifier_independent_of_signing_time() {
    let first = sample_v2();
    let builder = QrBuilder::new()
        .field("V2")
        .field("2")
        .field("123420251101090000000")
        .field("Rahul Kumar Sharma")
        .field("15-08-1990")
        .field("M");
    let second = address(builder).field("5678").bytes(PHOTO);
    let a = parse_aadhaar_data(first.data, first.length, first.delimiters(18));
    let b = parse_aadhaar_data(second.data, second.length, second.delimiters(18));
    assert_eq(
        calculate_aadhaar_private_nullifier(a.photo_hash),
        calculate_aadhaar_private_nullifier(b.photo_hash),
    );
    let (comm_a, _) = commit_to_disclosure_aadhaar(a, 1, 2, 3, 4);
    let (comm_b, _) = commit_to_disclosure_aadhaar(b, 1, 2, 3, 4);
    assert(comm_a != comm_b);
}
