pub fn get_array_slice<N, M>(arr: [u8; N], start: u32, end: u32) -> [u8; M] {
    let mut slice = [0 as u8; M];
    for i in start..end {
        slice[i - start] = arr[i];
    }
    slice
}

pub fn get_letter_from_utf8_code(byte: u8) -> str<1> {
    let code_for_A = 65;
    let utf8_code = byte - code_for_A;
    let alphabet: [str<1>; 26] = [
        "A", "B", "C", "D", "E", "F", "G", "H", "I", "J",
        "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T",
        "U", "V", "W", "X", "Y", "Z"
    ];
    alphabet[utf8_code as u8]
}
