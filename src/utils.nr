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

// Reverse the bytes of an array so you can switch from
// big endian to little endian order and vice versa
pub fn reverse_bytes_array<N>(arr: [u8; N]) -> [u8; N] {
    let mut reversed_arr = [0 as u8; N];
    for i in 0..N {
        // Reverse
        reversed_arr[i] = arr[N - 1 - i];
    }
    reversed_arr
}

pub fn is_array_empty<N>(arr: [u8; N]) -> bool {
    let mut is_empty = true;
    for i in 0..N {
        if arr[i] != 0 {
            is_empty = false;
        }
    }
    is_empty
}

pub fn insert_into_array<N, M>(mut arr: [u8; N], sub_arr: [u8; M], index: u32) -> [u8; N] {
    for i in index..index + M {
        arr[i] = sub_arr[i - index];
    }
    arr
}

/**
* Rather hacky but in some cases we cannot use a for loop as the compiler 
* won't be able to determine its bounds at compile time
*/
pub fn insert_32_bytes_into_array<N>(mut arr: [u8; N], sub_arr: [u8; 32], index: u32) -> [u8; N] {
    arr[index] = sub_arr[0];
    arr[index + 1] = sub_arr[1];
    arr[index + 2] = sub_arr[2];
    arr[index + 3] = sub_arr[3];
    arr[index + 4] = sub_arr[4];
    arr[index + 5] = sub_arr[5];
    arr[index + 6] = sub_arr[6];
    arr[index + 7] = sub_arr[7];
    arr[index + 8] = sub_arr[8];
    arr[index + 9] = sub_arr[9];
    arr[index + 10] = sub_arr[10];

    arr[index + 11] = sub_arr[11];
    arr[index + 12] = sub_arr[12];
    arr[index + 13] = sub_arr[13];
    arr[index + 14] = sub_arr[14];
    arr[index + 15] = sub_arr[15];
    arr[index + 16] = sub_arr[16];
    arr[index + 17] = sub_arr[17];
    arr[index + 18] = sub_arr[18];
    arr[index + 19] = sub_arr[19];
    arr[index + 20] = sub_arr[20];

    arr[index + 21] = sub_arr[21];
    arr[index + 22] = sub_arr[22];
    arr[index + 23] = sub_arr[23];
    arr[index + 24] = sub_arr[24];
    arr[index + 25] = sub_arr[25];
    arr[index + 26] = sub_arr[26];
    arr[index + 27] = sub_arr[27];
    arr[index + 28] = sub_arr[28];
    arr[index + 29] = sub_arr[29];
    arr[index + 30] = sub_arr[30];

    arr[index + 31] = sub_arr[31];

    arr
}

pub fn insert_7_bytes_into_array<N>(mut arr: [u8; N], sub_arr: [u8; 7], index: u32) -> [u8; N] {
    arr[index] = sub_arr[0];
    arr[index + 1] = sub_arr[1];
    arr[index + 2] = sub_arr[2];
    arr[index + 3] = sub_arr[3];
    arr[index + 4] = sub_arr[4];
    arr[index + 5] = sub_arr[5];
    arr[index + 6] = sub_arr[6];
    arr
}

