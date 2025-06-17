pub fn get_array_slice<let N: u32, let M: u32>(arr: [u8; N], start: u32, end: u32) -> [u8; M] {
    let mut slice = [0 as u8; M];
    for i in start..end {
        slice[i - start] = arr[i];
    }
    slice
}

pub fn get_array_slice_constant<let N: u32, let M: u32>(arr: [u8; N]) -> [u8; M] {
    let mut slice = [0 as u8; M];
    for i in 0..M {
        slice[i] = arr[i];
    }
    slice
}

// Reverse the bytes of an array so you can switch from
// big endian to little endian order and vice versa
pub fn reverse_bytes_array<let N: u32>(arr: [u8; N]) -> [u8; N] {
    let mut reversed_arr = [0 as u8; N];
    for i in 0..N {
        // Reverse
        reversed_arr[i] = arr[N - 1 - i];
    }
    reversed_arr
}

pub fn insert_into_array<let N: u32, let M: u32>(
    mut arr: [u8; N],
    sub_arr: [u8; M],
    index: u32,
) -> [u8; N] {
    for i in index..index + M {
        arr[i] = sub_arr[i - index];
    }
    arr
}

pub fn dynamic_insert_into_array<let N: u32, let M: u32>(
    mut arr: [u8; N],
    sub_arr: [u8; M],
    index: u32,
    max_size: u32,
) -> [u8; N] {
    for i in index..index + max_size {
        if i - index < M {
            arr[i] = sub_arr[i - index];
        }
    }
    arr
}

pub fn split_array<let N: u32>(array: [u8; N * 2]) -> ([u8; N], [u8; N]) {
    let mut array_x = [0 as u8; N];
    let mut array_y = [0 as u8; N];
    for i in 0..N {
        array_x[i] = array[i];
        array_y[i] = array[i + N];
    }
    (array_x, array_y)
}

pub fn concat_array<let N: u32>(array_x: [u8; N], array_y: [u8; N]) -> [u8; N * 2] {
    let mut array = [0 as u8; N * 2];
    for i in 0..N {
        array[i] = array_x[i];
        array[i + N] = array_y[i];
    }
    array
}

pub fn check_zero_padding<let N: u32, T>(padded_array: [T; N], len: u32)
where
    T: Eq,
    T: Default,
{
    for i in 0..N {
        if i >= len {
            assert_eq(padded_array[i], T::default());
        }
    }
}
