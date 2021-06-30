use std::iter::Iterator;

const BIN_TO_ASCII: [u8; 64] = [
    65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 
    85, 86, 87, 88, 89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 
    109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 48, 49, 50,
    51, 52, 53, 54, 55, 56, 57, 43, 47
];

pub fn data_to_radix64(buffer: &[u8]) -> Vec<u8>{
    let mut encoded: Vec<u8> = Vec::with_capacity((buffer.len()+2)/3 * 4 + 1);
    
    let rem = buffer.len() % 3;
    let len = buffer.len() - rem;
    for i in (0..len).step_by(3) {
        encoded.push(BIN_TO_ASCII[((buffer[i] >> 2) & 0o77) as usize]);
        encoded.push(BIN_TO_ASCII[((((buffer[i] << 4) & 0o60) |
                     ((buffer[i+1] >> 4)&0o17))&0o77) as usize]);
        encoded.push(BIN_TO_ASCII[((((buffer[i+1] << 2) & 0o74) |
                    ((buffer[i+2] >> 6)& 0o3)) & 0o77) as usize]);
        encoded.push(BIN_TO_ASCII[(buffer[i+2] & 0o77) as usize]);
    }

    if rem == 2 {
        encoded.push(BIN_TO_ASCII[((buffer[len] >> 2) & 0o77) as usize]);
        encoded.push(BIN_TO_ASCII[((((buffer[len] << 4) & 0o60)|
                     ((buffer[len+1] >> 4) & 0o17)) & 0o77) as usize]);
        encoded.push(BIN_TO_ASCII[(((buffer[len+1] << 2) & 0o74)) as usize]);
    }

    if rem == 1 {
        encoded.push(BIN_TO_ASCII[((buffer[len] >> 2) & 0o77) as usize]);
        encoded.push(BIN_TO_ASCII[((buffer[len] << 4) & 0o60) as usize]);
    }
    encoded
}
