use std::cmp::min;

pub type Bytes = Vec<u8>;
pub type Mask = Vec<bool>;

pub const CLIENT_ENCRYPTION_TABLE: &[u8] = &[0x00, 0x20, 0x2D, 0x2E, 0x30, 0x31, 0x32, 0x33,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0xFF, 0x00];
pub const CLIENT_DECRYPTION_TABLE: &[u8] = &[0x00, 0x20, 0x2D, 0x2E, 0x30, 0x31, 0x32, 0x33,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x0A, 0x00];

pub const SERVER_ENCRYPTION_TABLE: &[u8] = &[0x00, 0x20, 0x2D, 0x2E, 0x30, 0x31, 0x32, 0x33,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x0A, 0x00];
pub const SERVER_DECRYPTION_TABLE: &[u8] = &[0x00, 0x20, 0x2D, 0x2E, 0x30, 0x31, 0x32, 0x33,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0xFF, 0x00];

pub fn get_mask_part(byte: u8, charset: &Bytes) -> bool {
    match byte {
        0 => false,
        _ => charset.contains(&byte)
    }
}

pub fn get_mask(packet: &Bytes, charset: &Bytes) -> Mask {
    let mut output = vec![];
    for &byte in packet {
        match byte {
            0 => break,
            _ => output.push(get_mask_part(byte, charset)),
        }
    }
    output
}

pub fn get_length_of_mask(start: usize, mask: &Mask, value: bool) -> usize {
    let mut current_length: usize = 0;
    for index in start..mask.len() {
        if mask[index] == value {
            current_length += 1;
        } else {
            break;
        }
    }
    current_length
}

pub fn pack(packet: &Bytes, characters_to_pack: &Bytes) -> Bytes {
    let mut output: Bytes = vec![];
    let mask = get_mask(packet, characters_to_pack);
    let mut pos = 0;
    while mask.len() > pos {
        let current_chunk_len = get_length_of_mask(pos, &mask, false);

        for index in 0..current_chunk_len {
            if pos > mask.len() {
                break;
            }
            if index % 0x7E == 0 {
                output.push(min((current_chunk_len - index) as u8, 0x7E));
            }
            output.push(packet[pos] ^ 0xFF);
            pos += 1;
        }

        let current_chunk_len = get_length_of_mask(pos, &mask, true);
        for index in 0..current_chunk_len {
            if pos > mask.len() {
                break;
            }
            if index % 0x7E == 0 {
                output.push(min((current_chunk_len - index) as u8, 0x7E) | 0x80);
            }
            let current_value = characters_to_pack.iter()
                .position(|&r| r == packet[pos]).unwrap() as u8;
            if index % 2 == 0 {
                output.push(current_value << 4);
            } else {
                let output_length = output.len();
                output[output_length - 1] |= current_value;
            }
            pos += 1;
        }
    }
    output.push(0xFF);
    output
}

pub fn unpack(packet: &Bytes, characters_to_unpack: &Bytes) -> Bytes {
    let mut output = vec![];
    let mut pos = 0;
    while packet.len() > pos {
        if packet[pos] == 0xFF {
            break;
        }
        let current_chunk_length = packet[pos] & 0x7F;
        let is_packed = (packet[pos] & 0x80) != 0;
        pos += 1;

        if is_packed {
            for _ in 0..(current_chunk_length + 1) / 2 {
                if pos >= packet.len() {
                    break;
                }
                let two_characters = packet[pos];
                pos += 1;
                let left_character = two_characters >> 4;
                output.push(characters_to_unpack[left_character as usize]);

                let right_character = two_characters & 0xF;
                if right_character == 0 {
                    break;
                }
                output.push(characters_to_unpack[right_character as usize]);
            }
        } else {
            for _ in 0..current_chunk_length {
                if pos >= packet.len() {
                    break;
                }
                output.push(packet[pos] ^ 0xFF);
                pos += 1;
            }
        }
    }
    output
}

#[cfg(test)]
mod test {
    use crate::utils::{pack, CLIENT_ENCRYPTION_TABLE, unpack, CLIENT_DECRYPTION_TABLE};

    #[test]
    fn test_pack_1() {
        assert_eq!(pack(&"17535 walk 20 26 1 11".as_bytes().to_vec(), &CLIENT_ENCRYPTION_TABLE.to_vec()),
                   b"\x86\x5B\x97\x91\x04\x88\x9E\x93\x94\x8B\x16\x41\x6A\x15\x15\x50\xFF".to_vec());
    }

    #[test]
    fn test_pack_2() {
        assert_eq!(pack(&"48967 c_blist  0 0 0 0 0 0 0 0 17 185 302 882 942 999 1591 1592 4083 5065 5068 5069 5070 5206 5307 5361 5982 5991".as_bytes().to_vec(),
                        &CLIENT_ENCRYPTION_TABLE.to_vec()),
                   b"\x86\x8C\xDA\xB1\x07\x9C\xA0\x9D\x93\x96\x8C\x8B\xE4\x11\x41\x41\x41\x41\x41\x41\x41\x41\x5B\x15\xC9\x17\x46\x1C\xC6\x1D\x86\x1D\xDD\x15\x9D\x51\x59\xD6\x18\x4C\x71\x94\xA9\x19\x4A\xC1\x94\xAD\x19\x4B\x41\x96\x4A\x19\x74\xB1\x97\xA5\x19\xDC\x61\x9D\xD5\xFF".to_vec());
    }

    #[test]
    fn test_unpack() {
        assert_eq!(unpack(&pack(&"2137 say ąźć123pd".as_bytes().to_vec(), &CLIENT_ENCRYPTION_TABLE.to_vec()), &CLIENT_DECRYPTION_TABLE.to_vec()), "2137 say ąźć123pd".as_bytes().to_vec())
    }
}