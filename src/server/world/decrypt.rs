use crate::utils::{Bytes, unpack, SERVER_DECRYPTION_TABLE};

pub fn decrypt(packet: &Bytes, session: u32, is_first_packet: bool) -> Bytes {
    let mut output: Bytes = vec![];

    let stype = match is_first_packet {
        true => -1,
        false => ((session >> 6) & 3) as i32,
    };

    let key = (session & 0xFF) as u8;

    for byte in packet {
        output.push(match stype {
            0 => byte.wrapping_sub(key).wrapping_sub(0x40) & 0xFF,
            1 => byte.wrapping_add(key).wrapping_add(0x40) & 0xFF,
            2 => (byte.wrapping_sub(key).wrapping_sub(0x40) ^ 0xC3) & 0xFF,
            3 => (byte.wrapping_add(key).wrapping_add(0x40) ^ 0xC3) & 0xFF,
            _ => byte.wrapping_sub(0xF) & 0xFF,
        })
    }
    unpack(&output, &SERVER_DECRYPTION_TABLE.to_vec()) // TODO: seems like coping?
}

#[cfg(test)]
mod test {
    use crate::server::world::decrypt;

    #[test]
    fn test_decrypt_1() {
        assert_eq!(decrypt(&b"\xFA\xCF\x0B\x05\x78\xFC\x12\x07\x08\xFF\x8A\xB5\xDE\x89\x89\xC4\x73".to_vec(), 53836, false),
                   b"17535 walk 20 26 1 11".to_vec());
    }
}