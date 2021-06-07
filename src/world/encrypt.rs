use crate::utils::{Bytes, pack, CLIENT_ENCRYPTION_TABLE};
use std::num::Wrapping;

pub fn encrypt(packet: &Bytes, session: u32, is_first_packet: bool) -> Bytes {
    let packed = pack(packet, &CLIENT_ENCRYPTION_TABLE.to_vec());
    let mut output = vec![];

    let stype = match is_first_packet {
        true => -1,
        false => ((session >> 6) & 3) as i32,
    };

    let key = (session & 0xFF) as u8;

    for byte in packed {
        output.push(match stype {
            0 => (Wrapping(byte) + Wrapping(key) + Wrapping(0x40)).0 & 0xFF,
            1 => (Wrapping(byte) - Wrapping(key) - Wrapping(0x40)).0 & 0xFF,
            2 => ((Wrapping(byte) ^ Wrapping(0xC3)) + Wrapping(key) + Wrapping(0x40)).0 & 0xFF,
            3 => ((Wrapping(byte) ^ Wrapping(0xC3)) - Wrapping(key) - Wrapping(0x40)).0 & 0xFF,
            _ => (Wrapping(byte) + Wrapping(0xF)).0 & 0xFF,
        })
    }
    output
}

#[cfg(test)]
mod test {
    use crate::world::encrypt::encrypt;
    use encoding::{Encoding, EncoderTrap};
    use encoding::all::WINDOWS_1250;

    #[test]
    fn test_encrypt_1() {
        assert_eq!(encrypt(&b"17535 walk 20 26 1 11".to_vec(), 53836, false),
                   b"\xFA\xCF\x0B\x05\x78\xFC\x12\x07\x08\xFF\x8A\xB5\xDE\x89\x89\xC4\x73".to_vec());
    }

    #[test]
    fn test_encrypt_2() {
        assert_eq!(encrypt(&b"48967 c_blist  0 0 0 0 0 0 0 0 17 185 302 882 942 999 1591 1592 4083 5065 5068 5069 5070 5206 5307 5361 5982 5991".to_vec(), 10685, false),
                   b"\x42\x4C\x16\x6F\xC1\x5C\x60\x5B\x4D\x52\x4C\x45\x24\xCF\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x95\xD3\x07\xD1\x82\xDC\x02\xDB\x42\xDB\x1B\xD3\x5B\x8F\x97\x12\xD8\x8C\xAF\x54\x67\xD7\x86\xFF\x54\x6B\xD7\x85\x7F\x52\x86\xD7\xB4\x6F\x51\x63\xD7\x1C\x9F\x5B\x13\x39".to_vec());
    }

    #[test]
    fn test_encrypt_special_characters() {
        assert_eq!(encrypt(&WINDOWS_1250.encode("14326 say dfskjda12312ąśąźżźżććżąąąśąąą2137dadaęóąśłżźćń;1122", EncoderTrap::Strict).unwrap(), 34353, false),
                   b"\xF7\xC9\xE7\x12\x74\xFD\x0F\xF7\xF2\x81\x78\x0C\x0A\xFD\x05\x06\x0C\x0F\xF6\xC7\xE6\xD1\x82\xB7\xD4\xB7\xD1\xB1\xD1\xB1\x8A\x8A\xB1\xB7\xB7\xB7\xD4\xB7\xB7\xB7\xF5\xD6\xEC\x7F\x0C\x0F\x0C\x0F\x86\x7D\xB7\xD4\xBD\xB1\xD1\x8A\x7F\x35\xF5\xC6\xD7\x70".to_vec());
    }
}