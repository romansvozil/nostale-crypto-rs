use crate::utils::Bytes;

pub fn encrypt(packet: &Bytes) -> Bytes {
    let mut packet = packet.clone();  // TODO: do not clone whole packet for adding one extra character..
    let mut output = vec![];

    if packet[packet.len() - 1] != 0xA {
        packet.push('\n' as u8);
    }
    for byte in packet {
        let value = byte.wrapping_add(0xF);
        output.push(value & 0xFF);
    }
    output
}

#[cfg(test)]
mod test {
    use crate::server::login::encrypt::encrypt;

    #[test]
    fn test_encrypt_new_line_ending() {
        assert_eq!(encrypt(&b"Test".to_vec()), encrypt(&b"Test\n".to_vec()));
    }

    #[test]
    fn test_encrypt() {
        assert_eq!(encrypt(&"failc 5\n".as_bytes().to_vec()),
                   b"\x75\x70\x78\x7B\x72\x2F\x44\x19".to_vec()
        )
    }
}