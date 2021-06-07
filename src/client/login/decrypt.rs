use crate::utils::Bytes;

pub fn decrypt(packet: &Bytes) -> Bytes {
    let mut output = vec![];
    for &byte in packet {
        let value = byte.wrapping_sub(0xF);
        output.push(value & 0xFF);
    }
    output
}

#[cfg(test)]
mod test {
    use crate::client::login::decrypt::decrypt;

    #[test]
    fn test_decrypt() {
        assert_eq!(decrypt(&b"\x75\x70\x78\x7B\x72\x2F\x44\x19".to_vec()), b"failc 5\n".to_vec());
    }
}