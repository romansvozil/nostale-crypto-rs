use crate::utils::{Bytes, unpack, CLIENT_DECRYPTION_TABLE};

pub fn decrypt(packet: &Bytes) -> Bytes {
    unpack(packet, &CLIENT_DECRYPTION_TABLE.to_vec())
}

#[cfg(test)]
mod test {
    use crate::client::world::decrypt::decrypt;

    #[test]
    fn test_decrypt() {
        assert_eq!(decrypt(&b"\x04\x8C\x8B\x9E\x8B\x96\x16\x65\x16\x65\x1A\x41\xA4\x14\x15\x46\x8E\xFF".to_vec()), b"stat 221 221 60 60 0 1024\n".to_vec())
    }
}