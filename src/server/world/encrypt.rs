use crate::utils::{Bytes, pack, SERVER_ENCRYPTION_TABLE};

pub fn encrypt(packet: &Bytes) -> Bytes {
    pack(packet, &SERVER_ENCRYPTION_TABLE.to_vec())
}

#[cfg(test)]
mod test {
    use crate::server::world::encrypt::encrypt;

    #[test]
    fn test_encrypt() {
        assert_eq!(encrypt(&"stat 221 221 60 60 0 1024\n".as_bytes().to_vec()), b"\x04\x8C\x8B\x9E\x8B\x96\x16\x65\x16\x65\x1A\x41\xA4\x14\x15\x46\x8E\xFF".to_vec());
    }
}