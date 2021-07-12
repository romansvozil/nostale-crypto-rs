use nostale_crypto::server::login::encrypt;

fn main() {
    println!("Packet: {:?}", encrypt(&b"login pls".to_vec()));
}
