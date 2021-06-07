use nostale_crypto_rs::server::login::encrypt;

fn main() {
    println!("Packet: {:?}", encrypt(&b"login pls".to_vec()));
}
