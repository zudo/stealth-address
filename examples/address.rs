use rand_core::OsRng;
use stealth_address::SpendKey;
fn main() {
    let rng = &mut OsRng;
    let spend_key = SpendKey::new(rng);
    let view_key = spend_key.view_key();
    let stealth_address = spend_key.stealth_address();
    println!("spnd: {}", hex::encode(&spend_key.to_bytes()));
    println!("view: {}", hex::encode(&view_key.to_bytes()));
    println!("addr: {}", hex::encode(&stealth_address.to_bytes()));
}
