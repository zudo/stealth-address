use rand_core::OsRng;
use sha2::Sha256;
use stealth_address::SpendKey;
fn main() {
    let rng = &mut OsRng;
    let spend_key = SpendKey::new(rng);
    let view_key = spend_key.view_key();
    let stealth_address = spend_key.stealth_address();
    println!("spnd: {}", hex::encode(&spend_key.to_bytes()));
    println!("view: {}", hex::encode(&view_key.to_bytes()));
    println!("addr: {}", hex::encode(&stealth_address.to_bytes()));
    let (r, public) = stealth_address.generate_ephemeral::<Sha256>(rng);
    println!("r: {}", hex::encode(&r.to_bytes()));
    println!("ephemeral public: {}", hex::encode(&public.to_bytes()));
    let secret = spend_key.derive_ephemeral_secret::<Sha256>(r);
    println!("ephemeral secret: {}", hex::encode(&secret.to_bytes()));
    println!("check: {}", view_key.check::<Sha256>(r, public));
}
