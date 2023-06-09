use curve25519_dalek::Scalar;
use rand_core::OsRng;
use rand_core::RngCore;
pub fn random() -> Scalar {
    let mut rng = OsRng {};
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order(bytes)
}
