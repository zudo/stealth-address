use curve25519_dalek::RistrettoPoint;
use curve25519_dalek::Scalar;
use digest::typenum::U32;
use digest::Digest;
use rand_core::CryptoRngCore;
pub fn random(rng: &mut impl CryptoRngCore) -> Scalar {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order(bytes)
}
pub fn point<Hash: Digest<OutputSize = U32>>(p: RistrettoPoint) -> Scalar {
    let bytes = Hash::new()
        .chain_update(p.compress().as_bytes())
        .finalize()
        .into();
    Scalar::from_bytes_mod_order(bytes)
}
