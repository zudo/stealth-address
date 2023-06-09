use crate::scalar;
use crate::StealthAddress;
use crate::G;
use curve25519_dalek::RistrettoPoint;
use curve25519_dalek::Scalar;
use digest::typenum::U32;
use digest::Digest;
use rand_core::CryptoRngCore;
pub fn ephemeral_public<Hash: Digest<OutputSize = U32>>(
    address: StealthAddress,
    r: Scalar,
) -> RistrettoPoint {
    let c = scalar::point::<Hash>(r * address.s);
    c * G + address.b
}
pub fn r(rng: &mut impl CryptoRngCore) -> (Scalar, RistrettoPoint) {
    let r = scalar::random(rng);
    (r, r * G)
}
