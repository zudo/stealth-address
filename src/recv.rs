use crate::scalar;
use crate::SpendKey;
use crate::ViewKey;
use crate::G;
use curve25519_dalek::RistrettoPoint;
use curve25519_dalek::Scalar;
use digest::typenum::U32;
use digest::Digest;
pub fn ephemeral_public<Hash: Digest<OutputSize = U32>>(
    key: ViewKey,
    r: RistrettoPoint,
) -> RistrettoPoint {
    let c = scalar::point::<Hash>(key.s * r);
    c * G + key.b
}
pub fn ephemeral_secret<Hash: Digest<OutputSize = U32>>(
    key: SpendKey,
    r: RistrettoPoint,
) -> Scalar {
    let c = scalar::point::<Hash>(key.s * r);
    c + key.b
}
