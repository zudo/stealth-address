use crate::scalar;
use crate::SpndKeypair;
use crate::ViewKeypair;
use crate::G;
use curve25519_dalek::RistrettoPoint;
use curve25519_dalek::Scalar;
use digest::typenum::U32;
use digest::Digest;
pub fn ephemeral_public<Hash: Digest<OutputSize = U32>>(
    keypair: ViewKeypair,
    r: RistrettoPoint,
) -> RistrettoPoint {
    let c = scalar::point::<Hash>(keypair.view * r);
    c * G + keypair.spnd
}
pub fn ephemeral_secret<Hash: Digest<OutputSize = U32>>(
    keypair: SpndKeypair,
    r: RistrettoPoint,
) -> Scalar {
    let c = scalar::point::<Hash>(keypair.view * r);
    c + keypair.spnd
}
