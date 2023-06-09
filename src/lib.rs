pub mod recv;
pub mod scalar;
pub mod send;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::RistrettoPoint;
use curve25519_dalek::Scalar;
use rand_core::CryptoRngCore;
pub const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
pub struct StealthAddress {
    s: RistrettoPoint,
    b: RistrettoPoint,
}
pub struct ViewKey {
    s: Scalar,
    b: RistrettoPoint,
}
pub struct SpendKey {
    s: Scalar,
    b: Scalar,
}
impl StealthAddress {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(self.s.compress().as_bytes());
        bytes[32..].copy_from_slice(self.b.compress().as_bytes());
        bytes
    }
    pub fn from_slice(bytes: &[u8; 64]) -> Option<StealthAddress> {
        let s = CompressedRistretto::from_slice(&bytes[..32])
            .unwrap()
            .decompress()?;
        let b = CompressedRistretto::from_slice(&bytes[32..])
            .unwrap()
            .decompress()?;
        Some(StealthAddress { s, b })
    }
}
impl SpendKey {
    pub fn new(rng: &mut impl CryptoRngCore) -> SpendKey {
        let s = scalar::random(rng);
        let b = scalar::random(rng);
        SpendKey { s, b }
    }
    pub fn stealth_address(&self) -> StealthAddress {
        StealthAddress {
            s: self.s * G,
            b: self.b * G,
        }
    }
    pub fn view_key(&self) -> ViewKey {
        ViewKey {
            s: self.s,
            b: self.b * G,
        }
    }
}
#[cfg(test)]
mod test {
    use super::*;
    use rand_core::OsRng;
    use sha2::Sha256;
    #[test]
    fn test() {
        let rng = &mut OsRng;
        let spend_key = SpendKey::new(rng);
        let stealth_address = spend_key.stealth_address();
        let view_key = spend_key.view_key();
        let (r_secret, r_public) = send::r(rng);
        let send_ephemeral_public = send::ephemeral_public::<Sha256>(stealth_address, r_secret);
        let recv_ephemeral_public = recv::ephemeral_public::<Sha256>(view_key, r_public);
        assert_eq!(send_ephemeral_public, recv_ephemeral_public);
        let ephemeral_secret = recv::ephemeral_secret::<Sha256>(spend_key, r_public);
        assert_eq!(ephemeral_secret * G, recv_ephemeral_public);
    }
}
