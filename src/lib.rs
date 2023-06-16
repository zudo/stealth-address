use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
pub use curve25519_dalek::RistrettoPoint;
pub use curve25519_dalek::Scalar;
use digest::typenum::U32;
use digest::Digest;
use rand_core::CryptoRngCore;
pub const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
pub fn point_from_slice(bytes: &[u8; 32]) -> Option<RistrettoPoint> {
    CompressedRistretto::from_slice(bytes).unwrap().decompress()
}
pub fn scalar_random(rng: &mut impl CryptoRngCore) -> Scalar {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order(bytes)
}
pub fn scalar_point<Hash: Digest<OutputSize = U32>>(p: RistrettoPoint) -> Scalar {
    let bytes = Hash::new()
        .chain_update(p.compress().as_bytes())
        .finalize()
        .into();
    Scalar::from_bytes_mod_order(bytes)
}
pub fn scalar_from_canonical(bytes: [u8; 32]) -> Option<Scalar> {
    Scalar::from_canonical_bytes(bytes).into()
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StealthAddress {
    s: RistrettoPoint,
    b: RistrettoPoint,
}
impl StealthAddress {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(self.s.compress().as_bytes());
        bytes[32..].copy_from_slice(self.b.compress().as_bytes());
        bytes
    }
    pub fn from_slice(bytes: &[u8; 64]) -> Option<StealthAddress> {
        let s = point_from_slice(&bytes[..32].try_into().unwrap())?;
        let b = point_from_slice(&bytes[32..].try_into().unwrap())?;
        Some(StealthAddress { s, b })
    }
    pub fn generate_ephemeral<Hash: Digest<OutputSize = U32>>(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> (RistrettoPoint, RistrettoPoint) {
        let r = scalar_random(rng);
        let c = scalar_point::<Hash>(r * self.s);
        let public = c * G + self.b;
        let r = r * G;
        (r, public)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ViewKey {
    s: Scalar,
    b: RistrettoPoint,
}
impl ViewKey {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(self.s.as_bytes());
        bytes[32..].copy_from_slice(self.b.compress().as_bytes());
        bytes
    }
    pub fn from_slice(bytes: &[u8; 64]) -> Option<ViewKey> {
        let s = scalar_from_canonical(bytes[..32].try_into().unwrap())?;
        let b = point_from_slice(&bytes[32..].try_into().unwrap())?;
        Some(ViewKey { s, b })
    }
    pub fn derive_ephemeral_public<Hash: Digest<OutputSize = U32>>(
        &self,
        r: RistrettoPoint,
    ) -> RistrettoPoint {
        let c = scalar_point::<Hash>(self.s * r);
        c * G + self.b
    }
    pub fn check<Hash: Digest<OutputSize = U32>>(
        &self,
        r: RistrettoPoint,
        public: RistrettoPoint,
    ) -> bool {
        public == self.derive_ephemeral_public::<Hash>(r)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpendKey {
    s: Scalar,
    b: Scalar,
}
impl SpendKey {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(self.s.as_bytes());
        bytes[32..].copy_from_slice(self.b.as_bytes());
        bytes
    }
    pub fn from_slice(bytes: &[u8; 64]) -> Option<SpendKey> {
        let s = scalar_from_canonical(bytes[..32].try_into().unwrap())?;
        let b = scalar_from_canonical(bytes[32..].try_into().unwrap())?;
        Some(SpendKey { s, b })
    }
    pub fn new(rng: &mut impl CryptoRngCore) -> SpendKey {
        let s = scalar_random(rng);
        let b = scalar_random(rng);
        SpendKey { s, b }
    }
    pub fn view_key(&self) -> ViewKey {
        ViewKey {
            s: self.s,
            b: self.b * G,
        }
    }
    pub fn stealth_address(&self) -> StealthAddress {
        StealthAddress {
            s: self.s * G,
            b: self.b * G,
        }
    }
    pub fn derive_ephemeral_secret<Hash: Digest<OutputSize = U32>>(
        &self,
        r: RistrettoPoint,
    ) -> Scalar {
        let c = scalar_point::<Hash>(self.s * r);
        c + self.b
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use sha2::Sha256;
    #[test]
    fn derive() {
        let rng = &mut OsRng;
        let spend_key = SpendKey::new(rng);
        let stealth_address = spend_key.stealth_address();
        let view_key = spend_key.view_key();
        let (r, public_0) = stealth_address.generate_ephemeral::<Sha256>(rng);
        assert!(view_key.check::<Sha256>(r, public_0));
        let secret = spend_key.derive_ephemeral_secret::<Sha256>(r);
        let public_1 = view_key.derive_ephemeral_public::<Sha256>(r);
        let public_2 = secret * G;
        assert_eq!(public_0, public_1);
        assert_eq!(public_1, public_2);
    }
    #[test]
    fn to_bytes_from_slice() {
        let rng = &mut OsRng;
        let spend_key = SpendKey::new(rng);
        let stealth_address = spend_key.stealth_address();
        let view_key = spend_key.view_key();
        let (r, public) = stealth_address.generate_ephemeral::<Sha256>(rng);
        let secret = spend_key.derive_ephemeral_secret::<Sha256>(r);
        let spend_key_bytes = spend_key.to_bytes();
        let stealth_address_bytes = stealth_address.to_bytes();
        let view_key_bytes = view_key.to_bytes();
        let r_bytes = r.compress().to_bytes();
        let public_bytes = public.compress().to_bytes();
        let secret_bytes = secret.to_bytes();
        assert_eq!(spend_key, SpendKey::from_slice(&spend_key_bytes).unwrap());
        assert_eq!(
            stealth_address,
            StealthAddress::from_slice(&stealth_address_bytes).unwrap()
        );
        assert_eq!(view_key, ViewKey::from_slice(&view_key_bytes).unwrap());
        assert_eq!(r, point_from_slice(&r_bytes).unwrap());
        assert_eq!(public, point_from_slice(&public_bytes).unwrap());
        assert_eq!(secret, scalar_from_canonical(secret_bytes).unwrap());
    }
}
