pub mod point;
pub mod scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::RistrettoPoint;
use curve25519_dalek::Scalar;
use digest::typenum::U32;
use digest::Digest;
use rand_core::CryptoRngCore;
pub const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R(RistrettoPoint);
impl R {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }
    pub fn from_slice(bytes: &[u8; 32]) -> Option<R> {
        Some(R(point::from_slice(bytes)?))
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Public(RistrettoPoint);
impl Public {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }
    pub fn from_slice(bytes: &[u8; 32]) -> Option<Public> {
        Some(Public(point::from_slice(bytes)?))
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Secret(Scalar);
impl Secret {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
    pub fn from_canonical(bytes: [u8; 32]) -> Option<Secret> {
        Some(Secret(scalar::from_canonical(bytes)?))
    }
    pub fn public(&self) -> Public {
        Public(self.0 * G)
    }
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
        let s = point::from_slice(&bytes[..32].try_into().unwrap())?;
        let b = point::from_slice(&bytes[32..].try_into().unwrap())?;
        Some(StealthAddress { s, b })
    }
    pub fn generate_ephemeral<Hash: Digest<OutputSize = U32>>(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> (R, Public) {
        let r = scalar::random(rng);
        let c = scalar::point::<Hash>(r * self.s);
        let public = Public(c * G + self.b);
        let r = R(r * G);
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
        let s = scalar::from_canonical(bytes[..32].try_into().unwrap())?;
        let b = point::from_slice(&bytes[32..].try_into().unwrap())?;
        Some(ViewKey { s, b })
    }
    pub fn derive_ephemeral_public<Hash: Digest<OutputSize = U32>>(&self, r: R) -> Public {
        let c = scalar::point::<Hash>(self.s * r.0);
        Public(c * G + self.b)
    }
    pub fn check<Hash: Digest<OutputSize = U32>>(&self, r: R, public: Public) -> bool {
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
        let s = scalar::from_canonical(bytes[..32].try_into().unwrap())?;
        let b = scalar::from_canonical(bytes[32..].try_into().unwrap())?;
        Some(SpendKey { s, b })
    }
    pub fn new(rng: &mut impl CryptoRngCore) -> SpendKey {
        let s = scalar::random(rng);
        let b = scalar::random(rng);
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
    pub fn derive_ephemeral_secret<Hash: Digest<OutputSize = U32>>(&self, r: R) -> Secret {
        let c = scalar::point::<Hash>(self.s * r.0);
        Secret(c + self.b)
    }
}
#[cfg(test)]
mod test {
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
        let public_2 = secret.public();
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
        let r_bytes = r.to_bytes();
        let public_bytes = public.to_bytes();
        let secret_bytes = secret.to_bytes();
        assert_eq!(spend_key, SpendKey::from_slice(&spend_key_bytes).unwrap());
        assert_eq!(
            stealth_address,
            StealthAddress::from_slice(&stealth_address_bytes).unwrap()
        );
        assert_eq!(view_key, ViewKey::from_slice(&view_key_bytes).unwrap());
        assert_eq!(r, R::from_slice(&r_bytes).unwrap());
        assert_eq!(public, Public::from_slice(&public_bytes).unwrap());
        assert_eq!(secret, Secret::from_canonical(secret_bytes).unwrap());
    }
}
