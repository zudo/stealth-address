use crate::Public;
use crate::Secret;
use crate::SpendKey;
use crate::StealthAddress;
use crate::ViewKey;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::Scalar;
impl StealthAddress {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(self.s.0.compress().as_bytes());
        bytes[32..].copy_from_slice(self.b.0.compress().as_bytes());
        bytes
    }
    pub fn from_slice(bytes: &[u8; 64]) -> Option<StealthAddress> {
        let s = Public(
            CompressedRistretto::from_slice(&bytes[..32])
                .unwrap()
                .decompress()?,
        );
        let b = Public(
            CompressedRistretto::from_slice(&bytes[32..])
                .unwrap()
                .decompress()?,
        );
        Some(StealthAddress { s, b })
    }
}
impl ViewKey {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(self.s.0.as_bytes());
        bytes[32..].copy_from_slice(self.b.0.compress().as_bytes());
        bytes
    }
    pub fn from_slice(bytes: &[u8; 64]) -> Option<ViewKey> {
        let s: Option<_> = Scalar::from_canonical_bytes(bytes[..32].try_into().unwrap()).into();
        let s = Secret(s?);
        let b = Public(
            CompressedRistretto::from_slice(&bytes[32..])
                .unwrap()
                .decompress()?,
        );
        Some(ViewKey { s, b })
    }
}
impl SpendKey {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(self.s.0.as_bytes());
        bytes[32..].copy_from_slice(self.b.0.as_bytes());
        bytes
    }
    pub fn from_slice(bytes: &[u8; 64]) -> Option<SpendKey> {
        let s: Option<_> = Scalar::from_canonical_bytes(bytes[..32].try_into().unwrap()).into();
        let s = Secret(s?);
        let b: Option<_> = Scalar::from_canonical_bytes(bytes[32..].try_into().unwrap()).into();
        let b = Secret(b?);
        Some(SpendKey { s, b })
    }
}
