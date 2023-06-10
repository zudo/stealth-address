use crate::SpendKey;
use crate::StealthAddress;
use crate::ViewKey;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::Scalar;
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
impl ViewKey {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(self.s.as_bytes());
        bytes[32..].copy_from_slice(self.b.compress().as_bytes());
        bytes
    }
    pub fn from_slice(bytes: &[u8; 64]) -> Option<ViewKey> {
        let s: Option<_> = Scalar::from_canonical_bytes(bytes[..32].try_into().unwrap()).into();
        let s = s?;
        let b = CompressedRistretto::from_slice(&bytes[32..])
            .unwrap()
            .decompress()?;
        Some(ViewKey { s, b })
    }
}
impl SpendKey {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(self.s.as_bytes());
        bytes[32..].copy_from_slice(self.b.as_bytes());
        bytes
    }
    pub fn from_slice(bytes: &[u8; 64]) -> Option<SpendKey> {
        let s: Option<_> = Scalar::from_canonical_bytes(bytes[..32].try_into().unwrap()).into();
        let s = s?;
        let b: Option<_> = Scalar::from_canonical_bytes(bytes[32..].try_into().unwrap()).into();
        let b = b?;
        Some(SpendKey { s, b })
    }
}
