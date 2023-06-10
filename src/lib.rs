pub mod scalar;
pub mod util;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::RistrettoPoint;
use curve25519_dalek::Scalar;
use digest::typenum::U32;
use digest::Digest;
use rand_core::CryptoRngCore;
pub const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R(RistrettoPoint);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Public(RistrettoPoint);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Secret(Scalar);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StealthAddress {
    s: RistrettoPoint,
    b: RistrettoPoint,
}
impl StealthAddress {
    pub fn send<Hash: Digest<OutputSize = U32>>(
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
    pub fn receive<Hash: Digest<OutputSize = U32>>(&self, r: R) -> Public {
        let c = scalar::point::<Hash>(self.s * r.0);
        Public(c * G + self.b)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpendKey {
    s: Scalar,
    b: Scalar,
}
impl SpendKey {
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
    pub fn spend<Hash: Digest<OutputSize = U32>>(&self, r: R) -> Secret {
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
    fn test() {
        let rng = &mut OsRng;
        let spend_key = SpendKey::new(rng);
        let stealth_address = spend_key.stealth_address();
        let view_key = spend_key.view_key();
        let (r, public_0) = stealth_address.send::<Sha256>(rng);
        let public_1 = view_key.receive::<Sha256>(r);
        assert_eq!(public_0, public_1);
        let secret = spend_key.spend::<Sha256>(r);
        let public_2 = Public(secret.0 * G);
        assert_eq!(public_1, public_2);
    }
}
