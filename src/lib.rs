pub mod scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::RistrettoPoint;
use curve25519_dalek::Scalar;
use digest::typenum::U32;
use digest::Digest;
use rand_core::CryptoRngCore;
pub const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct ViewSecret(Scalar);
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct ViewPublic(RistrettoPoint);
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct SpendSecret(Scalar);
pub struct SpendPublic(RistrettoPoint);
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct RSecret(Scalar);
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct RPublic(RistrettoPoint);
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct CSecret(Scalar);
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct CPublic(RistrettoPoint);
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct EphemeralSecret(Scalar);
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct EphemeralPublic(RistrettoPoint);
impl ViewSecret {
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        Self(scalar::random(rng))
    }
    pub fn public(&self) -> ViewPublic {
        ViewPublic(self.0 * G)
    }
}
impl SpendSecret {
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        Self(scalar::random(rng))
    }
    pub fn public(&self) -> SpendPublic {
        SpendPublic(self.0 * G)
    }
}
impl RSecret {
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        Self(scalar::random(rng))
    }
    pub fn public(&self) -> RPublic {
        RPublic(self.0 * G)
    }
}
impl CSecret {
    // Sender uses this to generate the shared secret
    pub fn from_sender<Hash: Digest<OutputSize = U32>>(rs: RSecret, vp: ViewPublic) -> Self {
        Self(Self::hash::<Hash>(rs.0 * vp.0))
    }
    // Receiver uses this to generate the shared secret
    pub fn from_receiver<Hash: Digest<OutputSize = U32>>(vs: ViewSecret, rp: RPublic) -> Self {
        Self(Self::hash::<Hash>(vs.0 * rp.0))
    }
    pub fn public(&self) -> CPublic {
        CPublic(self.0 * G)
    }
    fn hash<Hash: Digest<OutputSize = U32>>(p: RistrettoPoint) -> Scalar {
        Scalar::from_bytes_mod_order(
            Hash::new()
                .chain_update(p.compress().as_bytes())
                .finalize()
                .into(),
        )
    }
}
impl EphemeralSecret {
    pub fn from(cs: CSecret, ss: SpendSecret) -> Self {
        Self(cs.0 + ss.0)
    }
    pub fn public(&self) -> EphemeralPublic {
        EphemeralPublic(self.0 * G)
    }
}
impl EphemeralPublic {
    pub fn from(cp: CPublic, sp: SpendPublic) -> Self {
        Self(cp.0 + sp.0)
    }
}
#[cfg(test)]
mod test {
    use super::*;
    use rand_core::OsRng;
    use sha2::Sha256;
    #[allow(non_snake_case)]
    #[test]
    fn test() {
        let rng = &mut OsRng;
        let vs = ViewSecret::generate(rng);
        let ss = SpendSecret::generate(rng);
        let vp = vs.public();
        let sp = ss.public();
        let rs = RSecret::generate(rng);
        let rp = rs.public();
        let cs_0 = CSecret::from_sender::<Sha256>(rs, vp);
        let cs_1 = CSecret::from_receiver::<Sha256>(vs, rp);
        assert_eq!(cs_0, cs_1);
        let cp = cs_0.public();
        let es = EphemeralSecret::from(cs_0, ss);
        let ep_0 = es.public();
        let ep_1 = EphemeralPublic::from(cp, sp);
        assert_eq!(ep_0, ep_1)
    }
}
