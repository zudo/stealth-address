pub mod recv;
pub mod scalar;
pub mod send;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::RistrettoPoint;
use curve25519_dalek::Scalar;
use rand_core::CryptoRngCore;
pub const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
pub struct PblcKeypair {
    view: RistrettoPoint,
    spnd: RistrettoPoint,
}
pub struct ViewKeypair {
    view: Scalar,
    spnd: RistrettoPoint,
}
pub struct SpndKeypair {
    view: Scalar,
    spnd: Scalar,
}
impl SpndKeypair {
    pub fn new(rng: &mut impl CryptoRngCore) -> SpndKeypair {
        let view = scalar::random(rng);
        let spnd = scalar::random(rng);
        SpndKeypair { view, spnd }
    }
    pub fn address(&self) -> PblcKeypair {
        PblcKeypair {
            view: self.view * G,
            spnd: self.spnd * G,
        }
    }
    pub fn view(&self) -> ViewKeypair {
        ViewKeypair {
            view: self.view,
            spnd: self.spnd * G,
        }
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
        let spnd_keypair = SpndKeypair::new(rng);
        let pblc_keypair = spnd_keypair.address();
        let view_keypair = spnd_keypair.view();
        let (r, R) = send::r(rng);
        let send_ephemeral_public = send::ephemeral_public::<Sha256>(pblc_keypair, r);
        let recv_ephemeral_public = recv::ephemeral_public::<Sha256>(view_keypair, R);
        assert_eq!(send_ephemeral_public, recv_ephemeral_public);
        let ephemeral_secret = recv::ephemeral_secret::<Sha256>(spnd_keypair, R);
        assert_eq!(ephemeral_secret * G, recv_ephemeral_public);
    }
}
