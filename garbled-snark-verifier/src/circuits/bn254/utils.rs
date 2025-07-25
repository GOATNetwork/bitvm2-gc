use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{One, Zero};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

fn extended_gcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    let (mut x, mut y) = (BigInt::one(), BigInt::zero());
    let (mut x1, mut y1) = (BigInt::zero(), BigInt::one());
    let (mut a1, mut b1) = (a.clone(), b.clone());

    while !b1.is_zero() {
        let q = &a1 / &b1;

        (x, x1) = (x1.clone(), &x - q.clone() * x1);
        (y, y1) = (y1.clone(), &y - q.clone() * y1);
        (a1, b1) = (b1.clone(), &a1 - q.clone() * b1);
    }

    (a1, x, y)
}

pub fn calculate_montgomery_constants(modulus: BigUint, r: BigUint) -> (BigUint, BigUint) {
    let modulus_signed = modulus.to_bigint().unwrap();
    let r_signed = r.to_bigint().unwrap();

    let (gcd, r_inv_signed, n_inv_signed) = extended_gcd(&r_signed, &modulus_signed);
    assert_eq!(gcd, BigInt::one(), "r and modulus must be coprime");

    let r_inv = ((r_inv_signed % modulus_signed.clone() + modulus_signed.clone())
        % modulus_signed.clone())
    .to_biguint()
    .unwrap();

    let n_prime = ((n_inv_signed % r_signed.clone() + r_signed.clone()) % r_signed.clone())
        .to_biguint()
        .unwrap();

    (r_inv, n_prime)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::circuits::bn254::{fp254impl::Fp254Impl, fq::Fq, fr::Fr};

    fn test_montgomery_constants<T: Fp254Impl>() {
        let modulus = T::modulus_as_biguint();
        let r = T::montgomery_r_as_biguint();
        let (r_inv, n_p) = calculate_montgomery_constants(modulus.clone(), r.clone());

        assert_eq!((r.clone() * r_inv.clone()) % modulus.clone(), BigUint::one());
        assert_eq!((n_p.clone() * modulus.clone()) % r.clone(), BigUint::one());

        println!("modulus inverse: {}\nr_inverse: {}", n_p, r_inv);

        assert_eq!(T::montgomery_m_inverse_as_biguint(), n_p);
        assert_eq!(T::montgomery_r_inverse_as_biguint(), r_inv);
    }

    #[test]
    fn test_montgomery_constants_fq() {
        test_montgomery_constants::<Fq>();
    }

    #[test]
    fn test_montgomery_constants_fr() {
        test_montgomery_constants::<Fr>();
    }
}

pub fn random_seed<const D: usize>() -> [u8; D] {
    let mut seed = [0u8; D];

    #[cfg(feature = "_getrandom")]
    {
        getrandom::getrandom(&mut seed).expect("_getrandom: getrandom failed");
    }

    #[cfg(not(feature = "_getrandom"))]
    {
        use rand::RngCore;
        let mut rng = rand::rngs::OsRng;
        rng.fill_bytes(&mut seed);
    }
    seed
}

pub fn create_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed(random_seed::<32>())
}
