use crate::{
    bag::*,
    circuits::bn254::{fp254impl::Fp254Impl, utils::create_rng},
};
use ark_ff::UniformRand;
use num_bigint::BigUint;

pub struct Fr;

impl Fp254Impl for Fr {
    const MODULUS: &'static str =
        "21888242871839275222246405745257275088548364400416034343698204186575808495617";
    const MONTGOMERY_M_INVERSE: &'static str =
        "5441563794177615591428663161977496376097281981129373443346157590346630955009";
    const MONTGOMERY_R_INVERSE: &'static str =
        "17773755579518009376303681366703133516854333631346829854655645366227550102839";
    const N_BITS: usize = 254;

    fn half_modulus() -> BigUint {
        BigUint::from(ark_bn254::Fr::from(1) / ark_bn254::Fr::from(2))
    }

    fn one_third_modulus() -> BigUint {
        BigUint::from(ark_bn254::Fr::from(1) / ark_bn254::Fr::from(3))
    }
    fn two_third_modulus() -> BigUint {
        BigUint::from(ark_bn254::Fr::from(2) / ark_bn254::Fr::from(3))
    }
}

impl Fr {
    pub fn as_montgomery(a: ark_bn254::Fr) -> ark_bn254::Fr {
        a * ark_bn254::Fr::from(Self::montgomery_r_as_biguint())
    }

    pub fn from_montgomery(a: ark_bn254::Fr) -> ark_bn254::Fr {
        a / ark_bn254::Fr::from(Self::montgomery_r_as_biguint())
    }

    pub fn random() -> ark_bn254::Fr {
        let mut prng = create_rng();
        ark_bn254::Fr::rand(&mut prng)
    }

    pub fn to_bits(u: ark_bn254::Fr) -> Vec<bool> {
        let mut bytes = BigUint::from(u).to_bytes_le();
        bytes.extend(vec![0_u8; 32 - bytes.len()]);
        let mut bits = Vec::new();
        for byte in bytes {
            for i in 0..8 {
                bits.push(((byte >> i) & 1) == 1)
            }
        }
        bits.pop();
        bits.pop();
        bits
    }

    pub fn from_bits(bits: Vec<bool>) -> ark_bn254::Fr {
        let zero = BigUint::ZERO;
        let one = BigUint::from(1_u8);
        let mut u = zero.clone();
        for bit in bits.iter().rev() {
            u = u.clone() + u.clone() + if *bit { one.clone() } else { zero.clone() };
        }
        ark_bn254::Fr::from(u)
    }

    pub fn wires() -> Wires {
        (0..Self::N_BITS).map(|_| new_wirex()).collect()
    }

    pub fn wires_set(u: ark_bn254::Fr) -> Wires {
        Self::to_bits(u)[0..Self::N_BITS]
            .iter()
            .map(|bit| {
                let wire = new_wirex();
                wire.borrow_mut().set(*bit);
                wire
            })
            .collect()
    }

    pub fn wires_set_montgomery(u: ark_bn254::Fr) -> Wires {
        Self::wires_set(Self::as_montgomery(u))
    }

    pub fn from_wires(wires: Wires) -> ark_bn254::Fr {
        Self::from_bits(wires.iter().map(|wire| wire.borrow().get_value()).collect())
    }

    pub fn from_montgomery_wires(wires: Wires) -> ark_bn254::Fr {
        Self::from_montgomery(Self::from_wires(wires))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fr_random() {
        let u = Fr::random();
        println!("u: {:?}", u);
        let b = Fr::to_bits(u);
        let v = Fr::from_bits(b);
        println!("v: {:?}", v);
        assert_eq!(u, v);
    }
}
