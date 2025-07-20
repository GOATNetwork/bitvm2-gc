use core::{iter::zip, ops::Add};

use crate::circuits::bn254::utils::random_seed;
use crate::core::utils::poseidon2_hash;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct S(pub [u8; 32]);

impl S {
    pub const fn one() -> Self {
        let mut s = [0_u8; 32];
        s[31] = 1;
        Self(s)
    }

    pub fn random() -> Self {
        //Self(rng().random::<[u8; 32]>())
        Self(random_seed())
    }

    pub fn neg(&self) -> Self {
        let mut s = self.0;
        for (i, si) in s.iter_mut().enumerate() {
            *si = 255 - self.0[i];
        }
        Self(s) + Self::one()
    }

    pub fn hash(&self) -> Self {
        Self(poseidon2_hash(&self.0))
    }

    pub fn hash_together(a: Self, b: Self) -> Self {
        let mut h = a.0.to_vec();
        h.extend(b.0.to_vec());
        Self(poseidon2_hash(&h))
    }

    pub fn xor(mut a: Self, b: Self) -> Self {
        for i in 0..32 {
            a.0[i] ^= b.0[i];
        }
        a
    }
}

impl Add for S {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut s = [0_u8; 32];
        let mut carry = 0;
        for (i, (u, v)) in zip(self.0, rhs.0).enumerate().rev() {
            let x = (u as u32) + (v as u32) + carry;
            s[i] = (x % 256) as u8;
            carry = x / 256;
        }
        Self(s)
    }
}
