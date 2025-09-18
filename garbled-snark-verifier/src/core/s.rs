use core::{iter::zip, ops::Add};
use std::ops::BitXor;

use serde::{Deserialize, Serialize};

use crate::circuits::bn254::utils::random_seed;
use crate::core::utils::{LABEL_SIZE, hash};

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct S(pub [u8; LABEL_SIZE]);

impl S {
    pub const fn one() -> Self {
        let mut s = [0_u8; LABEL_SIZE];
        s[LABEL_SIZE - 1] = 1;
        Self(s)
    }

    pub fn random() -> Self {
        Self(random_seed::<LABEL_SIZE>())
    }

    pub fn neg(&self) -> Self {
        let mut s = self.0;
        for (i, si) in s.iter_mut().enumerate() {
            *si = 255 - self.0[i];
        }
        Self(s) + Self::one()
    }

    pub fn hash(&self) -> Self {
        Self(hash(&self.0))
    }

    pub fn hash_ext(&self, gid: u32) -> Self {
        let mut input = [0u8; LABEL_SIZE + 4];
        input[..LABEL_SIZE].copy_from_slice(&self.0);
        input[LABEL_SIZE..].copy_from_slice(&gid.to_le_bytes());
        Self(hash(&input))
    }

    pub fn hash_together(a: Self, b: Self) -> Self {
        let mut h = a.0.to_vec();
        h.extend(b.0.to_vec());
        Self(hash(&h))
    }

    pub fn xor(mut a: Self, b: Self) -> Self {
        for i in 0..LABEL_SIZE {
            a.0[i] ^= b.0[i];
        }
        a
    }
}

impl Add for S {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut s = [0_u8; LABEL_SIZE];
        let mut carry = 0;
        for (i, (u, v)) in zip(self.0, rhs.0).enumerate().rev() {
            let x = (u as u32) + (v as u32) + carry;
            s[i] = (x % 256) as u8;
            carry = x / 256;
        }
        Self(s)
    }
}

impl BitXor for S {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self::Output {
        let mut a = self;
        for i in 0..LABEL_SIZE {
            a.0[i] ^= rhs.0[i];
        }
        a
    }
}
