use ark_bn254::{Fq, Fr, G1Affine};
use ark_ff::{UniformRand, Zero};
use garbled_snark_verifier::bag::S;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::RngCore;
use crate::dre::{N, utils::sample_rhos};

pub struct InstanceSecrets {
    /// 2 deltas for 2 garbled circuits
    pub delta:         [S; 2],
    pub r:             Fr,
    pub msg:           [u8; 32],
    /// label0 per input wire, for 2 circuits
    /// fgc input size = 2 * N // pi_1
    /// sgc input size = N // x_d
    pub input_0labels: [Vec<S>; 2],
    /// Constant 0labels.
    /// fgc size = 2 (0/1)
    /// sgc size = 2 + 2 * N (for B)
    pub constant_0labels: [Vec<S>; 2],
    pub rhos:          [Vec<G1Affine>; 2],
    pub fq_deltas:     [Vec<Fq>; 2],
    pub b: G1Affine,
}

impl InstanceSecrets {
    pub fn new_from_seed(seed: u64) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);

        let delta = [gen_s(&mut rng, 1)[0], gen_s(&mut rng, 1)[0]];

        let r = Fr::rand(&mut rng);

        let mut msg = [0u8; 32];
        rng.fill_bytes(&mut msg);

        let input_0labels = [gen_s(&mut rng, 2 * N), gen_s(&mut rng, N)];

        let constant_val_labels = [gen_s(&mut rng, 2), gen_s(&mut rng, 2 + 2 * N)];

        let rhos = [sample_rhos(&mut rng), sample_rhos(&mut rng)];

        let fq_deltas = [gen_fq_deltas(&mut rng, N), gen_fq_deltas(&mut rng, N)];

        let b = G1Affine::rand(&mut rng);

        Self {
            delta,
            r,
            msg,
            input_0labels,
            constant_0labels: constant_val_labels,
            rhos,
            fq_deltas,
            b,
        }
    }
}

fn gen_s<R: rand::RngCore>(rng: &mut R, n: usize) -> Vec<S> {
    (0..n)
        .map(|_| {
            let mut b = [0u8; 16];
            rng.fill_bytes(&mut b);
            S(b)
        })
        .collect()
}

fn gen_fq_deltas<R: rand::RngCore>(rng: &mut R, n: usize) -> Vec<Fq> {
    (0..n)
        .map(|_| loop {
            let v = Fq::rand(rng);
            if !v.is_zero() {
                break v;
            }
        })
        .collect()
}
