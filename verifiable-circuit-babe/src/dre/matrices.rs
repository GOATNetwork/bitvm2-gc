use ark_bn254::{Fq, G1Affine};
use ark_ff::{BigInteger, One, PrimeField, Zero};
use crate::dre::{L, N};

/// Build the 3×6 matrix C(δ, φ) over F_p.
///
/// Row 0: [ 6δ + (1-δ)x,     δx²,      -2δy,          δx,        0,      0       ]
/// Row 1: [ 9δy + (1-δ)y,    0,        -δ(y²+9),      3δxy,      δy,     -3δx²   ]
/// Row 2: [ -δx + (1-δ),     δ,        0,             0,         0,      0      ]
fn build_c(delta: Fq, phi: &G1Affine) -> [[Fq; 6]; 3] {
    let x = phi.x;
    let y = phi.y;
    let one_minus_delta = Fq::from(1u64) - delta;
    assert!(delta.is_zero() || delta.is_one(), "δ must be 0 or 1");
    [
        // Row 0
        [
            Fq::from(6u64) * delta + one_minus_delta * x, // 6δ + (1-δ)x
            delta * x * x,                                 // δx²
            -(Fq::from(2u64) * delta * y),                 // -2δy
            delta * x,                                     // δx
            Fq::zero(),
            Fq::zero(),
        ],
        // Row 1
        [
            Fq::from(9u64) * delta * y + one_minus_delta * y, // 9δy + (1-δ)y
            Fq::zero(),
            -(delta * (y * y + Fq::from(9u64))), // -δ(y² + 9)
            Fq::from(3u64) * delta * x * y,      // 3δxy
            delta * y,                            // δy
            -(Fq::from(3u64) * delta * x * x),   // -3δx²
        ],
        // Row 2
        [
            -(delta * x) + one_minus_delta, // -δx + (1-δ)
            delta,
            Fq::zero(),
            Fq::zero(),
            Fq::zero(),
            Fq::zero(),
        ],
    ]
}

/// Compute D = C(δ, φ) × G, returning a 3×L matrix as a flat row-major Vec.
/// Todo: opt D by remove zeroes.
pub fn build_d(delta: Fq, phi: &G1Affine) -> Vec<Fq> {
    let c = build_c(delta, phi);
    let mut d = vec![Fq::zero(); 3 * L];
    let two = Fq::from(2u64);

    for row in 0..3 {
        // Column 0
        d[row * L] = c[row][0];

        // For i=1..=5: G[i][(i-1)*N+1 .. i*N] = (2^0, 2^1, ..., 2^{N-1})
        for i in 1..=5usize {
            let col_start = (i - 1) * N + 1;
            let mut power = Fq::from(1u64);
            for k in 0..N {
                d[row * L + col_start + k] = c[row][i] * power;
                power *= two;
            }
        }
    }

    d
}

/// Lemma5: Build diag(λ) = diag(λ², λ³, λ) for λ in base field F_p.
pub fn build_diag(lambda: Fq) -> [[Fq; 3]; 3] {
    [
        [lambda * lambda, Fq::zero(),                    Fq::zero()],
        [Fq::zero(),      lambda * lambda * lambda,      Fq::zero()],
        [Fq::zero(),      Fq::zero(),                    lambda    ],
    ]
}

/// D_i = diag(λ_i², λ_i³, λ_i) × D(r_i, ρ_i) ∈ F_p^{3×L}
pub fn build_d_i(lambda: Fq, r_i: Fq, rho_i: &G1Affine) -> Vec<Fq> {
    let d = build_d(r_i, rho_i);
    let lambda2 = lambda * lambda;
    let lambda3 = lambda2 * lambda;
    let scales = [lambda2, lambda3, lambda];

    let mut d_i = d.clone();
    for row in 0..3 {
        for col in 0..L {
            d_i[row * L + col] *= scales[row];
        }
    }
    d_i
}

/// u(π) = (1, x, y, x², y², xy)
fn u_vec(pi: &G1Affine) -> [Fq; 6] {
    let (x, y) = (pi.x, pi.y);
    [Fq::one(), x, y, x * x, y * y, x * y]
}

/// ū(π) binary decomposition of u(π).
/// Layout: (1, bits(x), bits(y), bits(x²), bits(y²), bits(xy)) in LSB-first
pub fn u_bar_vec(pi: &G1Affine) -> Vec<Fq> {
    let u = u_vec(pi);
    let mut u_bar = Vec::with_capacity(L);
    u_bar.push(Fq::one()); // u_0 = 1
    for u_i in &u[1..] {
        let bits = u_i.into_bigint().to_bits_le();
        for k in 0..N {
            u_bar.push(if bits[k] { Fq::one() } else { Fq::zero() });
        }
    }
    u_bar
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::G1Projective;
    use ark_ec::CurveGroup;
    use ark_ff::{Field, UniformRand};
    use crate::dre::utils::jacobian_to_affine;

    /// Verify Jacobian (X:Y:Z) → affine via (X/Z², Y/Z³) matches expected point.
    fn check_jacobian(xyz: [Fq; 3], expected: &G1Affine) {
        let aff = jacobian_to_affine((xyz[0], xyz[1], xyz[2]));
        assert_eq!(aff, *expected, "Jacobian coordinates do not match expected affine point");
    }

    fn mul_c_u(c: &[[Fq; 6]; 3], u: &[Fq; 6]) -> [Fq; 3] {
        let mut out = [Fq::zero(); 3];
        for row in 0..3 {
            for j in 0..6 {
                out[row] += c[row][j] * u[j];
            }
        }
        out
    }

    fn mul_d_ubar(d: &[Fq], u_bar: &[Fq]) -> [Fq; 3] {
        let mut out = [Fq::zero(); 3];
        for row in 0..3 {
            for j in 0..L {
                out[row] += d[row * L + j] * u_bar[j];
            }
        }
        out
    }


    /// Pick two random G1 affine points with x(φ) ≠ x(π) (Lemma 4 precondition).
    fn random_pair() -> (G1Affine, G1Affine) {
        let mut rng = rand::thread_rng();
        loop {
            let phi = G1Projective::rand(&mut rng).into_affine();
            let pi  = G1Projective::rand(&mut rng).into_affine();
            if phi.x != pi.x { return (phi, pi); }
        }
    }

    #[test]
    fn test_u_bar_vec() {
        let mut rng = rand::thread_rng();
        let pi = G1Projective::rand(&mut rng).into_affine();
        let u = u_vec(&pi);
        let u_bar = u_bar_vec(&pi);

        // Check length
        assert_eq!(u_bar.len(), L);

        // First entry must be 1
        assert_eq!(u_bar[0], Fq::one());

        // All entries must be bits (0 or 1)
        for (i, b) in u_bar.iter().enumerate() {
            assert!(b.is_zero() || b.is_one(), "u_bar[{i}] is not a bit");
        }

        // Reconstruct each u_j from its bits and verify: u_j = ∑_k bits[k] · 2^k
        let two = Fq::from(2u64);
        for j in 1..=5usize {
            let col_start = (j - 1) * N + 1;
            let mut reconstructed = Fq::zero();
            let mut power = Fq::one();
            for k in 0..N {
                reconstructed += u_bar[col_start + k] * power;
                power *= two;
            }
            assert_eq!(reconstructed, u[j], "binary reconstruction failed for u_{j}");
        }
    }

    #[test]
    fn test_diag() {
        let mut rng = rand::thread_rng();

        let pi = G1Projective::rand(&mut rng);
        let lambda = loop {
            let l = Fq::rand(&mut rng);
            if !l.is_zero() { break l; }
        };

        let x = pi.x;
        let y = pi.y;
        let z = pi.z;

        // Apply diag(λ): (X, Y, Z) → (λ²X, λ³Y, λZ)
        let diag = build_diag(lambda);
        let xyz_scaled = [
            diag[0][0] * x,
            diag[1][1] * y,
            diag[2][2] * z,
        ];

        // Both must represent the same affine point
        let new_pi = G1Projective::new(xyz_scaled[0], xyz_scaled[1], xyz_scaled[2]);
        assert_eq!(new_pi, pi, "diag(λ) should not change the affine point");
    }

    //--- C(δ,φ) × u^T(π) = Jacobian coords of (φ + δπ) ---
    #[test]
    fn test_c_delta_0() {
        let (phi, pi) = random_pair();
        let xyz = mul_c_u(&build_c(Fq::zero(), &phi), &u_vec(&pi));
        // φ + 0·π = φ, which has Jacobian coords (x(φ) : y(φ) : 1)
        check_jacobian(xyz, &phi);
    }

    #[test]
    fn test_c_delta_1() {
        let (phi, pi) = random_pair();
        let expected = (G1Projective::from(phi) + G1Projective::from(pi)).into_affine();
        let xyz = mul_c_u(&build_c(Fq::one(), &phi), &u_vec(&pi));
        check_jacobian(xyz, &expected);
    }

    //--- D(δ,φ) × ū^T(π) = Jacobian coords of (φ + δπ) ---

    #[test]
    fn test_d_delta_0() {
        let (phi, pi) = random_pair();
        let u_bar = u_bar_vec(&pi);
        assert_eq!(u_bar.len(), L);
        let xyz = mul_d_ubar(&build_d(Fq::zero(), &phi), &u_bar);
        check_jacobian(xyz, &phi);
    }

    #[test]
    fn test_d_delta_1() {
        let (phi, pi) = random_pair();
        let expected = (G1Projective::from(phi) + G1Projective::from(pi)).into_affine();
        let u_bar = u_bar_vec(&pi);
        let xyz = mul_d_ubar(&build_d(Fq::one(), &phi), &u_bar);
        check_jacobian(xyz, &expected);
    }
}