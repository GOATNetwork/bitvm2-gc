use ark_ec::PrimeGroup;
use ark_ff::Field;
use num_bigint::BigUint;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

use crate::dv_bn254::{fp254impl::Fp254Impl, fq::Fq, g1::G1Projective as DvG1Projective};
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::AdditiveGroup;

/// Argo MAC parameters for G1.
#[derive(Debug, Clone, Copy)]
pub struct ArgoMacParamsG1 {
    /// Security parameter in bits.
    pub lambda: usize,
    /// Number of MAC components.
    pub kappa: usize,
}

impl Default for ArgoMacParamsG1 {
    fn default() -> Self {
        // Using d = 6 endomorphisms and lambda = 128, we need kappa >= ceil(128 / log2(6)) = 50.
        Self { lambda: 128, kappa: 50 }
    }
}

/// Degree-1 endomorphisms on BN254 G1 used in M1.
#[derive(Debug, Clone, Copy)]
pub enum G1Endomorphism {
    /// phi(P) = P
    Id,
    /// phi(P) = (beta * x(P), y(P))
    Psi,
    /// phi(P) = (beta^2 * x(P), y(P))
    Psi2,
    /// phi(P) = -P
    NegId,
    /// phi(P) = -(beta * x(P), y(P))
    NegPsi,
    /// phi(P) = -(beta^2 * x(P), y(P))
    NegPsi2,
}

#[derive(Debug, Clone)]
pub struct ArgoMacKeyComponentG1 {
    pub phi: G1Endomorphism,
    pub k: ark_bn254::G1Projective,
}

#[derive(Debug, Clone)]
pub struct ArgoMacKeyG1 {
    pub beta: ark_bn254::Fq,
    pub beta2: ark_bn254::Fq,
    pub components: Vec<ArgoMacKeyComponentG1>,
}

#[derive(Debug, Clone)]
pub struct ArgoMacTagG1 {
    pub components: Vec<ark_bn254::G1Projective>,
}

/// Public tag sent from Garbler to Evaluator in the role-separated flow.
/// We use:
///   U_i(P) = T_i(P) - K_i = phi_i(P).
/// This lets Evaluator compute linear combinations without knowing K_i.
#[derive(Debug, Clone)]
pub struct ArgoPublicTagG1 {
    pub components: Vec<ark_bn254::G1Projective>,
}

/// Message emitted by Garbler for DV Step4 role-separated verification.
#[derive(Debug, Clone)]
pub struct ArgoStep4Message {
    /// Input validity bit from Garbler-side checks:
    ///   Z != 0 and Y^2 = X^3 + b*Z^6 for both points.
    pub input_valid: bool,
    /// Public tag for signed generator term.
    pub g_tag: ArgoPublicTagG1,
    /// Public tag for signed Q term.
    pub q_tag: ArgoPublicTagG1,
    /// Public tag for signed P term.
    pub p_tag: ArgoPublicTagG1,
    /// Absolute scalar values for the 3 terms.
    pub x1_abs: BigUint,
    pub x2_abs: BigUint,
    pub z_abs: BigUint,
}

/// Garbler role: holds secret MAC key material (phi_i, K_i).
#[derive(Debug, Clone)]
pub struct ArgoStep4Garbler {
    key: ArgoMacKeyG1,
}

/// Evaluator role: only receives public tags/messages and computes verification.
#[derive(Debug, Clone, Default)]
pub struct ArgoStep4Evaluator;

/// Returns a non-trivial cubic root of unity beta in Fq, i.e. beta^3 = 1 and beta != 1.
fn bn254_nontrivial_cubic_root_of_unity() -> ark_bn254::Fq {
    // beta = g^((p-1)/3), where p is the Fq modulus and g is any non-cube in Fq*.
    let p_minus_1 = Fq::modulus_as_biguint() - BigUint::from(1_u8);
    let exp = (&p_minus_1 / BigUint::from(3_u8)).to_u64_digits();

    for base in 2u64..1024 {
        let candidate = ark_bn254::Fq::from(base).pow(&exp);
        if candidate != ark_bn254::Fq::ONE && candidate.square() * candidate == ark_bn254::Fq::ONE {
            return candidate;
        }
    }

    panic!("failed to find non-trivial cubic root of unity in BN254 Fq")
}

impl ArgoMacKeyG1 {
    pub fn keygen(params: ArgoMacParamsG1, seed: u64) -> Self {
        let beta = bn254_nontrivial_cubic_root_of_unity();
        let beta2 = beta.square();
        let mut rng = ChaCha12Rng::seed_from_u64(seed);
        let mut components = Vec::with_capacity(params.kappa);

        for _ in 0..params.kappa {
            let phi = match rng.gen_range(0u8..6u8) {
                0 => G1Endomorphism::Id,
                1 => G1Endomorphism::Psi,
                2 => G1Endomorphism::Psi2,
                3 => G1Endomorphism::NegId,
                4 => G1Endomorphism::NegPsi,
                _ => G1Endomorphism::NegPsi2,
            };
            // K_i = r_i * G, with random scalar r_i.
            let r_i = ark_bn254::Fr::from(rng.r#gen::<u128>());
            let k = ark_bn254::G1Projective::generator() * r_i;
            components.push(ArgoMacKeyComponentG1 { phi, k });
        }

        Self { beta, beta2, components }
    }

    /// Apply phi to P according to:
    /// - Id:      phi(P) = P
    /// - Psi:     phi(P) = (beta*x(P), y(P))
    /// - Psi2:    phi(P) = (beta^2*x(P), y(P))
    /// - Neg*:    phi(P) = -phi_base(P)
    pub fn apply_phi(&self, phi: G1Endomorphism, p: ark_bn254::G1Projective) -> ark_bn254::G1Projective {
        let mut q = p;
        match phi {
            G1Endomorphism::Id => {}
            G1Endomorphism::Psi => {
                q.x *= self.beta;
            }
            G1Endomorphism::Psi2 => {
                q.x *= self.beta2;
            }
            G1Endomorphism::NegId => {
                q = -q;
            }
            G1Endomorphism::NegPsi => {
                q.x *= self.beta;
                q = -q;
            }
            G1Endomorphism::NegPsi2 => {
                q.x *= self.beta2;
                q = -q;
            }
        }
        q
    }

    /// Encode with Argo MAC component-wise:
    /// T_i(P) = phi_i(P) + K_i.
    pub fn encode_point(&self, p: ark_bn254::G1Projective) -> ArgoMacTagG1 {
        let components = self
            .components
            .iter()
            .map(|c| self.apply_phi(c.phi, p) + c.k)
            .collect();
        ArgoMacTagG1 { components }
    }

    /// Zero tag satisfies T_i(O) = K_i because phi_i(O) = O.
    pub fn zero_tag(&self) -> ArgoMacTagG1 {
        ArgoMacTagG1 { components: self.components.iter().map(|c| c.k.clone()).collect() }
    }

    /// Homomorphic add in MAC domain:
    /// T_i(A + B) = T_i(A) + T_i(B) - K_i.
    pub fn add_tags(&self, a: &ArgoMacTagG1, b: &ArgoMacTagG1) -> ArgoMacTagG1 {
        let components = a
            .components
            .iter()
            .zip(b.components.iter())
            .zip(self.components.iter())
            .map(|((ta, tb), c)| ta.clone() + tb.clone() - c.k.clone())
            .collect();
        ArgoMacTagG1 { components }
    }

    /// Homomorphic negation in MAC domain:
    /// T_i(-A) = -T_i(A) + 2*K_i.
    pub fn neg_tag(&self, a: &ArgoMacTagG1) -> ArgoMacTagG1 {
        let components = a
            .components
            .iter()
            .zip(self.components.iter())
            .map(|(ta, c)| -ta.clone() + c.k.clone() + c.k.clone())
            .collect();
        ArgoMacTagG1 { components }
    }

    /// Homomorphic doubling in MAC domain:
    /// T_i(2A) = T_i(A) + T_i(A) - K_i.
    pub fn double_tag(&self, a: &ArgoMacTagG1) -> ArgoMacTagG1 {
        self.add_tags(a, a)
    }

    /// Scalar multiplication in MAC domain using double-and-add:
    /// T([s]A) via iterative use of
    ///   acc <- T(acc + cur) and cur <- T(2*cur).
    pub fn scalar_mul_tag(&self, s: &BigUint, a: &ArgoMacTagG1) -> ArgoMacTagG1 {
        let mut acc = self.zero_tag();
        let mut cur = a.clone();

        for byte in s.to_bytes_le() {
            for bit_idx in 0..8 {
                if ((byte >> bit_idx) & 1u8) == 1u8 {
                    acc = self.add_tags(&acc, &cur);
                }
                cur = self.double_tag(&cur);
            }
        }
        acc
    }

    /// Check R == O via MAC components:
    /// R == O  <=>  for all i, T_i(R) == T_i(O) == K_i.
    pub fn is_zero_tag(&self, r: &ArgoMacTagG1) -> bool {
        r.components
            .iter()
            .zip(self.components.iter())
            .all(|(tr, c)| tr == &c.k)
    }

    /// Public tag for role-separated verification:
    ///   U_i(P) = T_i(P) - K_i = phi_i(P).
    pub fn encode_public_tag(&self, p: ark_bn254::G1Projective) -> ArgoPublicTagG1 {
        let components = self
            .components
            .iter()
            .map(|c| self.apply_phi(c.phi, p))
            .collect();
        ArgoPublicTagG1 { components }
    }
}

impl ArgoStep4Garbler {
    pub fn new(params: ArgoMacParamsG1, seed: u64) -> Self {
        Self { key: ArgoMacKeyG1::keygen(params, seed) }
    }

    /// Garbler prepares role-separated Step4 message.
    ///
    /// Formula implemented for signed points:
    ///   R = x1*G + x2*Q + z_signed*P.
    /// Garbler sends U-tags where U_i(P)=phi_i(P) only.
    pub fn prepare_step4_message(
        &self,
        q_mont: ark_bn254::G1Projective,
        p_mont: ark_bn254::G1Projective,
        x1_abs: BigUint,
        x1_neg: bool,
        x2_abs: BigUint,
        x2_neg: bool,
        z_abs: BigUint,
        z_pos: bool,
    ) -> ArgoStep4Message {
        // Convert witness points from Montgomery representation to canonical group coordinates.
        let q = DvG1Projective::from_montgomery(q_mont);
        let p = DvG1Projective::from_montgomery(p_mont);

        // Input validity checks (formula-level): Z != 0 and Y^2 = X^3 + b*Z^6.
        let input_valid = validate_g1_projective_non_infinity(q) && validate_g1_projective_non_infinity(p);

        let (g_signed, q_signed, p_signed) = signed_step4_points(q, p, x1_neg, x2_neg, z_pos);

        // U_i(P) = phi_i(P), i.e. T_i(P)-K_i.
        let g_tag = self.key.encode_public_tag(g_signed);
        let q_tag = self.key.encode_public_tag(q_signed);
        let p_tag = self.key.encode_public_tag(p_signed);

        ArgoStep4Message { input_valid, g_tag, q_tag, p_tag, x1_abs, x2_abs, z_abs }
    }
}

impl ArgoStep4Evaluator {
    /// U-tag add:
    ///   U_i(A + B) = U_i(A) + U_i(B), because U_i(P)=phi_i(P) is homomorphic.
    pub fn add_public_tags(a: &ArgoPublicTagG1, b: &ArgoPublicTagG1) -> ArgoPublicTagG1 {
        let components = a
            .components
            .iter()
            .zip(b.components.iter())
            .map(|(ua, ub)| ua.clone() + ub.clone())
            .collect();
        ArgoPublicTagG1 { components }
    }

    /// U-tag doubling:
    ///   U_i(2A) = 2 * U_i(A).
    pub fn double_public_tag(a: &ArgoPublicTagG1) -> ArgoPublicTagG1 {
        let components = a.components.iter().map(|ua| ua.clone() + ua.clone()).collect();
        ArgoPublicTagG1 { components }
    }

    /// U-tag scalar multiplication:
    ///   U_i([s]A) = [s]U_i(A).
    pub fn scalar_mul_public_tag(s: &BigUint, a: &ArgoPublicTagG1) -> ArgoPublicTagG1 {
        let mut acc = ArgoPublicTagG1 {
            components: vec![ark_bn254::G1Projective::ZERO; a.components.len()],
        };
        let mut cur = a.clone();

        for byte in s.to_bytes_le() {
            for bit_idx in 0..8 {
                if ((byte >> bit_idx) & 1u8) == 1u8 {
                    acc = Self::add_public_tags(&acc, &cur);
                }
                cur = Self::double_public_tag(&cur);
            }
        }
        acc
    }

    /// Zero check on U-tags:
    ///   R == O  <=>  for all i, U_i(R) = phi_i(O) = O.
    pub fn is_zero_public_tag(r: &ArgoPublicTagG1) -> bool {
        r.components.iter().all(|ur| *ur == ark_bn254::G1Projective::ZERO)
    }

    /// Evaluator verifies Step4 relation from role-separated Garbler message:
    ///   R = x1*G + x2*Q + z_signed*P
    ///   accept iff input_valid && R == O.
    pub fn verify_step4_message(msg: &ArgoStep4Message) -> bool {
        if !msg.input_valid {
            return false;
        }
        let x1_term = Self::scalar_mul_public_tag(&msg.x1_abs, &msg.g_tag);
        let x2_term = Self::scalar_mul_public_tag(&msg.x2_abs, &msg.q_tag);
        let z_term = Self::scalar_mul_public_tag(&msg.z_abs, &msg.p_tag);
        let lhs = Self::add_public_tags(&Self::add_public_tags(&x1_term, &x2_term), &z_term);
        Self::is_zero_public_tag(&lhs)
    }
}

/// Validate projective point in affine-short form y^2 = x^3 + b with Jacobian relation:
/// For P = (X:Y:Z), valid if Z != 0 and Y^2 = X^3 + b*Z^6.
pub fn validate_g1_projective_non_infinity(p: ark_bn254::G1Projective) -> bool {
    if p.z == ark_bn254::Fq::ZERO {
        return false;
    }

    // Formula: Y^2 = X^3 + b * Z^6.
    let y2 = p.y.square();
    let x3 = p.x.square() * p.x;
    let z2 = p.z.square();
    let z6 = z2 * z2 * z2;
    let rhs = x3 + ark_bn254::g1::Config::COEFF_B * z6;
    y2 == rhs
}

/// Apply the same point-sign conventions as dv_ckt step4:
/// - x1 uses negate_with_neg_selector: if x1_neg then -G else G.
/// - x2 uses negate_with_neg_selector: if x2_neg then -Q else Q.
/// - z uses negate_with_pos_selector: if z_pos then P else -P.
pub fn signed_step4_points(
    q: ark_bn254::G1Projective,
    p: ark_bn254::G1Projective,
    x1_neg: bool,
    x2_neg: bool,
    z_pos: bool,
) -> (ark_bn254::G1Projective, ark_bn254::G1Projective, ark_bn254::G1Projective) {
    let g = if x1_neg { -ark_bn254::G1Projective::generator() } else { ark_bn254::G1Projective::generator() };
    let q_signed = if x2_neg { -q } else { q };
    let p_signed = if z_pos { p } else { -p };
    (g, q_signed, p_signed)
}

/// Verify step4 relation in Argo MAC domain:
///   x1*G + x2*Q + z_signed*P == O,
/// where z_signed follows the existing negate_with_pos_selector convention.
pub fn verify_step4_with_argo_mac(
    q_mont: ark_bn254::G1Projective,
    p_mont: ark_bn254::G1Projective,
    x1_abs: BigUint,
    x1_neg: bool,
    x2_abs: BigUint,
    x2_neg: bool,
    z_abs: BigUint,
    z_pos: bool,
    seed: u64,
) -> bool {
    verify_step4_with_argo_roles(
        q_mont, p_mont, x1_abs, x1_neg, x2_abs, x2_neg, z_abs, z_pos, seed,
    )
}

/// Role-separated wrapper:
/// 1) Garbler prepares message with U-tags and validity bit.
/// 2) Evaluator verifies R == O from public message.
pub fn verify_step4_with_argo_roles(
    q_mont: ark_bn254::G1Projective,
    p_mont: ark_bn254::G1Projective,
    x1_abs: BigUint,
    x1_neg: bool,
    x2_abs: BigUint,
    x2_neg: bool,
    z_abs: BigUint,
    z_pos: bool,
    seed: u64,
) -> bool {
    let params = ArgoMacParamsG1::default();
    let garbler = ArgoStep4Garbler::new(params, seed);
    let msg =
        garbler.prepare_step4_message(q_mont, p_mont, x1_abs, x1_neg, x2_abs, x2_neg, z_abs, z_pos);
    ArgoStep4Evaluator::verify_step4_message(&msg)
}
