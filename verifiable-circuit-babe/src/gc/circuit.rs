use ark_bn254::G1Affine;
use garbled_snark_verifier::bag::{Circuit, Wires};
use garbled_snark_verifier::circuits::sect233k1::builder::{CircuitAdapter, CircuitTrait};
use garbled_snark_verifier::dv_bn254::basic::selector;
use garbled_snark_verifier::dv_bn254::fp254impl::Fp254Impl;
use garbled_snark_verifier::dv_bn254::fq::Fq;

use crate::dre::{L, N};

/// Compile the BABE circuit structure without fixing witness values.
pub fn compile_babe_gc(g: G1Affine) -> (CircuitAdapter, Vec<usize>) {
    let mut bld = CircuitAdapter::default();
    // Allocate input wire
    let pi_x = Fq::wires(&mut bld);
    let pi_y = Fq::wires(&mut bld);
    let output_indices = emit_babe_gc(&mut bld, &pi_x.0, &pi_y.0, g);
    (bld, output_indices)
}

/// Garbled circuit for BABE:
/// 0. Input wire indices: pi_x (bits 0..N), pi_y (bits N..2N) — LSB first.
/// 1. Validates input point π = (x, y) lies on BN254 curve E: y² = x³ + 3 (mod p)
/// 2. If valid:   outputs binary decomposition ū(π) = bits(1, x, y, x², y², xy)
///    If invalid: outputs ū(g) for a fixed fallback point g ∈ G₁
fn emit_babe_gc(
    bld: &mut CircuitAdapter,
    pi_x: &[usize],
    pi_y: &[usize],
    g: G1Affine,
) -> Vec<usize> {
    // R² mod p
    let r_sq = Fq::as_montgomery(Fq::as_montgomery(ark_bn254::Fq::from(1u64)));
    let r_sq_w = Fq::wires_set(bld, r_sq);

    // Convert x, y to Montgomery form
    let x_m = Fq::mul_montgomery(bld, pi_x, &r_sq_w.0);
    let y_m = Fq::mul_montgomery(bld, pi_y, &r_sq_w.0);

    // Compute x², y², xy, x³ — all in Montgomery form
    let x_sq_m = Fq::square_montgomery(bld, &x_m);
    let y_sq_m = Fq::square_montgomery(bld, &y_m);
    let xy_m = Fq::mul_montgomery(bld, &x_m, &y_m);
    let x_cu_m = Fq::mul_montgomery(bld, &x_sq_m, &x_m);

    // Curve check: y² ≡ x³ + 3 (mod p)
    let three_mont = Fq::as_montgomery(ark_bn254::Fq::from(3u64));
    let rhs_m = Fq::add_constant(bld, &x_cu_m, three_mont);
    let on_curve = Fq::equal(bld, &y_sq_m, &rhs_m);

    // Convert x², y², xy from Montgomery back to standard form.
    // mul_montgomery(A·R, 1) = A·R · 1 · R⁻¹ = A
    let one_w = Fq::wires_set(bld, ark_bn254::Fq::from(1u64));
    let x_sq = Fq::mul_montgomery(bld, &x_sq_m, &one_w.0);
    let y_sq = Fq::mul_montgomery(bld, &y_sq_m, &one_w.0);
    let xy = Fq::mul_montgomery(bld, &xy_m, &one_w.0);

    // Build ū(π)
    let mut pi_u_bar: Vec<usize> = Vec::with_capacity(L);
    pi_u_bar.push(bld.one());
    pi_u_bar.extend_from_slice(pi_x);
    pi_u_bar.extend_from_slice(pi_y);
    pi_u_bar.extend(x_sq);
    pi_u_bar.extend(y_sq);
    pi_u_bar.extend(xy);
    assert_eq!(pi_u_bar.len(), L);

    // Build constant ū(g) for the fallback point
    let g_u_bar = g_u_bar_indices(bld, g);

    // Output: select ū(π) if on_curve, else ū(g)
    (0..L)
        .map(|k| selector(bld, pi_u_bar[k], g_u_bar[k], on_curve))
        .collect()
}

/// Build constant wire indices for ū(g)
fn g_u_bar_indices(bld: &mut CircuitAdapter, g: G1Affine) -> Vec<usize> {
    let x = g.x;
    let y = g.y;
    let x_sq = x * x;
    let y_sq = y * y;
    let xy = x * y;

    let mut indices: Vec<usize> = Vec::with_capacity(L);
    indices.push(bld.one());

    for val in [x, y, x_sq, y_sq, xy] {
        let bits = Fq::to_bits(val);
        for &b in bits.iter().take(N) {
            indices.push(if b { bld.one() } else { bld.zero() });
        }
    }

    assert_eq!(indices.len(), L);
    indices
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::CurveGroup;
    use ark_ff::{UniformRand, Zero};
    use garbled_snark_verifier::bag::S;
    use garbled_snark_verifier::core::utils::reset_gid;
    use crate::dre::matrices::u_bar_vec;

    fn random_g1_affine() -> G1Affine {
        let mut rng = rand::thread_rng();
        ark_bn254::G1Projective::rand(&mut rng).into_affine()
    }

    #[test]
    fn test_babe_gc_on_curve() {
        let pi = random_g1_affine();
        let g = random_g1_affine();

        let witness: Vec<bool> = Fq::to_bits(pi.x)
            .into_iter()
            .chain(Fq::to_bits(pi.y).into_iter())
            .collect();

        // build circuit
        reset_gid();
        let (bld, output_indices) = compile_babe_gc(g);
        let mut circuit = bld.build(&witness);
        circuit.gate_counts().print();

        // Evaluate the circuit
        for gate in &mut circuit.1 {
            gate.evaluate();
        }

        let output: Vec<bool> = output_indices
            .iter()
            .map(|&i| circuit.0[i].borrow().get_value())
            .collect();

        assert_eq!(output.len(), L);

        // u₀ = 1
        assert!(output[0]);

        // bits 1..=N match bits of x
        let x_bits = Fq::to_bits(pi.x);
        for k in 0..N {
            assert_eq!(output[1 + k], x_bits[k], "x bit {k} mismatch");
        }

        // bits N+1..=2N match bits of y
        let y_bits = Fq::to_bits(pi.y);
        for k in 0..N {
            assert_eq!(output[1 + N + k], y_bits[k], "y bit {k} mismatch");
        }

        // bits 2N+1..=3N match bits of x²
        let x_sq_bits = Fq::to_bits(pi.x * pi.x);
        for k in 0..N {
            assert_eq!(output[1 + 2 * N + k], x_sq_bits[k], "x² bit {k} mismatch");
        }

        // bits 3N+1..=4N match bits of y²
        let y_sq_bits = Fq::to_bits(pi.y * pi.y);
        for k in 0..N {
            assert_eq!(output[1 + 3 * N + k], y_sq_bits[k], "y² bit {k} mismatch");
        }

        // bits 4N+1..=5N match bits of xy
        let xy_bits = Fq::to_bits(pi.x * pi.y);
        for k in 0..N {
            assert_eq!(output[1 + 4 * N + k], xy_bits[k], "xy bit {k} mismatch");
        }
    }

    #[test]
    fn test_babe_gc_off_curve_falls_back_to_g() {
        let pi = random_g1_affine();
        let g = random_g1_affine();

        // Perturb y to force off-curve
        let bad_y = pi.y + ark_bn254::Fq::from(1u64);
        let witness: Vec<bool> = Fq::to_bits(pi.x)
            .into_iter()
            .chain(Fq::to_bits(bad_y).into_iter())
            .collect();

        // circuit
        reset_gid();
        let (bld, output_indices) = compile_babe_gc(g);
        let mut circuit = bld.build(&witness);
        for gate in &mut circuit.1 {
            gate.evaluate();
        }

        let output: Vec<bool> = output_indices
            .iter()
            .map(|&i| circuit.0[i].borrow().get_value())
            .collect();
        assert_eq!(output.len(), L);

        // u₀ = 1
        assert!(output[0]);

        // Should fall back to g
        let gx_bits = Fq::to_bits(g.x);
        for k in 0..N {
            assert_eq!(output[1 + k], gx_bits[k], "g.x bit {k} mismatch");
        }

        let gy_bits = Fq::to_bits(g.y);
        for k in 0..N {
            assert_eq!(output[1 + N + k], gy_bits[k], "g.y bit {k} mismatch");
        }
    }

    /// Tests the full garbled circuit flow for BABE GC.
    /// With the `garbled` feature, Wire::new() auto-assigns random labels.
    #[cfg(feature = "garbled")]
    #[test]
    fn test_babe_gc_garbled_labels() {
        let pi = random_g1_affine();
        let g = random_g1_affine();

        reset_gid();
        let (bld, output_indices) = compile_babe_gc(g);
        let mut circuit = bld.build(&vec![]);

        let witness: Vec<bool> = Fq::to_bits(pi.x)
            .into_iter()
            .chain(Fq::to_bits(pi.y).into_iter())
            .collect();

        circuit.set_witness_value(&witness);
        for gate in &mut circuit.1 {
            gate.evaluate();
        }
        let garblings = circuit.garbled_gates();
        let _ = circuit.garbled_evaluate(&garblings);

        let output_labels: Vec<S> = output_indices
            .iter()
            .map(|&i| {
                let w = &circuit.0[i];
                w.borrow().select(w.borrow().get_value())
            }).collect();
        assert_eq!(output_labels.len(), L);

        // compute expected u_bar(π) for the given π
        let u_bar = u_bar_vec(&pi);
        assert_eq!(u_bar.len(), L);
        for k in 0..L {
            let expected_bit = !u_bar[k].is_zero();
            let expected_label = circuit.0[output_indices[k]].borrow().select(expected_bit);
            assert_eq!(
                output_labels[k],
                expected_label,
                "garbled output label mismatch at ū[{k}]"
            );
        }
    }

    #[cfg(feature = "garbled")]
    #[test]
    fn test_output_labels() {
        use garbled_snark_verifier::core::utils::DELTA;

        let g = random_g1_affine();

        // Generate the circuit.
        reset_gid();
        let (bld, output_indices) = compile_babe_gc(g);
        let mut circuit = bld.build(&[]);

        // Encoding keys: random 0-labels for each of the 2*N input wires (x bits then y bits).
        // The 1-label for wire i is encoding_keys[i] XOR DELTA (Free XOR).
        let encoding_keys: Vec<S> = (0..2 * crate::dre::N).map(|_| S::random()).collect();
        // Override the circuit's input wire labels with our encoding keys.
        for (i, &key) in encoding_keys.iter().enumerate() {
            circuit.0[2 + i].borrow_mut().label = Some(key);
        }

        // Two random G1 points.
        let mut rng = rand::thread_rng();
        let p1a = ark_bn254::G1Projective::rand(&mut rng).into_affine();
        let p1b = ark_bn254::G1Projective::rand(&mut rng).into_affine();

        // Evaluate the circuit for a given point and return the output labels.
        // For each output wire k, select the label corresponding to the output bit value.
        let eval = |circuit: &mut Circuit, p: &ark_bn254::G1Affine| -> Vec<S> {
            let witness: Vec<bool> = Fq::to_bits(p.x)
                .into_iter()
                .chain(Fq::to_bits(p.y).into_iter())
                .collect();

            // Reset all non-constant wire values so the circuit can be re-evaluated.
            for wire in circuit.0.iter().skip(2) {
                wire.borrow_mut().value = None;
            }
            circuit.set_witness_value(&witness);
            for gate in &mut circuit.1 {
                gate.evaluate();
            }
            let garblings = circuit.garbled_gates();
            let _ = circuit.garbled_evaluate(&garblings);

            output_indices
                .iter()
                .map(|&i| {
                    let w = &circuit.0[i];
                    w.borrow().select(w.borrow().get_value())
                })
                .collect()
        };

        let labels_a = eval(&mut circuit, &p1a);
        let labels_b = eval(&mut circuit, &p1b);

        // Verify the Free XOR property on output labels:
        //   same u_bar bit  → labels are equal
        //   different u_bar → labels XOR DELTA
        let u_bar_a = u_bar_vec(&p1a);
        let u_bar_b = u_bar_vec(&p1b);
        assert_eq!(u_bar_a.len(), L);
        assert_eq!(u_bar_b.len(), L);

        for k in 0..L {
            let bit_a = !u_bar_a[k].is_zero();
            let bit_b = !u_bar_b[k].is_zero();
            if bit_a == bit_b {
                assert_eq!(labels_a[k], labels_b[k], "k={k}: same u_bar bit → equal output labels");
            } else {
                assert_eq!(
                    labels_a[k] ^ labels_b[k],
                    DELTA,
                    "k={k}: different u_bar bits → labels must differ by DELTA"
                );
            }
        }
    }
}
