use ark_bn254::G1Affine;
use garbled_snark_verifier::bag::*;
use garbled_snark_verifier::circuits::basic::selector;
use garbled_snark_verifier::circuits::bn254::fp254impl::Fp254Impl;
use garbled_snark_verifier::circuits::bn254::fq::Fq;

use crate::dre::{L, N};

/// Garbled circuit for BABE:
/// 1. Validates input point π = (x, y) lies on BN254 curve E: y² = x³ + 3 (mod p)
/// 2. If valid:   outputs binary decomposition ū(π) ∈ {0,1}^L of
///    If invalid: outputs ū(g) for a fixed fallback point g ∈ G₁
/// Todo: Consider if we should hardcoded g, instead of passing it as an argument.
pub fn babe_gc(pi_x: Wires, pi_y: Wires, g: G1Affine) -> Circuit {
    assert_eq!(pi_x.len(), N);
    assert_eq!(pi_y.len(), N);

    let mut circuit = Circuit::empty();

    // R² mod p as a constant field element (standard form).
    // using for mul montgomery.
    let r_sq = Fq::as_montgomery(Fq::as_montgomery(ark_bn254::Fq::from(1u64)));
    let r_sq_wires = Fq::wires_set(r_sq);

    // --- Convert x, y, x², y², xy, x³ to Montgomery form ---
    let x_m = circuit.extend(Fq::mul_montgomery(pi_x.clone(), r_sq_wires.clone()));
    let y_m = circuit.extend(Fq::mul_montgomery(pi_y.clone(), r_sq_wires));

    let x_sq_m = circuit.extend(Fq::square_montgomery(x_m.clone()));
    let y_sq_m = circuit.extend(Fq::square_montgomery(y_m.clone()));
    let xy_m = circuit.extend(Fq::mul_montgomery(x_m.clone(), y_m));
    let x_cu_m = circuit.extend(Fq::mul_montgomery(x_sq_m.clone(), x_m));

    // --- Curve check: y² ≡ x³ + 3 (mod p) ---
    let three_mont = Fq::as_montgomery(ark_bn254::Fq::from(3u64));
    let rhs_m = circuit.extend(Fq::add_constant(x_cu_m, three_mont));
    let on_curve_wires = circuit.extend(Fq::equal(y_sq_m.clone(), rhs_m));
    let on_curve = on_curve_wires[0].clone();

    // --- Convert x², y², xy from Montgomery to standard form ---
    // mul_montgomery(A*R, 1) = A*R * 1 * R⁻¹ = A
    let one_wires = Fq::wires_set(ark_bn254::Fq::from(1u64));
    let x_sq = circuit.extend(Fq::mul_montgomery(x_sq_m, one_wires.clone()));
    let y_sq = circuit.extend(Fq::mul_montgomery(y_sq_m, one_wires.clone()));
    let xy = circuit.extend(Fq::mul_montgomery(xy_m, one_wires));

    // --- Build ū(π) = [1, x_bits, y_bits, x²_bits, y²_bits, xy_bits] ---
    let const_one = {
        let w = new_wirex();
        w.borrow_mut().set(true);
        w
    };
    let mut pi_u_bar: Wires = Vec::with_capacity(L);
    pi_u_bar.push(const_one);
    pi_u_bar.extend_from_slice(&pi_x);
    pi_u_bar.extend_from_slice(&pi_y);
    pi_u_bar.extend(x_sq);
    pi_u_bar.extend(y_sq);
    pi_u_bar.extend(xy);
    assert_eq!(pi_u_bar.len(), L);

    // --- Build constant ū(g) for the fallback point g ---
    let g_u_bar = g_u_bar_wires(g);

    // --- Select ū(π) if on curve, ū(g) otherwise ---
    for k in 0..L {
        let out_bit = circuit
            .extend(selector(
                pi_u_bar[k].clone(),
                g_u_bar[k].clone(),
                on_curve.clone(),
            ))[0]
            .clone();
        circuit.add_wire(out_bit);
    }

    circuit
}

/// Constructs constant wires for ū(g).
fn g_u_bar_wires(g: G1Affine) -> Wires {
    let x = g.x;
    let y = g.y;
    let x_sq = x * x;
    let y_sq = y * y;
    let xy = x * y;

    let mut wires: Wires = Vec::with_capacity(L);
    let w = new_wirex();
    w.borrow_mut().set(true);
    wires.push(w);

    // N-bit standard-form decompositions of x, y, x², y², xy (LSB first)
    for val in [x, y, x_sq, y_sq, xy] {
        let bits = Fq::to_bits(val);
        for &b in bits.iter().take(N) {
            let w = new_wirex();
            w.borrow_mut().set(b);
            wires.push(w);
        }
    }

    assert_eq!(wires.len(), L);
    wires
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::CurveGroup;
    use ark_ff::UniformRand;
    use garbled_snark_verifier::circuits::bn254::fq::Fq;
    use ark_ff::Zero;
    use garbled_snark_verifier::bag::S;
    use crate::dre::matrices::u_bar_vec;

    fn random_g1_affine() -> G1Affine {
        let mut rng = rand::thread_rng();
        ark_bn254::G1Projective::rand(&mut rng).into_affine()
    }

    fn set_pi_wires(pi: &G1Affine) -> (Wires, Wires) {
        let x_wires = Fq::wires_set(pi.x);
        let y_wires = Fq::wires_set(pi.y);
        (x_wires, y_wires)
    }

    #[test]
    fn test_babe_gc_on_curve() {
        let pi = random_g1_affine();
        let g = random_g1_affine();

        let (pi_x, pi_y) = set_pi_wires(&pi);
        let mut circuit = babe_gc(pi_x, pi_y, g);

        // print number of gates by type
        circuit.gate_counts().print();

        for gate in &mut circuit.1 {
            gate.evaluate();
        }

        // Output should be ū(π)
        let output: Vec<bool> = circuit.0.iter().map(|w| w.borrow().get_value()).collect();
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
        // Construct a point (x, y) that is NOT on the curve by using a random x, y pair.
        let pi = random_g1_affine();
        let g = random_g1_affine();
        let bad_y = pi.y + ark_bn254::Fq::from(1u64);

        let (pi_x, bad_pi_y) = {
            let x_wires = Fq::wires_set(pi.x);
            let y_wires = Fq::wires_set(bad_y);
            (x_wires, y_wires)
        };

        let mut circuit = babe_gc(pi_x, bad_pi_y, g);
        for gate in &mut circuit.1 {
            gate.evaluate();
        }

        // Output should be ū(g)
        let output: Vec<bool> = circuit.0.iter().map(|w| w.borrow().get_value()).collect();
        assert_eq!(output.len(), L);

        // u₀ = 1
        assert!(output[0]);

        // Check x bits match g.x
        let gx_bits = Fq::to_bits(g.x);
        for k in 0..N {
            assert_eq!(output[1 + k], gx_bits[k], "g.x bit {k} mismatch");
        }

        // Check y bits match g.y
        let gy_bits = Fq::to_bits(g.y);
        for k in 0..N {
            assert_eq!(output[1 + N + k], gy_bits[k], "g.y bit {k} mismatch");
        }
    }

    /// Tests the full garbled circuit flow for BABE GC, including garbling
    /// and garbled evaluation.
    #[test]
    fn test_babe_gc_garbled_labels() {
        let pi = random_g1_affine();
        let g = random_g1_affine();

        let (pi_x, pi_y) = set_pi_wires(&pi);
        let mut circuit = babe_gc(pi_x, pi_y, g);

        for gate in &mut circuit.1 {
            gate.evaluate();
        }
        let garblings = circuit.garbled_gates();

        // Run the garbled evaluator path.  Internal asserts check every gate is correct.
        let _ = circuit.garbled_evaluate(&garblings);

        let output_labels: Vec<S> = circuit
            .0
            .iter()
            .map(|w| w.borrow().select(w.borrow().get_value()))
            .collect();
        assert_eq!(output_labels.len(), L);

        // === Verify labels decode to the expected ū(π) bits ===
        let u_bar = u_bar_vec(&pi);
        assert_eq!(u_bar.len(), L);

        for k in 0..L {
            let expected_bit = !u_bar[k].is_zero();
            let expected_label = circuit.0[k].borrow().select(expected_bit);
            assert_eq!(
                output_labels[k], expected_label,
                "garbled output label mismatch at ū[{k}]"
            );
        }
    }
}
