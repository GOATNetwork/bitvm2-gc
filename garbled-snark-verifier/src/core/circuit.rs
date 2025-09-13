use crate::{
    bag::*,
    core::gate::{GateCount, GateTrait},
};

// wires, gates
#[derive(Debug)]
pub struct Circuit(pub Wires, pub Vec<Gate<Wirex>>);

impl Circuit {
    pub fn empty() -> Self {
        Self(Vec::new(), Vec::new())
    }

    pub fn new(wires: Wires, gates: Vec<Gate<Wirex>>) -> Self {
        Self(wires, gates)
    }

    // calculate all ciphertext, and send to evaluator
    pub fn garbled_gates(&self) -> Vec<Option<S>> {
        self.1
            .iter()
            .enumerate()
            .map(|(i, gate)| {
                if i.is_multiple_of(1000000) {
                    println!("Garble batch: {}/{}", i, self.1.len());
                }
                gate.garbled()
            })
            .collect()
    }

    pub fn extend(&mut self, circuit: Self) -> Wires {
        self.1.extend(circuit.1);
        circuit.0
    }

    pub fn add(&mut self, gate: Gate<Wirex>) {
        self.1.push(gate);
    }

    pub fn add_wire(&mut self, wire: Wirex) {
        self.0.push(wire);
    }

    pub fn add_wires(&mut self, wires: Wires) {
        self.0.extend(wires);
    }

    pub fn gate_count(&self) -> usize {
        self.1.len()
    }

    pub fn gate_counts(&self) -> GateCount {
        let mut gc = GateCount::default();
        for gate in self.1.iter() {
            gc.0[gate.gate_type as usize] += 1;
        }
        gc
    }

    pub fn garbled_evaluate(&self, garblings: &[Option<S>]) -> S {
        let mut garbled_evaluations = vec![];
        for (i, gate) in self.1.iter().enumerate() {
            let (output, output_label) = gate.e()(
                gate.wire_a.borrow().get_value(),
                gate.wire_b.borrow().get_value(),
                gate.wire_a.borrow().select(gate.wire_a.borrow().get_value()),
                gate.wire_b.borrow().select(gate.wire_b.borrow().get_value()),
                garblings[i],
                gate.gid,
            );
            // check the output is correct
            assert_eq!(output, gate.wire_c.borrow().get_value());
            garbled_evaluations.push((output, output_label));
        }

        for (i, gate) in self.1.iter().enumerate() {
            let check = gate.check_garbled_circuit(garbled_evaluations[i].1);
            assert!(check);
        }

        garbled_evaluations.last().unwrap().1
    }
}

#[cfg(test)]
mod tests {
    use crate::bag::new_wirex;
    use crate::circuits::basic::selector;
    use crate::circuits::bn254::fq6::Fq6;
    use crate::circuits::bn254::g1::{projective_to_affine_montgomery, G1Projective};
    use crate::core::utils::DELTA;
    use ark_ec::CurveGroup;
    use ark_ff::{AdditiveGroup, Field};

    #[cfg(feature = "garbled")]
    #[test]
    fn test_selector_circuit_garbled_evaluation() {
        let mut wire_a = new_wirex();
        wire_a.borrow_mut().set(false);

        let mut wire_b = new_wirex();
        wire_b.borrow_mut().set(true);

        let mut wire_c = new_wirex();
        wire_c.borrow_mut().set(false);

        let mut circuit = selector(wire_a, wire_b, wire_c);

        for gate in &mut circuit.1 {
            gate.evaluate();
        }
        let garblings = circuit.garbled_gates();
        let output_label = circuit.garbled_evaluate(&garblings);

        // hand-computing output label
        let g1_output_label = circuit.1[0].wire_a.borrow().select(false).hash_ext(circuit.1[0].gid);
        let g2_output_label = circuit.1[1].wire_a.borrow().select(false).hash_ext(circuit.1[1].gid)
            ^ garblings[1].unwrap()
            ^ circuit.1[1].wire_b.borrow().select(true);
        let computed_output_label = (g1_output_label).hash_ext(circuit.1[2].gid)
            ^ garblings[2].unwrap()
            ^ (g2_output_label ^ DELTA);

        assert_eq!(output_label, computed_output_label);
    }

    #[cfg(feature = "garbled")]
    #[test]
    fn test_fq6_mul_montgomery_circuit_garbled_evaluation() {
        let a = Fq6::random();
        let b = Fq6::random();
        let mut circuit = Fq6::mul_montgomery(
            Fq6::wires_set(Fq6::as_montgomery(a)),
            Fq6::wires_set(Fq6::as_montgomery(b)),
        );
        circuit.gate_counts().print();
        for gate in &mut circuit.1 {
            gate.evaluate();
        }
        let garblings = circuit.garbled_gates();
        let _ = circuit.garbled_evaluate(&garblings);
    }

    #[cfg(feature = "garbled")]
    #[test]
    fn test_g1_projective_to_affine_montgomery_circuit_garbled_evaluation() {
        let p_projective = G1Projective::random().double();
        assert_ne!(p_projective.z, ark_bn254::Fq::ONE);
        let p_affine = p_projective.into_affine();
        let mut circuit =
            projective_to_affine_montgomery(G1Projective::wires_set_montgomery(p_projective));
        circuit.gate_counts().print();
        for gate in &mut circuit.1 {
            gate.evaluate();
        }
        let garblings = circuit.garbled_gates();
        let _ = circuit.garbled_evaluate(&garblings);
    }
}
