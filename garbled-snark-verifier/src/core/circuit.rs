use crate::{bag::*, core::gate::GateCount};

// wires, gates
#[derive(Debug)]
pub struct Circuit(pub Wires, pub Vec<Gate>);

impl Circuit {
    pub fn empty() -> Self {
        Self(Vec::new(), Vec::new())
    }

    pub fn new(wires: Wires, gates: Vec<Gate>) -> Self {
        Self(wires, gates)
    }

    // calculate all ciphertext, and send to evaluator
    pub fn garbled_gates(&self) -> Vec<Option<S>> {
        self.1.iter().enumerate().map(|(i, gate)| {
            if i.is_multiple_of(1000000) {
                println!("Garble batch: {}/{}", i, self.1.len());
            }
            gate.garbled()
        }).collect()
    }

    pub fn extend(&mut self, circuit: Self) -> Wires {
        self.1.extend(circuit.1);
        circuit.0
    }

    pub fn add(&mut self, gate: Gate) {
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

    pub fn garbled_evaluate(&mut self) -> Vec<(bool, S)> {
        let garbled = self.garbled_gates();
        for gate in self.1.iter_mut() {
            gate.evaluate();
        }
        let mut res = vec![];
        for (i, gate) in self.1.iter_mut().enumerate() {
            let (output, output_label) = gate.e()(
                gate.wire_a.borrow().get_value(),
                gate.wire_b.borrow().get_value(),
                gate.wire_a.borrow().get_label(),
                gate.wire_b.borrow().get_label(),
                garbled[i],
                i as u32
            );
            res.push((output, output_label));
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use crate::bag::{new_wirex, Circuit, Gate, Wirex};
    use crate::circuits::basic::selector;
    use crate::core::utils::DELTA;

    #[test]
    fn test_garbled_selector_circuit() {
        let mut wire_a = new_wirex();
        wire_a.borrow_mut().set(true);

        let mut wire_b = new_wirex();
        wire_b.borrow_mut().set(false);

        // let mut wire_c = new_wirex();
        // wire_c.borrow_mut().set(false);
        //
        // let mut circuit = selector(wire_a, wire_b, wire_c);
        let d = new_wirex();
        let gate_1 = Gate::nand(wire_a, wire_b, d.clone());
        let mut circuit = Circuit::new(vec![d], vec![gate_1]);
        let garbled_evaluate = circuit.garbled_evaluate();

        for (i, gate) in circuit.1.iter().enumerate() {
            assert_eq!(gate.wire_c.borrow().get_value(), garbled_evaluate[i].0);

            if gate.wire_a.borrow().get_value() { // x = 1, O_1
                assert_eq!(garbled_evaluate[i].1, gate.wire_c.borrow().get_label() ^ DELTA);
            } else { // x = 0, O_0
                assert_eq!(garbled_evaluate[i].1, gate.wire_c.borrow().get_label());
            }
        }
    }
}