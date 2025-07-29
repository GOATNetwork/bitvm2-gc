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

    pub fn garbled_evaluate(&mut self) {
        let garbled = self.garbled_gates();
        for gate in self.1.iter_mut() {
            gate.evaluate();
        }
        let mut garbled_evaluate = vec![];
        for (i, gate) in self.1.iter_mut().enumerate() {
            let (output, output_label) = gate.e()(
                gate.wire_a.borrow().get_value(),
                gate.wire_b.borrow().get_value(),
                gate.wire_a.borrow().select(gate.wire_a.borrow().get_value()),
                gate.wire_b.borrow().select(gate.wire_b.borrow().get_value()),
                garbled[i],
                gate.gid,
            );
            garbled_evaluate.push((output, output_label));
        }

        for (i, gate) in self.1.iter_mut().enumerate() {
            let check = gate.check_garbled_circuit(garbled_evaluate[i].1);
            assert!(check);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::bag::{new_wirex, Circuit, Gate};
    use crate::circuits::basic::selector;

    #[test]
    fn test_garbled_selector_circuit() {
        let mut wire_a = new_wirex();
        wire_a.borrow_mut().set(false);

        let mut wire_b = new_wirex();
        wire_b.borrow_mut().set(true);

        let mut wire_c = new_wirex();
        wire_c.borrow_mut().set(false);

        let mut circuit = selector(wire_a, wire_b, wire_c);
        circuit.garbled_evaluate();
    }
}
