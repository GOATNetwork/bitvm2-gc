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

    // garbled_evaluate evaluates the circuit with garbled gates
    // return a vector of (output_value, output_label, garbled_c)
    pub fn garbled_evaluate(&mut self) -> Vec<(bool, S, Option<S>)> {
        let garbled = self.garbled_gates();
        for gate in self.1.iter_mut() {
            gate.evaluate();
        }
        let mut res = vec![];
        for (i, gate) in self.1.iter_mut().enumerate() {
            let (output, output_label) = gate.e()(
                gate.wire_a.borrow().get_value(),
                gate.wire_b.borrow().get_value(),
                gate.wire_a.borrow().select(gate.wire_a.borrow().get_value()),
                gate.wire_b.borrow().select(gate.wire_b.borrow().get_value()),
                garbled[i],
                gate.gid,
            );
            res.push((output, output_label, garbled[i]));
        }
        res
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

        // let mut wire_c = new_wirex();
        // wire_c.borrow_mut().set(false);
        //
        // let mut circuit = selector(wire_a, wire_b, wire_c);
        // let garbled_evaluate = circuit.garbled_evaluate();

        let d = new_wirex();
        let gate_1 = Gate::cimp(wire_a, wire_b, d.clone());
        let mut circuit = Circuit::new(vec![d], vec![gate_1]);

        let garbled = circuit.garbled_gates();
        let o_1 = circuit.1[0].wire_a.borrow().select(true).hash_ext(circuit.1[0].gid);

        let o_2 = circuit.1[0].wire_a.borrow().select(false).hash_ext(circuit.1[0].gid)
            ^ garbled[0].unwrap()
            ^ circuit.1[0].wire_b.borrow().select(true);

        // println!("wire_a_0: {:?}", circuit.1[0].wire_a.borrow().select(false));
        // println!("wire_a_1: {:?}", circuit.1[0].wire_a.borrow().select(true));
        // println!("h0 = o_1 = : {:?}", o_1);
        // println!("h_")

        assert_eq!(o_1, o_2);

        // let garbled_evaluate = circuit.garbled_evaluate();

        // // check x values
        // for (i, gate) in circuit.1.iter_mut().enumerate() {
        //     println!("Garbled gate: {:?}", gate.gate_type);
        //     let gate_x = gate.get_garbled_evaluation_x(&garbled_evaluate[i]);
        //     println!("i: {:?}", i);
        //     assert_eq!(gate_x, gate.wire_a.borrow().get_value());
        // }
        //
        // // hand compute output label
        // let gate1_c0 = circuit.1[0].wire_a.borrow().select(false).hash_ext(circuit.1[0].gid);
        // assert_eq!(gate1_c0, circuit.1[0].wire_c.borrow().select(true));
        //
        // let gate2_c0 = circuit.1[1].wire_a.borrow().select(false).hash_ext(circuit.1[1].gid)
        //     ^ garbled_evaluate[1].2.unwrap()
        //     ^ circuit.1[1].wire_b.borrow().select(true);
        // assert_eq!(gate2_c0, circuit.1[1].wire_c.borrow().select(true));
    }
}
