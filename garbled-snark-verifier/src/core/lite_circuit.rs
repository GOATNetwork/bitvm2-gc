use crate::bag::{Gate, GateCount, Wire, WireIds, S};
use crate::core::gate::GateTrait;
use crate::core::wire::WireId;

#[derive(Debug)]
pub struct LiteCircuit(pub WireIds, pub Vec<Gate<WireId>>, pub Vec<Wire>);

impl LiteCircuit {
    pub fn empty() -> Self {
        Self(Vec::new(), Vec::new(), Vec::new())
    }

    pub fn new(wire_ids: WireIds, gates: Vec<Gate<WireId>>, wires: Vec<Wire>) -> Self {
        Self(wire_ids, gates, wires)
    }

    // calculate all ciphertext, and send to evaluator
    pub fn garbled_gates(&mut self) -> Vec<Option<S>> {
        self.1
            .iter()
            .enumerate()
            .map(|(i, gate)| {
                if i.is_multiple_of(1000000) {
                    println!("Garble batch: {}/{}", i, self.1.len());
                }
                gate.garbled(&mut self.2)
            })
            .collect()
    }

    pub fn extend(&mut self, circuit: Self) -> WireIds {
        self.1.extend(circuit.1);
        circuit.0
    }

    pub fn add(&mut self, gate: Gate<WireId>) {
        self.1.push(gate);
    }

    pub fn add_wire(&mut self, wire: WireId) {
        self.0.push(wire);
    }

    pub fn add_wires(&mut self, wires: WireIds) {
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

    pub fn garbled_evaluate(&mut self, garblings: &[Option<S>]) -> S {
        let mut garbled_evaluations = vec![];
        for (i, gate) in self.1.iter().enumerate() {
            let (output, output_label) = gate.e()(
                self.2[gate.wire_a as usize].get_value(),
                self.2[gate.wire_b as usize].get_value(),
                self.2[gate.wire_a as usize].select(self.2[gate.wire_a as usize].get_value()),
                self.2[gate.wire_b as usize].select(self.2[gate.wire_b as usize].get_value()),
                garblings[i],
                gate.gid,
            );
            // check the output is correct
            assert_eq!(output, self.2[gate.wire_c as usize].get_value());
            garbled_evaluations.push((output, output_label));
        }

        for (i, gate) in self.1.iter().enumerate() {
            let check = gate.check_garbled_circuit(garbled_evaluations[i].1, &mut self.2);
            assert!(check);
        }

        garbled_evaluations.last().unwrap().1
    }
}