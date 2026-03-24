mod adaptor;
pub mod utils;
pub mod circuit;

use std::cell::RefCell;
use std::fs;
use std::rc::Rc;
pub use circuit::*;
pub use adaptor::*;
use garbled_snark_verifier::bag::{Circuit, Gate, Wire};
use garbled_snark_verifier::core::gate::GateType;
use garbled_snark_verifier::core::utils::SerializableGate;
pub use utils::*;

pub const GC_GATES_FILE: &str = "babe_gc_gates.bin";
pub const GC_INDICES_FILE: &str = "babe_gc_indices.bin";

pub fn read_fresh_circuit() -> (Circuit, Vec<usize>) {
    let (num_wires_read, gates_read): (u32, Vec<SerializableGate>) =
        bincode::deserialize(&fs::read(GC_GATES_FILE).unwrap())
            .expect("deserialize gates");

    let output_indices_read: Vec<usize> =
        bincode::deserialize(&fs::read(GC_INDICES_FILE).unwrap())
            .expect("deserialize indices");

    let wires_reconstructed: Vec<_> = (0..num_wires_read)
        .map(|id| Rc::new(RefCell::new(Wire { label: None, value: None, id: Some(id) })))
        .collect();

    let gates_reconstructed: Vec<Gate> = gates_read.iter().map(|sg| {
        Gate::new_with_gid(
            wires_reconstructed[sg.wire_a_id as usize].clone(),
            wires_reconstructed[sg.wire_b_id as usize].clone(),
            wires_reconstructed[sg.wire_c_id as usize].clone(),
            GateType::try_from(sg.gate_type).expect("unknown gate type"),
            sg.gid,
        )
    }).collect();

    (Circuit(wires_reconstructed, gates_reconstructed), output_indices_read)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use ark_bn254::G1Affine;
    use ark_ec::AffineRepr;
    use garbled_snark_verifier::core::utils::{reset_gid, SerializableGate};
    use super::{compile_babe_gc, GC_GATES_FILE, GC_INDICES_FILE};

    #[test]
    fn test_babe_gc_serialize_roundtrip() {
        reset_gid();
        let g = G1Affine::generator();
        let (bld, output_indices) = compile_babe_gc(g);
        let circuit = bld.build(&[]);

        // --- Serialize ---

        // File 1: (num_wires: u32, gates: Vec<SerializableGate>)
        let num_wires = circuit.0.len() as u32;
        let gates: Vec<SerializableGate> = circuit.1.iter().map(|gate| SerializableGate {
            gate_type: gate.gate_type as u8,
            wire_a_id: gate.wire_a.borrow().id.unwrap(),
            wire_b_id: gate.wire_b.borrow().id.unwrap(),
            wire_c_id: gate.wire_c.borrow().id.unwrap(),
            gid: gate.gid,
        }).collect();
        let gates_bytes = bincode::serialize(&(num_wires, &gates)).expect("serialize gates");
        fs::write(GC_GATES_FILE, &gates_bytes).expect("write gates");

        // File 2: Vec<usize> output indices
        let indices_bytes = bincode::serialize(&output_indices).expect("serialize indices");
        fs::write(GC_INDICES_FILE, &indices_bytes).expect("write indices");


        // --- Reconstruct Circuit ---

        let (circuit_reconstructed, output_indices_reconstructed) = super::read_fresh_circuit();


        assert_eq!(circuit_reconstructed.0.len(), circuit.0.len(), "reconstructed wire count mismatch");
        assert_eq!(circuit_reconstructed.1.len(), circuit.1.len(), "reconstructed gate count mismatch");

        for (i, (orig, rec)) in circuit.1.iter().zip(circuit_reconstructed.1.iter()).enumerate() {
            assert_eq!(orig.gate_type, rec.gate_type, "reconstructed gate[{i}] type mismatch");
            assert_eq!(orig.wire_a.borrow().id, rec.wire_a.borrow().id, "reconstructed gate[{i}] wire_a id mismatch");
            assert_eq!(orig.wire_b.borrow().id, rec.wire_b.borrow().id, "reconstructed gate[{i}] wire_b id mismatch");
            assert_eq!(orig.wire_c.borrow().id, rec.wire_c.borrow().id, "reconstructed gate[{i}] wire_c id mismatch");
            assert_eq!(orig.gid, rec.gid, "reconstructed gate[{i}] gid mismatch");
        }

        println!("wires={num_wires}, gates={}, output_indices={}", gates.len(), output_indices.len());
        println!("Circuit reconstructed successfully from serialized data.");

        // Cleanup
        // fs::remove_file("test_babe_gc_gates.bin").ok();
        // fs::remove_file("test_babe_gc_indices.bin").ok();
    }
}