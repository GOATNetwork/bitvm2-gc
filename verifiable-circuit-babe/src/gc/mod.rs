mod adaptor;
pub mod utils;
pub mod circuit;

use std::cell::RefCell;
use std::fs;
use std::rc::Rc;
use std::sync::OnceLock;
use ark_bn254::G1Affine;
use ark_ec::AffineRepr;
pub use circuit::*;
pub use adaptor::*;
use garbled_snark_verifier::bag::{Circuit, Gate, Wire};
use garbled_snark_verifier::core::gate::GateType;
use garbled_snark_verifier::core::utils::{reset_gid, SerializableGate};
pub use utils::*;

fn gc_gates_path() -> String {
    std::env::var("GC_GATES_PATH").unwrap_or_else(|_| "./babe_gc_gates.bin".to_string())
}

fn gc_indices_path() -> String {
    std::env::var("GC_INDICES_PATH").unwrap_or_else(|_| "./babe_gc_indices.bin".to_string())
}

/// Raw circuit bytes cached on first read.
static CIRCUIT_BYTES: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();

pub fn read_fresh_circuit() -> (Circuit, Vec<usize>) {
    let (gates_bytes, indices_bytes) = CIRCUIT_BYTES.get_or_init(|| {
        let gates_path = gc_gates_path();
        let indices_path = gc_indices_path();
        let g = fs::read(&gates_path)
            .unwrap_or_else(|_| panic!("'{}' not found — run function generate_and_write_fresh_circuit() to generate it.", gates_path));
        let i = fs::read(&indices_path)
            .unwrap_or_else(|_| panic!("'{}' not found — run function generate_and_write_fresh_circuit() to generate it.", indices_path));
        (g, i)
    });

    let (num_wires, gates_read): (u32, Vec<SerializableGate>) =
        bincode::deserialize(gates_bytes).expect("deserialize gates");
    let output_indices: Vec<usize> =
        bincode::deserialize(indices_bytes).expect("deserialize indices");

    let wires: Vec<_> = (0..num_wires)
        .map(|id| Rc::new(RefCell::new(Wire { label: None, value: None, id: Some(id) })))
        .collect();
    wires[0].borrow_mut().value = Some(false);
    wires[1].borrow_mut().value = Some(true);

    let gates: Vec<Gate> = gates_read.iter().map(|sg| {
        Gate::new_with_gid(
            wires[sg.wire_a_id as usize].clone(),
            wires[sg.wire_b_id as usize].clone(),
            wires[sg.wire_c_id as usize].clone(),
            GateType::try_from(sg.gate_type).expect("unknown gate type"),
            sg.gid,
        )
    }).collect();

    (Circuit(wires, gates), output_indices)
}

pub fn generate_and_write_fresh_circuit() {
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
    fs::write(gc_gates_path(), &gates_bytes).expect("write gates");

    // File 2: Vec<usize> output indices
    let indices_bytes = bincode::serialize(&output_indices).expect("serialize indices");
    fs::write(gc_indices_path(), &indices_bytes).expect("write indices");
}

#[cfg(test)]
mod tests {
    use std::fs;
    use ark_bn254::G1Affine;
    use ark_ec::AffineRepr;
    use garbled_snark_verifier::core::utils::{reset_gid, SerializableGate};
    use super::{compile_babe_gc, generate_and_write_fresh_circuit};

    #[test]
    #[ignore]
    fn test_babe_gc_serialize_roundtrip() {
        generate_and_write_fresh_circuit();

        reset_gid();
        let g = G1Affine::generator();
        let (bld, output_indices) = compile_babe_gc(g);
        let circuit = bld.build(&[]);
        let num_wires = circuit.0.len() as u32;

        // --- Reconstruct Circuit ---

        let (circuit_reconstructed, _) = super::read_fresh_circuit();


        assert_eq!(circuit_reconstructed.0.len(), circuit.0.len(), "reconstructed wire count mismatch");
        assert_eq!(circuit_reconstructed.1.len(), circuit.1.len(), "reconstructed gate count mismatch");

        for (i, (orig, rec)) in circuit.1.iter().zip(circuit_reconstructed.1.iter()).enumerate() {
            assert_eq!(orig.gate_type, rec.gate_type, "reconstructed gate[{i}] type mismatch");
            assert_eq!(orig.wire_a.borrow().id, rec.wire_a.borrow().id, "reconstructed gate[{i}] wire_a id mismatch");
            assert_eq!(orig.wire_b.borrow().id, rec.wire_b.borrow().id, "reconstructed gate[{i}] wire_b id mismatch");
            assert_eq!(orig.wire_c.borrow().id, rec.wire_c.borrow().id, "reconstructed gate[{i}] wire_c id mismatch");
            assert_eq!(orig.gid, rec.gid, "reconstructed gate[{i}] gid mismatch");
        }

        println!("wires={num_wires}, gates={}, output_indices={}", circuit.1.len(), output_indices.len());
        println!("Circuit reconstructed successfully from serialized data.");
    }
}