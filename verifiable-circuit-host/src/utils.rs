use crate::mem_fs;
use garbled_snark_verifier::bag::Circuit;
use garbled_snark_verifier::core::utils::{SerializableCircuit, SerializableGate};
use std::time::Instant;
use tracing::info;

pub fn gen_sub_circuits(circuit: &mut Circuit, max_gates: usize) {
    let start = Instant::now();
    let mut garbled_gates = circuit.garbled_gates();
    let elapsed = start.elapsed();
    info!(step = "garble gates", elapsed =? elapsed, "garbled gates: {}", garbled_gates.len());

    let size = circuit.1.len().div_ceil(max_gates);

    let start = Instant::now();
    circuit.1.chunks(max_gates).enumerate().zip(garbled_gates.chunks_mut(max_gates)).for_each(
        |((i, w), garblings)| {
            info!(step = "gen_sub_circuits", "Split batch {i}/{size}");
            let out = SerializableCircuit {
                gates: w
                    .iter()
                    .map(|w| SerializableGate {
                        wire_a: w.wire_a.borrow().clone(),
                        wire_b: w.wire_b.borrow().clone(),
                        wire_c: w.wire_c.borrow().clone(),
                        gate_type: w.gate_type,
                        gid: w.gid,
                    })
                    .collect(),
                garblings: garblings.to_vec(),
            };
            // In this demo, we only save the first sub-circuit
            if i == 0 {
                let start = Instant::now();
                bincode::serialize_into(
                    //std::fs::File::create(format!("garbled_{i}.bin")).unwrap(),
                    mem_fs::MemFile::create(format!("garbled_{i}.bin")).unwrap(),
                    &out,
                )
                .unwrap();
                let elapsed = start.elapsed();
                info!(step = "gen_sub_circuits", elapsed = ?elapsed, "Writing garbled_{i}.bin");
            }
        },
    );
    let elapsed = start.elapsed();
    info!(step = "gen_sub_circuits", elapsed =? elapsed, "total time");
}
