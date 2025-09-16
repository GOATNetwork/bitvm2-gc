use std::{cell::RefCell, rc::Rc, sync::atomic::AtomicU32};

use serde::{Deserialize, Serialize};

use crate::{
    bag::{Circuit, Gate, S, Wire},
    core::gate::{GateType, gate_garbled},
};

use std::sync::atomic::Ordering;

pub const LABLE_SIZE: usize = 16;
// FIXME: set up a private global difference
pub static DELTA: S = S::one();

// u32 is not enough for current gates scale.
pub static GID: AtomicU32 = AtomicU32::new(0);

#[inline(always)]
pub fn inc_gid() -> u32 {
    GID.fetch_add(1, Ordering::SeqCst) + 1
}

pub fn bit_to_usize(bit: bool) -> usize {
    if bit { 1 } else { 0 }
}

#[allow(unused_variables)]
pub fn hash(input: &[u8]) -> [u8; LABLE_SIZE] {
    #[allow(unused_assignments, unused_mut)]
    let mut output = [0u8; 32];

    #[cfg(feature = "_blake3")]
    {
        use blake3::hash;
        output = *hash(input).as_bytes();
    }

    #[cfg(feature = "_sha2")]
    {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(input);
        let result = hasher.finalize();
        output.copy_from_slice(&result[..32]);
    }

    #[cfg(feature = "_poseidon2")]
    {
        use poseidon2::poseidon2;
        output = poseidon2(input);
    }
    #[cfg(feature = "_aes")]
    {
        use aes::Aes128;
        use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
        use std::cmp::min;

        // hardcoded AES key
        let key = GenericArray::from_slice(&[0u8; 16]);
        let cipher = Aes128::new(&key);

        // using Cipher Block Chaining
        // hardcoded IV
        let mut block = GenericArray::clone_from_slice(&[0u8; 16]);

        // using Cipher Block Chaining
        for chunk in input.chunks(16) {
            for i in 0..min(chunk.len(), 16) {
                block[i] ^= chunk[i];
            }
            cipher.encrypt_block(&mut block);
        }
        output[..16].copy_from_slice(&block);
    }
    unsafe { *(output.as_ptr() as *const [u8; LABLE_SIZE]) }
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct SerializableGate {
    pub wire_a: Wire,
    pub wire_b: Wire,
    pub wire_c: Wire,
    pub gate_type: GateType,
    pub gid: u32,
}

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct SerializableCircuit {
    pub gates: Vec<SerializableGate>, // Must also be serializable
    pub garblings: Vec<Option<S>>,
}

impl SerializableCircuit {
    fn garbled_gates(&mut self) -> Vec<Option<S>> {
        self.gates
            .iter_mut()
            .enumerate()
            .map(|(i, gate)| {
                let a0 = gate.wire_a.select(false);
                let b0 = gate.wire_b.select(false);

                let (c0, ciphertext) = gate_garbled(a0, b0, gate.gid, gate.gate_type);
                gate.wire_c.set_label(c0);

                ciphertext
            })
            .collect()
    }
}

impl From<&Circuit> for SerializableCircuit {
    fn from(c: &Circuit) -> Self {
        //let wires = c.0.iter().map(|w| w.borrow().clone()).collect();
        let gates =
            c.1.iter()
                .map(|w| SerializableGate {
                    wire_a: w.wire_a.borrow().clone(),
                    wire_b: w.wire_b.borrow().clone(),
                    wire_c: w.wire_c.borrow().clone(),
                    gate_type: w.gate_type,
                    gid: w.gid,
                })
                .collect();
        Self { gates, garblings: Vec::new() }
    }
}

impl From<&SerializableCircuit> for Circuit {
    fn from(sc: &SerializableCircuit) -> Self {
        let mut wires = vec![];
        let gates = sc
            .gates
            .iter()
            .map(|g| {
                wires.push(Rc::new(RefCell::new(g.wire_a.clone())));
                wires.push(Rc::new(RefCell::new(g.wire_b.clone())));
                wires.push(Rc::new(RefCell::new(g.wire_c.clone())));
                Gate {
                    wire_a: wires[wires.len() - 3].clone(),
                    wire_b: wires[wires.len() - 2].clone(),
                    wire_c: wires[wires.len() - 1].clone(),
                    gate_type: g.gate_type,
                    gid: g.gid,
                }
            })
            .collect();
        Self(wires, gates)
    }
}

pub fn check_guest(buf: &[u8]) {
    let mut sc: SerializableCircuit = bincode::deserialize(buf).unwrap();
    let garblings = sc.garbled_gates();
    assert_eq!(garblings, sc.garblings);
}
