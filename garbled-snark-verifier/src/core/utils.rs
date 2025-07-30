use std::{cell::RefCell, rc::Rc, sync::atomic::AtomicU32};

use serde::{Deserialize, Serialize};

use crate::{
    bag::{Circuit, Gate, S, Wire},
    core::gate::GateType,
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
    let sc: SerializableCircuit = bincode::deserialize(buf).unwrap();
    let circuit: Circuit = (&sc).into();
    let garblings = circuit.garbled_gates();
    assert!(garblings == sc.garblings);
}
