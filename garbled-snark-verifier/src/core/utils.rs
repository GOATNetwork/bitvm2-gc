use std::{cell::RefCell, rc::Rc};

use serde::{Serialize, Deserialize};

use crate::{bag::{Circuit, Gate, Wire}, core::gate::GateType};

pub fn bit_to_usize(bit: bool) -> usize {
    if bit { 1 } else { 0 }
}

#[allow(unused_variables)]
pub fn hash(input: &[u8]) -> [u8; 32] {
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
        use zkm_zkvm::lib::poseidon2::poseidon2;
        output = poseidon2(input);
    }
    output
}

#[derive(Serialize, Deserialize)]
pub struct SerializableGate {
    pub wire_a: Wire,
    pub wire_b: Wire,
    pub wire_c: Wire,
    pub gate_type: GateType,
}

#[derive(Serialize, Deserialize)]
pub struct SerializableCircuit {
    wires: Vec<Wire>,  // Not RefCell, just the plain struct
    gates: Vec<SerializableGate>,  // Must also be serializable
}

impl From<&Circuit> for SerializableCircuit {
    fn from(c: &Circuit) -> Self {
        let wires = c.0.iter().map(|w| w.borrow().clone()).collect();
        let gates = c.1.iter().map(|w| SerializableGate{
            wire_a: w.wire_a.borrow().clone(),
            wire_b: w.wire_b.borrow().clone(),
            wire_c: w.wire_c.borrow().clone(),
            gate_type: w.gate_type,
        }).collect();
        Self { wires, gates }
    }
}

impl From<SerializableCircuit> for Circuit {
    fn from(sc: SerializableCircuit) -> Self {
        let wires = sc.wires.into_iter()
            .map(|w| Rc::new(RefCell::new(w)))
            .collect();
        let gates = sc.gates.iter().map(|g| Gate {
            wire_a: Rc::new(RefCell::new(g.wire_a.clone())), 
            wire_b: Rc::new(RefCell::new(g.wire_b.clone())), 
            wire_c: Rc::new(RefCell::new(g.wire_c.clone())), 
            gate_type: g.gate_type,
        }).collect(); 
        Self(wires, gates)
    }
}