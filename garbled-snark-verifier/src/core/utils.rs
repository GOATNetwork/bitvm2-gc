use std::{cell::RefCell, rc::Rc, sync::atomic::AtomicU32};

use serde::{Deserialize, Serialize};

use crate::{
    bag::{Circuit, Gate, S, Wire},
    core::gate::{GateType, gate_garbled},
};

use std::sync::atomic::Ordering;

pub const LABEL_SIZE: usize = 16;
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
pub fn hash(input: &[u8]) -> [u8; LABEL_SIZE] {
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
    unsafe { *(output.as_ptr() as *const [u8; LABEL_SIZE]) }
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
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

struct Reader<'a> {
    buf: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, cursor: 0 }
    }

    fn read_u8(&mut self) -> u8 {
        let b = self.buf[self.cursor];
        self.cursor += 1;
        b
    }

    fn read_u32(&mut self) -> u32 {
        let start = self.cursor;
        let v = u32::from_le_bytes(self.buf[start..start + 4].try_into().unwrap());
        self.cursor += 4;
        v
    }

    fn read_u64(&mut self) -> u64 {
        let start = self.cursor;
        let v = u64::from_le_bytes(self.buf[start..start + 8].try_into().unwrap());
        self.cursor += 8;
        v
    }

    fn read_s(&mut self) -> S {
        let mut arr = [0u8; LABEL_SIZE];
        arr.copy_from_slice(&self.buf[self.cursor..self.cursor + LABEL_SIZE]);
        self.cursor += LABEL_SIZE;
        S(arr)
    }

    fn read_option_s(&mut self) -> Option<S> {
        match self.read_u8() {
            0 => None,
            1 => Some(self.read_s()),
            other => panic!("Invalid Option<S> tag: {}", other),
        }
    }

    fn skip_option_bool(&mut self) {
        if self.read_u8() != 0 {
            self.cursor += 1;
        }
    }

    fn skip_wire(&mut self) {
        // Option<S>
        if self.read_u8() != 0 {
            self.cursor += LABEL_SIZE;
        }
        // Option<bool>
        self.skip_option_bool();
    }

    fn read_gate_type(&mut self) -> GateType {
        let d = self.read_u32();
        GateType::try_from(d as u8).expect("Invalid GateType")
    }
}

pub fn check_guest(buf: &[u8]) {
    let mut reader = Reader::new(buf);

    // 1. Read the number of gates from the start of the buffer.
    // bincode serializes Vec length as a u64.
    let num_gates = reader.read_u64() as usize;

    // 2. Create a vector to store the computed garblings.
    let mut computed_garblings = Vec::with_capacity(num_gates);

    // 3. Loop through each gate's data in the stream.
    for _ in 0..num_gates {
        // For wire_a, read the label and correctly skip the rest of the wire.
        let a0 = reader.read_option_s().expect("Missing wire_a label");
        reader.skip_option_bool();

        // For wire_b, read the label and correctly skip the rest of the wire.
        let b0 = reader.read_option_s().expect("Missing wire_b label");
        reader.skip_option_bool();

        // Skip wire_c entirely.
        reader.skip_wire();

        // Read gate_type and gid.
        let gate_type = reader.read_gate_type();
        let gid = reader.read_u32();

        // Immediately compute the garbling.
        let (_, ciphertext) = gate_garbled(a0, b0, gid, gate_type);
        computed_garblings.push(ciphertext);
    }

    // 4. At this point, the reader is at the start of the serialized `garblings` Vec.
    // Read the number of expected garblings.
    let num_garblings = reader.read_u64() as usize;
    assert_eq!(num_gates, num_garblings, "Mismatch in number of garblings");

    // 5. Compare computed garblings with expected garblings from the stream.
    for i in 0..num_garblings {
        let expected_garbling = reader.read_option_s();
        assert_eq!(computed_garblings[i], expected_garbling, "Garbling mismatch at index {}", i);
    }
}
