use std::{cell::RefCell, rc::Rc, slice, sync::atomic::AtomicU32};

use serde::{Deserialize, Serialize};

use crate::{
    bag::{Circuit, Gate, S, Wire},
    core::gate::{GateType, gate_garbled},
};

use std::sync::atomic::Ordering;

pub const SUB_CIRCUIT_MAX_GATES: usize = 1_000_000;
pub const SUB_INPUT_GATES_PART_SIZE: usize = 200_000;
pub const SUB_INPUT_GATES_PARTS: usize = 5;
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

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SerializableGate {
    pub gate_type: u8,
    pub wire_a_id: u32,
    pub wire_b_id: u32,
    pub wire_c_id: u32,
    pub gid: u32,
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct SerializableSubCircuitGates<const N: usize> {
    pub gates: [SerializableGate; N],
}

pub fn serialize_to_bytes<const N: usize>(s: &SerializableSubCircuitGates<N>) -> Vec<u8> {
    unsafe {
        let ptr = s as *const SerializableSubCircuitGates<N> as *const u8;
        let bytes = slice::from_raw_parts(ptr, size_of::<SerializableSubCircuitGates<N>>());
        bytes.to_vec()
    }
}

pub fn deserialize_from_bytes<const N: usize>(buf: &[u8]) -> SerializableSubCircuitGates<N> {
    assert!(buf.len() >= std::mem::size_of::<SerializableSubCircuitGates<N>>());
    unsafe {
        let ptr = buf.as_ptr() as *const SerializableSubCircuitGates<N>;
        ptr.read_unaligned()
    }
}


#[repr(C)]
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct SerializableWire {
    pub label: S,
    pub value: Option<bool>,
}

#[repr(C)]
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct SerializableSubWires {
    pub labels: Vec<S>,
    pub value: Vec<Option<bool>>,
}

impl SerializableSubWires {
    pub fn from_serialzable_wires(wires: &[SerializableWire]) -> Self {
        let mut labels = Vec::with_capacity(wires.len());
        let mut value = Vec::with_capacity(wires.len());
        for wire in wires {
            labels.push(wire.label);
            value.push(wire.value);
        }
        SerializableSubWires { labels, value }
    }
}

pub fn check_guest(
    sub_gates_parts: &[Vec<u8>; SUB_INPUT_GATES_PARTS],
    sub_wires: &[u8],
    sub_ciphertexts: &[u8],
) -> Vec<u8>  {
    // read sub_ciphertexts:
    let mut c_start = 0;
    let num_ciphertexts = u64::from_le_bytes(sub_ciphertexts[c_start..c_start + 8].try_into().unwrap());
    c_start += 8;

    // create input for ciphertext check syscall
    let mut input = Vec::new();
    let mut index = 0;
    input.extend_from_slice(&DELTA.0);
    for part in 0..SUB_INPUT_GATES_PARTS {
        let sub_gates: SerializableSubCircuitGates<SUB_INPUT_GATES_PART_SIZE> = deserialize_from_bytes(&sub_gates_parts[part]);
        for i in 0..sub_gates.gates.len() {
            if sub_gates.gates[i].gate_type < 8 { // and | or gate
                let gate = &sub_gates.gates[i];
                let base = 8usize;
                let start_a0 = base + (gate.wire_a_id as usize) * LABEL_SIZE;
                let start_b0 = base + (gate.wire_b_id as usize) * LABEL_SIZE;

                let a0 = S(sub_wires[start_a0..start_a0 + LABEL_SIZE].try_into().unwrap());
                let gid = gate.gid;
                let a1 = a0 ^ DELTA;

                let h0 = a0.hash_ext(gid);
                let h1 = a1.hash_ext(gid);

                // align memory
                input.extend_from_slice(&(sub_gates.gates[i].gate_type as u32).to_le_bytes().to_vec());
                input.extend_from_slice(&h0.0);
                input.extend_from_slice(&h1.0);
                input.extend_from_slice(&sub_wires[start_b0..start_b0 + LABEL_SIZE]);
                input.extend_from_slice(&sub_ciphertexts[c_start..c_start + LABEL_SIZE]);
                index += 1;
                c_start += LABEL_SIZE;
            }
        }
    }
    assert_eq!(index, num_ciphertexts);
    input
}
