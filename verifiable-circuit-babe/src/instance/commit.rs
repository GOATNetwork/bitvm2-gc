use crate::babe::compute_epk_with_delta;
use crate::gc::gc_ciphertexts_commit;
use crate::instance::BABEInstance;
use crate::utils::{derive_hashlock, h_256};

/// Per-instance commitment sent from Verifier to Prover during C&C commit phase.
#[derive(Debug, Clone)]
pub struct CACInstanceCommit {
    /// SHA256(label0) and SHA256(label1) for each input wire.
    pub epk: Vec<[[u8; 32]; 2]>,
    /// SHA256(label0) and SHA256(label1) for each of the 2 constant wires.
    pub constant_commits: [[[u8; 32]; 2]; 2],
    pub h_msg: [u8; 20],
    /// RO(ct_setup) = SHA256(ct2_r_delta_g2 || ct3_masked_msg).
    pub h_ct_setup: [u8; 32],
    /// SHA256 commitment to the adaptor table.
    pub com_adaptor: [u8; 32],
    /// SHA256 commitment to the GC gate ciphertexts.
    pub com_gc: [u8; 32],
}

impl CACInstanceCommit {
    pub fn from_instance(instance: &BABEInstance) -> Self {
        let delta = instance.secrets.delta;

        let input_commits = compute_epk_with_delta(&instance.secrets.encoding_keys, delta).0;

        let constant_commits = std::array::from_fn(|w| {
            let l0 = instance.secrets.constant_0labels[w];
            [h_256(&l0.0), h_256(&(l0 ^ delta).0)]
        });

        let mut ct_setup_bytes = Vec::new();
        ct_setup_bytes.extend_from_slice(&instance.ct_setup.ct2_r_delta_g2);
        ct_setup_bytes.extend_from_slice(&instance.ct_setup.ct3_masked_msg);

        CACInstanceCommit {
            epk: input_commits,
            constant_commits,
            h_msg: derive_hashlock(&instance.secrets.msg),
            h_ct_setup: h_256(&ct_setup_bytes),
            com_adaptor: instance.adaptor_table.commit(),
            com_gc: gc_ciphertexts_commit(&instance.ciphertexts),
        }
    }
}
