use crate::babe::{compute_epk_with_delta, derive_hashlock, h, WeKnownPi1SetupCt};
use crate::gc::gc_ciphertexts_commit;
use crate::instance::BABEInstance;

/// Per-instance commitment sent from Verifier to Prover during C&C commit phase.
#[derive(Debug, Clone)]
pub struct CACInstanceCommit {
    /// SHA256 of label0 and label1 for each input wire
    pub input_commits: Vec<[[u8; 32]; 2]>,
    /// SHA256 of label0 and label1 for each of the 2 constant wires.
    pub constant_commits: [[[u8; 32]; 2]; 2],
    pub h_msg: [u8; 32],
    pub ct_setup: WeKnownPi1SetupCt,
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
            [h(&l0.0), h(&(l0 ^ delta).0)]
        });

        CACInstanceCommit {
            input_commits,
            constant_commits,
            h_msg: derive_hashlock(&instance.secrets.msg),
            ct_setup: instance.ct_setup.clone(),
            com_adaptor: instance.adaptor_table.commit(),
            com_gc: gc_ciphertexts_commit(&instance.ciphertexts),
        }
    }
}
