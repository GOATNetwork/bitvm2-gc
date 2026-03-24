use crate::instance::commit::CACInstanceCommit;

/// What the Verifier sends to the Prover during the C&C commit phase.
pub struct CACSetupPackage {
    /// One commit per C&C instance, in instance order.
    pub commits: Vec<CACInstanceCommit>,
}
