use verifiable_circuit_babe::babe::{run_babe_e2e, verify_babe_protocol_bundle};

#[test]
fn e2e_babe_bundle_verifies() {
    let run = run_babe_e2e();
    assert!(verify_babe_protocol_bundle(&run.protocol_bundle));
}
