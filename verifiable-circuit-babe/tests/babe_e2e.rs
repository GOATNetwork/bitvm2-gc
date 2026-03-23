#[cfg(feature = "garbled")]
#[test]
fn e2e_babe_with_one_instance_flow() {
    use verifiable_circuit_babe::babe::{run_babe_e2e_with_one_instance, derive_hashlock, OnchainSize};
    let run = run_babe_e2e_with_one_instance();
    // The decrypted msg must satisfy the hashlock.
    assert_eq!(derive_hashlock(&run.wrongly_challenged_witness.msg), run.h_msg);
    // Witness sizes are as expected.
    assert_eq!(run.assert_witness.size_bytes(), 8161);
    assert_eq!(run.challenge_assert_witness.size_bytes(), 16320);
    assert_eq!(run.wrongly_challenged_witness.size_bytes(), 64);
}
