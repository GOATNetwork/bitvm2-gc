# Argo MAC Optimization of DV-SNARK Verification in BitVM2 + Garbled Circuits

- Version date: 2026-02-25

## 1. Background and Goal

The goal is to remove the heaviest part of the DV-SNARK verifier (especially the G1 linear-relation check) from the large Boolean GC, execute it in the Argo G1 MAC domain, and inject only one external Boolean result bit back into GC. This significantly reduces gate count.

Core constraints:
- Keep DV-SNARK verification semantics unchanged.
- Keep transcript binding (`root_yao`, `root_argo`, `public input`, `vk hash`) in one commitment.
- Support role separation (garbler / evaluator).

## 2. Principle (from verifier equation to Argo MAC)

### 2.1 Original Step4 verifier relation

The key verifier relation (following current code notation) is:

```text
x1 * G + x2 * Q + z_signed * P = O
```

where `O` is the point at infinity. In the baseline, this is implemented as full MSM/addition/equality checks inside GC, which makes Step4 very expensive.

### 2.2 Argo G1 MAC replacement idea

For each point `R`, instead of checking `R == O` with EC arithmetic inside GC, we check equality in the MAC-tag domain:

```text
For each component i, verify T_i(R) == T_i(O) == K_i
```

Accept iff all components pass.

In implementation, the public-tag form is:

```text
U_i(P) = phi_i(P) = T_i(P) - K_i
```

So `R == O` is equivalent to checking `U_i(R) == U_i(O)` for all `i`.

### 2.3 Why gate count drops

- The heaviest Step4 logic (large MSM + EC operations) is moved out of GC into Argo MAC.
- GC keeps only one external bit `step4_valid_external`, with a simple constraint:

```text
step4_valid_external == 1
```

So Step4 complexity in GC drops from huge arithmetic/logic circuits to constant-level Boolean checks.

## 3. Implementation mapping (current repository)

### 3.1 New module
- `garbled-snark-verifier/src/argo_mac.rs`
  - BN254 G1 endomorphism set
  - Role-separated API: `ArgoStep4Garbler` / `ArgoStep4Evaluator` / `ArgoStep4Message`
  - Step4 wrapper: `verify_step4_with_argo_roles(...)`

### 3.2 DV-SNARK integration
- `garbled-snark-verifier/src/dv_bn254/dv_snark.rs`
  - Added `dv_snark_step4_argo_mac_verify(witness)`
  - Verifier circuit path now consumes Argo Step4 result

### 3.3 GC hybrid compile path
- `garbled-snark-verifier/src/dv_bn254/dv_ckt.rs`
  - `compile_verifier_argo_hybrid()`
  - `verify_with_external_step4(...)`
  - Replaces heavy Step4 subcircuit with one external input-bit constraint

### 3.4 Transcript commitment binding
- `garbled-snark-verifier/src/transcript_commit.rs`
  - `CommitInputs`
  - `commit_root = H(domain_sep || session_id || vk_hash || root_yao || root_argo || public_input_hash)`
  - Merkle root/proof helpers

### 3.5 Host-side artifacts
- `verifiable-circuit-host/src/bn254_dv_snark.rs`
  - Emits `argo_step4_valid.bin`
  - Emits `root_argo.bin`, `root_yao.bin`, `commit_root.bin`

## 4. Experimental method

Test case:
- `test_hybrid_step4_reduces_gate_count` (ignored slow test)

Command:

```bash
cargo test -p garbled-snark-verifier test_hybrid_step4_reduces_gate_count -- --ignored --nocapture
```

Metrics:
- `direct_and` / `direct_xor` / `direct_or`
- `total_native_gates` (primary comparison metric)

## 5. Final results

### 5.1 Baseline (original Step4 inside GC)
- `direct_and`: `499,784,184`
- `direct_xor`: `1,468,555,744`
- `direct_or`: `6,274,719`
- `total_native_gates`: `1,974,614,647`

### 5.2 Hybrid (Step4 moved to Argo MAC)
- `direct_and`: `21,161,359`
- `direct_xor`: `37,464,483`
- `direct_or`: `3,516,815`
- `total_native_gates`: `62,142,657`

### 5.3 Improvement
- `reduced = 1,912,471,990` gates
- `reduction ratio = 96.8529%`

Conclusion:
Under the current implementation and test input, moving Step4 out of GC reduces native GC gates by about **96.85%**.

## 6. Correctness and engineering implications

### 6.1 Semantic preservation
- The verifier still checks the same algebraic relation.
- Only the checking domain changes: from EC operations inside GC to equality checks in Argo MAC plus one GC Boolean result bit.

### 6.2 Security binding
- `commit_root` binds `root_yao`, `root_argo`, `vk`, and public-input hash into one transcript.
- This prevents cross-session / cross-instance mix-and-match.

### 6.3 System benefit
- Major GC size reduction, lowering garbling/evaluation cost.
- Smaller data surface for on-chain commitment and dispute workflows.

## 7. Suggested next steps

1. Add fine-grained profiling: Step1..Step5 share across input sizes.
2. Add wall-clock benchmarks (garble/evaluate time and memory peak).
3. Add CI regression threshold (e.g., hybrid reduction must stay `>= 95%`).
