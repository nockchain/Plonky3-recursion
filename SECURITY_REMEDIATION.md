# Plonky3 recursion remediation status

## Scope

This repository is the recursive-proof substrate pinned by Nockchain AI-PoW. A malicious miner can choose prover witnesses and proof metadata, so verifier-owned data must be bound by public inputs, verifier-key digests, preprocessed commitments, or typed metadata gates before any recursive proof is accepted.

## Release status

PASS for the remediated AI-PoW recursion scope at these commits:

- `cbc3a15` — Bind verifier-owned recursion witnesses
- `12c05f2` — Harden recursive proof metadata validation
- `e5a3838` — Harden recursive Tip5 MMCS proving
- `58351c6` — Count recompose coefficient reads before NPO preprocessing
- `804e550` — Decompose D1 MMCS extension leaves with fresh limbs
- `4408be2` — Format Tip5 recursion modules
- `74dd341` — Harden recursive lookup terminal shape

## Remediated invariants

### Verifier-owned witness binding

Compile-time constants, standard recompose coefficients, recursive challenger `sample_ext` coefficients, public inputs, and serialized table metadata are verifier-owned. Proof metadata cannot choose these values without a verifier-side binding failure.

Covered boundaries:

- `circuit-prover/src/air/const_air.rs`
- `circuit-prover/src/batch_stark_prover.rs`
- `circuit-prover/src/batch_stark_prover/recompose.rs`
- `circuit-prover/src/common.rs`
- `circuit/src/circuit.rs`
- `circuit/src/builder/circuit_builder.rs`
- `circuit/src/ops/recompose.rs`
- `recursion/src/challenger/circuit.rs`

### Malformed proof metadata gates

Malformed caps, non-power-of-two caps, over-tall caps, invalid FRI schedules, bad public-binding lanes, zero serialized row counts, zero NPO lanes, and tampered `stark_common` row metadata return typed verifier errors instead of panics or silent shape truncation.

Covered boundaries:

- `recursion/src/pcs/mmcs.rs`
- `recursion/src/pcs/fri/targets.rs`
- `recursion/src/pcs/fri/verifier.rs`
- `recursion/src/types/proof.rs`
- `circuit-prover/src/batch_stark_prover/packing.rs`

### Batch lookup terminal shape

A batch proof's lookup-terminal vector must have exactly one entry per AIR instance, and an instance carries a terminal iff it declares lookups. Both are checked before challenge generation and before recursive verifier construction, so a proof cannot drop the terminal of an instance whose lookups would not balance, nor add a terminal for a lookup-free instance to cancel another's. The cross-AIR check then requires the present terminals to sum to zero.

Covered boundaries:

- `recursion/src/generation.rs`
- `recursion/src/types/proof.rs`
- `recursion/src/verifier/batch_stark.rs`
- `recursion/src/traits/recursive.rs`

### Tip5 recursion and MMCS binding

The recursive Tip5 table uses the canonical Goldilocks width-16, rate-10, 5-round permutation profile. Tip5 transcript behavior, MMCS digest-width packing, D=1 extension-opened leaf hashing, and pure-query soundness profile checks are covered by permanent tests.

Covered boundaries:

- `tip5-circuit-air/src/air_circuit.rs`
- `circuit/src/ops/tip5_perm/*`
- `circuit-prover/src/batch_stark_prover/tip5.rs`
- `circuit-prover/src/config.rs`
- `recursion/src/pcs/mmcs.rs`
- `recursion/src/backend/fri.rs`

### AI-PoW acceptance boundary

AI-PoW compact recursion rejects statement-public-input drift and preserves the fixed recursive-verifier stack through Nockchain package tests with the local Plonky3 patch configuration.

Covered boundaries:

- `../nockchain/crates/ai-pow-zk`
- `../nockchain/crates/ai-pow`
- `../nockchain/crates/ai-pow-jets`
- `../nockchain/crates/ai-pow-miner`

## Validation executed

### Plonky3 focused gates

```text
cargo +nightly-2026-04-03 test -p p3-circuit-prover batch_stark_prover::tests::const_values_are_verifier_bound -- --exact --nocapture
cargo +nightly-2026-04-03 test -p p3-circuit-prover batch_stark_prover::tests::recompose_reads_existing_coefficients -- --exact --nocapture
cargo +nightly-2026-04-03 test -p p3-recursion --test challenger_transcript goldilocks_d2::circuit_challenger_sample_ext_is_bound_to_base_samples -- --exact --nocapture
cargo +nightly-2026-04-03 test -p p3-recursion binary_mmcs_rejects_malformed_caps_without_panicking -- --exact --nocapture
cargo +nightly-2026-04-03 test -p p3-recursion arity4_mmcs_rejects_malformed_caps_without_panicking -- --exact --nocapture
cargo +nightly-2026-04-03 test -p p3-circuit-prover validate_rejects_invalid_serialized_table_packing -- --exact --nocapture
cargo +nightly-2026-04-03 test -p p3-tip5-circuit-air fixture -- --nocapture
cargo +nightly-2026-04-03 test -p p3-recursion --test tip5_mmcs -- --nocapture
cargo +nightly-2026-04-03 test -p p3-circuit-prover config::tests::goldilocks_tip5_pure_query -- --nocapture
cargo +nightly-2026-04-03 test -p p3-recursion --test fibonacci_batch_stark_prover_quintic test_fibonacci_batch_verifier_quintic_koala -- --exact --nocapture
cargo +nightly-2026-04-03 test -p p3-recursion lookup_terminal -- --nocapture
cargo +nightly-2026-04-03 test -p p3-circuit-prover goldilocks_tip5_pure_query_profile -- --nocapture
```

### Plonky3 package suite

The `p3-tip5-circuit-air` KATs read the 5-round golden fixture at
`$CARGO_MANIFEST_DIR/../../ai-pow-zk/tests/fixtures/tip5_5round_golden_kat.txt`,
i.e. they require an `ai-pow-zk` directory as a SIBLING of this checkout. In a
layout where Nockchain is cloned whole (fixture at
`nockchain/crates/ai-pow-zk/tests/fixtures/`), five Tip5 tests abort on a
missing-file panic until that path resolves.

```text
cargo +nightly-2026-04-03 test -p p3-circuit-prover -p p3-recursion -p p3-tip5-circuit-air --all-targets
```

Result: `300 passed (30 suites)` at `74dd341` — the three added over `4408be2`'s
`297` are the lookup-terminal shape tests.

### Nockchain focused AI-PoW gates

Run with `/tmp/nockchain-p3-recursion-patch.toml` pointing Nockchain's pinned Plonky3 recursion dependencies at this checkout.

```text
cargo +nightly-2026-04-03 test --config /tmp/nockchain-p3-recursion-patch.toml -p ai-pow-zk --features recursion,test-support,dev-unsafe recursion::tests::compact_batch_l1_statement_digest_binds_10_program_commitment -- --exact --nocapture
cargo +nightly-2026-04-03 test --config /tmp/nockchain-p3-recursion-patch.toml -p ai-pow-zk --features recursion,test-support,dev-unsafe recursion::tests::recursive_certificate_rejects_wrong_statement_public_inputs -- --exact --nocapture
cargo +nightly-2026-04-03 test --config /tmp/nockchain-p3-recursion-patch.toml -p ai-pow --features zk --test adversarial -- --nocapture
cargo +nightly-2026-04-03 test -p ai-pow-jets target_atom_to_32_saturates_only_oversized_targets -- --exact --nocapture
cargo +nightly-2026-04-03 test -p ai-pow-miner --features node --lib pearl_merge_ticket_artifact_builder_rejects_statement_drift -- --exact --nocapture
```

### Nockchain package suites

```text
cargo +nightly-2026-04-03 test --config /tmp/nockchain-p3-recursion-patch.toml -p ai-pow-zk --features recursion,test-support,dev-unsafe
cargo +nightly-2026-04-03 test --config /tmp/nockchain-p3-recursion-patch.toml -p ai-pow --features zk
cargo +nightly-2026-04-03 test -p ai-pow-jets
cargo +nightly-2026-04-03 test -p ai-pow-miner --features node --lib
```

Results:

- `ai-pow-zk`: `467 passed (4 suites, 7 ignored)`
- `ai-pow`: `361 passed (18 suites, 12 ignored)`
- `ai-pow-jets`: `16 passed (2 suites, 15 ignored)`
- `ai-pow-miner --lib`: `138 passed (1 suite, 9 ignored)`

## Residual assumptions

These gates do not replace a formal proof-system soundness proof. The recursion stack still relies on the external assumptions behind the configured STARK, FRI, MMCS, field-extension, and canonical Tip5 permutation parameters.
