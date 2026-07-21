use p3_batch_stark::ProverData;
use p3_circuit::ops::{Tip5Config, Tip5Goldilocks, generate_tip5_trace, perm_private_data};
use p3_circuit::{Circuit, CircuitBuilder, CircuitError, CircuitRunner, NonPrimitiveOpId, Traces};
use p3_circuit_prover::batch_stark_prover::{tip5_air_builders, tip5_preprocessor};
use p3_circuit_prover::common::{NpoPreprocessor, get_airs_and_degrees_with_prep};
use p3_circuit_prover::config::{
    self, GOLDILOCKS_TIP5_RECURSIVE_PURE_QUERY_LOG_BLOWUP,
    GOLDILOCKS_TIP5_RECURSIVE_PURE_QUERY_LOG_FINAL_POLY_LEN, GoldilocksTipsConfig,
};
use p3_circuit_prover::{BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking};
use p3_commit::Mmcs;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_recursion::Target;
use p3_recursion::pcs::verify_batch_circuit;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_tip5_circuit_air::Tip5Perm;

const TIP5_WIDTH: usize = 16;
const TIP5_RATE: usize = 10;
const TIP5_DIGEST: usize = 5;

type F = Goldilocks;
type Tip5Hash = PaddingFreeSponge<Tip5Perm, TIP5_WIDTH, TIP5_RATE, TIP5_DIGEST>;
type Tip5Compress = TruncatedPermutation<Tip5Perm, 2, TIP5_DIGEST, TIP5_WIDTH>;
type Tip5Mmcs = MerkleTreeMmcs<F, F, Tip5Hash, Tip5Compress, 2, TIP5_DIGEST>;

fn tip5_mmcs(cap_height: usize) -> Tip5Mmcs {
    let perm = Tip5Perm;
    Tip5Mmcs::new(Tip5Hash::new(perm), Tip5Compress::new(perm), cap_height)
}

fn matrix(height: usize, width: usize) -> RowMajorMatrix<F> {
    let values = (0..height * width)
        .map(|i| F::from_u64((i as u64).wrapping_mul(17).wrapping_add(3)))
        .collect();
    RowMajorMatrix::new(values, width)
}

fn setup_builder() -> CircuitBuilder<F> {
    let mut builder = CircuitBuilder::<F>::new();
    builder
        .enable_tip5_perm::<Tip5Goldilocks, _>(generate_tip5_trace::<F, Tip5Goldilocks>, Tip5Perm);
    builder
}

fn set_sibling_private_data(
    runner: &mut CircuitRunner<'_, F>,
    op_ids: &[NonPrimitiveOpId],
    opening_proof: &[[F; TIP5_DIGEST]],
) {
    assert_eq!(op_ids.len(), opening_proof.len());
    for (op_id, sibling) in op_ids.iter().zip(opening_proof) {
        runner
            .set_private_data(
                *op_id,
                perm_private_data(Tip5Config::GOLDILOCKS_W16, sibling.to_vec()),
            )
            .expect("set Tip5 sibling private data");
    }
}

fn build_tip5_mmcs_circuit(
    height: usize,
    width: usize,
    index: usize,
    cap_height: usize,
) -> (
    Circuit<F>,
    Vec<NonPrimitiveOpId>,
    Vec<F>,
    Vec<[F; TIP5_DIGEST]>,
) {
    let mmcs = tip5_mmcs(cap_height);
    let matrix = matrix(height, width);
    let dimensions = vec![matrix.dimensions()];
    let (commitment, prover_data) = mmcs.commit(vec![matrix]);
    let opening = mmcs.open_batch(index, &prover_data);

    let log_max_height = height.next_power_of_two().trailing_zeros() as usize;
    let mut builder = setup_builder();
    let opened: Vec<Target> = (0..width).map(|_| builder.public_input()).collect();
    let directions = builder.alloc_public_inputs(log_max_height, "tip5 directions");
    let root: Vec<Target> = (0..TIP5_DIGEST).map(|_| builder.public_input()).collect();
    let op_ids = verify_batch_circuit::<F, F>(
        &mut builder,
        Tip5Config::GOLDILOCKS_W16,
        &[root],
        &dimensions,
        &directions,
        &[opened],
        None,
    )
    .expect("build Tip5 MMCS verifier circuit");

    let mut public_inputs: Vec<F> = opening
        .opened_values
        .iter()
        .flat_map(|row| row.iter().copied())
        .collect();
    public_inputs.extend((0..log_max_height).map(|k| F::from_bool((index >> k) & 1 == 1)));
    public_inputs.extend(commitment.roots()[0].iter().copied());

    (
        builder.build().expect("build Tip5 MMCS circuit"),
        op_ids,
        public_inputs,
        opening.opening_proof,
    )
}

fn run_tip5_mmcs_circuit(
    height: usize,
    width: usize,
    index: usize,
    cap_height: usize,
    tamper_sibling: bool,
) -> Result<Traces<F>, CircuitError> {
    let (circuit, op_ids, public_inputs, mut opening_proof) =
        build_tip5_mmcs_circuit(height, width, index, cap_height);
    if tamper_sibling {
        opening_proof[0][0] += F::ONE;
    }
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public_inputs)?;
    set_sibling_private_data(&mut runner, &op_ids, &opening_proof);
    runner.run()
}

fn prove_tip5_tables(circuit: &Circuit<F>, traces: &Traces<F>) {
    let table_packing = TablePacking::default().with_fri_params(
        GOLDILOCKS_TIP5_RECURSIVE_PURE_QUERY_LOG_FINAL_POLY_LEN,
        GOLDILOCKS_TIP5_RECURSIVE_PURE_QUERY_LOG_BLOWUP,
    );
    let stark_config = config::goldilocks_tip5_60bit();
    let npo_prep: Vec<Box<dyn NpoPreprocessor<F>>> = vec![tip5_preprocessor::<F>()];
    let air_builders = tip5_air_builders::<GoldilocksTipsConfig, 1>();
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<GoldilocksTipsConfig, _, 1>(
            circuit,
            &table_packing,
            &npo_prep,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("derive Tip5 AIRs and preprocessed columns");
    let (airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();
    let prover_data = ProverData::from_airs_and_degrees(&stark_config, &airs, &degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
    let mut prover = BatchStarkProver::new(stark_config).with_table_packing(table_packing);
    prover.register_tip5_table::<1>(Tip5Config::GOLDILOCKS_W16);
    let proof = prover
        .prove_all_tables(traces, &circuit_prover_data)
        .expect("prove Tip5 MMCS circuit tables");
    prover
        .verify_all_tables::<F>(&proof)
        .expect("verify Tip5 MMCS circuit tables");
}

#[test]
fn tip5_mmcs_circuit_accepts_native_opening() {
    run_tip5_mmcs_circuit(8, 4, 5, 0, false).expect("native Tip5 MMCS opening should verify");
}

#[test]
fn tip5_mmcs_circuit_rejects_tampered_sibling() {
    assert!(
        run_tip5_mmcs_circuit(8, 4, 5, 0, true).is_err(),
        "tampered Tip5 MMCS sibling was accepted"
    );
}

#[test]
fn tip5_mmcs_round_trip_proves_and_verifies_tables() {
    let (circuit, op_ids, public_inputs, opening_proof) = build_tip5_mmcs_circuit(8, 4, 5, 0);
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&public_inputs)
        .expect("set public inputs");
    set_sibling_private_data(&mut runner, &op_ids, &opening_proof);
    let traces = runner.run().expect("Tip5 MMCS circuit should run");
    prove_tip5_tables(&circuit, &traces);
}
