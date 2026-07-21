//! STARK proving configurations.
//!
//! This module provides STARK configurations for different prime fields.
//!
//! # Quick Start
//!
//! ```ignore
//! use p3_circuit_prover::config;
//!
//! // Use a preconfigured setup
//! let config = config::baby_bear();
//! ```

use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};
use p3_blake3::Blake3;
use p3_challenger::{DuplexChallenger, HashChallenger, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon2_16};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{
    CompressionFunctionFromHasher, CryptographicPermutation, PaddingFreeSponge, SerializingHasher,
    TruncatedPermutation,
};
use p3_tip5_circuit_air::Tip5Perm;
use p3_uni_stark::StarkConfig;

/// Compression function arity (number of inputs per compression).
const COMPRESS_ARITY: usize = 2;

/// A STARK configuration with all cryptographic primitives specified.
///
/// ### Type Parameters
/// - `F`: Base field.
/// - `PermHash`: Permutation function used for sponge hashing (leaves, transcript absorption).
/// - `PermCompress`: Permutation function used for Merkle tree compression.
/// - `HASH_PERM_WIDTH`: Width of the hash permutation state.
/// - `COMPRESS_PERM_WIDTH`: Width of the compression permutation state.
/// - `RATE`: Number of field elements absorbed per permutation in sponge mode.
/// - `OUT`: Number of output elements squeezed per permutation.
/// - `COMPRESS_CHUNK`: Number of elements per compression chunk in Merkle commitments.
/// - `CHALLENGE_DEGREE`: Extension field degree.
pub type Config<
    F,
    PermHash,
    PermCompress,
    const HASH_PERM_WIDTH: usize,
    const COMPRESS_PERM_WIDTH: usize,
    const RATE: usize,
    const OUT: usize,
    const COMPRESS_CHUNK: usize,
    const CHALLENGE_DEGREE: usize,
> = StarkConfig<
    TwoAdicFriPcs<
        F,
        Radix2DitParallel<F>,
        MerkleTreeMmcs<
            F,
            F,
            PaddingFreeSponge<PermHash, HASH_PERM_WIDTH, RATE, OUT>,
            TruncatedPermutation<PermCompress, COMPRESS_ARITY, COMPRESS_CHUNK, COMPRESS_PERM_WIDTH>,
            2,
            COMPRESS_CHUNK,
        >,
        ExtensionMmcs<
            F,
            BinomialExtensionField<F, CHALLENGE_DEGREE>,
            MerkleTreeMmcs<
                F,
                F,
                PaddingFreeSponge<PermHash, HASH_PERM_WIDTH, RATE, OUT>,
                TruncatedPermutation<
                    PermCompress,
                    COMPRESS_ARITY,
                    COMPRESS_CHUNK,
                    COMPRESS_PERM_WIDTH,
                >,
                2,
                COMPRESS_CHUNK,
            >,
        >,
    >,
    BinomialExtensionField<F, CHALLENGE_DEGREE>,
    DuplexChallenger<F, PermHash, HASH_PERM_WIDTH, RATE>,
>;

/// Builds a STARK configuration directly from the hash and compression permutations.
///
/// This replaces the former `ConfigBuilder` (which was only ever used internally,
/// immediately followed by `.build()`): the field factories below call this and
/// return the concrete config, so callers no longer chain `.build()`.
#[allow(clippy::type_complexity)]
fn build_poseidon2_stark_config<
    F,
    PermHash,
    PermCompress,
    const HASH_PERM_WIDTH: usize,
    const COMPRESS_PERM_WIDTH: usize,
    const RATE: usize,
    const OUT: usize,
    const COMPRESS_CHUNK: usize,
    const CHALLENGE_DEGREE: usize,
>(
    perm_hash: PermHash,
    perm_compress: PermCompress,
) -> Config<
    F,
    PermHash,
    PermCompress,
    HASH_PERM_WIDTH,
    COMPRESS_PERM_WIDTH,
    RATE,
    OUT,
    COMPRESS_CHUNK,
    CHALLENGE_DEGREE,
>
where
    F: Field,
    PermHash: Clone + CryptographicPermutation<[F; HASH_PERM_WIDTH]>,
    PermCompress: Clone + CryptographicPermutation<[F; COMPRESS_PERM_WIDTH]>,
{
    type Hash<Perm, const PERM_WIDTH: usize, const RATE: usize, const OUT: usize> =
        PaddingFreeSponge<Perm, PERM_WIDTH, RATE, OUT>;
    type Compress<Perm, const PERM_WIDTH: usize, const COMPRESS_CHUNK: usize> =
        TruncatedPermutation<Perm, COMPRESS_ARITY, COMPRESS_CHUNK, PERM_WIDTH>;

    let hash = Hash::<PermHash, HASH_PERM_WIDTH, RATE, OUT>::new(perm_hash.clone());
    let compress =
        Compress::<PermCompress, COMPRESS_PERM_WIDTH, COMPRESS_CHUNK>::new(perm_compress);
    let val_mmcs = MerkleTreeMmcs::new(hash, compress, 3);
    let challenge_mmcs = ExtensionMmcs::new(val_mmcs.clone());
    let dft = Radix2DitParallel::default();
    let fri_params = FriParameters::new_benchmark_high_arity(challenge_mmcs);
    let pcs = TwoAdicFriPcs::new(dft, val_mmcs, fri_params);
    let challenger = DuplexChallenger::new(perm_hash);

    StarkConfig::new(pcs, challenger)
}

/// Creates a standard BabyBear configuration.
///
/// BabyBear is a 31-bit prime field (2^31 - 2^27 + 1).
///
/// # Parameters
/// - **Hash permutation width**: 16 (appropriate for 32-bit fields)
/// - **Compression permutation width**: 16
/// - **Rate**: 8 (256 bits / 32 bits per element)
/// - **Output size**: 8 (256 bits / 32 bits per element)
/// - **Challenge degree**: 4
///
/// # Examples
///
/// ```ignore
/// let config = config::baby_bear();
/// let prover = BatchStarkProver::new(config);
/// ```
#[inline]
pub fn baby_bear() -> BabyBearConfig {
    let perm = default_babybear_poseidon2_16();
    build_poseidon2_stark_config(perm.clone(), perm)
}

/// Creates a standard KoalaBear configuration.
///
/// KoalaBear is a 31-bit prime field (2^31 - 2^24 + 1).
///
/// # Parameters
/// - **Hash permutation width**: 16 (appropriate for 32-bit fields)
/// - **Compression permutation width**: 16
/// - **Rate**: 8 (256 bits / 32 bits per element)
/// - **Output size**: 8 (256 bits / 32 bits per element)
/// - **Challenge degree**: 4
///
/// # Examples
///
/// ```ignore
/// let config = config::koala_bear();
/// let prover = BatchStarkProver::new(config);
/// ```
#[inline]
pub fn koala_bear() -> KoalaBearConfig {
    let perm = default_koalabear_poseidon2_16();
    build_poseidon2_stark_config(perm.clone(), perm)
}

/// Creates a standard Goldilocks configuration.
///
/// Goldilocks is a 64-bit prime field (2^64 - 2^32 + 1).
///
/// # Parameters
/// - **Hash permutation width**: 8 (appropriate for 64-bit fields)
/// - **Compression permutation width**: 8
/// - **Rate**: 4 (256 bits / 64 bits per element)
/// - **Output size**: 4 (256 bits / 64 bits per element)
/// - **Challenge degree**: 2
///
/// # Examples
///
/// ```ignore
/// let config = config::goldilocks();
/// let prover = BatchStarkProver::new(config);
/// ```
#[inline]
pub fn goldilocks() -> GoldilocksConfig {
    use rand::SeedableRng;
    let mut rng = rand::rngs::SmallRng::seed_from_u64(1);
    let perm = p3_goldilocks::Poseidon2Goldilocks::<8>::new_from_rng_128(&mut rng);
    build_poseidon2_stark_config(perm.clone(), perm)
}

/// Type alias for BabyBear STARK configuration.
pub type BabyBearConfig =
    Config<BabyBear, Poseidon2BabyBear<16>, Poseidon2BabyBear<16>, 16, 16, 8, 8, 8, 4>;

/// Type alias for KoalaBear STARK configuration.
pub type KoalaBearConfig =
    Config<KoalaBear, Poseidon2KoalaBear<16>, Poseidon2KoalaBear<16>, 16, 16, 8, 8, 8, 4>;

/// Type alias for Goldilocks STARK configuration.
pub type GoldilocksConfig =
    Config<Goldilocks, Poseidon2Goldilocks<8>, Poseidon2Goldilocks<8>, 8, 8, 4, 4, 4, 2>;

pub const GOLDILOCKS_TIP5_RECURSIVE_PURE_QUERY_LOG_BLOWUP: usize = 4;
pub const GOLDILOCKS_TIP5_RECURSIVE_PURE_QUERY_LOG_FINAL_POLY_LEN: usize = 2;
pub const GOLDILOCKS_TIP5_RECURSIVE_PURE_QUERY_MAX_LOG_ARITY: usize = 3;
pub const GOLDILOCKS_TIP5_RECURSIVE_PURE_QUERY_NUM_QUERIES: usize = 15;
pub const GOLDILOCKS_TIP5_RECURSIVE_PURE_QUERY_COMMIT_POW_BITS: usize = 0;
pub const GOLDILOCKS_TIP5_RECURSIVE_PURE_QUERY_QUERY_POW_BITS: usize = 0;
pub const GOLDILOCKS_TIP5_RECURSIVE_PURE_QUERY_CAP_HEIGHT: usize = 5;
pub const GOLDILOCKS_TIP5_RECURSIVE_PURE_QUERY_JOHNSON_BITS: usize =
    GOLDILOCKS_TIP5_RECURSIVE_PURE_QUERY_LOG_BLOWUP
        * GOLDILOCKS_TIP5_RECURSIVE_PURE_QUERY_NUM_QUERIES;

pub type GoldilocksTipsConfig = Config<Goldilocks, Tip5Perm, Tip5Perm, 16, 16, 10, 5, 5, 2>;

#[inline]
fn goldilocks_tip5_with_fri_params(
    log_blowup: usize,
    log_final_poly_len: usize,
    max_log_arity: usize,
    num_queries: usize,
    commit_proof_of_work_bits: usize,
    query_proof_of_work_bits: usize,
    cap_height: usize,
) -> GoldilocksTipsConfig {
    let perm = Tip5Perm;
    let hash = PaddingFreeSponge::<_, 16, 10, 5>::new(perm);
    let compress = TruncatedPermutation::<_, COMPRESS_ARITY, 5, 16>::new(perm);
    let val_mmcs = MerkleTreeMmcs::new(hash, compress, cap_height);
    let challenge_mmcs = ExtensionMmcs::new(val_mmcs.clone());
    let dft = Radix2DitParallel::default();
    let fri_params = FriParameters {
        log_blowup,
        log_final_poly_len,
        max_log_arity,
        num_queries,
        commit_proof_of_work_bits,
        query_proof_of_work_bits,
        mmcs: challenge_mmcs,
    };
    let pcs = TwoAdicFriPcs::new(dft, val_mmcs, fri_params);
    let challenger = DuplexChallenger::new(perm);
    StarkConfig::new(pcs, challenger)
}

#[inline]
pub fn goldilocks_tip5_60bit() -> GoldilocksTipsConfig {
    goldilocks_tip5_pure_query_60bit_with_shape_and_cap(4, 15, 5)
}

#[inline]
pub fn goldilocks_tip5_pure_query_60bit_with_shape_and_cap(
    log_blowup: usize,
    num_queries: usize,
    cap_height: usize,
) -> GoldilocksTipsConfig {
    assert!(
        log_blowup * num_queries >= GOLDILOCKS_TIP5_RECURSIVE_PURE_QUERY_JOHNSON_BITS,
        "pure-query recursive Tip5 profile must provide at least 60 Johnson bits"
    );
    goldilocks_tip5_with_fri_params(
        log_blowup,
        GOLDILOCKS_TIP5_RECURSIVE_PURE_QUERY_LOG_FINAL_POLY_LEN,
        GOLDILOCKS_TIP5_RECURSIVE_PURE_QUERY_MAX_LOG_ARITY,
        num_queries,
        GOLDILOCKS_TIP5_RECURSIVE_PURE_QUERY_COMMIT_POW_BITS,
        GOLDILOCKS_TIP5_RECURSIVE_PURE_QUERY_QUERY_POW_BITS,
        cap_height,
    )
}

pub type GoldilocksBlake3Challenge = BinomialExtensionField<Goldilocks, 2>;
type GoldilocksBlake3Hash = SerializingHasher<Blake3>;
type GoldilocksBlake3Compress = CompressionFunctionFromHasher<Blake3, 2, 32>;
pub type GoldilocksBlake3ValMmcs =
    MerkleTreeMmcs<Goldilocks, u8, GoldilocksBlake3Hash, GoldilocksBlake3Compress, 2, 32>;
type GoldilocksBlake3ChallengeMmcs =
    ExtensionMmcs<Goldilocks, GoldilocksBlake3Challenge, GoldilocksBlake3ValMmcs>;
type GoldilocksBlake3Challenger =
    SerializingChallenger64<Goldilocks, HashChallenger<u8, Blake3, 32>>;

pub type GoldilocksBlake3Config = StarkConfig<
    TwoAdicFriPcs<
        Goldilocks,
        Radix2DitParallel<Goldilocks>,
        GoldilocksBlake3ValMmcs,
        GoldilocksBlake3ChallengeMmcs,
    >,
    GoldilocksBlake3Challenge,
    GoldilocksBlake3Challenger,
>;

#[inline]
pub fn goldilocks_blake3_val_mmcs(cap_height: usize) -> GoldilocksBlake3ValMmcs {
    let hash = SerializingHasher::new(Blake3);
    let compress = CompressionFunctionFromHasher::<Blake3, 2, 32>::new(Blake3);
    MerkleTreeMmcs::new(hash, compress, cap_height)
}

#[inline]
pub fn goldilocks_blake3_with_fri_shape(
    log_blowup: usize,
    num_queries: usize,
    log_final_poly_len: usize,
    max_log_arity: usize,
    cap_height: usize,
) -> GoldilocksBlake3Config {
    let val_mmcs = goldilocks_blake3_val_mmcs(cap_height);
    let challenge_mmcs = ExtensionMmcs::new(val_mmcs.clone());
    let dft = Radix2DitParallel::default();
    let fri_params = FriParameters {
        log_blowup,
        log_final_poly_len,
        max_log_arity,
        num_queries,
        commit_proof_of_work_bits: GOLDILOCKS_TIP5_RECURSIVE_PURE_QUERY_COMMIT_POW_BITS,
        query_proof_of_work_bits: GOLDILOCKS_TIP5_RECURSIVE_PURE_QUERY_QUERY_POW_BITS,
        mmcs: challenge_mmcs,
    };
    let pcs = TwoAdicFriPcs::new(dft, val_mmcs, fri_params);
    let challenger = SerializingChallenger64::from_hasher(
        b"p3-goldilocks-blake3-final-layer-v1".to_vec(),
        Blake3,
    );
    StarkConfig::new(pcs, challenger)
}

/// Trait bounds for STARK-compatible fields.
pub trait StarkField: Field + PrimeCharacteristicRing + TwoAdicField + PrimeField64 {}

impl<F> StarkField for F where F: Field + PrimeCharacteristicRing + TwoAdicField + PrimeField64 {}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn all_fields_configs_compile() {
        let _bb: BabyBearConfig = baby_bear();
        let _kb: KoalaBearConfig = koala_bear();
        let _gl: GoldilocksConfig = goldilocks();
    }

    #[test]
    fn goldilocks_tip5_pure_query_profile_pins_60_johnson_bits() {
        assert_eq!(
            GOLDILOCKS_TIP5_RECURSIVE_PURE_QUERY_LOG_BLOWUP
                * GOLDILOCKS_TIP5_RECURSIVE_PURE_QUERY_NUM_QUERIES,
            GOLDILOCKS_TIP5_RECURSIVE_PURE_QUERY_JOHNSON_BITS
        );
        assert_eq!(GOLDILOCKS_TIP5_RECURSIVE_PURE_QUERY_JOHNSON_BITS, 60);
        let _default = goldilocks_tip5_60bit();
        let _equivalent = goldilocks_tip5_pure_query_60bit_with_shape_and_cap(5, 12, 5);
    }

    #[test]
    fn goldilocks_tip5_pure_query_profile_rejects_sub_60bit_query_budget() {
        let result = std::panic::catch_unwind(|| {
            goldilocks_tip5_pure_query_60bit_with_shape_and_cap(4, 14, 5);
        });
        assert!(result.is_err());
    }
}
