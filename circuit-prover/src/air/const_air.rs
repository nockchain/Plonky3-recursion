//! [`ConstAir`] binds compile-time constants to verifier-owned preprocessed values.
//!
//! # Column layout
//!
//! The AIR is generic over an extension degree `D`.
//! Each constant row has `D` committed main columns and `D + 2` preprocessed columns.
//!
//! - main: `value[0], value[1], ..., value[D-1]`
//! - preprocessed: `multiplicity, index, expected[0], ..., expected[D-1]`
//!
//! # Constraints
//!
//! The witness bus sends the verifier-owned expected value. Committed main columns are not
//! trusted for constant values.
//!
//! # Global Interactions
//!
//! One interaction with the global witness bus (WitnessChecks):
//!
//! - send `(index, expected[0..D])` with multiplicity `multiplicity`

use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_circuit::tables::ConstTrace;
use p3_field::{BasedVectorSpace, Field};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use tracing::instrument;

/// ConstAir: vector-valued constant binding with generic extension degree D.
///
/// Layout per row:
/// - main: `[value[0..D-1]]` (prover trace, not trusted for binding)
/// - preprocessed: `[multiplicity, index, expected[0..D-1]]`
#[derive(Debug, Clone)]
pub struct ConstAir<F, const D: usize = 1> {
    /// Total number of logical constant rows in the trace.
    pub num_ops: usize,
    /// Flattened verifier-owned rows.
    pub preprocessed: Vec<F>,
    /// Minimum trace height for FRI compatibility.
    pub min_height: usize,
    _phantom: PhantomData<F>,
}

impl<F: Field, const D: usize> ConstAir<F, D> {
    /// Construct a new `ConstAir` instance.
    pub const fn new(num_ops: usize) -> Self {
        Self {
            num_ops,
            preprocessed: Vec::new(),
            min_height: 1,
            _phantom: PhantomData,
        }
    }

    pub const fn new_with_preprocessed(num_ops: usize, preprocessed: Vec<F>) -> Self {
        Self {
            num_ops,
            preprocessed,
            min_height: 1,
            _phantom: PhantomData,
        }
    }

    /// Set the minimum trace height for FRI compatibility.
    ///
    /// FRI requires: `log_trace_height > log_final_poly_len + log_blowup`
    /// So `min_height` should be >= `2^(log_final_poly_len + log_blowup + 1)`.
    pub const fn with_min_height(mut self, min_height: usize) -> Self {
        self.min_height = min_height;
        self
    }

    /// Number of preprocessed columns: multiplicity + index + expected value.
    pub const fn preprocessed_width() -> usize {
        D + 2
    }

    /// Convert a `ConstTrace` into a `RowMajorMatrix` suitable for the STARK prover.
    ///
    /// This function is responsible for:
    ///
    /// 1. Decomposing each extension element in the trace into `D` basis coordinates.
    /// 2. Padding the trace to have a power-of-two number of rows.
    #[inline]
    #[instrument(skip_all, name = "ConstAir::build_trace")]
    pub fn trace_to_matrix<ExtF: BasedVectorSpace<F>>(
        trace: &ConstTrace<ExtF>,
        min_height: usize,
    ) -> RowMajorMatrix<F> {
        let height = trace.values.len();
        assert_eq!(
            height,
            trace.index.len(),
            "ConstTrace column length mismatch: values vs indices"
        );
        let width = D;

        let mut values = Vec::with_capacity(height * width);

        for i in 0..height {
            let coeffs = trace.values[i].as_basis_coefficients_slice();
            debug_assert_eq!(
                coeffs.len(),
                D,
                "extension degree mismatch for ConstTrace value"
            );
            values.extend_from_slice(coeffs);
        }

        let mut mat = RowMajorMatrix::new(values, width);
        mat.pad_to_min_power_of_two_height(
            core::cmp::max(min_height, mat.height().next_power_of_two()),
            F::ZERO,
        );

        mat
    }
}

impl<F: Field, const D: usize> BaseAir<F> for ConstAir<F, D> {
    fn width(&self) -> usize {
        D
    }

    fn preprocessed_width(&self) -> usize {
        Self::preprocessed_width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let width = Self::preprocessed_width();
        let mut mat = RowMajorMatrix::from_flat_padded(self.preprocessed.to_vec(), width, F::ZERO);
        mat.pad_to_min_power_of_two_height(self.min_height, F::ZERO);
        Some(mat)
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}

impl<AB: AirBuilder + InteractionBuilder, const D: usize> Air<AB> for ConstAir<AB::F, D>
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let prep = builder.preprocessed().clone();
        let prep_local = prep.current_slice();

        let multiplicity: AB::Expr = prep_local[0].into();
        let witness_idx: AB::Expr = prep_local[1].into();

        let mut fields: Vec<AB::Expr> = Vec::with_capacity(1 + D);
        fields.push(witness_idx);
        for j in 0..D {
            fields.push(prep_local[2 + j].into());
        }

        builder.push_interaction("WitnessChecks", fields, Count::bounded(multiplicity, 1));
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_circuit::WitnessId;
    use p3_matrix::Matrix;
    use p3_test_utils::baby_bear_params::{
        BabyBear as F, BinomialExtensionField, PrimeCharacteristicRing,
    };

    use super::*;

    type EF = BinomialExtensionField<F, 4>;

    #[test]
    fn test_const_air_base_field() {
        // Create a CONST trace with several constant values
        // Toy example used: assert(37 * x - 111 = 0)
        let const_values = vec![
            F::from_u64(37),  // CONST 1 37
            F::from_u64(111), // CONST 3 111
            F::from_u64(0),   // CONST 4 0
        ];
        // Witness IDs these constants bind to
        let const_indices = vec![WitnessId(1), WitnessId(3), WitnessId(4)];

        // Preprocessed values are [ext_mult, index, expected] rows.
        let preprocessed_values = const_indices
            .iter()
            .zip(const_values.iter())
            .flat_map(|(idx, value)| [F::ONE, F::from_u64(idx.0 as u64), *value])
            .collect::<Vec<_>>();

        let trace = ConstTrace {
            index: const_indices.clone(),
            values: const_values,
        };

        // Convert to matrix using the ConstAir
        let matrix = ConstAir::<F, 1>::trace_to_matrix(&trace, 1);

        // Verify matrix dimensions
        assert_eq!(matrix.width(), 1);

        // Height should be next power of two >= 3
        let height = matrix.height();
        assert_eq!(height, 4);

        // Verify the data layout: [value] per row (no index in main trace)
        let data = &matrix.values;

        // First row: value=37
        assert_eq!(data[0], F::from_u64(37));

        // Second row: value=111
        assert_eq!(data[1], F::from_u64(111));

        // Third row: value=0
        assert_eq!(data[2], F::from_u64(0));

        let air = ConstAir::<F, 1>::new_with_preprocessed(height, preprocessed_values);

        let preprocessed_matrix = air.preprocessed_trace().unwrap();
        assert_eq!(preprocessed_matrix.height(), height);

        // Assert the preprocessed values were properly created.
        // Layout: [ext_mult, index, expected] (width=3)
        const_indices
            .iter()
            .zip([F::from_u64(37), F::from_u64(111), F::from_u64(0)])
            .enumerate()
            .for_each(|(i, (const_idx, value))| {
                let row = preprocessed_matrix.row_slice(i).unwrap();
                assert_eq!(row[0], F::ONE);
                assert_eq!(row[1], F::from_u32(const_idx.0));
                assert_eq!(row[2], value);
            });
        // Check the padding row
        let last_row = preprocessed_matrix.row_slice(height - 1).unwrap();
        assert_eq!(last_row[0], F::ZERO);
        assert_eq!(last_row[1], F::ZERO);
        assert_eq!(last_row[2], F::ZERO);
    }

    #[test]
    fn test_const_air_extension_field() {
        // Create extension field constants with all non-zero coefficients
        let const1 = EF::from_basis_coefficients_slice(&[
            F::from_u64(1), // a0
            F::from_u64(2), // a1
            F::from_u64(3), // a2
            F::from_u64(4), // a3
        ])
        .unwrap();

        let const2 = EF::from_basis_coefficients_slice(&[
            F::from_u64(5), // b0
            F::from_u64(6), // b1
            F::from_u64(7), // b2
            F::from_u64(8), // b3
        ])
        .unwrap();

        let const_values = vec![const1, const2];
        let const_indices = vec![WitnessId(10), WitnessId(20)];
        // Preprocessed values are [ext_mult, index, expected[0..D]] rows; indices are D-scaled.
        let preprocessed_values = const_indices
            .iter()
            .zip(const_values.iter())
            .flat_map(|(idx, value)| {
                let coeffs = value.as_basis_coefficients_slice();
                [
                    F::ONE,
                    F::from_u64(idx.0 as u64 * 4),
                    coeffs[0],
                    coeffs[1],
                    coeffs[2],
                    coeffs[3],
                ]
            })
            .collect::<Vec<_>>();

        let trace = ConstTrace {
            index: const_indices,
            values: const_values,
        };

        // Convert to matrix for D=4 extension field
        let matrix: RowMajorMatrix<F> = ConstAir::<F, 4>::trace_to_matrix(&trace, 1);

        // Verify matrix dimensions: D = 4 (4 value coefficients)
        assert_eq!(matrix.width(), 4);
        let height = matrix.height();
        assert_eq!(height, 2);

        let data = &matrix.values;

        // First row: [a0, a1, a2, a3] = [1, 2, 3, 4]
        assert_eq!(data[0], F::from_u64(1));
        assert_eq!(data[1], F::from_u64(2));
        assert_eq!(data[2], F::from_u64(3));
        assert_eq!(data[3], F::from_u64(4));

        // Second row: [b0, b1, b2, b3] = [5, 6, 7, 8]
        assert_eq!(data[4], F::from_u64(5));
        assert_eq!(data[5], F::from_u64(6));
        assert_eq!(data[6], F::from_u64(7));
        assert_eq!(data[7], F::from_u64(8));

        let air = ConstAir::<F, 4>::new_with_preprocessed(height, preprocessed_values);
        let preprocessed_matrix = air.preprocessed_trace().unwrap();
        // Layout: [ext_mult, index, expected[0..D]] (width=6, D-scaled indices)
        let row0 = preprocessed_matrix.row_slice(0).unwrap();
        assert_eq!(
            &*row0,
            &[
                F::ONE,
                F::from_u64(40),
                F::ONE,
                F::TWO,
                F::from_u64(3),
                F::from_u64(4)
            ]
        );
        let last_row = preprocessed_matrix.row_slice(height - 1).unwrap();
        assert_eq!(
            &*last_row,
            &[
                F::ONE,
                F::from_u64(80),
                F::from_u64(5),
                F::from_u64(6),
                F::from_u64(7),
                F::from_u64(8),
            ]
        );
    }

    #[test]
    fn test_air_constraint_degree() {
        let air = ConstAir::<F, 1>::new_with_preprocessed(
            8,
            vec![F::ZERO; 8 * ConstAir::<F, 1>::preprocessed_width()],
        );
        p3_test_utils::assert_air_constraint_degree!(air, "ConstAir");
    }
}
