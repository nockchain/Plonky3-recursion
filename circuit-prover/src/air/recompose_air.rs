//! [`RecomposeAir`] defines the AIR for the recompose NPO table.
//!
//! Each row packs D base-field witnesses into one extension-field witness.
//! Multiple operations can be packed side-by-side as independent lanes.
//! WitnessChecks binds both the output witness and every coefficient witness.
//!
//! Circuits use two logical tables when extension degree can differ from a base-width Poseidon2:
//! - **`recompose`**: standard BF→EF packing.
//! - **`recompose/coeff`**: packing rows whose coefficient outputs are also consumed directly
//!   by lower-degree readers.
//!
//! # Column layout (per lane)
//!
//! **Main columns** (D per lane): `v_0, v_1, ..., v_{D-1}` — the base-field coefficient values.
//!
//! **Preprocessed columns** per lane:
//! - `output_idx`, `out_mult`.
//! - `coeff_i_idx`, `coeff_i_mult` for each `i`.
//!
//! # CTL lookups (per lane per row)
//!
//! **Output** `[output_idx, v_0, ..., v_{D-1}]` with multiplicity `out_mult`.
//!
//! **Coefficient** `[coeff_i_idx, v_i, 0, ..., 0]` with multiplicity `coeff_i_mult` (×D).

use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use tracing::instrument;

use super::recompose_columns::{RECOMPOSE_PREP_LANE_COL_MAP, RECOMPOSE_PREP_LANE_WIDTH};

/// AIR for the recompose (BF→EF packing) table.
///
/// WitnessChecks bus interactions bind the output and coefficient witness IDs.
#[derive(Debug, Clone)]
pub struct RecomposeAir<F, const D: usize> {
    pub(crate) lanes: usize,
    pub(crate) preprocessed: Vec<F>,
    pub(crate) min_height: usize,
    /// Distinguishes the standard table from the coefficient-link table at registration time.
    /// Both tables bind their coefficient witness IDs; the coefficient-link table is used when
    /// those witnesses are exposed to lower-degree readers after decomposition.
    pub(crate) coeff_lookups: bool,
    _phantom: PhantomData<F>,
}

impl<F: Field + PrimeCharacteristicRing, const D: usize> RecomposeAir<F, D> {
    /// Main trace width per lane: D columns (one per BF coefficient).
    pub const fn lane_width() -> usize {
        D
    }

    /// Preprocessed width per lane.
    ///
    /// `[output_idx, out_mult] + D × [coeff_idx, coeff_mult]`.
    pub const fn preprocessed_lane_width_for(_coeff_lookups: bool) -> usize {
        RECOMPOSE_PREP_LANE_WIDTH + 2 * D
    }

    /// Preprocessed width per lane for this AIR instance.
    pub const fn preprocessed_lane_width(&self) -> usize {
        Self::preprocessed_lane_width_for(self.coeff_lookups)
    }

    /// Create a new `RecomposeAir` with the given preprocessed data and lane count.
    pub fn new_with_preprocessed(
        lanes: usize,
        preprocessed: Vec<F>,
        min_height: usize,
        coeff_lookups: bool,
    ) -> Self {
        Self {
            lanes: lanes.max(1),
            preprocessed,
            min_height,
            coeff_lookups,
            _phantom: PhantomData,
        }
    }

    /// Build the main trace matrix from recompose circuit rows with lane packing.
    #[instrument(skip_all, name = "RecomposeAir::build_trace")]
    pub fn trace_to_matrix(
        rows: &[p3_circuit::ops::recompose::RecomposeCircuitRow<F>],
        lanes: usize,
    ) -> RowMajorMatrix<F> {
        let lane_w = Self::lane_width();
        let row_width = lanes * lane_w;
        let num_ops = rows.len();
        let num_rows = num_ops.div_ceil(lanes).max(1);

        let mut values = F::zero_vec(num_rows * row_width);

        // Rows are independent (no cross-row state), so each row is filled in parallel from
        // its `lanes` ops.
        values
            .par_chunks_mut(row_width)
            .enumerate()
            .for_each(|(r, row_slice)| {
                for l in 0..lanes {
                    let op_idx = r * lanes + l;
                    if let Some(row) = rows.get(op_idx) {
                        let base = l * lane_w;
                        row_slice[base..base + row.values.len()].copy_from_slice(&row.values);
                    }
                }
            });

        let mut mat = RowMajorMatrix::new(values, row_width);
        mat.pad_to_power_of_two_height(F::ZERO);
        mat
    }
}

impl<F: Field, const D: usize> BaseAir<F> for RecomposeAir<F, D> {
    fn width(&self) -> usize {
        self.lanes * Self::lane_width()
    }

    fn preprocessed_width(&self) -> usize {
        self.lanes * self.preprocessed_lane_width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let width = self.lanes * self.preprocessed_lane_width();
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

impl<AB: AirBuilder + InteractionBuilder, const D: usize> Air<AB> for RecomposeAir<AB::F, D>
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let main_local = main.current_slice();
        let prep = builder.preprocessed().clone();
        let prep_local = prep.current_slice();

        let lane_w = Self::lane_width();
        let prep_lane_w = self.preprocessed_lane_width();

        for lane in 0..self.lanes {
            let main_off = lane * lane_w;
            let prep_off = lane * prep_lane_w;

            let output_idx: AB::Expr =
                prep_local[prep_off + RECOMPOSE_PREP_LANE_COL_MAP.output_idx].into();
            let out_mult: AB::Expr =
                prep_local[prep_off + RECOMPOSE_PREP_LANE_COL_MAP.out_mult].into();

            let mut values: Vec<AB::Expr> = Vec::with_capacity(1 + D);
            values.push(output_idx);
            for j in 0..D {
                values.push(main_local[main_off + j].into());
            }
            builder.push_interaction("WitnessChecks", values, Count::bounded(out_mult, 1));

            for i in 0..D {
                let coeff_idx: AB::Expr =
                    prep_local[prep_off + RECOMPOSE_PREP_LANE_WIDTH + i * 2].into();
                let coeff_mult: AB::Expr =
                    prep_local[prep_off + RECOMPOSE_PREP_LANE_WIDTH + i * 2 + 1].into();

                let mut coeff_values: Vec<AB::Expr> = Vec::with_capacity(1 + D);
                coeff_values.push(coeff_idx);
                coeff_values.push(main_local[main_off + i].into());
                for _ in 1..D {
                    coeff_values.push(AB::Expr::ZERO);
                }
                builder.push_interaction(
                    "WitnessChecks",
                    coeff_values,
                    Count::bounded(coeff_mult, 1),
                );
            }
        }
    }
}
