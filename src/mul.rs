#![allow(dead_code)]

use pairing::group::ff::Field;
use snark_verifier::halo2_base::halo2_proofs::{
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};

#[derive(Clone, Debug)]
/// Configuration elements for the circuit are defined here.
pub struct MulConfig {
    /// Configures a column for a.
    a: Column<Advice>,
    /// Configures a column for b.
    b: Column<Advice>,
    // Instance column
    ins: Column<Instance>,
    /// Configures a fixed boolean value for each row of the circuit.
    selector: Selector,
}
/// Constructs individual cell for the configuration element.
pub struct MulChip<F: Field> {
    /// Assigns a cell for the items.
    a: Value<F>,
    b: Value<F>,
}

impl<F: Field> MulChip<F> {
    /// Create a new chip.
    pub fn new(a: F, b: F) -> Self {
        MulChip {
            a: Value::known(a),
            b: Value::known(b),
        }
    }
}

impl<F: Field> Circuit<F> for MulChip<F> {
    type Config = MulConfig;

    type FloorPlanner = SimpleFloorPlanner;

    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            a: Value::unknown(),
            b: Value::unknown(),
        }
    }

    /// Make the circuit config.
    fn configure(meta: &mut ConstraintSystem<F>) -> MulConfig {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let ins = meta.instance_column();
        let fixed = meta.fixed_column();
        let s = meta.selector();

        meta.enable_equality(a);
        meta.enable_equality(b);
        meta.enable_equality(ins);
        meta.enable_constant(fixed);

        meta.create_gate("mul", |v_cells| {
            let a_current = v_cells.query_advice(a, Rotation::cur());
            let b = v_cells.query_advice(b, Rotation::cur());
            let a_next = v_cells.query_advice(a, Rotation::next());

            let s = v_cells.query_selector(s);

            vec![s * (a_current * b - a_next)]
        });

        MulConfig {
            a,
            b,
            ins,
            selector: s,
        }
    }

    /// Synthesize the circuit.
    fn synthesize(&self, config: MulConfig, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let result = layouter.assign_region(
            || "Mul",
            |mut region: Region<'_, F>| {
                config.selector.enable(&mut region, 1)?;
                let val = self.a * self.b;
                let mul = region.assign_advice(config.a, 1, val);

                Ok(mul)
            },
        )?;
        layouter.constrain_instance(result.cell(), config.ins, 0);

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use snark_verifier::halo2_base::halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};

    #[test]
    fn test_mul() {
        // Testing 5 * 2
        let test_chip = MulChip::new(Fr::from(5), Fr::from(2));
        let k = 4;
        let pub_ins = vec![Fr::from(10)];
        let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
