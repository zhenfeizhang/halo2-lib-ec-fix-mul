use halo2_ecc::{
    ecc::fixed_base,
    fields::{
        fp::{FpConfig, FpStrategy},
        FieldChip,
    },
    halo2_base::{
        halo2_proofs::{
            circuit::{Layouter, SimpleFloorPlanner, Value},
            halo2curves::{
                bn256::Fr,
                secp256k1::{Fp, Fq, Secp256k1Affine},
            },
            plonk::{Circuit, ConstraintSystem, Error},
        },
        utils::modulus,
        SKIP_FIRST_PASS,
    },
};

#[derive(Debug, Clone, Copy, Default)]
pub struct TestCricuit {
    scalar: Fq,
}
#[derive(Debug, Clone)]
pub struct TestCircuitConfig {
    fp_chip: FpConfig<Fr, Fp>,
}

impl Circuit<Fr> for TestCricuit {
    /// This is a configuration object that stores things like columns.
    type Config = TestCircuitConfig;

    /// The floor planner used for this circuit. This is an associated type of the
    /// `Circuit` trait because its behaviour is circuit-critical.
    type FloorPlanner = SimpleFloorPlanner;

    /// Returns a copy of this circuit with no witness values (i.e. all witnesses set to
    /// `None`). For most circuits, this will be equal to `Self::default()`.
    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    /// The circuit is given an opportunity to describe the exact gate
    /// arrangement, column arrangement, etc.
    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        Self::Config {
            fp_chip: FpConfig::configure(
                meta,
                FpStrategy::Simple,
                &[20],
                &[10],
                1,
                18,
                88,
                3,
                modulus::<Fp>(),
                0,
                19, // maximum k of the chip
            ),
        }
    }

    /// Given the provided `cs`, synthesize the circuit. The concrete type of
    /// the caller will be different depending on the context, and they may or
    /// may not expect to have a witness present.
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        config.fp_chip.range.load_lookup_table(&mut layouter)?;

        let mut first_pass = SKIP_FIRST_PASS;

        layouter.assign_region(
            || "ec mul",
            |region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }

                let mut ctx = config.fp_chip.new_context(region);
                let scalar_chip = FpConfig::<Fr, Fq>::construct(
                    config.fp_chip.range.clone(),
                    config.fp_chip.limb_bits,
                    config.fp_chip.num_limbs,
                    modulus::<Fq>(),
                );
                let scalar = scalar_chip.load_private(
                    &mut ctx,
                    FpConfig::<Fr, Fq>::fe_to_witness(&Value::known(self.scalar)),
                );
                fixed_base::scalar_multiply::<Fr, _, _>(
                    &config.fp_chip,
                    &mut ctx,
                    &Secp256k1Affine::generator(),
                    &scalar.truncation.limbs,
                    config.fp_chip.limb_bits,
                    4,
                );
                Ok(())
            },
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use halo2_ecc::halo2_base::halo2_proofs::dev::MockProver;

    use super::*;

    #[test]
    fn test_mul_neg_two() {
        let two_circuit = TestCricuit { scalar: -Fq::from(2) };

        let prover = match MockProver::run(19, &two_circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{e:#?}"),
        };
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_mul_neg_one() {
        let two_circuit = TestCricuit { scalar: -Fq::from(1) };

        let prover = match MockProver::run(19, &two_circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{e:#?}"),
        };
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_mul_one() {
        let two_circuit = TestCricuit { scalar: Fq::from(1) };

        let prover = match MockProver::run(19, &two_circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{e:#?}"),
        };
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_mul_two() {
        let two_circuit = TestCricuit { scalar: Fq::from(2) };

        let prover = match MockProver::run(19, &two_circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{e:#?}"),
        };
        assert_eq!(prover.verify(), Ok(()));
    }
}
