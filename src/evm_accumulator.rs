#![allow(dead_code)]

use itertools::Itertools;
use rand::rngs::OsRng;
use snark_verifier::{
    halo2_base::halo2_proofs::{
        halo2curves::bn256::{Bn256, Fq, Fr, G1Affine},
        plonk::{
            Circuit, ProvingKey, VerifyingKey, create_proof, keygen_pk, keygen_vk, verify_proof,
        },
        poly::{
            VerificationStrategy,
            commitment::ParamsProver,
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsKZG},
                multiopen::{ProverGWC, VerifierGWC},
                strategy::AccumulatorStrategy,
            },
        },
        transcript::{EncodedChallenge, TranscriptReadBuffer, TranscriptWriterBuffer},
    },
    loader::evm::{self, EvmLoader},
    pcs::kzg::{Gwc19, KzgAs, LimbsEncoding},
    system::halo2::{Config, compile, transcript::evm::EvmTranscript},
    verifier::{self, SnarkVerifier},
};
use std::{io::Cursor, rc::Rc};

const LIMBS: usize = 3;
const BITS: usize = 88;

type As = KzgAs<Bn256, Gwc19>;
type PlonkSuccinctVerifier = verifier::plonk::PlonkSuccinctVerifier<As, LimbsEncoding<LIMBS, BITS>>;
type PlonkVerifier = verifier::plonk::PlonkVerifier<As, LimbsEncoding<LIMBS, BITS>>;

mod aggregation {
    use std::{mem, rc::Rc};

    use itertools::Itertools;
    use rand::rngs::OsRng;
    use snark_verifier::{
        halo2_base::{
            gates::{
                circuit::{BaseCircuitParams, CircuitBuilderStage, builder::BaseCircuitBuilder},
                flex_gate::MultiPhaseThreadBreakPoints,
            },
            halo2_proofs::halo2curves::bn256::{Fr, G1Affine},
        },
        halo2_ecc::{self, bn254::FpChip},
        loader::{self, native::NativeLoader},
        pcs::{
            AccumulationScheme, AccumulationSchemeProver,
            kzg::{KzgAccumulator, KzgSuccinctVerifyingKey},
        },
        system,
        util::arithmetic::fe_to_limbs,
        verifier::{SnarkVerifier, plonk::PlonkProtocol},
    };

    use super::{As, BITS, LIMBS, PlonkSuccinctVerifier};

    const T: usize = 3;
    const RATE: usize = 2;
    const R_F: usize = 8;
    const R_P: usize = 57;
    const SECURE_MDS: usize = 0;

    type Svk = KzgSuccinctVerifyingKey<G1Affine>;
    type BaseFieldEccChip<'chip> = halo2_ecc::ecc::BaseFieldEccChip<'chip, G1Affine>;
    type Halo2Loader<'chip> = loader::halo2::Halo2Loader<G1Affine, BaseFieldEccChip<'chip>>;
    pub type PoseidonTranscript<L, S> =
        system::halo2::transcript::halo2::PoseidonTranscript<G1Affine, L, S, T, RATE, R_F, R_P>;

    #[derive(Clone)]
    pub struct Snark {
        protocol: PlonkProtocol<G1Affine>,
        instances: Vec<Vec<Fr>>,
        proof: Vec<u8>,
    }

    impl Snark {
        pub fn new(
            protocol: PlonkProtocol<G1Affine>,
            instances: Vec<Vec<Fr>>,
            proof: Vec<u8>,
        ) -> Self {
            Self {
                protocol,
                instances,
                proof,
            }
        }
    }

    impl Snark {
        fn proof(&self) -> &[u8] {
            self.proof.as_slice()
        }
    }

    pub fn aggregate<'a>(
        svk: &Svk,
        loader: &Rc<Halo2Loader<'a>>,
        snarks: &[Snark],
        as_proof: &[u8],
    ) -> KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>> {
        let assign_instances = |instances: &[Vec<Fr>]| {
            instances
                .iter()
                .map(|instances| {
                    instances
                        .iter()
                        .map(|instance| loader.assign_scalar(*instance))
                        .collect_vec()
                })
                .collect_vec()
        };

        let accumulators = snarks
            .iter()
            .flat_map(|snark| {
                let protocol = snark.protocol.loaded(loader);
                let instances = assign_instances(&snark.instances);
                let mut transcript =
                    PoseidonTranscript::<Rc<Halo2Loader>, _>::new::<0>(loader, snark.proof());
                let proof =
                    PlonkSuccinctVerifier::read_proof(svk, &protocol, &instances, &mut transcript)
                        .unwrap();
                PlonkSuccinctVerifier::verify(svk, &protocol, &instances, &proof).unwrap()
            })
            .collect_vec();

        let mut transcript =
            PoseidonTranscript::<Rc<Halo2Loader>, _>::new::<SECURE_MDS>(loader, as_proof);
        let proof = As::read_proof(&Default::default(), &accumulators, &mut transcript).unwrap();
        As::verify(&Default::default(), &accumulators, &proof).unwrap()
    }

    #[derive(serde::Serialize, serde::Deserialize, Default)]
    pub struct AggregationConfigParams {
        pub degree: u32,
        pub num_advice: usize,
        pub num_lookup_advice: usize,
        pub num_fixed: usize,
        pub lookup_bits: usize,
    }

    #[derive(Clone, Debug)]
    pub struct AggregationCircuit {
        pub inner: BaseCircuitBuilder<Fr>,
        pub as_proof: Vec<u8>,
    }

    impl AggregationCircuit {
        pub fn new(
            stage: CircuitBuilderStage,
            circuit_params: BaseCircuitParams,
            break_points: Option<MultiPhaseThreadBreakPoints>,
            params_g0: G1Affine,
            snarks: impl IntoIterator<Item = Snark>,
        ) -> Self {
            let svk: Svk = params_g0.into();
            let snarks = snarks.into_iter().collect_vec();

            // verify the snarks natively to get public instances
            let accumulators = snarks
                .iter()
                .flat_map(|snark| {
                    let mut transcript = PoseidonTranscript::<NativeLoader, _>::new::<SECURE_MDS>(
                        snark.proof.as_slice(),
                    );
                    let proof = PlonkSuccinctVerifier::read_proof(
                        &svk,
                        &snark.protocol,
                        &snark.instances,
                        &mut transcript,
                    )
                    .unwrap();
                    PlonkSuccinctVerifier::verify(&svk, &snark.protocol, &snark.instances, &proof)
                        .unwrap()
                })
                .collect_vec();

            let (_accumulator, as_proof) = {
                let mut transcript =
                    PoseidonTranscript::<NativeLoader, _>::new::<SECURE_MDS>(Vec::new());
                let accumulator =
                    As::create_proof(&Default::default(), &accumulators, &mut transcript, OsRng)
                        .unwrap();
                (accumulator, transcript.finalize())
            };

            let mut builder = BaseCircuitBuilder::from_stage(stage).use_params(circuit_params);
            // create halo2loader
            let range = builder.range_chip();
            let fp_chip = FpChip::<Fr>::new(&range, BITS, LIMBS);
            let ecc_chip = BaseFieldEccChip::new(&fp_chip);
            let pool = mem::take(builder.pool(0));
            let loader = Halo2Loader::new(ecc_chip, pool);

            // witness generation
            let KzgAccumulator { lhs, rhs } =
                aggregate(&svk, &loader, &snarks, as_proof.as_slice());
            let lhs = lhs.assigned();
            let rhs = rhs.assigned();
            let assigned_instances = lhs
                .x()
                .limbs()
                .iter()
                .chain(lhs.y().limbs().iter())
                .chain(rhs.x().limbs().iter())
                .chain(rhs.y().limbs().iter())
                .copied()
                .collect_vec();

            #[cfg(debug_assertions)]
            {
                let KzgAccumulator { lhs, rhs } = _accumulator;
                let instances = [lhs.x, lhs.y, rhs.x, rhs.y]
                    .map(fe_to_limbs::<_, Fr, LIMBS, BITS>)
                    .concat();
                for (lhs, rhs) in instances.iter().zip(assigned_instances.iter()) {
                    assert_eq!(lhs, rhs.value());
                }
            }

            *builder.pool(0) = loader.take_ctx();
            builder.assigned_instances[0] = assigned_instances;
            if let Some(break_points) = break_points {
                builder.set_break_points(break_points);
            }
            Self {
                inner: builder,
                as_proof,
            }
        }

        pub fn num_instance() -> Vec<usize> {
            // [..lhs, ..rhs]
            vec![4 * LIMBS]
        }

        pub fn instances(&self) -> Vec<Vec<Fr>> {
            self.inner
                .assigned_instances
                .iter()
                .map(|v| v.iter().map(|v| *v.value()).collect_vec())
                .collect()
        }

        pub fn accumulator_indices() -> Vec<(usize, usize)> {
            (0..4 * LIMBS).map(|idx| (0, idx)).collect()
        }
    }
}

fn gen_pk<C: Circuit<Fr>>(params: &ParamsKZG<Bn256>, circuit: &C) -> ProvingKey<G1Affine> {
    let vk = keygen_vk(params, circuit).unwrap();
    println!("finished vk");
    let pk = keygen_pk(params, vk, circuit).unwrap();
    println!("finished pk");
    pk
}

fn gen_proof<
    C: Circuit<Fr>,
    E: EncodedChallenge<G1Affine>,
    TR: TranscriptReadBuffer<Cursor<Vec<u8>>, G1Affine, E>,
    TW: TranscriptWriterBuffer<Vec<u8>, G1Affine, E>,
>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    instances: Vec<Vec<Fr>>,
) -> Vec<u8> {
    let instances = instances
        .iter()
        .map(|instances| instances.as_slice())
        .collect_vec();
    let proof = {
        let mut transcript = TW::init(Vec::new());
        create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, TW, _>(
            params,
            pk,
            &[circuit],
            &[instances.as_slice()],
            OsRng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    let accept = {
        let mut transcript = TR::init(Cursor::new(proof.clone()));
        VerificationStrategy::<_, VerifierGWC<_>>::finalize(
            verify_proof::<_, VerifierGWC<_>, _, TR, _>(
                params.verifier_params(),
                pk.get_vk(),
                AccumulatorStrategy::new(params.verifier_params()),
                &[instances.as_slice()],
                &mut transcript,
            )
            .unwrap(),
        )
    };
    assert!(accept);

    proof
}

fn gen_aggregation_evm_verifier(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
    accumulator_indices: Vec<(usize, usize)>,
) -> Vec<u8> {
    let protocol = compile(
        params,
        vk,
        Config::kzg()
            .with_num_instance(num_instance.clone())
            .with_accumulator_indices(Some(accumulator_indices)),
    );
    let vk = (params.get_g()[0], params.g2(), params.s_g2()).into();

    let loader = EvmLoader::new::<Fq, Fr>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    let instances = transcript.load_instances(num_instance);
    let proof = PlonkVerifier::read_proof(&vk, &protocol, &instances, &mut transcript).unwrap();
    PlonkVerifier::verify(&vk, &protocol, &instances, &proof).unwrap();

    evm::compile_solidity(&loader.solidity_code())
}

#[cfg(test)]
mod test {
    use super::{
        aggregation::{self, AggregationCircuit, AggregationConfigParams, Snark},
        gen_aggregation_evm_verifier, gen_pk, gen_proof,
    };
    use crate::mul::MulChip;
    use snark_verifier::{
        halo2_base::{
            gates::circuit::{BaseCircuitParams, CircuitBuilderStage},
            halo2_proofs::{
                dev::MockProver,
                halo2curves::bn256::{Bn256, Fr, G1Affine},
                poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
            },
            utils::fs::gen_srs,
        },
        loader::native::NativeLoader,
        system::halo2::{Config, compile, transcript::evm::EvmTranscript},
    };

    #[test]
    fn test_aggregation() {
        // Testing Aggregator
        let k = 21;
        let params_app = gen_srs(k);

        let params = ParamsKZG::<Bn256>::new(k);

        let random_circuit_1 = MulChip::new(Fr::one(), Fr::one());
        let random_circuit_2 = MulChip::new(Fr::one(), Fr::one());

        let instances_1: Vec<Vec<Fr>> = vec![vec![Fr::one()]];
        let instances_2: Vec<Vec<Fr>> = vec![vec![Fr::one()]];

        let pk_1 = gen_pk(&params, &random_circuit_1);
        let protocol_1 = compile(
            &params,
            pk_1.get_vk(),
            Config::kzg().with_num_instance(vec![instances_1[0].len()]),
        );

        let proof_1 = gen_proof::<
            _,
            _,
            aggregation::PoseidonTranscript<NativeLoader, _>,
            aggregation::PoseidonTranscript<NativeLoader, _>,
        >(&params, &pk_1, random_circuit_1, instances_1.clone());
        aggregation::Snark::new(protocol_1.clone(), instances_1.clone(), proof_1.clone());

        let pk_2 = gen_pk(&params, &random_circuit_2);
        let protocol_2 = compile(
            &params,
            pk_2.get_vk(),
            Config::kzg().with_num_instance(vec![instances_2[0].len()]),
        );

        let proof_2 = gen_proof::<
            _,
            _,
            aggregation::PoseidonTranscript<NativeLoader, _>,
            aggregation::PoseidonTranscript<NativeLoader, _>,
        >(&params, &pk_2, random_circuit_2, instances_2.clone());
        aggregation::Snark::new(protocol_2.clone(), instances_2.clone(), proof_2.clone());

        let snark_1 = Snark::new(protocol_1, instances_1, proof_1);
        let snark_2 = Snark::new(protocol_2, instances_2, proof_2);
        let snarks = [snark_1, snark_2];
        let agg_config = AggregationConfigParams {
            degree: k,
            num_advice: 3,
            num_lookup_advice: 1,
            num_fixed: 1,
            lookup_bits: 20,
        };

        let mut circuit_params = BaseCircuitParams {
            k: agg_config.degree as usize,
            num_advice_per_phase: vec![agg_config.num_advice],
            num_lookup_advice_per_phase: vec![agg_config.num_lookup_advice],
            num_fixed: agg_config.num_fixed,
            lookup_bits: Some(agg_config.lookup_bits),
            num_instance_columns: 1,
        };

        let mut agg_circuit = AggregationCircuit::new(
            CircuitBuilderStage::Mock,
            circuit_params,
            None,
            params_app.get_g()[0],
            snarks.clone(),
        );

        circuit_params = agg_circuit.inner.calculate_params(Some(9));
        #[cfg(debug_assertions)]
        {
            MockProver::run(
                agg_config.degree,
                &agg_circuit.inner,
                agg_circuit.instances(),
            )
            .unwrap()
            .assert_satisfied();
            println!("mock prover passed");
        }

        let params = gen_srs(agg_config.degree);
        let pk = gen_pk(&params, &agg_circuit.inner);
        let _deployment_code = gen_aggregation_evm_verifier(
            &params,
            pk.get_vk(),
            aggregation::AggregationCircuit::num_instance(),
            aggregation::AggregationCircuit::accumulator_indices(),
        );

        let break_points = agg_circuit.inner.break_points();
        drop(agg_circuit);

        let agg_circuit = AggregationCircuit::new(
            CircuitBuilderStage::Prover,
            circuit_params,
            Some(break_points),
            params_app.get_g()[0],
            snarks,
        );
        let instances = agg_circuit.instances();
        let _proof = gen_proof::<
            _,
            _,
            EvmTranscript<G1Affine, _, _, _>,
            EvmTranscript<G1Affine, _, _, _>,
        >(&params, &pk, agg_circuit.inner, instances.clone());
    }
}
