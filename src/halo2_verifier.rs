#[cfg(test)]
mod test {
    use crate::{
        evm_accumulator::{
            aggregation::{self, AggregationCircuit, AggregationConfigParams, Snark},
            gen_aggregation_evm_verifier, gen_pk, gen_proof,
        },
        mul::MulChip,
    };
    use halo2_solidity_verifier::{
        BatchOpenScheme::Bdfg21, Evm, SolidityGenerator, compile_solidity, encode_calldata,
    };
    use snark_verifier::{halo2_base::utils::fs::gen_srs, system::halo2::Config};
    use snark_verifier::{
        halo2_base::{
            gates::circuit::{BaseCircuitParams, CircuitBuilderStage},
            halo2_proofs::{
                dev::MockProver,
                halo2curves::bn256::{Bn256, Fr, G1Affine},
                poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
                transcript::{Keccak256Read, Keccak256Write},
            },
        },
        loader::native::NativeLoader,
        system::halo2::{compile, transcript::evm::EvmTranscript},
    };

    fn aggregator() -> Vec<u8> {
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

        // let _deployment_code = gen_aggregation_evm_verifier(
        //     &params,
        //     pk.get_vk(),
        //     aggregation::AggregationCircuit::num_instance(),
        //     aggregation::AggregationCircuit::accumulator_indices(),
        // );

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
        let proof = gen_proof::<
            _,
            _,
            EvmTranscript<G1Affine, _, _, _>,
            EvmTranscript<G1Affine, _, _, _>,
        >(&params, &pk, agg_circuit.inner, instances.clone());

        proof
    }

    #[test]
    pub fn test_verifier() {
        // Testing Aggregator verification
        let k = 21;
        let params = gen_srs(k);

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
            params.get_g()[0],
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

        let pk = gen_pk(&params, &agg_circuit.inner);

        let actual_num_instance_columns = pk.get_vk().cs().num_instance_columns();
        println!("VerifyingKey says num_instance_columns = {actual_num_instance_columns}");

        // let _deployment_code = gen_aggregation_evm_verifier(
        //     &params,
        //     pk.get_vk(),
        //     aggregation::AggregationCircuit::num_instance(),
        //     aggregation::AggregationCircuit::accumulator_indices(),
        // );

        let break_points = agg_circuit.inner.break_points();
        drop(agg_circuit);

        let agg_circuit = AggregationCircuit::new(
            CircuitBuilderStage::Prover,
            circuit_params,
            Some(break_points),
            params.get_g()[0],
            snarks,
        );
        let instances = agg_circuit.instances();

        let proof = gen_proof::<_, _, Keccak256Read<_, _, _>, Keccak256Write<_, _, _>>(
            &params,
            &pk,
            agg_circuit.inner,
            instances.clone(),
        );

        println!("E2E proof size = {} bytes", proof.len());
        println!("Local verification succeeded!");

        // --------------------------------------------------
        // (B) Generate a Solidity verifier & test in an EVM
        // --------------------------------------------------
        let num_public_inputs = instances[0].len();

        let generator = SolidityGenerator::new(&params, pk.get_vk(), Bdfg21, num_public_inputs);

        // Render the Solidity code as a single contract
        let verifier_solidity: String = generator.render().expect("render contract");

        // Compile it
        let creation_code = compile_solidity(&verifier_solidity);
        let code_size = creation_code.len();
        println!("Verifier creation code size: {}", code_size);

        // Deploy it to a local EVM
        let mut evm = Evm::default();
        let verifier_address = evm.create(creation_code);
        println!("verifier_address = {:?}", verifier_address);

        // Encode the calldata: we have None for "inlined" verifying key in the same contract
        let calldata = encode_calldata(None, &proof, &instances[0]);

        // Call the contract
        let (gas_cost, output) = evm.call(verifier_address, calldata);

        assert_eq!(output.last(), Some(&1u8), "EVM returned 'false'");
        println!("EVM verification success with gas cost = {gas_cost}");
    }
}
