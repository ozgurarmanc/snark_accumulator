#[cfg(test)]
mod test {
    use halo2_solidity_verifier::{
        BatchOpenScheme::Bdfg21, Evm, Keccak256Transcript, SolidityGenerator, compile_solidity,
        encode_calldata,
    };
    use pairing::group::ff::Field;
    use rand::{
        RngCore, SeedableRng,
        rngs::{OsRng, StdRng},
    };
    use snark_verifier::halo2_base::halo2_proofs::{
        halo2curves::bn256::Bn256,
        plonk::verify_proof,
        poly::{
            commitment::ParamsProver,
            kzg::{commitment::ParamsKZG, multiopen::VerifierSHPLONK, strategy::SingleStrategy},
        },
    };
    use snark_verifier::halo2_base::halo2_proofs::{
        halo2curves::bn256::Fr,
        plonk::{create_proof, keygen_pk, keygen_vk},
        poly::kzg::multiopen::ProverSHPLONK,
        transcript::TranscriptWriterBuffer,
    };

    use crate::mul::MulChip;

    #[test]
    pub fn test_pk_enc_full_prover() {
        let k = 10;
        //let kzg_params = gen_srs(k);
        let circuit = MulChip::new(Fr::one(), Fr::one());
        let kzg_params = ParamsKZG::<Bn256>::new(k);
        let instances = [[Fr::ONE]];

        // Keygen VerifyingKey / ProvingKey
        let vk = keygen_vk(&kzg_params, &circuit).unwrap();
        let pk = keygen_pk(&kzg_params, vk, &circuit).unwrap();
        let actual_num_instance_columns = pk.get_vk().cs().num_instance_columns();
        println!("VerifyingKey says num_instance_columns = {actual_num_instance_columns}");

        // Create a proof
        let mut rng = StdRng::seed_from_u64(OsRng.next_u64());
        let instance_refs = vec![instances[0].as_slice()];

        let proof = {
            let mut transcript = Keccak256Transcript::new(Vec::new());
            create_proof::<_, ProverSHPLONK<_>, _, _, _, _>(
                &kzg_params,
                &pk,
                &[circuit],
                &[&instance_refs],
                &mut rng,
                &mut transcript,
            )
            .unwrap();
            transcript.finalize()
        };

        println!("E2E proof size = {} bytes", proof.len());

        // Verify it locally
        let result = {
            let mut transcript = Keccak256Transcript::new(proof.as_slice());
            verify_proof::<_, VerifierSHPLONK<_>, _, _, SingleStrategy<_>>(
                &kzg_params,
                pk.get_vk(),
                SingleStrategy::new(&kzg_params),
                &[&instance_refs],
                &mut transcript,
            )
        };
        assert!(result.is_ok());
        println!("Local verification succeeded!");

        // --------------------------------------------------
        // (B) Generate a Solidity verifier & test in an EVM
        // --------------------------------------------------
        let num_public_inputs = instances[0].len();

        let generator = SolidityGenerator::new(&kzg_params, pk.get_vk(), Bdfg21, num_public_inputs);

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
