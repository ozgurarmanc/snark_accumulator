use std::{
    fs::{File, create_dir_all},
    io::Write,
};

use num_bigint::BigInt;
use num_traits::Num;
use pairing::group::ff::PrimeField;
use snark_verifier::loader::{
    evm::compile_solidity,
    halo2::halo2_wrong_ecc::halo2::{
        halo2curves::bn256::{Bn256, Fr},
        plonk::keygen_vk,
        poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
    },
};

const LEVELS: usize = 4;
const N_CURRENCIES: usize = 2;
const N_BYTES: usize = 8;

fn save_solidity(name: impl AsRef<str>, solidity: &str) {
    const DIR_GENERATED: &str = "../contracts/src";

    create_dir_all(DIR_GENERATED).unwrap();
    let path = format!("{DIR_GENERATED}/{}", name.as_ref());
    File::create(&path)
        .unwrap()
        .write_all(solidity.as_bytes())
        .unwrap();
    println!("Saved {path}");
}

#[cfg(test)]
mod test {
    use halo2_solidity_verifier::{BatchOpenScheme, SolidityGenerator};
    use snark_verifier::loader::{
        evm::compile_solidity,
        halo2::halo2_wrong_ecc::halo2::{
            halo2curves::bn256::{Bn256, Fr},
            plonk::keygen_vk,
            poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
        },
    };

    use crate::{halo2_verifier::save_solidity, mul::MulChip};

    #[test]
    fn test_verifier() {
        let k = 21;
        let circuit = MulChip::new(Fr::one(), Fr::one());
        let params = ParamsKZG::<Bn256>::new(k);
        let num_instances = 2;

        let vk = keygen_vk(&params, &circuit).unwrap();

        let generator =
            SolidityGenerator::new(&params, &vk, BatchOpenScheme::Bdfg21, num_instances);

        let verifier_solidity = generator
            .render()
            .unwrap()
            .replace("Halo2Verifier", "Verifier")
            .replace(") public returns (bool)", ") public view returns (bool)");
        save_solidity("InclusionVerifier.sol", &verifier_solidity);
        let deployment_code = compile_solidity(&verifier_solidity);
        let verifier_creation_code_size = deployment_code.len();
        println!("Verifier creation code size: {verifier_creation_code_size}");
    }
}
