use ark_ec::PairingEngine;
use arkworks_circuits::setup::common::{setup_keys, setup_keys_unchecked};
use arkworks_circuits::setup::anchor::AnchorProverSetup;
use arkworks_circuits::setup::mixer::MixerProverSetup;
use arkworks_utils::utils::common::{setup_params_x5_3, setup_params_x5_5, setup_params_x5_4, Curve};
use ark_std::test_rng;
use ark_bn254::Bn254;
use std::fs::write;
use std::env::current_dir;

pub const N: usize = 30;
pub const M: usize = 2;
type AnchorProverSetupBn254_30<F> = AnchorProverSetup<F, M, N>;
type MixerProverSetupBn254_30<F> = MixerProverSetup<F, N>;

fn generate_anchor_keys<E: PairingEngine>(curve: Curve, path: &str) {
	let mut rng = test_rng();
	let params3 = setup_params_x5_3::<E::Fr>(curve);
	let params4 = setup_params_x5_4::<E::Fr>(curve);

	let prover = AnchorProverSetupBn254_30::new(params3, params4);
	let (circuit, ..) = prover.setup_random_circuit(&mut rng).unwrap();

	let (pk, vk) = setup_keys::<E, _, _>(circuit.clone(), &mut rng).unwrap();
	let (pk_unchecked, vk_unchecked) = setup_keys_unchecked::<E, _, _>(circuit, &mut rng).unwrap();

	write(format!("{}/proving_key.bin", path), pk).unwrap();
	write(format!("{}/verifying_key.bin", path), vk).unwrap();
	write(format!("{}/proving_key_unchecked.bin", path), pk_unchecked).unwrap();
	write(format!("{}/verifying_key_unchecked.bin", path), vk_unchecked).unwrap();
}

fn generate_mixer_keys<E: PairingEngine>(curve: Curve, path: &str) {
	let mut rng = test_rng();
	let params3 = setup_params_x5_3::<E::Fr>(curve);
	let params5 = setup_params_x5_5::<E::Fr>(curve);

	let prover = MixerProverSetupBn254_30::new(params3, params5);
	let (circuit, ..) = prover.setup_random_circuit(&mut rng).unwrap();

	let (pk, vk) = setup_keys::<E, _, _>(circuit.clone(), &mut rng).unwrap();
	let (pk_unchecked, vk_unchecked) = setup_keys_unchecked::<E, _, _>(circuit, &mut rng).unwrap();

	write(format!("{}/proving_key.bin", path), pk).unwrap();
	write(format!("{}/verifying_key.bin", path), vk).unwrap();
	write(format!("{}/proving_key_unchecked.bin", path), pk_unchecked).unwrap();
	write(format!("{}/verifying_key_unchecked.bin", path), vk_unchecked).unwrap();
}

fn main() {
	let current_path = current_dir().unwrap();
	let anchor_path = format!("{}/../fixed-anchor/bn254/x5", current_path.display());
	generate_anchor_keys::<Bn254>(Curve::Bn254, &anchor_path);
	let mixer_path = format!("{}/../mixer/bn254/x5", current_path.display());
	generate_mixer_keys::<Bn254>(Curve::Bn254, &mixer_path);
}
