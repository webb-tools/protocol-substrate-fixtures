use ark_ec::PairingEngine;
use arkworks_circuits::setup::anchor::AnchorProverSetup;
use arkworks_circuits::setup::mixer::MixerProverSetup;
use arkworks_utils::utils::common::{setup_params_x5_3, setup_params_x5_5, setup_params_x5_4, Curve};
use arkworks_circuits::prelude::ark_crypto_primitives::SNARK;
use ark_serialize::{CanonicalSerialize};
use ark_groth16::{Groth16};
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

	let (proving_key, verifying_key) = Groth16::<E>::circuit_specific_setup(circuit, &mut rng).unwrap();

	let mut pk = Vec::new();
	let mut vk = Vec::new();
	proving_key.serialize(&mut pk).unwrap();
	verifying_key.serialize(&mut vk).unwrap();

	let mut pk_uncompressed = Vec::new();
	let mut vk_uncompressed = Vec::new();
	proving_key.serialize_unchecked(&mut pk_uncompressed).unwrap();
	verifying_key.serialize_unchecked(&mut vk_uncompressed).unwrap();

	write(format!("{}/proving_key.bin", path), pk).unwrap();
	write(format!("{}/verifying_key.bin", path), vk).unwrap();
	write(format!("{}/proving_key_uncompressed.bin", path), pk_uncompressed).unwrap();
	write(format!("{}/verifying_key_uncompressed.bin", path), vk_uncompressed).unwrap();
}

fn generate_mixer_keys<E: PairingEngine>(curve: Curve, path: &str) {
	let mut rng = test_rng();
	let params3 = setup_params_x5_3::<E::Fr>(curve);
	let params5 = setup_params_x5_5::<E::Fr>(curve);

	let prover = MixerProverSetupBn254_30::new(params3, params5);
	let (circuit, ..) = prover.setup_random_circuit(&mut rng).unwrap();

	let (proving_key, verifying_key) = Groth16::<E>::circuit_specific_setup(circuit, &mut rng).unwrap();

	let mut pk = Vec::new();
	let mut vk = Vec::new();
	proving_key.serialize(&mut pk).unwrap();
	verifying_key.serialize(&mut vk).unwrap();

	let mut pk_uncompressed = Vec::new();
	let mut vk_uncompressed = Vec::new();
	proving_key.serialize_unchecked(&mut pk_uncompressed).unwrap();
	verifying_key.serialize_unchecked(&mut vk_uncompressed).unwrap();

	write(format!("{}/proving_key.bin", path), pk).unwrap();
	write(format!("{}/verifying_key.bin", path), vk).unwrap();
	write(format!("{}/proving_key_uncompressed.bin", path), pk_uncompressed).unwrap();
	write(format!("{}/verifying_key_uncompressed.bin", path), vk_uncompressed).unwrap();
}

fn main() {
	let current_path = current_dir().unwrap();
	let anchor_path = format!("{}/../fixed-anchor/bn254/x5", current_path.display());
	generate_anchor_keys::<Bn254>(Curve::Bn254, &anchor_path);
	let mixer_path = format!("{}/../mixer/bn254/x5", current_path.display());
	generate_mixer_keys::<Bn254>(Curve::Bn254, &mixer_path);
}
