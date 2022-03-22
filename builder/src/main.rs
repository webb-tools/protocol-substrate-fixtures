use arkworks_setups::r1cs::mixer::MixerR1CSProver;
use arkworks_setups::r1cs::anchor::AnchorR1CSProver;
use arkworks_setups::r1cs::vanchor::VAnchorR1CSProver;
use ark_crypto_primitives::SNARK;
use arkworks_utils::Curve;
use ark_ec::PairingEngine;
use ark_serialize::CanonicalSerialize;
use ark_groth16::{ProvingKey, VerifyingKey, Groth16};
use ark_std::test_rng;
use std::fs::write;
use std::env::current_dir;

use ark_bn254::Bn254;

const TREE_HEIGHT: usize = 30;
type MixerProverSetupBn254_30 = MixerR1CSProver<Bn254, TREE_HEIGHT>;

const ANCHOR_CT: usize = 2;
type AnchorProverSetupBn254_30 = AnchorR1CSProver<Bn254, TREE_HEIGHT, ANCHOR_CT>;

const NUM_INS_2: usize = 2;
const NUM_OUTS_2: usize = 2;
type VAnchorProverSetupBn254_30_2x2 = VAnchorR1CSProver<Bn254, TREE_HEIGHT, ANCHOR_CT, NUM_INS_2, NUM_OUTS_2>;

const NUM_INS_16: usize = 16;
const NUM_OUTS_16: usize = 2;
type VAnchorProverSetupBn254_30_16x2 = VAnchorR1CSProver<Bn254, TREE_HEIGHT, ANCHOR_CT, NUM_INS_16, NUM_OUTS_16>;

fn save_keys<E: PairingEngine>(proving_key: ProvingKey<E>, verifying_key: VerifyingKey<E>, path: &str) {
	let mut pk = Vec::new();
	let mut vk = Vec::new();
	proving_key.serialize(&mut pk).unwrap();
	verifying_key.serialize(&mut vk).unwrap();

	let mut pk_uncompressed = Vec::new();
	let mut vk_uncompressed = Vec::new();
	proving_key.serialize_uncompressed(&mut pk_uncompressed).unwrap();
	verifying_key.serialize_uncompressed(&mut vk_uncompressed).unwrap();

	let current_path = current_dir().unwrap();
	write(format!("{}/{}/proving_key.bin", current_path.display(), path), pk).unwrap();
	write(format!("{}/{}/verifying_key.bin", current_path.display(), path), vk).unwrap();
	write(format!("{}/{}/proving_key_uncompressed.bin", current_path.display(), path), pk_uncompressed).unwrap();
	write(format!("{}/{}/verifying_key_uncompressed.bin", current_path.display(), path), vk_uncompressed).unwrap();
}

fn generate_mixer_keys<E: PairingEngine>(curve: Curve) {
	let rng = &mut test_rng();

	// Setup random circuit
	let (c, ..) = MixerProverSetupBn254_30::setup_random_circuit(curve, [0u8; 32], rng).unwrap();
	// Generate the keys
	let (proving_key, verifying_key) = Groth16::<Bn254>::circuit_specific_setup(c, rng).unwrap();

	save_keys(proving_key, verifying_key, "../mixer/bn254/x5");
}

fn generate_anchor_keys<E: PairingEngine>(curve: Curve) {
	let rng = &mut test_rng();

	// Setup random circuit
	let (c, ..) = AnchorProverSetupBn254_30::setup_random_circuit(curve, [0u8; 32], rng).unwrap();
	// Generate the keys
	let (proving_key, verifying_key) = Groth16::<Bn254>::circuit_specific_setup(c, rng).unwrap();

	save_keys(proving_key, verifying_key, "../fixed-anchor/bn254/x5");
}

fn generate_vanchor_2_keys<E: PairingEngine>(curve: Curve) {
	let rng = &mut test_rng();

	// Setup random circuit
	let c = VAnchorProverSetupBn254_30_2x2::setup_random_circuit(curve, [0u8; 32], rng).unwrap();
	// Generate the keys
	let (proving_key, verifying_key) = Groth16::<Bn254>::circuit_specific_setup(c, rng).unwrap();

	save_keys(proving_key, verifying_key, "../vanchor/bn254/x5/2");
}

fn generate_vanchor_16_keys<E: PairingEngine>(curve: Curve) {
	let rng = &mut test_rng();

	// Setup random circuit
	let c = VAnchorProverSetupBn254_30_16x2::setup_random_circuit(curve, [0u8; 32], rng).unwrap();
	// Generate the keys
	let (proving_key, verifying_key) = Groth16::<Bn254>::circuit_specific_setup(c, rng).unwrap();

	save_keys(proving_key, verifying_key, "../vanchor/bn254/x5/16");
}

fn main() {
	// Generate Mixer keys with tree of heigth 30
	generate_mixer_keys::<Bn254>(Curve::Bn254);

	// Generate anchor keys with tree of heigth 30
	// and anchor count of 2
	generate_anchor_keys::<Bn254>(Curve::Bn254);

	// Generate vanchor keys with tree of height 30
	// and anchor count of 2
	// and number of inputs of 2
	// and number of outputs of 2
	generate_vanchor_2_keys::<Bn254>(Curve::Bn254);

	// Generate vanchor keys with tree of height 30
	// and anchor count of 2
	// and number of inputs of 16
	// and number of outputs of 2
	generate_vanchor_16_keys::<Bn254>(Curve::Bn254);
}
