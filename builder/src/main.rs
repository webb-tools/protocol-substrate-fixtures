use std::fmt::Display;
use std::fs::File;

use arkworks_gadgets::ark_std::fmt::{Formatter, Result};
use arkworks_gadgets::prelude::{ark_bls12_381, ark_bn254, ark_std};
use arkworks_circuits::setup::{
	common::setup_tree_and_create_path_tree_x5,
	mixer::{
		setup_groth16_random_circuit_x5
	},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use arkworks_utils::{utils::common::Curve};
use std::io::Write;

const TREE_DEPTH:usize  =30;


pub fn get_keys(curve: Curve, pk_bytes: &mut Vec<u8>, vk_bytes: &mut Vec<u8>, pk_uncompressed_bytes: &mut Vec<u8>) {
	let rng = &mut ark_std::test_rng();
	match curve {
		Curve::Bn254 => {
			let (pk, vk) = setup_groth16_random_circuit_x5::<_, ark_bn254::Bn254, TREE_DEPTH>(rng, curve);
			vk.serialize(vk_bytes).unwrap();
			pk.serialize(pk_bytes).unwrap();
			CanonicalSerialize::serialize_uncompressed(&pk, pk_uncompressed_bytes).unwrap();
		}
		Curve::Bls381 => {
			let (pk, vk) = setup_groth16_random_circuit_x5::<_, ark_bls12_381::Bls12_381, TREE_DEPTH>(rng, curve);
			vk.serialize(vk_bytes).unwrap();
			pk.serialize(pk_bytes).unwrap();
			CanonicalSerialize::serialize_uncompressed(&pk, pk_uncompressed_bytes).unwrap();
		}
	};
}

pub fn write_keys(pk: &[u8], vk: &[u8], pk_u: &[u8]) {
	let mut verifying_key = File::create("./fixtures/verifying_key.bin").unwrap();
	let mut proving_key = File::create("./fixtures/proving_key.bin").unwrap();
	let mut proving_key_compressed = File::create("./fixtures/proving_key_uncompresed.bin").unwrap();
	verifying_key.write_all(&vk).unwrap();
	proving_key.write_all(&pk).unwrap();
	proving_key_compressed.write_all(&pk_u).unwrap();
	print!("Wrote files")
}

pub fn generate_and_wire_keys(curve: Curve) {
	let mut pk = Vec::new();
	let mut pk_u = Vec::new();
	let mut vk = Vec::new();
	get_keys(curve, &mut pk, &mut vk, &mut pk_u);
	write_keys(&pk, &vk, &pk_u);
}

fn main() {
	/// mixer x5
	generate_and_wire_keys(Curve::Bn254)
}
