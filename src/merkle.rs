use blake2::{Blake2s256, Digest};
use ethers::types::H256;
use merkle_cbt::merkle_tree::{Merge, CBMT};

struct MergeH256 {}

impl Merge for MergeH256 {
    type Item = H256;

    fn merge(left: &Self::Item, right: &Self::Item) -> Self::Item {
        let left_and_right = left
            .as_bytes()
            .iter()
            .chain(right.as_bytes().iter())
            .cloned()
            .collect::<Vec<_>>();

        H256::from_slice(Blake2s256::digest(left_and_right).as_slice())
    }
}

#[allow(non_camel_case_types)]
type CBMT_H256 = CBMT<H256, MergeH256>;

pub fn verify(hashes: &[H256], indices: &[u32], proof_leaves: &[H256]) -> bool {
    let root = CBMT_H256::build_merkle_root(hashes);
    let proof = CBMT_H256::build_merkle_proof(hashes, indices).unwrap();
    proof.verify(&root, proof_leaves)
}
