use types::{EventProof, ReceiptMerkleProof, H256};

mod common;

#[test]
fn block_verification() {
    let test_block = include_str!("../tests/suits/block_17819525.json");
    let (hash, block_header) = common::load_block(test_block);
    let block_hash = H256::hash(&block_header);
    assert_eq!(hash, block_hash);

    let block_receipts = include_str!("../tests/suits/block_17819525_receipts.json");

    let receipts = common::load_receipts(block_receipts);

    for (i, receipt) in receipts.iter().enumerate() {
        println!("Proving receipt {}", i);
        let proof = ReceiptMerkleProof::from_transactions(receipts.clone(), i);
        let hash = H256::hash(receipt);
        let proof = EventProof {
            block_hash,
            block_header: block_header.clone(),
            transaction_receipt: receipt.clone(),
            transaction_receipt_hash: hash,
            merkle_proof_of_receipt: proof,
        };

        println!(
            "root: {}",
            hex::encode(
                proof
                    .merkle_proof_of_receipt
                    .merkle_root(&proof.transaction_receipt)
                    .0
            )
        );
        proof.validate().unwrap()
    }
}
