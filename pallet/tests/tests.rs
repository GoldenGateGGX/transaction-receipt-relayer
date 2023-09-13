use eth_types::{eth2::LightClientUpdate, pallet::InitInput, BlockHeader};
use frame_support::sp_runtime::AccountId32;
use frame_support::{assert_err, assert_ok};
use webb_proposals::TypedChainId;

use pallet_receipt_registry::Error;
use types::{Bloom, EventProof, MerkleProof, TransactionReceipt, H160, H256, U256};

mod mock;
use mock::{new_test_ext, Eth2Client, ReceiptRegistry, RuntimeOrigin, System, Test};

mod test_utils;
use test_utils::*;

#[path = "../../merkle/tests/common.rs"]
pub mod common;

pub const MAINNET_CHAIN: TypedChainId = TypedChainId::Evm(1);
pub const GOERLI_CHAIN: TypedChainId = TypedChainId::Evm(5);
pub const ALICE: AccountId32 = AccountId32::new([1u8; 32]);

pub fn get_test_context(
    init_options: Option<InitOptions<[u8; 32]>>,
) -> (
    &'static Vec<Vec<BlockHeader>>,
    &'static Vec<LightClientUpdate>,
    InitInput<[u8; 32]>,
) {
    let (headers, updates, init_input_0) = get_test_data(init_options);
    let init_input = init_input_0.clone().map_into();

    assert_ok!(Eth2Client::init(
        RuntimeOrigin::signed(ALICE.clone()),
        GOERLI_CHAIN,
        Box::new(init_input)
    ));

    assert_eq!(
        Eth2Client::last_block_number(GOERLI_CHAIN),
        headers[0][0].number
    );

    (headers, updates, init_input_0)
}

fn balance_of_user(user: &AccountId32) -> u128 {
    System::account(user).data.free
}

fn create_proof(receipts: &[TransactionReceipt], index_to_prove: usize) -> MerkleProof {
    use merkle_generator::IterativeTrie;

    let mut trie = merkle_generator::PatriciaTrie::new();
    receipts.iter().enumerate().for_each(|(i, receipt)| {
        trie.insert(alloy_rlp::encode(i), alloy_rlp::encode(receipt));
    });
    trie.merkle_proof(alloy_rlp::encode(index_to_prove))
}

fn block_header_convert(header: eth_types::BlockHeader) -> types::BlockHeader {
    let hash: [u8; 32] = header.calculate_hash().0 .0;
    let block_header = types::BlockHeader {
        parent_hash: H256(header.parent_hash.0 .0),
        beneficiary: H160(header.author.0 .0),
        state_root: H256(header.state_root.0 .0),
        transactions_root: H256(header.transactions_root.0 .0),
        receipts_root: H256(header.receipts_root.0 .0),
        withdrawals_root: header.withdrawals_root.map(|r| H256(r.0 .0)),
        logs_bloom: Bloom::new(header.log_bloom.0 .0),
        number: header.number,
        gas_limit: header.gas_limit.0.as_u64(),
        gas_used: header.gas_used.0.as_u64(),
        timestamp: header.timestamp,
        mix_hash: H256(header.mix_hash.0 .0),
        base_fee_per_gas: Some(header.base_fee_per_gas.unwrap()),
        extra_data: header.extra_data,

        // Defaults
        ommers_hash: H256(header.uncles_hash.0 .0),
        difficulty: U256::from_slice(
            header
                .difficulty
                .0
                 .0
                .into_iter()
                .flat_map(u64::to_be_bytes)
                .collect::<Vec<u8>>()
                .as_slice(),
        ),
        nonce: header.nonce.0.to_low_u64_be(),

        // TODO: add conversion once ExecutionPayload has 4844 fields
        blob_gas_used: None,
        excess_blob_gas: None,
    };
    assert_eq!(hash, H256::hash(&block_header).0);

    block_header
}

#[test]
pub fn test_submit_proof_deserialize_fail() {
    new_test_ext().execute_with(|| {
        assert_err!(
            ReceiptRegistry::submit_proof(RuntimeOrigin::signed(ALICE), MAINNET_CHAIN, vec![1]),
            Error::<Test>::DeserializeFail
        );
    });
}

#[test]
pub fn test_submit_proof_header_hash_do_not_exist() {
    new_test_ext().execute_with(|| {
        let proof = EventProof {
            block_header: types::BlockHeader {
                parent_hash: types::H256::zero(),
                ommers_hash: types::H256::zero(),
                beneficiary: types::H160::new([0u8; 20]),
                state_root: types::H256::zero(),
                transactions_root: types::H256::zero(),
                receipts_root: types::H256::zero(),
                withdrawals_root: None,
                logs_bloom: types::Bloom::new([0; 256]),
                difficulty: 0.into(),
                number: 0,
                gas_limit: 0,
                gas_used: 0,
                timestamp: 0,
                mix_hash: types::H256::zero(),
                nonce: 0,
                base_fee_per_gas: None,
                blob_gas_used: None,
                excess_blob_gas: None,
                extra_data: vec![0],
            },
            block_hash: types::H256::zero(),
            transaction_receipt: types::TransactionReceipt {
                bloom: types::Bloom::new([0; 256]),
                receipt: types::Receipt {
                    tx_type: types::TxType::Legacy,
                    success: false,
                    cumulative_gas_used: 0,
                    logs: vec![],
                },
            },
            transaction_receipt_hash: types::H256::zero(),
            merkle_proof_of_receipt: types::MerkleProof {
                proof: vec![],
                key: vec![],
            },
        };
        let serialized_proof = serde_json::to_string(&proof).unwrap();

        assert_err!(
            ReceiptRegistry::submit_proof(
                RuntimeOrigin::signed(ALICE),
                GOERLI_CHAIN,
                serialized_proof.into()
            ),
            Error::<Test>::HeaderHashDoesNotExist
        );
    });
}

#[test]
pub fn test_submit_proof_block_hash_do_not_match() {
    new_test_ext().execute_with(|| {
        let (headers, _updates, _init_input) = get_test_context(None);

        let proof = EventProof {
            block_header: types::BlockHeader {
                parent_hash: types::H256::zero(),
                ommers_hash: types::H256::zero(),
                beneficiary: types::H160::new([0u8; 20]),
                state_root: types::H256::zero(),
                transactions_root: types::H256::zero(),
                receipts_root: types::H256::zero(),
                withdrawals_root: None,
                logs_bloom: types::Bloom::new([0; 256]),
                difficulty: 0.into(),
                number: headers[0][0].number,
                gas_limit: 0,
                gas_used: 0,
                timestamp: 0,
                mix_hash: types::H256::zero(),
                nonce: 0,
                base_fee_per_gas: None,
                blob_gas_used: None,
                excess_blob_gas: None,
                extra_data: vec![0],
            },
            block_hash: types::H256::zero(),
            transaction_receipt: types::TransactionReceipt {
                bloom: types::Bloom::new([0; 256]),
                receipt: types::Receipt {
                    tx_type: types::TxType::Legacy,
                    success: false,
                    cumulative_gas_used: 0,
                    logs: vec![],
                },
            },
            transaction_receipt_hash: types::H256::zero(),
            merkle_proof_of_receipt: Default::default(),
        };
        let serialized_proof = serde_json::to_string(&proof).unwrap();

        assert_err!(
            ReceiptRegistry::submit_proof(
                RuntimeOrigin::signed(ALICE),
                GOERLI_CHAIN,
                serialized_proof.into()
            ),
            Error::<Test>::BlockHashesDoNotMatch
        );
    });
}

#[test]
pub fn test_submit_proof_processed_receipts_hash_do_not_contains_key_verify_proof_fail() {
    new_test_ext().execute_with(|| {
        let (headers, _updates, _init_input) = get_test_context(Some(InitOptions {
            validate_updates: true,
            verify_bls_signatures: true,
            hashes_gc_threshold: 7100,
            trusted_signer: Some([2u8; 32]),
        }));

        let proof = EventProof {
            block_header: types::BlockHeader {
                parent_hash: types::H256::zero(),
                ommers_hash: types::H256::zero(),
                beneficiary: types::H160::new([0u8; 20]),
                state_root: types::H256::zero(),
                transactions_root: types::H256::zero(),
                receipts_root: types::H256::zero(),
                withdrawals_root: None,
                logs_bloom: types::Bloom::new([0; 256]),
                difficulty: 0.into(),
                number: headers[0][0].number,
                gas_limit: 0,
                gas_used: 0,
                timestamp: 0,
                mix_hash: types::H256::zero(),
                nonce: 0,
                base_fee_per_gas: None,
                blob_gas_used: None,
                excess_blob_gas: None,
                extra_data: vec![0],
            },
            block_hash: types::H256(headers[0][0].calculate_hash().0 .0),
            transaction_receipt: types::TransactionReceipt {
                bloom: types::Bloom::new([0; 256]),
                receipt: types::Receipt {
                    tx_type: types::TxType::Legacy,
                    success: false,
                    cumulative_gas_used: 0,
                    logs: vec![],
                },
            },
            transaction_receipt_hash: types::H256::zero(),
            merkle_proof_of_receipt: Default::default(),
        };
        let serialized_proof = serde_json::to_string(&proof).unwrap();

        assert_err!(
            ReceiptRegistry::submit_proof(
                RuntimeOrigin::signed(ALICE),
                GOERLI_CHAIN,
                serialized_proof.into()
            ),
            Error::<Test>::VerifyProofFail
        );
    });
}

#[test]
pub fn test_submit_proof_processed_receipts_hash_do_not_contains_key_verify_proof_success() {
    new_test_ext().execute_with(|| {
        let (headers, _updates, _init_input) = get_test_context(Some(InitOptions {
            validate_updates: true,
            verify_bls_signatures: true,
            hashes_gc_threshold: 7100,
            trusted_signer: Some([2u8; 32]),
        }));

        const PROOF_DEPOSIT: u128 = 1;
        const PROOF_REWARD: u128 = 2;
        assert_ok!(ReceiptRegistry::update_proof_fee(
            RuntimeOrigin::root(),
            GOERLI_CHAIN,
            PROOF_DEPOSIT,
            PROOF_REWARD
        ));

        assert_eq!(ReceiptRegistry::proof_deposit(GOERLI_CHAIN), PROOF_DEPOSIT);
        assert_eq!(ReceiptRegistry::proof_reward(GOERLI_CHAIN), PROOF_REWARD);

        let address = H160(hex_literal::hex!(
            "228612206ba22b5af70b6812cb722dfe508a83ef"
        ));
        assert_ok!(ReceiptRegistry::update_watching_address(
            RuntimeOrigin::root(),
            GOERLI_CHAIN,
            address,
            true
        ));

        assert_eq!(
            ReceiptRegistry::watched_contracts(GOERLI_CHAIN)
                .unwrap()
                .to_vec(),
            vec![address]
        );

        let block_header = headers[0][0].clone();
        let block_header = block_header_convert(block_header);
        let block_hash = H256::hash(block_header.clone());
        assert_eq!(block_header.number, 8652100);

        let receipts = common::load_receipts(include_str!("./data/goerli/receipts_8652100.json"));
        let merkle_proof_of_receipt = create_proof(&receipts, 0);

        let proof = EventProof {
            block_header,
            block_hash,
            transaction_receipt: receipts[0].clone(),
            transaction_receipt_hash: H256::hash(&receipts[0]),
            merkle_proof_of_receipt,
        };

        let serialized_proof = serde_json::to_string(&proof).unwrap();

        let balance_before = balance_of_user(&ALICE);
        assert_ok!(ReceiptRegistry::submit_proof(
            RuntimeOrigin::signed(ALICE),
            GOERLI_CHAIN,
            serialized_proof.into()
        ));
        let balance_after = balance_of_user(&ALICE);

        let transaction_receipt_hash = proof.transaction_receipt_hash;
        let block_number = proof.block_header.number;
        assert_eq!(
            ReceiptRegistry::processed_receipts((
                GOERLI_CHAIN,
                block_number,
                transaction_receipt_hash
            )),
            Some(())
        );
        assert_eq!(
            ReceiptRegistry::processed_receipts_hash(GOERLI_CHAIN, transaction_receipt_hash),
            Some(())
        );
        assert_eq!(balance_before + PROOF_REWARD, balance_after);
    });
}

#[test]
pub fn test_submit_proof_processed_receipts_hash_do_not_contains_key_but_not_in_watch_contract() {
    new_test_ext().execute_with(|| {
        let (headers, _updates, _init_input) = get_test_context(Some(InitOptions {
            validate_updates: true,
            verify_bls_signatures: true,
            hashes_gc_threshold: 7100,
            trusted_signer: Some([2u8; 32]),
        }));

        let block_header = headers[0][0].clone();
        let block_header = block_header_convert(block_header);
        let block_hash = H256::hash(block_header.clone());
        assert_eq!(block_header.number, 8652100);

        let receipts = common::load_receipts(include_str!("./data/goerli/receipts_8652100.json"));
        let merkle_proof_of_receipt = create_proof(&receipts, 0);

        let proof = EventProof {
            block_header,
            block_hash,
            transaction_receipt: receipts[0].clone(),
            transaction_receipt_hash: H256::hash(&receipts[0]),
            merkle_proof_of_receipt,
        };

        let serialized_proof = serde_json::to_string(&proof).unwrap();

        let balance_before = balance_of_user(&ALICE);
        assert_eq!(
            ReceiptRegistry::submit_proof(
                RuntimeOrigin::signed(ALICE),
                GOERLI_CHAIN,
                serialized_proof.into()
            ),
            Err(Error::<Test>::NoMonitoredAddressesForChain.into())
        );
        let balance_after = balance_of_user(&ALICE);

        let transaction_receipt_hash: H256 = proof.transaction_receipt_hash;
        let block_number = proof.block_header.number;
        assert_eq!(
            ReceiptRegistry::processed_receipts((
                GOERLI_CHAIN,
                block_number,
                transaction_receipt_hash
            )),
            None
        );
        assert_eq!(
            ReceiptRegistry::processed_receipts_hash(GOERLI_CHAIN, transaction_receipt_hash),
            None
        );
        assert_eq!(
            balance_before,
            balance_after - ReceiptRegistry::proof_deposit(GOERLI_CHAIN)
        );
    });
}

#[test]
pub fn test_submit_proof_processed_receipts_hash_contains_key() {
    new_test_ext().execute_with(|| {
        let (headers, _updates, init_input) = get_test_data(Some(InitOptions {
            validate_updates: true,
            verify_bls_signatures: false,
            hashes_gc_threshold: 500,
            trusted_signer: None,
        }));

        assert_ok!(Eth2Client::init(
            RuntimeOrigin::signed(ALICE),
            GOERLI_CHAIN,
            Box::new(init_input.map_into())
        ));

        const PROOF_DEPOSIT: u128 = 1;
        const PROOF_REWARD: u128 = 2;

        assert_ok!(ReceiptRegistry::update_proof_fee(
            RuntimeOrigin::root(),
            GOERLI_CHAIN,
            PROOF_DEPOSIT,
            PROOF_REWARD
        ));

        assert_eq!(ReceiptRegistry::proof_deposit(GOERLI_CHAIN), PROOF_DEPOSIT);
        assert_eq!(ReceiptRegistry::proof_reward(GOERLI_CHAIN), PROOF_REWARD);

        let address = H160(hex_literal::hex!(
            "228612206ba22b5af70b6812cb722dfe508a83ef"
        ));
        assert_ok!(ReceiptRegistry::update_watching_address(
            RuntimeOrigin::root(),
            GOERLI_CHAIN,
            address,
            true
        ));
        assert_eq!(
            ReceiptRegistry::watched_contracts(GOERLI_CHAIN)
                .unwrap()
                .to_vec(),
            vec![address]
        );

        let block_header = headers[0][0].clone();
        let block_header = block_header_convert(block_header);
        let block_hash = H256::hash(block_header.clone());
        assert_eq!(block_header.number, 8652100);

        let receipts = common::load_receipts(include_str!("./data/goerli/receipts_8652100.json"));
        let merkle_proof_of_receipt = create_proof(&receipts, 0);

        let proof = EventProof {
            block_header,
            block_hash,
            transaction_receipt: receipts[0].clone(),
            transaction_receipt_hash: H256::hash(&receipts[0]),
            merkle_proof_of_receipt,
        };

        let serialized_proof = serde_json::to_string(&proof).unwrap();

        // first submit_proof
        let balance_before = balance_of_user(&ALICE);
        assert_ok!(ReceiptRegistry::submit_proof(
            RuntimeOrigin::signed(ALICE),
            GOERLI_CHAIN,
            serialized_proof.clone().into()
        ));
        let balance_after = balance_of_user(&ALICE);

        let transaction_receipt_hash: H256 = proof.transaction_receipt_hash;
        let block_number = proof.block_header.number;
        assert_eq!(
            ReceiptRegistry::processed_receipts((
                GOERLI_CHAIN,
                block_number,
                transaction_receipt_hash
            )),
            Some(())
        );
        assert_eq!(
            ReceiptRegistry::processed_receipts_hash(GOERLI_CHAIN, transaction_receipt_hash),
            Some(())
        );
        assert_eq!(balance_before + PROOF_REWARD, balance_after);

        // second time
        let balance_before = balance_of_user(&ALICE);
        assert_ok!(ReceiptRegistry::submit_proof(
            RuntimeOrigin::signed(ALICE),
            GOERLI_CHAIN,
            serialized_proof.clone().into()
        ));
        let balance_after = balance_of_user(&ALICE);

        assert_eq!(
            ReceiptRegistry::processed_receipts((
                GOERLI_CHAIN,
                block_number,
                transaction_receipt_hash
            )),
            Some(())
        );
        assert_eq!(
            ReceiptRegistry::processed_receipts_hash(GOERLI_CHAIN, transaction_receipt_hash),
            Some(())
        );
        assert_eq!(balance_before - PROOF_DEPOSIT, balance_after);
    });
}

#[test]
pub fn test_update_watching_address() {
    new_test_ext().execute_with(|| {
        assert_eq!(ReceiptRegistry::watched_contracts(GOERLI_CHAIN), None);

        let address: H160 = H160::from_slice(&[1u8; 20]);
        assert_ok!(ReceiptRegistry::update_watching_address(
            RuntimeOrigin::root(),
            GOERLI_CHAIN,
            address,
            true
        ));

        assert_eq!(
            ReceiptRegistry::watched_contracts(GOERLI_CHAIN)
                .unwrap()
                .to_vec(),
            vec![address]
        );

        assert_ok!(ReceiptRegistry::update_watching_address(
            RuntimeOrigin::root(),
            GOERLI_CHAIN,
            address,
            false
        ));

        assert_eq!(
            ReceiptRegistry::watched_contracts(GOERLI_CHAIN).unwrap(),
            vec![]
        );
    });
}

#[test]
pub fn update_proof_fee() {
    new_test_ext().execute_with(|| {
        assert_eq!(
            ReceiptRegistry::proof_deposit(GOERLI_CHAIN),
            Default::default()
        );
        assert_eq!(
            ReceiptRegistry::proof_reward(GOERLI_CHAIN),
            Default::default()
        );

        assert_ok!(ReceiptRegistry::update_proof_fee(
            RuntimeOrigin::root(),
            GOERLI_CHAIN,
            1,
            2
        ));

        assert_eq!(ReceiptRegistry::proof_deposit(GOERLI_CHAIN), 1);
        assert_eq!(ReceiptRegistry::proof_reward(GOERLI_CHAIN), 2);
    });
}
