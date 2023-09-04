use crate::{
    mock::{Eth2Client, RuntimeOrigin, System},
    test_utils::*,
    ContractAddress, EventProof, ProcessedReceipts, ProcessedReceiptsHash, ProofDeposit,
    ProofReward,
};

use bitvec::{bitarr, order::Lsb0};
use eth_types::H160;
use eth_types::{eth2::LightClientUpdate, pallet::InitInput, BlockHeader, H256, U256};
use frame_support::{assert_err, assert_ok};
use hex::FromHex;
use sp_runtime::AccountId32;
use tree_hash::TreeHash;
use webb_proposals::TypedChainId;

pub const MAINNET_CHAIN: TypedChainId = TypedChainId::Evm(1);
pub const GOERLI_CHAIN: TypedChainId = TypedChainId::Evm(5);
pub const ALICE: AccountId32 = AccountId32::new([1u8; 32]);

pub fn submit_and_check_execution_headers(
    origin: RuntimeOrigin,
    typed_chain_id: TypedChainId,
    headers: Vec<&BlockHeader>,
) {
    for header in headers {
        assert_ok!(Eth2Client::submit_execution_header(
            origin.clone(),
            typed_chain_id,
            header.clone()
        ));
        assert!(Eth2Client::is_known_execution_header(
            typed_chain_id,
            header.number
        ));
    }
}

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

mod generic_tests {
    use consensus::{EPOCHS_PER_SYNC_COMMITTEE_PERIOD, SLOTS_PER_EPOCH};

    use super::*;
    use crate::{
        mock::{new_test_ext, Eth2Client, Test},
        test_utils::read_beacon_header,
        Error, Paused,
    };

    #[test]
    pub fn test_header_root() {
        let header =
            read_beacon_header(format!("./src/data/goerli/beacon_header_{}.json", 5258752));
        assert_eq!(
            H256(header.tree_hash_root()),
            Vec::from_hex("cd669c0007ab6ff261a02cc3335ba470088e92f0460bf1efac451009efb9ec0a")
                .unwrap()
                .into()
        );

        let header =
            read_beacon_header(format!("./src/data/mainnet/beacon_header_{}.json", 4100000));
        assert_eq!(
            H256(header.tree_hash_root()),
            Vec::from_hex("342ca1455e976f300cc96a209106bed2cbdf87243167fab61edc6e2250a0be6c")
                .unwrap()
                .into()
        );
    }

    #[test]
    pub fn test_submit_update_two_periods() {
        new_test_ext().execute_with(|| {
            let (headers, updates, _init_input) = get_test_context(None);
            assert_ok!(Eth2Client::submit_beacon_chain_light_client_update(
                RuntimeOrigin::signed(ALICE),
                GOERLI_CHAIN,
                updates[1].clone()
            ));

            submit_and_check_execution_headers(
                RuntimeOrigin::signed(ALICE),
                GOERLI_CHAIN,
                headers[0].iter().skip(1).rev().collect(),
            );

            for header in headers[0].iter().skip(1) {
                let header_hash = header.calculate_hash();
                assert!(
                    Eth2Client::block_hash_safe(GOERLI_CHAIN, header.number).unwrap_or_default()
                        == header_hash,
                    "Execution block hash is not finalized: {header_hash:?}"
                );
            }

            assert_eq!(
                Eth2Client::last_block_number(GOERLI_CHAIN),
                headers[0].last().unwrap().number
            );
        })
    }

    #[test]
    pub fn test_panic_on_submit_execution_block_from_fork_chain() {
        new_test_ext().execute_with(|| {
            let (headers, updates, _init_input) = get_test_context(None);
            assert_ok!(Eth2Client::submit_beacon_chain_light_client_update(
                RuntimeOrigin::signed(ALICE),
                GOERLI_CHAIN,
                updates[1].clone()
            ));

            // Submit execution header with different hash
            let mut fork_header = headers[0][1].clone();
            // Difficulty is modified just in order to get a different header hash. Any other field
            // would be suitable too
            fork_header.difficulty = U256::from(ethereum_types::U256::from(99));
            assert_err!(
                Eth2Client::submit_execution_header(
                    RuntimeOrigin::signed(ALICE),
                    GOERLI_CHAIN,
                    fork_header
                ),
                Error::<Test>::BlockHashesDoNotMatch
            );
        });
    }

    #[test]
    pub fn test_gc_headers() {
        new_test_ext().execute_with(|| {
            let hashes_gc_threshold: usize = 9500;
            let (headers, updates, _init_input) = get_test_context(Some(InitOptions {
                validate_updates: true,
                verify_bls_signatures: true,
                hashes_gc_threshold: hashes_gc_threshold as u64,
                trusted_signer: None,
            }));
            assert_ok!(Eth2Client::submit_beacon_chain_light_client_update(
                RuntimeOrigin::signed(ALICE),
                GOERLI_CHAIN,
                updates[1].clone()
            ));

            submit_and_check_execution_headers(
                RuntimeOrigin::signed(ALICE),
                GOERLI_CHAIN,
                headers[0].iter().skip(1).rev().collect(),
            );

            for header in headers[0].iter().skip(1) {
                assert!(
                    Eth2Client::block_hash_safe(GOERLI_CHAIN, header.number).unwrap_or_default()
                        == header.calculate_hash(),
                    "Execution block hash is not finalized: {:?}",
                    header.calculate_hash()
                );
            }

            assert_ok!(Eth2Client::submit_beacon_chain_light_client_update(
                RuntimeOrigin::signed(ALICE),
                GOERLI_CHAIN,
                updates[2].clone()
            ));

            submit_and_check_execution_headers(
                RuntimeOrigin::signed(ALICE),
                GOERLI_CHAIN,
                headers[1].iter().rev().collect(),
            );

            assert_eq!(
                Eth2Client::last_block_number(GOERLI_CHAIN),
                headers[1].last().unwrap().number
            );

            for header in headers[1].iter() {
                assert!(
                    Eth2Client::block_hash_safe(GOERLI_CHAIN, header.number).unwrap_or_default()
                        == header.calculate_hash(),
                    "Execution block hash is not finalized: {:?}",
                    header.calculate_hash()
                );
            }

            for header in headers.concat().iter().rev().skip(hashes_gc_threshold + 2) {
                assert!(
                    Eth2Client::block_hash_safe(GOERLI_CHAIN, header.number).is_none(),
                    "Execution block hash was not removed: {:?}",
                    header.calculate_hash()
                );
            }
        })
    }

    #[test]
    pub fn test_trusted_signer() {
        new_test_ext().execute_with(|| {
            let (_headers, updates, _init_input) = get_test_context(Some(InitOptions {
                validate_updates: true,
                verify_bls_signatures: true,
                hashes_gc_threshold: 7100,
                trusted_signer: Some([2u8; 32]),
            }));
            assert_err!(
                Eth2Client::submit_beacon_chain_light_client_update(
                    RuntimeOrigin::signed(ALICE),
                    GOERLI_CHAIN,
                    updates[1].clone()
                ),
                Error::<Test>::NotTrustedSigner,
            );
        });
    }

    #[test]
    pub fn test_panic_on_invalid_finality_proof() {
        new_test_ext().execute_with(|| {
            let (_headers, updates, _init_input) = get_test_context(None);
            let mut update = updates[1].clone();
            update.finality_update.finality_branch[5] = H256::from(
                hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                    .unwrap(),
            );
            assert_err!(
                Eth2Client::submit_beacon_chain_light_client_update(
                    RuntimeOrigin::signed(ALICE),
                    GOERLI_CHAIN,
                    update
                ),
                Error::<Test>::InvalidFinalityProof,
            );
        });
    }

    #[test]
    pub fn test_panic_on_empty_finality_proof() {
        new_test_ext().execute_with(|| {
            let (_headers, updates, _init_input) = get_test_context(None);
            let mut update = updates[1].clone();
            update.finality_update.finality_branch = vec![];
            assert_err!(
                Eth2Client::submit_beacon_chain_light_client_update(
                    RuntimeOrigin::signed(ALICE),
                    GOERLI_CHAIN,
                    update
                ),
                Error::<Test>::InvalidFinalityProof,
            );
        });
    }

    #[test]
    pub fn test_panic_on_invalid_execution_block_proof() {
        new_test_ext().execute_with(|| {
            let (_headers, updates, _init_input) = get_test_context(None);
            let mut update = updates[1].clone();
            update.finality_update.header_update.execution_hash_branch[5] = H256::from(
                hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                    .unwrap(),
            );
            assert_err!(
                Eth2Client::submit_beacon_chain_light_client_update(
                    RuntimeOrigin::signed(ALICE),
                    GOERLI_CHAIN,
                    update
                ),
                Error::<Test>::InvalidExecutionBlockHashProof
            );
        });
    }

    #[test]
    pub fn test_panic_on_empty_execution_block_proof() {
        new_test_ext().execute_with(|| {
            let (_headers, updates, _init_input) = get_test_context(None);
            let mut update = updates[1].clone();
            update.finality_update.header_update.execution_hash_branch = vec![];
            assert_err!(
                Eth2Client::submit_beacon_chain_light_client_update(
                    RuntimeOrigin::signed(ALICE),
                    GOERLI_CHAIN,
                    update
                ),
                Error::<Test>::InvalidExecutionBlockHashProof
            );
        });
    }

    #[test]
    pub fn test_panic_on_skip_update_period() {
        new_test_ext().execute_with(|| {
            let (_headers, updates, _init_input) = get_test_context(None);
            let mut update = updates[1].clone();
            update.finality_update.header_update.beacon_header.slot =
                update.signature_slot + EPOCHS_PER_SYNC_COMMITTEE_PERIOD * SLOTS_PER_EPOCH * 10;
            assert_err!(
                Eth2Client::submit_beacon_chain_light_client_update(
                    RuntimeOrigin::signed(ALICE),
                    GOERLI_CHAIN,
                    update
                ),
                Error::<Test>::UpdateHeaderSlotLessThanFinalizedHeaderSlot
            );
        });
    }

    #[test]
    pub fn test_panic_on_submit_update_with_missing_execution_blocks() {
        new_test_ext().execute_with(|| {
            let (headers, updates, _init_input) = get_test_context(None);
            assert_ok!(Eth2Client::submit_beacon_chain_light_client_update(
                RuntimeOrigin::signed(ALICE),
                GOERLI_CHAIN,
                updates[1].clone()
            ));

            for (_index, header) in headers[0].iter().skip(1).take(5).enumerate() {
                assert_err!(
                    Eth2Client::submit_execution_header(
                        RuntimeOrigin::signed(ALICE),
                        GOERLI_CHAIN,
                        header.clone()
                    ),
                    Error::<Test>::BlockHashesDoNotMatch
                );
            }
        });
    }

    #[test]
    pub fn test_panic_on_submit_same_execution_blocks() {
        new_test_ext().execute_with(|| {
            let (headers, updates, _init_input) = get_test_context(None);
            assert_ok!(Eth2Client::submit_beacon_chain_light_client_update(
                RuntimeOrigin::signed(ALICE),
                GOERLI_CHAIN,
                updates[1].clone()
            ));
            assert_ok!(Eth2Client::submit_execution_header(
                RuntimeOrigin::signed(ALICE),
                GOERLI_CHAIN,
                headers[0].last().unwrap().clone()
            ));
            assert_err!(
                Eth2Client::submit_execution_header(
                    RuntimeOrigin::signed(ALICE),
                    GOERLI_CHAIN,
                    headers[0].last().unwrap().clone()
                ),
                Error::<Test>::BlockHashesDoNotMatch
            );
        });
    }

    #[test]
    pub fn test_panic_on_submit_update_paused() {
        new_test_ext().execute_with(|| {
            let (_headers, updates, _init_input) = get_test_context(None);
            Paused::<Test>::insert(GOERLI_CHAIN, true);
            assert_err!(
                Eth2Client::submit_beacon_chain_light_client_update(
                    RuntimeOrigin::signed(ALICE),
                    GOERLI_CHAIN,
                    updates[1].clone()
                ),
                Error::<Test>::LightClientUpdateNotAllowed
            );
        });
    }

    #[test]
    pub fn test_panic_on_submit_outdated_update() {
        new_test_ext().execute_with(|| {
            let (_headers, updates, _init_input) = get_test_context(None);
            assert_err!(
                Eth2Client::submit_beacon_chain_light_client_update(
                    RuntimeOrigin::signed(ALICE),
                    GOERLI_CHAIN,
                    updates[0].clone()
                ),
                Error::<Test>::ActiveHeaderSlotLessThanFinalizedSlot,
            );
        });
    }

    #[test]
    pub fn test_panic_on_submit_blocks_with_unknown_parent() {
        new_test_ext().execute_with(|| {
            let (headers, updates, _init_input) = get_test_context(None);
            assert_eq!(
                Eth2Client::last_block_number(GOERLI_CHAIN),
                headers[0][0].number
            );
            assert_ok!(Eth2Client::submit_beacon_chain_light_client_update(
                RuntimeOrigin::signed(ALICE),
                GOERLI_CHAIN,
                updates[1].clone()
            ));

            let tmp_headers: Vec<_> = headers[0].iter().skip(1).rev().collect();
            assert_ok!(Eth2Client::submit_execution_header(
                RuntimeOrigin::signed(ALICE),
                GOERLI_CHAIN,
                tmp_headers[0].clone()
            ));
            // Skip 2th block
            assert_err!(
                Eth2Client::submit_execution_header(
                    RuntimeOrigin::signed(ALICE),
                    GOERLI_CHAIN,
                    tmp_headers[3].clone()
                ),
                Error::<Test>::BlockHashesDoNotMatch
            );
        });
    }

    #[test]
    // test_panic_on_submit_headers_in_worng_mode
    pub fn test_panic_on_submit_headers_in_wrong_mode() {
        new_test_ext().execute_with(|| {
            let (headers, _updates, _init_input) = get_test_context(None);
            assert_eq!(
                Eth2Client::last_block_number(GOERLI_CHAIN),
                headers[0][0].number
            );
            assert_err!(
                Eth2Client::submit_execution_header(
                    RuntimeOrigin::signed(ALICE),
                    GOERLI_CHAIN,
                    headers[0][1].clone()
                ),
                Error::<Test>::InvalidClientMode
            );
        });
    }

    #[test]
    pub fn test_panic_on_sync_committee_bits_is_less_than_threshold() {
        new_test_ext().execute_with(|| {
            let (_headers, updates, _init_input) = get_test_context(None);
            let mut update = updates[1].clone();

            let mut sync_committee_bits = bitarr![u8, Lsb0; 0; 512];

            // The number of participants should satisfy the inequality:
            // num_of_participants * 3 >= sync_committee_bits_size * 2
            // If the sync_committee_bits_size = 512, then
            // the minimum allowed value of num_of_participants is 342.

            // Fill the sync_committee_bits with 341 participants to trigger panic
            let num_of_participants = (((512.0 * 2.0 / 3.0) as f32).ceil() - 1.0) as usize;
            sync_committee_bits
                .get_mut(0..num_of_participants)
                .unwrap()
                .fill(true);
            update.sync_aggregate.sync_committee_bits =
                sync_committee_bits.as_raw_mut_slice().to_vec().into();
            assert_err!(
                Eth2Client::submit_beacon_chain_light_client_update(
                    RuntimeOrigin::signed(ALICE),
                    GOERLI_CHAIN,
                    update
                ),
                Error::<Test>::SyncCommitteeBitsSumLessThanThreshold,
            );
        });
    }

    #[test]
    pub fn test_panic_on_missing_sync_committee_update() {
        new_test_ext().execute_with(|| {
            let (_headers, updates, _init_input) = get_test_context(None);
            let mut update = updates[1].clone();
            update.sync_committee_update = None;

            assert_err!(
                Eth2Client::submit_beacon_chain_light_client_update(
                    RuntimeOrigin::signed(ALICE),
                    GOERLI_CHAIN,
                    update
                ),
                Error::<Test>::SyncCommitteeUpdateNotPresent
            );
        });
    }

    #[test]
    pub fn test_submit_proof_deserialize_fail() {
        new_test_ext().execute_with(|| {
            assert_err!(
                Eth2Client::submit_proof(RuntimeOrigin::signed(ALICE), MAINNET_CHAIN, vec![1]),
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
                merkle_proof_of_receipt: types::ReceiptMerkleProof {
                    proof: vec![],
                    size: 0,
                    transaction_index: 0,
                },
            };
            let serialized_proof = serde_json::to_string(&proof).unwrap();

            assert_err!(
                Eth2Client::submit_proof(
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
                merkle_proof_of_receipt: types::ReceiptMerkleProof {
                    proof: vec![],
                    size: 0,
                    transaction_index: 0,
                },
            };
            let serialized_proof = serde_json::to_string(&proof).unwrap();

            assert_err!(
                Eth2Client::submit_proof(
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
                block_hash: types::H256(headers[0][0].calculate_hash().0.into()),
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
                merkle_proof_of_receipt: types::ReceiptMerkleProof {
                    proof: vec![],
                    size: 0,
                    transaction_index: 0,
                },
            };
            let serialized_proof = serde_json::to_string(&proof).unwrap();

            assert_err!(
                Eth2Client::submit_proof(
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
            const PROOF_DEPOSIT: u128= 1;
            const PROOF_REWARD: u128= 2;
            assert_ok!(Eth2Client::update_proof_fee(RuntimeOrigin::root(), PROOF_DEPOSIT, PROOF_REWARD));

            let address: H160 = hex::decode("20790e28316c429a2c0411e7f14caf6b053a77ae").unwrap().into();
            assert_ok!(Eth2Client::update_watching_address(
                RuntimeOrigin::root(),
                address
            ));

            let (headers, _updates, _init_input) = get_test_context(Some(InitOptions {
                validate_updates: true,
                verify_bls_signatures: true,
                hashes_gc_threshold: 7100,
                trusted_signer: Some([2u8; 32]),
            }));

            let header: &BlockHeader = &headers[0][0];

            let transaction_receipt = types::TransactionReceipt { //https://goerli.etherscan.io/tx/0xe2ae376a9429b47e436dfc2eeccc49bff94fa562131fb53aaf6b8b56a3c41ae5
                bloom: types::Bloom::new(hex_literal::hex!("00000000000000000000040000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000200000080000000000000000800000000000000000000002000000000001000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000")),
                receipt: types::Receipt {
                    tx_type: types::TxType::EIP1559,
                    success: true,
                    cumulative_gas_used: 196913,
                    logs: vec![types::Log {
                        address: types::H160::new(hex_literal::hex!("9dc234c57c41f563bafc49fea24549d09eb83938")),
                        topics: vec![types::H256(hex_literal::hex!("24c9bb2620686dbe734e777d7b61fc8c088e12fb07e265a6bb90f9f9e0896012"))],
                        data: hex_literal::hex!("0000000000000000000000007eba7f5b306c6dd5333aaac0e2d4ab4c3a83c203833ad75d5c089ed54f85dc681b1739573baf02ec43408cf6b1e692034facd08c000000000000000000000000000000000000000000000000000000000000058b000000000000000000000000000000000000000000000000000000000000058c000000000000000000000000000000000000000000000000000000000084054200000000000000000000000000000000000000000000000000000001b3f6cfc000000000000000000000000020790e28316c429a2c0411e7f14caf6b053a77ae000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000064100a600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000000a4111b6e8d630a19217e9731fb1a64020b07b482de29c3f250891723d49f5997100555beb359b1f55a2e152f4d903d1addd3fb5fba0b0ba9707cbcb1dcd6efcc8f000040000000000200000002000d688c0000000000000000000000000000000000000000298c3f359cf306ad8b187e28c4905a3d8d49fbdab90bfb21b59cd0fe0db602931f85ae4c487123d667a3c0c6ba9bc158fe9ae6be5984601b651d82590ade755800000000000000000000000000000000000000000000000000000000" ).to_vec(),
                    },
                    types::Log {
                        address: types::H160::new(hex_literal::hex!("20790e28316c429a2c0411e7f14caf6b053a77ae")),
                        topics: vec![types::H256(hex_literal::hex!("a99ca06ac3461399088feac88ec48dc5a47d61c3b6839eab20146f2c4ee53584"))],
                        data: hex_literal::hex!("000000000000000000000000000000000000000000000000000000000000058c0000000000000000000000000000000000000000000000000000000000061d720000000000000000000000000000000000000000000000000000000000061da5").to_vec(),
                    },
                    ],
                },
            };

            let mut proof = EventProof {
                block_header: types::BlockHeader {//https://goerli.etherscan.io/block/8652100
                    parent_hash: types::H256(header.parent_hash.0.into()),
                    ommers_hash: types::H256(header.uncles_hash.0.into()),
                    beneficiary: types::H160::new(header.author.0.into()),
                    state_root: types::H256(header.state_root.0.into()),
                    transactions_root: types::H256(header.transactions_root.0.into()),
                    receipts_root: types::H256(header.receipts_root.0.into()),
                    withdrawals_root: Some(types::H256(header.withdrawals_root.unwrap_or_default().0.into())),
                    logs_bloom: types::Bloom::new(header.log_bloom.0.into()),
                    difficulty: types::U256(header.difficulty.0.into()),
                    number: header.number,
                    gas_limit: header.gas_limit.0.as_u64(),
                    gas_used: header.gas_used.0.as_u64(),
                    timestamp: header.timestamp,
                    mix_hash: types::H256(header.mix_hash.0.into()),
                    nonce: u64::from_be_bytes(header.nonce.0.into()),
                    base_fee_per_gas: header.base_fee_per_gas,
                    blob_gas_used: None, //todo,  not found in eth-types, can we set None
                    excess_blob_gas: None, //todo,  not found in eth-types, can we set None
                    extra_data: header.extra_data.clone(),
                },
                block_hash: types::H256(header.calculate_hash().0.into()),
                transaction_receipt: transaction_receipt.clone(),
                transaction_receipt_hash: types::H256(hex_literal::hex!("e2ae376a9429b47e436dfc2eeccc49bff94fa562131fb53aaf6b8b56a3c41ae5")),
                merkle_proof_of_receipt: types::ReceiptMerkleProof::from_transactions(vec![transaction_receipt], 0),
            };

            proof.transaction_receipt_hash = types::H256::hash(&proof.transaction_receipt);

            let serialized_proof = serde_json::to_string(&proof).unwrap();

            let balance_before = balance_of_user(&ALICE);
            assert_ok!(
                Eth2Client::submit_proof(
                    RuntimeOrigin::signed(ALICE),
                    GOERLI_CHAIN,
                    serialized_proof.into()
                )
            );
            let balance_after = balance_of_user(&ALICE);

            let transaction_receipt_hash: H256 = proof.transaction_receipt_hash.0[..].into();
            let block_number = proof.block_header.number;
            assert_eq!(ProcessedReceipts::<Test>::get((GOERLI_CHAIN, block_number, transaction_receipt_hash)), Some(()));
            assert_eq!(ProcessedReceiptsHash::<Test>::get(GOERLI_CHAIN, transaction_receipt_hash), Some(()));
            assert_eq!(balance_before + PROOF_REWARD, balance_after);
        });
    }

    #[test]
    pub fn test_submit_proof_processed_receipts_hash_do_not_contains_key_but_not_in_watch_contract()
    {
        new_test_ext().execute_with(|| {
            const PROOF_DEPOSIT: u128= 1;
            const PROOF_REWARD: u128= 2;
            assert_ok!(Eth2Client::update_proof_fee(RuntimeOrigin::root(), PROOF_DEPOSIT, PROOF_REWARD));

            let (headers, _updates, _init_input) = get_test_context(Some(InitOptions {
                validate_updates: true,
                verify_bls_signatures: true,
                hashes_gc_threshold: 7100,
                trusted_signer: Some([2u8; 32]),
            }));

            let header: &BlockHeader = &headers[0][0];
            let transaction_receipt = types::TransactionReceipt { //https://goerli.etherscan.io/tx/0xe2ae376a9429b47e436dfc2eeccc49bff94fa562131fb53aaf6b8b56a3c41ae5
                bloom: types::Bloom::new(hex_literal::hex!("00000000000000000000040000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000200000080000000000000000800000000000000000000002000000000001000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000")),
                receipt: types::Receipt {
                    tx_type: types::TxType::EIP1559,
                    success: true,
                    cumulative_gas_used: 196913,
                    logs: vec![types::Log {
                        address: types::H160::new(hex_literal::hex!("9dc234c57c41f563bafc49fea24549d09eb83938")),
                        topics: vec![types::H256(hex_literal::hex!("24c9bb2620686dbe734e777d7b61fc8c088e12fb07e265a6bb90f9f9e0896012"))],
                        data: hex_literal::hex!("0000000000000000000000007eba7f5b306c6dd5333aaac0e2d4ab4c3a83c203833ad75d5c089ed54f85dc681b1739573baf02ec43408cf6b1e692034facd08c000000000000000000000000000000000000000000000000000000000000058b000000000000000000000000000000000000000000000000000000000000058c000000000000000000000000000000000000000000000000000000000084054200000000000000000000000000000000000000000000000000000001b3f6cfc000000000000000000000000020790e28316c429a2c0411e7f14caf6b053a77ae000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000064100a600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000000a4111b6e8d630a19217e9731fb1a64020b07b482de29c3f250891723d49f5997100555beb359b1f55a2e152f4d903d1addd3fb5fba0b0ba9707cbcb1dcd6efcc8f000040000000000200000002000d688c0000000000000000000000000000000000000000298c3f359cf306ad8b187e28c4905a3d8d49fbdab90bfb21b59cd0fe0db602931f85ae4c487123d667a3c0c6ba9bc158fe9ae6be5984601b651d82590ade755800000000000000000000000000000000000000000000000000000000" ).to_vec(),
                    },
                    types::Log {
                        address: types::H160::new(hex_literal::hex!("20790e28316c429a2c0411e7f14caf6b053a77ae")),
                        topics: vec![types::H256(hex_literal::hex!("a99ca06ac3461399088feac88ec48dc5a47d61c3b6839eab20146f2c4ee53584"))],
                        data: hex_literal::hex!("000000000000000000000000000000000000000000000000000000000000058c0000000000000000000000000000000000000000000000000000000000061d720000000000000000000000000000000000000000000000000000000000061da5").to_vec(),
                    },
                    ],
                },
            };

            let mut proof = EventProof {
                block_header: types::BlockHeader {//https://goerli.etherscan.io/block/8652100
                    parent_hash: types::H256(header.parent_hash.0.into()),
                    ommers_hash: types::H256(header.uncles_hash.0.into()),
                    beneficiary: types::H160::new(header.author.0.into()),
                    state_root: types::H256(header.state_root.0.into()),
                    transactions_root: types::H256(header.transactions_root.0.into()),
                    receipts_root: types::H256(header.receipts_root.0.into()),
                    withdrawals_root: Some(types::H256(header.withdrawals_root.unwrap_or_default().0.into())),
                    logs_bloom: types::Bloom::new(header.log_bloom.0.into()),
                    difficulty: types::U256(header.difficulty.0.into()),
                    number: header.number,
                    gas_limit: header.gas_limit.0.as_u64(),
                    gas_used: header.gas_used.0.as_u64(),
                    timestamp: header.timestamp,
                    mix_hash: types::H256(header.mix_hash.0.into()),
                    nonce: u64::from_be_bytes(header.nonce.0.into()),
                    base_fee_per_gas: header.base_fee_per_gas,
                    blob_gas_used: None, //todo,  not found in eth-types, can we set None
                    excess_blob_gas: None, //todo,  not found in eth-types, can we set None
                    extra_data: header.extra_data.clone(),
                },
                block_hash: types::H256(header.calculate_hash().0.into()),
                transaction_receipt: transaction_receipt.clone(),
                transaction_receipt_hash: types::H256(hex_literal::hex!("e2ae376a9429b47e436dfc2eeccc49bff94fa562131fb53aaf6b8b56a3c41ae5")),
                merkle_proof_of_receipt: types::ReceiptMerkleProof::from_transactions(vec![transaction_receipt], 0),
            };

            proof.transaction_receipt_hash = types::H256::hash(&proof.transaction_receipt);
            let serialized_proof = serde_json::to_string(&proof).unwrap();

            let balance_before = balance_of_user(&ALICE);
            assert_ok!(
                Eth2Client::submit_proof(
                    RuntimeOrigin::signed(ALICE),
                    GOERLI_CHAIN,
                    serialized_proof.into()
                )
            );
            let balance_after = balance_of_user(&ALICE);

            let transaction_receipt_hash: H256 = proof.transaction_receipt_hash.0[..].into();
            let block_number = proof.block_header.number;
            assert_eq!(ProcessedReceipts::<Test>::get((GOERLI_CHAIN, block_number, transaction_receipt_hash)), None);
            assert_eq!(ProcessedReceiptsHash::<Test>::get(GOERLI_CHAIN, transaction_receipt_hash), None);
            assert_eq!(balance_before, balance_after);
        });
    }

    #[test]
    pub fn test_submit_proof_processed_receipts_hash_contains_key() {
        new_test_ext().execute_with(|| {
        const PROOF_DEPOSIT: u128= 1;
        const PROOF_REWARD: u128= 2;
            assert_ok!(Eth2Client::update_proof_fee(RuntimeOrigin::root(), PROOF_DEPOSIT, PROOF_REWARD));

            let address: H160 = hex::decode("20790e28316c429a2c0411e7f14caf6b053a77ae").unwrap().into();
            assert_ok!(Eth2Client::update_watching_address(
                RuntimeOrigin::root(),
                address
            ));

            let (headers, _updates, _init_input) = get_test_context(Some(InitOptions {
                validate_updates: true,
                verify_bls_signatures: true,
                hashes_gc_threshold: 7100,
                trusted_signer: Some([2u8; 32]),
            }));

            let header: &BlockHeader = &headers[0][0];
            let transaction_receipt = types::TransactionReceipt { //https://goerli.etherscan.io/tx/0xe2ae376a9429b47e436dfc2eeccc49bff94fa562131fb53aaf6b8b56a3c41ae5
                bloom: types::Bloom::new(hex_literal::hex!("00000000000000000000040000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000200000080000000000000000800000000000000000000002000000000001000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000")),
                receipt: types::Receipt {
                    tx_type: types::TxType::EIP1559,
                    success: true,
                    cumulative_gas_used: 196913,
                    logs: vec![types::Log {
                        address: types::H160::new(hex_literal::hex!("9dc234c57c41f563bafc49fea24549d09eb83938")),
                        topics: vec![types::H256(hex_literal::hex!("24c9bb2620686dbe734e777d7b61fc8c088e12fb07e265a6bb90f9f9e0896012"))],
                        data: hex_literal::hex!("0000000000000000000000007eba7f5b306c6dd5333aaac0e2d4ab4c3a83c203833ad75d5c089ed54f85dc681b1739573baf02ec43408cf6b1e692034facd08c000000000000000000000000000000000000000000000000000000000000058b000000000000000000000000000000000000000000000000000000000000058c000000000000000000000000000000000000000000000000000000000084054200000000000000000000000000000000000000000000000000000001b3f6cfc000000000000000000000000020790e28316c429a2c0411e7f14caf6b053a77ae000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000064100a600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000000a4111b6e8d630a19217e9731fb1a64020b07b482de29c3f250891723d49f5997100555beb359b1f55a2e152f4d903d1addd3fb5fba0b0ba9707cbcb1dcd6efcc8f000040000000000200000002000d688c0000000000000000000000000000000000000000298c3f359cf306ad8b187e28c4905a3d8d49fbdab90bfb21b59cd0fe0db602931f85ae4c487123d667a3c0c6ba9bc158fe9ae6be5984601b651d82590ade755800000000000000000000000000000000000000000000000000000000" ).to_vec(),
                    },
                    types::Log {
                        address: types::H160::new(hex_literal::hex!("20790e28316c429a2c0411e7f14caf6b053a77ae")),
                        topics: vec![types::H256(hex_literal::hex!("a99ca06ac3461399088feac88ec48dc5a47d61c3b6839eab20146f2c4ee53584"))],
                        data: hex_literal::hex!("000000000000000000000000000000000000000000000000000000000000058c0000000000000000000000000000000000000000000000000000000000061d720000000000000000000000000000000000000000000000000000000000061da5").to_vec(),
                    },
                    ],
                },
            };

            let mut proof = EventProof {
                block_header: types::BlockHeader {//https://goerli.etherscan.io/block/8652100
                    parent_hash: types::H256(header.parent_hash.0.into()),
                    ommers_hash: types::H256(header.uncles_hash.0.into()),
                    beneficiary: types::H160::new(header.author.0.into()),
                    state_root: types::H256(header.state_root.0.into()),
                    transactions_root: types::H256(header.transactions_root.0.into()),
                    receipts_root: types::H256(header.receipts_root.0.into()),
                    withdrawals_root: Some(types::H256(header.withdrawals_root.unwrap_or_default().0.into())),
                    logs_bloom: types::Bloom::new(header.log_bloom.0.into()),
                    difficulty: types::U256(header.difficulty.0.into()),
                    number: header.number,
                    gas_limit: header.gas_limit.0.as_u64(),
                    gas_used: header.gas_used.0.as_u64(),
                    timestamp: header.timestamp,
                    mix_hash: types::H256(header.mix_hash.0.into()),
                    nonce: u64::from_be_bytes(header.nonce.0.into()),
                    base_fee_per_gas: header.base_fee_per_gas,
                    blob_gas_used: None, //todo,  not found in eth-types, can we set None
                    excess_blob_gas: None, //todo,  not found in eth-types, can we set None
                    extra_data: header.extra_data.clone(),
                },
                block_hash: types::H256(header.calculate_hash().0.into()),
                transaction_receipt: transaction_receipt.clone(),
                transaction_receipt_hash: types::H256(hex_literal::hex!("e2ae376a9429b47e436dfc2eeccc49bff94fa562131fb53aaf6b8b56a3c41ae5")),
                merkle_proof_of_receipt: types::ReceiptMerkleProof::from_transactions(vec![transaction_receipt], 0),
            };

            proof.transaction_receipt_hash = types::H256::hash(&proof.transaction_receipt);
            let serialized_proof = serde_json::to_string(&proof).unwrap();

            // first submit_proof
            let balance_before = balance_of_user(&ALICE);
            assert_ok!(
                Eth2Client::submit_proof(
                    RuntimeOrigin::signed(ALICE),
                    GOERLI_CHAIN,
                    serialized_proof.clone().into()
                )
            );
            let balance_after = balance_of_user(&ALICE);

            let transaction_receipt_hash: H256 = proof.transaction_receipt_hash.0[..].into();
            let block_number = proof.block_header.number;
            assert_eq!(ProcessedReceipts::<Test>::get((GOERLI_CHAIN, block_number, transaction_receipt_hash)), Some(()));
            assert_eq!(ProcessedReceiptsHash::<Test>::get(GOERLI_CHAIN, transaction_receipt_hash), Some(()));
            assert_eq!(balance_before + PROOF_REWARD, balance_after);

            // second time
            let balance_before = balance_of_user(&ALICE);
            assert_ok!(
                Eth2Client::submit_proof(
                    RuntimeOrigin::signed(ALICE),
                    GOERLI_CHAIN,
                    serialized_proof.clone().into()
                )
            );
            let balance_after = balance_of_user(&ALICE);

            assert_eq!(ProcessedReceipts::<Test>::get((GOERLI_CHAIN, block_number, transaction_receipt_hash)), Some(()));
            assert_eq!(ProcessedReceiptsHash::<Test>::get(GOERLI_CHAIN, transaction_receipt_hash), Some(()));
            assert_eq!(balance_before - PROOF_DEPOSIT, balance_after);
        });
    }

    #[test]
    pub fn test_update_watching_address() {
        new_test_ext().execute_with(|| {
            assert_eq!(ContractAddress::<Test>::get(), None);

            let address: H160 = [1u8; 20].into();
            assert_ok!(Eth2Client::update_watching_address(
                RuntimeOrigin::root(),
                address
            ));

            assert_eq!(ContractAddress::<Test>::get(), Some(address));
        });
    }

    #[test]
    pub fn update_proof_fee() {
        new_test_ext().execute_with(|| {
            assert_eq!(ProofDeposit::<Test>::get(), Default::default());
            assert_eq!(ProofReward::<Test>::get(), Default::default());

            assert_ok!(Eth2Client::update_proof_fee(RuntimeOrigin::root(), 1, 2));

            assert_eq!(ProofDeposit::<Test>::get(), 1);
            assert_eq!(ProofReward::<Test>::get(), 2);
        });
    }
}

mod mainnet_tests {
    use crate::{
        mock::{new_test_ext, Test},
        Error,
    };

    use super::*;

    #[test]
    pub fn test_panic_on_init_in_trustless_mode_without_bls_on_mainnet() {
        new_test_ext().execute_with(|| {
            let (_headers, _updates, init_input) = get_test_data(Some(InitOptions {
                validate_updates: true,
                verify_bls_signatures: false,
                hashes_gc_threshold: 500,
                trusted_signer: None,
            }));

            assert_err!(
                Eth2Client::init(
                    RuntimeOrigin::signed(ALICE),
                    MAINNET_CHAIN,
                    Box::new(init_input.map_into())
                ),
                Error::<Test>::TrustlessModeError,
            );
        })
    }
}
