#![cfg_attr(not(feature = "std"), no_std)]
#![feature(slice_pattern)]

use frame_support::sp_std::{convert::TryInto, prelude::*};
use frame_support::traits::ExistenceRequirement::AllowDeath;
use frame_support::{pallet_prelude::ensure, traits::Get, PalletId};
pub use pallet::*;
use types::{EventProof, TransactionReceipt};
use types::{H160, H256};
use webb_proposals::TypedChainId;

use frame_support::{sp_runtime::traits::AccountIdConversion, traits::Currency};

type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

type CurrencyOf<T> = <T as Config>::Currency;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::{
        dispatch::DispatchResultWithPostInfo,
        pallet_prelude::{OptionQuery, ValueQuery, *},
        sp_runtime::BoundedVec,
        Blake2_128Concat,
    };
    use frame_system::pallet_prelude::*;
    use types::Log;

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::config]
    /// The module configuration trait.
    pub trait Config: frame_system::Config + pallet_eth2_light_client::Config {
        /// The overarching event type.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        #[pallet::constant]
        type PalletId: Get<PalletId>;

        type Currency: Currency<<Self as frame_system::Config>::AccountId>;

        type PrivilegedOrigin: EnsureOrigin<<Self as frame_system::Config>::RuntimeOrigin>;
    }

    /// ProcessedReceipts
    /// TODO: clean up the storage
    /// Hashes of transaction receipts already processed. Stores up to
    /// [`hashes_gc_threshold`][1] entries.
    ///
    /// TypedChainId -> BlockNumber -> TransactionReceiptHash -> ()
    ///
    /// [1]: https://github.com/webb-tools/pallet-eth2-light-client/blob/4d8a20ad325795a2d166fcd2a6118db3037581d3/pallet/src/lib.rs#L218-L219
    #[pallet::storage]
    #[pallet::getter(fn processed_receipts)]
    pub(crate) type ProcessedReceipts<T: Config> = StorageNMap<
        _,
        (
            NMapKey<Blake2_128Concat, TypedChainId>, // ChainList Id https://chainlist.org/
            NMapKey<Blake2_128Concat, u64>,          // Block height
            NMapKey<Blake2_128Concat, H256>,         // Hash of the receipt already processed
        ),
        Vec<Log>,
        OptionQuery,
    >;

    /// querying that the inclusion-proof for a receipt has been processed or not
    #[pallet::storage]
    #[pallet::getter(fn processed_receipts_hash)]
    pub(crate) type ProcessedReceiptsHash<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        TypedChainId, // ChainList Id https://chainlist.org/
        Blake2_128Concat,
        H256, // Hash of the receipt already processed
        (),
        OptionQuery,
    >;

    /// the contract addresses we're watching
    #[pallet::storage]
    #[pallet::getter(fn watched_contracts)]
    pub(crate) type WatchedContracts<T: Config> =
        StorageMap<_, Blake2_128Concat, TypedChainId, BoundedVec<H160, ConstU32<100>>, OptionQuery>;

    /// pay validator proof deposit
    #[pallet::storage]
    #[pallet::getter(fn proof_deposit)]
    pub(crate) type ProofDeposit<T: Config> =
        StorageMap<_, Blake2_128Concat, TypedChainId, BalanceOf<T>, ValueQuery>;

    /// reward for Proof of Submission
    #[pallet::storage]
    #[pallet::getter(fn proof_reward)]
    pub(crate) type ProofReward<T: Config> =
        StorageMap<_, Blake2_128Concat, TypedChainId, BalanceOf<T>, ValueQuery>;

    /************* STORAGE ************ */

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        SubmitProcessedReceipts {
            typed_chain_id: TypedChainId,
            block_number: u64,
            receipt_hash: H256,
        },
        AddedContractAddress {
            typed_chain_id: TypedChainId,
            address: H160,
        },
        RemovedContractAddress {
            typed_chain_id: TypedChainId,
            address: H160,
        },
        UpdateProofFee {
            typed_chain_id: TypedChainId,
            proof_deposit: BalanceOf<T>,
            proof_reward: BalanceOf<T>,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        ConvertToStringFailed,
        DeserializeFail,
        HeaderHashDoesNotExist,
        BlockHashesDoNotMatch,
        /// The proof verification failed
        VerifyProofFail,
        /// The chain is not monitored
        NoMonitoredAddressesForChain,
        /// Too many watched contracts
        TooManyAddresses,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// submitting proof that a receipt has been included in a block
        #[pallet::weight({6})]
        #[pallet::call_index(6)]
        pub fn submit_proof(
            origin: OriginFor<T>,
            typed_chain_id: TypedChainId,
            event_proof: Vec<u8>,
        ) -> DispatchResultWithPostInfo {
            let validator = ensure_signed(origin)?;

            // Create a str slice from the body.
            let event_proof_str = frame_support::sp_std::str::from_utf8(&event_proof)
                .map_err(|_| Error::<T>::ConvertToStringFailed)?;

            let event_proof: EventProof =
                serde_json::from_str(event_proof_str).map_err(|_| Error::<T>::DeserializeFail)?;

            let finalized_execution_header_hash =
                pallet_eth2_light_client::Pallet::<T>::finalized_execution_blocks(
                    typed_chain_id,
                    event_proof.block_header.number,
                )
                .ok_or(Error::<T>::HeaderHashDoesNotExist)?;

            let block_hash = event_proof.block_hash;

            ensure!(
                block_hash.0 == finalized_execution_header_hash.0 .0,
                Error::<T>::BlockHashesDoNotMatch,
            );

            // 1 verifying its cryptographic integrity
            ensure!(event_proof.validate().is_ok(), Error::<T>::VerifyProofFail);

            let treasury = Self::account_id();
            let transaction_receipt_hash: H256 = event_proof.transaction_receipt_hash;

            // If the receipt proof has already been processed
            let rewarded = if !<ProcessedReceiptsHash<T>>::contains_key(
                typed_chain_id,
                transaction_receipt_hash,
            ) {
                //2 checking the receipt includes a LOG emitted by a contract address we are watching.

                let block_number = event_proof.block_header.number;
                let mut rewarded = false;

                let addresses = Self::watched_contracts(typed_chain_id);
                ensure!(
                    addresses.is_some(),
                    Error::<T>::NoMonitoredAddressesForChain
                );

                for address in addresses.expect("checked above") {
                    if Self::is_contract_address_in_log(&event_proof.transaction_receipt, address) {
                        ProcessedReceipts::<T>::insert(
                            (typed_chain_id, block_number, transaction_receipt_hash),
                            event_proof.transaction_receipt.receipt.logs.clone(),
                        );
                        ProcessedReceiptsHash::<T>::insert(
                            typed_chain_id,
                            transaction_receipt_hash,
                            (),
                        );

                        Self::deposit_event(Event::SubmitProcessedReceipts {
                            typed_chain_id,
                            block_number,
                            receipt_hash: transaction_receipt_hash,
                        });
                        rewarded = true;
                    }
                }
                rewarded
            } else {
                false
            };

            let _success = if rewarded {
                // Rewarding relayer for submitting a proof of inclusion of a receipt
                CurrencyOf::<T>::transfer(
                    &treasury,
                    &validator,
                    Self::proof_reward(typed_chain_id),
                    AllowDeath,
                )
            } else {
                // Validator
                CurrencyOf::<T>::transfer(
                    &validator,
                    &treasury,
                    Self::proof_deposit(typed_chain_id),
                    AllowDeath,
                )
            };

            debug_assert!(_success.is_ok());

            Ok(().into())
        }

        /// update watching address
        #[pallet::weight({7})]
        #[pallet::call_index(7)]
        pub fn update_watching_address(
            origin: OriginFor<T>,
            typed_chain_id: TypedChainId,
            address: H160,
            add: bool,
        ) -> DispatchResultWithPostInfo {
            T::PrivilegedOrigin::ensure_origin(origin)?;

            let result =
                WatchedContracts::<T>::mutate(typed_chain_id, |addresses| match (addresses, add) {
                    (Some(ref mut addresses), true) => addresses.try_push(address),
                    (Some(ref mut addresses), false) => {
                        addresses.retain(|&x| x != address);
                        Ok(())
                    }
                    (option, true) if option.is_none() => {
                        *option = Some(
                            BoundedVec::try_from(vec![address]).expect("unfailable conversion"),
                        );
                        Ok(())
                    }
                    _ => Ok(()),
                });

            if result.is_err() {
                // Probably the only possible error is that the vector is full
                return Err(Error::<T>::TooManyAddresses.into());
            }

            if add {
                Self::deposit_event(Event::AddedContractAddress {
                    typed_chain_id,
                    address,
                });
            } else {
                Self::deposit_event(Event::RemovedContractAddress {
                    typed_chain_id,
                    address,
                });
            }

            Ok(().into())
        }

        /// update ProofDeposit and ProofReward
        #[pallet::weight({8})]
        #[pallet::call_index(8)]
        pub fn update_proof_fee(
            origin: OriginFor<T>,
            typed_chain_id: TypedChainId,
            proof_deposit: BalanceOf<T>,
            proof_reward: BalanceOf<T>,
        ) -> DispatchResultWithPostInfo {
            T::PrivilegedOrigin::ensure_origin(origin)?;

            ProofDeposit::<T>::insert(typed_chain_id, proof_deposit);
            ProofReward::<T>::insert(typed_chain_id, proof_reward);

            Self::deposit_event(Event::UpdateProofFee {
                typed_chain_id,
                proof_deposit,
                proof_reward,
            });

            Ok(().into())
        }
    }
}

impl<T: Config> Pallet<T> {
    pub fn account_id() -> <T as frame_system::Config>::AccountId {
        <T as Config>::PalletId::get().into_account_truncating()
    }

    pub fn is_contract_address_in_log(
        transaction_receipt: &TransactionReceipt,
        address: H160,
    ) -> bool {
        let index_of_log_address = transaction_receipt
            .receipt
            .logs
            .iter()
            .position(|x| x.address == address);

        index_of_log_address.is_some()
    }
}
