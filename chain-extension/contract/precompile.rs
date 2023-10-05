use ink::env::{chain_extension::FromStatusCode, DefaultEnvironment, Environment};
use ink::prelude::vec::Vec;

pub type Log = (Vec<types::H256>, Vec<u8>);

#[ink::chain_extension]
pub trait ReceiptRegistryExtension {
    type ErrorCode = Error;

    #[ink(extension = 0x00040001)]
    #[ink(handle_status = false)]
    fn logs_for_receipt(
        chain_id: u32,
        block_number: u64,
        receipt_hash: [u8; 32],
        contract_address: [u8; 20],
    ) -> Result<Vec<Log>, Error>;
}

/// chain extension errors.
#[derive(scale::Encode, scale::Decode, Debug)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub enum Error {
    FailRetrievalOfLogs,
}

impl FromStatusCode for Error {
    fn from_status_code(status_code: u32) -> core::result::Result<(), Self> {
        match status_code {
            0 => Err(Self::FailRetrievalOfLogs),
            1 => Ok(()),
            _ => panic!("encountered unknown status code"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub enum ReceiptRegistryDefaultEnvironment {}

impl Environment for ReceiptRegistryDefaultEnvironment {
    const MAX_EVENT_TOPICS: usize = <DefaultEnvironment as Environment>::MAX_EVENT_TOPICS;

    type AccountId = <DefaultEnvironment as Environment>::AccountId;
    type Balance = <DefaultEnvironment as Environment>::Balance;
    type Hash = <DefaultEnvironment as Environment>::Hash;
    type BlockNumber = <DefaultEnvironment as Environment>::BlockNumber;
    type Timestamp = <DefaultEnvironment as Environment>::Timestamp;

    type ChainExtension = ReceiptRegistryExtension;
}

impl From<scale::Error> for Error {
    fn from(_: scale::Error) -> Self {
        panic!("encountered unexpected invalid SCALE encoding")
    }
}
