use alloy_rlp::Encodable;
use bytes::BufMut;

const LEGACY_TX_TYPE_ID: isize = 0_isize;
const EIP2930_TX_TYPE_ID: isize = 1_isize;
const EIP1559_TX_TYPE_ID: isize = 2_isize;
const EIP4844_TX_TYPE_ID: isize = 3_isize;

/// Transaction Type enum; adapted from [`reth_primitives::TxType`][1].
///
/// [1]: https://github.com/paradigmxyz/reth/blob/f41386d28e89dd436feea872178452e5302314a5/crates/primitives/src/transaction/tx_type.rs#L22-L32
#[derive(Default, Debug, PartialEq)]
pub enum TxType {
    /// Legacy transaction pre EIP-2929
    #[default]
    Legacy = LEGACY_TX_TYPE_ID,
    /// AccessList transaction
    EIP2930 = EIP2930_TX_TYPE_ID,
    /// Transaction with Priority fee
    EIP1559 = EIP1559_TX_TYPE_ID,
    /// Shard Blob Transactions - EIP-4844
    EIP4844 = EIP4844_TX_TYPE_ID,
}

impl Encodable for TxType {
    fn encode(&self, out: &mut dyn BufMut) {
        match self {
            TxType::Legacy => LEGACY_TX_TYPE_ID.to_le_bytes().encode(out),
            TxType::EIP2930 => EIP2930_TX_TYPE_ID.to_le_bytes().encode(out),
            TxType::EIP1559 => EIP1559_TX_TYPE_ID.to_le_bytes().encode(out),
            TxType::EIP4844 => EIP4844_TX_TYPE_ID.to_le_bytes().encode(out),
        }
    }

    fn length(&self) -> usize {
        match self {
            TxType::Legacy => LEGACY_TX_TYPE_ID.to_le_bytes().len(),
            TxType::EIP2930 => EIP2930_TX_TYPE_ID.to_le_bytes().len(),
            TxType::EIP1559 => EIP1559_TX_TYPE_ID.to_le_bytes().len(),
            TxType::EIP4844 => EIP4844_TX_TYPE_ID.to_le_bytes().len(),
        }
    }
}
