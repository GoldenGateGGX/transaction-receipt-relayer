use alloy_rlp::Encodable;
use bytes::BufMut;

/// Transaction Type enum; adapted from [`reth_primitives::TxType`][1].
///
/// [1]: https://github.com/paradigmxyz/reth/blob/f41386d28e89dd436feea872178452e5302314a5/crates/primitives/src/transaction/tx_type.rs#L22-L32
#[derive(Default, Debug, PartialEq, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TxType {
    /// Legacy transaction pre EIP-2929
    #[default]
    Legacy = 0_isize,
    /// AccessList transaction
    EIP2930 = 1_isize,
    /// Transaction with Priority fee
    EIP1559 = 2_isize,
    /// Shard Blob Transactions - EIP-4844
    EIP4844 = 3_isize,
}

impl Encodable for TxType {
    /// TxType is encoded as [`u8`][1].
    ///
    /// [1]: https://github.com/paradigmxyz/reth/blob/f41386d28e89dd436feea872178452e5302314a5/crates/primitives/src/transaction/mod.rs#L556
    fn encode(&self, out: &mut dyn BufMut) {
        out.put_u8(*self as u8)
    }

    fn length(&self) -> usize {
        1 // byte size of u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn encode() {
        let mut buf = BytesMut::new();

        Encodable::encode(&TxType::Legacy, &mut buf);
        assert_eq!(buf[..], [0]);

        buf.clear();
        Encodable::encode(&TxType::EIP2930, &mut buf);
        assert_eq!(buf[..], [1]);

        buf.clear();
        Encodable::encode(&TxType::EIP1559, &mut buf);
        assert_eq!(buf[..], [2]);

        buf.clear();
        Encodable::encode(&TxType::EIP4844, &mut buf);
        assert_eq!(buf[..], [3]);
    }
}
