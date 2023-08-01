use alloy_rlp::{Encodable, RlpEncodable};
use keccak_hash::keccak;

#[derive(Debug, RlpEncodable, PartialEq, Clone)]
pub struct H256(pub [u8; 32]);

#[derive(Debug, RlpEncodable, PartialEq, Clone)]
pub struct H64(pub [u8; 8]);

#[derive(Debug, RlpEncodable, PartialEq, Clone)]
pub struct U256(pub [u8; 32]);

impl From<u64> for U256 {
    fn from(x: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&x.to_be_bytes());
        Self(bytes)
    }
}

#[derive(Debug, RlpEncodable, PartialEq, Clone)]
pub struct H160(pub [u8; 20]);

impl H256 {
    pub fn hash<T>(x: T) -> Self
    where
        T: Encodable,
    {
        let mut rlp = Vec::new();
        x.encode(&mut rlp);
        Self(keccak(&rlp).into())
    }
}

#[cfg(test)]
mod tests {
    use test_strategy::proptest;

    #[proptest]
    fn test_from_u64(a: u64) {
        let u256 = super::U256::from(a);
        let ethers_u256 = ethers_core::types::U256::from(a);
        let ethers_u256: [u8; 32] = ethers_u256.into();

        assert_eq!(u256.0, ethers_u256);
    }
}
