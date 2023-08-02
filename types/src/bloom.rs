use alloy_rlp::RlpEncodableWrapper;
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, RlpEncodableWrapper, PartialEq, Clone)]
pub struct Bloom(#[serde(with = "serde_big_array::BigArray")] pub [u8; 256]);
