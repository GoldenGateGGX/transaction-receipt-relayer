use alloy_rlp::RlpEncodableWrapper;

#[derive(Debug, RlpEncodableWrapper, PartialEq, Clone)]
pub struct Bloom(pub [u8; 256]);
