use alloy_rlp::RlpEncodable;

#[derive(Debug, RlpEncodable, PartialEq, Clone)]
pub struct Bloom(pub [u8; 256]);
