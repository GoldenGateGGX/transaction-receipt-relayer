use crate::H160;
use alloy_rlp::Encodable;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Bloom(ethbloom::Bloom);
impl Bloom {
    pub fn new(bytes: [u8; 256]) -> Self {
        Self(ethbloom::Bloom(bytes))
    }

    pub fn check_address(&self, address: &H160) -> bool {
        self.0.contains_input(ethbloom::Input::Raw(&address.0))
    }
}

impl Encodable for Bloom {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        self.0 .0.encode(out)
    }
}
