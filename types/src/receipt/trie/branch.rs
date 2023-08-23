use alloy_rlp::{BufMut, Encodable};

use crate::{encode::rlp_node, H256};

#[derive(Debug)]
pub struct BranchNode {
    pub branches: [Option<H256>; 16],
}

impl Encodable for BranchNode {
    fn encode(&self, result: &mut dyn BufMut) {
        let mut buf = vec![];
        let payload_length =
            self.branches.iter().fold(
                1usize,
                |acc, elem| if elem.is_some() { acc + 32 } else { 1 },
            );
        let header = alloy_rlp::Header {
            payload_length,
            list: true,
        };
        header.encode(&mut buf);

        for i in self.branches.iter() {
            if let Some(hash) = i {
                buf.put_slice(&hash.0);
            } else {
                buf.put_u8(alloy_rlp::EMPTY_STRING_CODE);
            }
        }

        buf.put_u8(alloy_rlp::EMPTY_STRING_CODE);
        rlp_node(&buf, result);
    }

    fn length(&self) -> usize {
        32 * 16
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hasher::HasherKeccak;

    use crate::H256;

    use super::BranchNode;

    fn test_encoding() {
        let mut trie = cita_trie::PatriciaTrie::new(
            Arc::new(cita_trie::MemoryDB::new(true)),
            Arc::new(HasherKeccak::new()),
        );

        let mut branch_node = BranchNode {
            branches: [Option::<H256>::None; 16],
        };

        for i in 0..16 {}
    }
}
