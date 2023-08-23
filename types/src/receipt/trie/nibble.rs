#[derive(Debug, Clone)]
pub struct Nibbles {
    /// The inner representation of the nibble sequence.
    hex_data: Vec<u8>,
}

impl Nibbles {
    pub fn new(raw: Vec<u8>) -> Self {
        let mut hex_data = vec![];
        for item in raw.into_iter() {
            hex_data.push(item / 16);
            hex_data.push(item % 16);
        }

        Nibbles { hex_data }
    }

    pub fn encode_path_leaf(&self, is_leaf: bool) -> Vec<u8> {
        let mut encoded = vec![0u8; self.hex_data.len() / 2 + 1];
        let odd_nibbles = self.hex_data.len() % 2 != 0;

        // Set the first byte of the encoded vector.
        encoded[0] = match (is_leaf, odd_nibbles) {
            (true, true) => 0x30 | self.hex_data[0],
            (true, false) => 0x20,
            (false, true) => 0x10 | self.hex_data[0],
            (false, false) => 0x00,
        };

        let mut nibble_idx = if odd_nibbles { 1 } else { 0 };
        for byte in encoded.iter_mut().skip(1) {
            *byte = (self.hex_data[nibble_idx] << 4) + self.hex_data[nibble_idx + 1];
            nibble_idx += 2;
        }

        encoded
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use crate::receipt::trie::nibble::Nibbles;

    #[test]
    fn encode_leaf_node_nibble() {
        let nibble = Nibbles {
            hex_data: hex!("0604060f").into(),
        };
        let encoded = nibble.encode_path_leaf(true);
        let expected = hex!("20646f").to_vec();
        assert_eq!(encoded, expected);
    }

    #[test]
    fn hashed_regression() {
        let nibbles = hex!("05010406040a040203030f010805020b050c04070003070e0909070f010b0a0805020301070c0a0902040b0f000f0006040a04050f020b090701000a0a040b");
        let nibbles = Nibbles {
            hex_data: nibbles.to_vec(),
        };
        let path = nibbles.encode_path_leaf(true);
        let expected = hex!("351464a4233f1852b5c47037e997f1ba852317ca924bf0f064a45f2b9710aa4b");
        assert_eq!(path, expected);
    }
}
