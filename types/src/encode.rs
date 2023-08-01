pub struct Encoder<'a>(pub &'a mut dyn alloy_rlp::BufMut);

impl<'a> Encoder<'a> {
    pub fn encode_value(&mut self, value: &[u8]) {
        println!("value.len(): {}", value.len());
        match value.len() {
            // just 0
            0 => self.0.put_u8(0x80u8),
            // byte is its own encoding if < 0x80
            1 if value[0] < 0x80 => self.0.put_u8(value[0]),
            // (prefix + length), followed by the string
            len @ 1..=55 => {
                self.0.put_u8(0x80u8 + len as u8);
                self.0.put_slice(value);
            }
            // (prefix + length of length), followed by the length, followd by the string
            // len => {
            //     self.0.put_u8(0);
            //     let position = self.buffer.len();
            //     let inserted_bytes = self.insert_size(len, position);
            //     self.buffer[position - 1] = 0xb7 + inserted_bytes;
            //     self.buffer.append_slice(value);
            // }
            len => unreachable!(),
        }
    }
}
