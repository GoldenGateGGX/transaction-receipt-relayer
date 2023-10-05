#![cfg_attr(not(feature = "std"), no_std, no_main)]

mod precompile;

#[ink::contract(env = crate::precompile::ReceiptRegistryDefaultEnvironment)]
mod dog_owner {
    use ink::prelude::string::String;

    #[ink(storage)]
    pub struct Dog {
        contract: [u8; 20],
    }

    #[ink(event)]
    pub struct Response {
        response: String,
    }

    impl Dog {
        /// Constructor that initializes the `bool` value to the given `init_value`.
        #[ink(constructor)]
        pub fn new(contract: [u8; 20]) -> Self {
            Self { contract }
        }

        #[ink(message)]
        pub fn process(&mut self, chain_id: u32, block_number: u64, receipt_hash: types::H256) {
            let logs = self
                .env()
                .extension()
                .logs_for_receipt(chain_id, block_number, receipt_hash.0, self.contract)
                .expect("failed to retrieve logs");

            for (topics, _) in logs {
                for topic in topics {
                    if topic.0 == keccak_hash::keccak("Bark(string)").0 {
                        self.env().emit_event(Response {
                            response: String::from("Bad boy"),
                        });
                    } else if topic.0 == keccak_hash::keccak("TailWag(string)").0 {
                        self.env().emit_event(Response {
                            response: String::from("Good boy"),
                        });
                    }
                }
            }
        }
    }
}
