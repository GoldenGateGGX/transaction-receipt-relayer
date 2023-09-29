use std::sync::OnceLock;

use eth_types::eth2::LightClientUpdate;

use eth_types::{pallet::InitInput, BlockHeader};

pub fn read_headers(filename: String) -> Vec<BlockHeader> {
    serde_json::from_reader(std::fs::File::open(std::path::Path::new(&filename)).unwrap()).unwrap()
}

pub fn read_client_update(filename: String) -> LightClientUpdate {
    serde_json::from_reader(std::fs::File::open(std::path::Path::new(&filename)).unwrap()).unwrap()
}

pub fn read_client_updates(
    network: String,
    start_period: u64,
    end_period: u64,
) -> Vec<LightClientUpdate> {
    let mut updates = vec![];
    for period_idx in start_period..=end_period {
        let client_update = read_client_update(format!(
            "./tests/data/{network}/light_client_update_period_{period_idx}.json"
        ));
        updates.push(client_update);
    }

    updates
}

pub struct InitOptions<AccountId> {
    pub validate_updates: bool,
    pub verify_bls_signatures: bool,
    pub hashes_gc_threshold: u64,
    pub trusted_signer: Option<AccountId>,
}

pub fn get_goerli_test_data(
    init_options: Option<InitOptions<[u8; 32]>>,
) -> (
    &'static Vec<Vec<BlockHeader>>,
    &'static Vec<LightClientUpdate>,
    InitInput<[u8; 32]>,
) {
    const NETWORK: &str = "goerli";
    static INIT_UPDATE: OnceLock<LightClientUpdate> = OnceLock::new();
    static UPDATES: OnceLock<Vec<LightClientUpdate>> = OnceLock::new();
    static HEADERS: OnceLock<Vec<Vec<BlockHeader>>> = OnceLock::new();

    let init_update =
        INIT_UPDATE.get_or_init(|| read_client_updates(NETWORK.to_string(), 632, 632)[0].clone());
    let updates = UPDATES.get_or_init(|| read_client_updates(NETWORK.to_string(), 633, 633));
    let headers = HEADERS.get_or_init(|| {
        vec![read_headers(format!(
            "./tests/data/{}/execution_blocks_{}_{}.json",
            NETWORK, 8652100, 8661554
        ))]
    });

    let init_options = init_options.unwrap_or(InitOptions {
        validate_updates: true,
        verify_bls_signatures: true,
        hashes_gc_threshold: 51000,
        trusted_signer: None,
    });

    let init_input = InitInput {
        finalized_execution_header: headers[0][0].clone(),
        finalized_beacon_header: UPDATES.get().unwrap()[0]
            .clone()
            .finality_update
            .header_update
            .into(),
        current_sync_committee: init_update
            .clone()
            .sync_committee_update
            .as_ref()
            .unwrap()
            .next_sync_committee
            .clone(),
        next_sync_committee: updates[0]
            .sync_committee_update
            .as_ref()
            .unwrap()
            .next_sync_committee
            .clone(),
        validate_updates: init_options.validate_updates,
        verify_bls_signatures: init_options.verify_bls_signatures,
        hashes_gc_threshold: init_options.hashes_gc_threshold,
        trusted_signer: init_options.trusted_signer,
    };

    (headers, updates, init_input)
}

pub fn get_test_data(
    init_options: Option<InitOptions<[u8; 32]>>,
) -> (
    &'static Vec<Vec<BlockHeader>>,
    &'static Vec<LightClientUpdate>,
    InitInput<[u8; 32]>,
) {
    get_goerli_test_data(init_options)
}
