// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface EthReceiptProvider {
    function logs_for_receipt(
        uint256 chain_id,
        uint256 block_number,
        bytes32 receipt_hash,
        address contract_addr
    )
        external
        returns (
            bytes32 [][] calldata,
            uint[][] calldata
        );
}


// Ethereum contract
contract Dog {
    event Bark(string message);
    event TailWag(string message);

    function bark() public {
        emit Bark("Woof! Woof!");
    }

    function wagTail() public {
        emit TailWag("The dog is happy and wagging its tail!");
    }
}

// GGXChain EVM contract that reacts on Dog contract
contract DogOwner {
    EthReceiptProvider public ethReceiptProvider;
    address public dogContractAddress;
    event Response(string message);

    constructor() {
        dogContractAddress = 0x3B123F7Dd131e724a2dC59c83d26640B77412D0d;
        ethReceiptProvider = EthReceiptProvider(0x0000000000000000000000000000000000009999);
    }

    function respondToDogActions(
        uint256 chain_id,
        uint256 block_number,
        bytes32 receipt_hash
    ) 
        public 
    {
        (bytes32[][] memory topics, uint[][] memory _data) = ethReceiptProvider.logs_for_receipt(
            chain_id,
            block_number,
            receipt_hash,
            dogContractAddress
        );

        for (uint i = 0; i < topics.length; i++) {
            for (uint j = 0; j < topics[i].length; j++) {
                if (topics[i][j] == keccak256("Bark(string)")) {
                    emit Response("Bad boy");
                } else if (topics[i][j] == keccak256("TailWag(string)")) {
                    emit Response("Good boy");
                }
            }
        }
    }
}