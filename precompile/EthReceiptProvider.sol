/// SPDX-License-Identifier: GPL-3.0-only
pragma solidity >=0.8.0;

/**
 * @title EthReceiptProvider Interface
 *
 * @dev This interface allows a contract to interact with the EthReceiptProvider at address
 *      0x0000000000000000000000000000000000009999, to retrieve log information of a specified
 *      contract from a given block on a specified chain.
 *
 */
interface EthReceiptProvider {
    
    /**
     * @notice Fetches logs of a specified contract from a given block on a specified chain.
     *
     * @dev This function returns log information in the form of topics and data arrays for a 
     *      specified contract from a given block on a specified chain. The log information is 
     *      returned as two separate arrays, where each entry corresponds to a log event.
     *
     * @param chain_id The ID of the chain from which to retrieve log information.
     * @param block_number The number of the block from which to retrieve log information.
     * @param receipt_hash The hash of the receipt for which to retrieve log information.
     * @param contract_addr The address of the contract for which to retrieve log information.
     *
     * @return Two separate arrays:
     *          - The first array contains arrays of bytes32 values, each representing a log topic.
     *          - The second array contains arrays of uint values, each representing log data.
     */
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