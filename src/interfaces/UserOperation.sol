// SPDX-License-Identifier: CC0
pragma solidity ^0.8.18;

/**
 * User Operation struct
 *
 * @param sender - The account making the operation
 * @param nonce - Anti-replay parameter
 * @param initCode - The initCode of the account (needed if and only if the account is not yet on-chain)
 * @param callData - The data to pass to the sender during the main execution call
 * @param callGasLimit - The amount of gas to allocate the main execution call
 * @param verificationGasLimit - The amount of gas to allocate for the verification step
 * @param preVerificationGas - The amount of gas to pay for to compensate the bundler for pre-verification execution,
 *                             calldata and any gas overhead that can’t be tracked on-chain
 * @param maxFeePerGas - Maximum fee per gas (similar to EIP-1559 max_fee_per_gas)
 * @param maxPriorityFeePerGas - Maximum priority fee per gas (similar to EIP-1559 max_priority_fee_per_gas)
 * @param paymasterAndData - Address of paymaster sponsoring the transaction, followed by extra data to send to the
 *                           paymaster (empty for self-sponsored transaction)
 * @param signature - Data passed into the account along with the nonce during the verification step
 */
struct UserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    uint256 callGasLimit;
    uint256 verificationGasLimit;
    uint256 preVerificationGas;
    uint256 maxFeePerGas;
    uint256 maxPriorityFeePerGas;
    bytes paymasterAndData;
    bytes signature;
}
