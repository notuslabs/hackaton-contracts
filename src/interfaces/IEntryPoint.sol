// SPDX-License-Identifier: CC0
pragma solidity ^0.8.18;

/**
 * Entry Point interface needed by paymaster contracts
 */
interface IEntryPoint {
    /*--- Stake management ---*/

    /**
     * Add a paymaster stake
     *
     * @param unstakeDelaySec - How long the stake will remain locked from withdrawing
     */
    function addStake(uint32 unstakeDelaySec) external payable;

    /**
     * Unlock the stake to later withdraw it
     *
     * Must wait unstakeDelaySec set by `addStake` before being able to withdraw
     *
     * Won't be able to use the paymaster with no stake except for some cases outlined on EIP-4337
     */
    function unlockStake() external;

    /**
     * Withdraw all the unlocked stake
     *
     * Stake must've been unlocked before
     *
     * @param withdrawAddress - Account to send funds to
     */
    function withdrawStake(address payable withdrawAddress) external;

    /*--- Balance management ---*/

    /**
     * Return the deposit to pay gas fees of an account (paymaster)
     *
     * @param account - Account to check current balance
     *
     * @return Current balance of native tokens to pay gas
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * Deposit more native tokens for an account
     *
     * @param account - Account to deposit balance to
     */
    function depositTo(address account) external payable;

    /**
     * Withdraw some funds from the deposit
     *
     * @param withdrawAddress - Account to send funds to
     * @param withdrawAmount - Amount to withdraw
     */
    function withdrawTo(address payable withdrawAddress, uint256 withdrawAmount) external;
}
