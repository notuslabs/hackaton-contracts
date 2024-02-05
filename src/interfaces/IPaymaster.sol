// SPDX-License-Identifier: CC0
pragma solidity ^0.8.18;

import { UserOperation } from "./UserOperation.sol";

/**
 * Necessary interface for paymaster contracts
 *
 * Paymaster pays the gas for user's operations. The payment will be deduced from a deposit made in the entry point.
 */
interface IPaymaster {
    // user op 'state' on postOp call
    // forgefmt: disable-start
    enum PostOpMode {
        opSucceeded,   // user op succeeded.
        opReverted,    // user op reverted, still has to pay for gas.
        postOpReverted // user op succeeded, but caused postOp to revert. 2nd call after user op was forcibly cancelled.
    }
    // forgefmt: disable-end

    /**
     * Asks the paymaster if they agree to pay for this user operation.
     *
     * This call must ensure sender is the entry point contract.
     *
     * Reverting rejects the request.
     *
     * @param userOp - The entire user operation data
     * @param userOpHash - Hash of entire user operation
     * @param maxCost - Maximum cost of this transaction (userOp's maximum gas * gas price)
     *
     * @return context - Data that will be sent to `postOp`, zero length means no context so postOp is not required
     * @return validationData - Value MUST be packed of authorizer, validUntil and validAfter timestamps.
     *          - authorizer: 0 for valid signature, 1 to mark signature failure. Otherwise, an address of an
     *                        authorizer contract.
     *          - validUntil: 6-byte timestamp value, or zero for “infinite”. The UserOp is valid only up to this time.
     *          - validAfter: 6-byte timestamp. The UserOp is valid only after this time.
     */
    function validatePaymasterUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
        external
        returns (bytes memory context, uint256 validationData);

    /**
     * Executed after the user operation has been executed.
     *
     * Entry points may skip this call if no context was returned by `validatePaymasterUserOp`.
     *
     * This call must ensure sender is the entry point contract.
     *
     * @param mode - Result state of the execution
     * @param context - Same data returned by `validatePaymasterUserOp`
     * @param actualGasCost - Gas amount used so far, not considering this final call
     */
    function postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost) external;
}
