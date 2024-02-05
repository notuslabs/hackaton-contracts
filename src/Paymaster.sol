// SPDX-License-Identifier: GPL-3.0-or-later
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

pragma solidity ^0.8.18;

import { ECDSA } from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";
import { IERC20, SafeERC20 } from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";

import { IEntryPoint } from "src/interfaces/IEntryPoint.sol";
import { IPaymaster } from "src/interfaces/IPaymaster.sol";
import { UserOperation } from "src/interfaces/UserOperation.sol";
import { ExternalUpgrader } from "src/abstracts/ExternalUpgrader.sol";

contract ChainlessPaymaster is IPaymaster, ExternalUpgrader {
    uint256 private constant _POST_OP_GAS_COST = 47_316;

    // forgefmt: disable-start
    bytes4 private constant _OPERATION_CODE = bytes4(hex"095ea7b3");
    uint256 private constant _OPERATION_CODE_START = 4 + 32 * 4;
    uint256 private constant _OPERATION_CODE_END   = 4 + 32 * 4 + 4;

    uint256 private constant _PAYING_TOKEN_OFFSET  = 20;
    uint256 private constant _EXCHANGE_RATE_OFFSET = 20 + 32 * 1;
    uint256 private constant _VALID_AFTER_OFFSET   = 20 + 32 * 2;
    uint256 private constant _VALID_UNTIL_OFFSET   = 20 + 32 * 3;
    uint256 private constant _SIGNATURE_OFFSET     = 20 + 32 * 4;
    // forgefmt: disable-end

    using SafeERC20 for IERC20;

    /**
     * Error for when the sender is not the Entry Point
     */
    error SenderIsNotEntryPoint(address sender);

    /**
     * Wrong paymaster signature length
     */
    error PaymasterSignatureLengthMismatch(bytes signature);

    /**
     * Paymaster not allowed to spend token
     */
    error PaymasterNotAllowedERC20(IERC20 token, uint256 requiredAmount);

    /**
     * Entry Point allowed to call paymaster
     */
    IEntryPoint public entryPoint;

    /**
     * Must call on deploy to initialize (constructor of upgradable contracts)
     *
     * @param allowedEntryPoint - Entry Point allowed to call this contract
     */
    function initialize(IEntryPoint allowedEntryPoint) public initializer {
        __Ownable_init(msg.sender);
        entryPoint = allowedEntryPoint;
    }

    /**
     * Require only entry point to call the function
     */
    modifier onlyEntryPoint() {
        if (msg.sender != address(entryPoint)) {
            revert SenderIsNotEntryPoint(msg.sender);
        }
        _;
    }

    /// @inheritdoc IPaymaster
    function validatePaymasterUserOp(UserOperation calldata userOp, bytes32, uint256 maxCost)
        external
        view
        override
        onlyEntryPoint
        returns (bytes memory context, uint256 validationData)
    {
        (IERC20 payingToken, uint256 exchangeRate, uint48 validAfter, uint48 validUntil, bytes calldata signature) =
            _parsePaymasterData(userOp.paymasterAndData);

        if (signature.length != 65) {
            revert PaymasterSignatureLengthMismatch(signature);
        }

        bytes4 operationCode;
        if (userOp.callData.length >= _OPERATION_CODE_END) {
            operationCode = bytes4(userOp.callData[_OPERATION_CODE_START:_OPERATION_CODE_END]);
        }

        // this is not exact but at least fails early most
        if (operationCode != _OPERATION_CODE && payingToken.allowance(userOp.sender, address(this)) < maxCost) {
            revert PaymasterNotAllowedERC20(payingToken, maxCost);
        }

        context = abi.encode(payingToken, exchangeRate, userOp.sender);

        validationData = ((validationData | validAfter) << 48 | validUntil) << 160;

        bytes32 msgHash = keccak256(userOp.paymasterAndData[_PAYING_TOKEN_OFFSET:_SIGNATURE_OFFSET]);
        address signedBy = ECDSA.recover(MessageHashUtils.toEthSignedMessageHash(msgHash), signature);

        if (signedBy != owner()) {
            validationData |= 1;
        }
    }

    /// @inheritdoc IPaymaster
    function postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost) external override onlyEntryPoint {
        IERC20 payingToken;
        uint256 exchangeRate;
        address sender;

        // cheaper abi.decode, we've ensured it's correct on `validatePaymasterUserOp`
        // solhint-disable-next-line no-inline-assembly
        assembly {
            payingToken := calldataload(add(context.offset, 0))
            exchangeRate := calldataload(add(context.offset, 32))
            sender := calldataload(add(context.offset, 64))
        }

        uint256 payingTokenCost = (((actualGasCost + _POST_OP_GAS_COST) * tx.gasprice) * exchangeRate) / 1e18;

        if (mode != PostOpMode.postOpReverted) {
            payingToken.safeTransferFrom(sender, owner(), payingTokenCost);
        }
    }

    /**
     * Parse packed userOp.paymasterAndData bytes into its data
     *
     * @param paymasterAndData - Complete userOp.paymasterAndData
     *
     * @return payingToken - Token to use to pay fees
     * @return exchangeRate - ERC20 token per gwei
     * @return validAfter - Timestamp this data becomes valid
     * @return validUntil - Timestamp this data will become invalid
     * @return signature - Paymaster owner signature to validate above data
     */
    function _parsePaymasterData(bytes calldata paymasterAndData)
        internal
        pure
        returns (
            IERC20 payingToken,
            uint256 exchangeRate,
            uint48 validAfter,
            uint48 validUntil,
            bytes calldata signature
        )
    {
        // parse it quick and cheap
        // solhint-disable-next-line no-inline-assembly
        assembly {
            payingToken := calldataload(add(paymasterAndData.offset, _PAYING_TOKEN_OFFSET))
            exchangeRate := calldataload(add(paymasterAndData.offset, _EXCHANGE_RATE_OFFSET))
            validAfter := calldataload(add(paymasterAndData.offset, _VALID_AFTER_OFFSET))
            validUntil := calldataload(add(paymasterAndData.offset, _VALID_UNTIL_OFFSET))
        }
        signature = paymasterAndData[_SIGNATURE_OFFSET:];
    }

    /**
     * Return paymaster's deposit on entry point.
     *
     * @return Current balance of native tokens to pay gas
     */
    function getDepositBalance() external view returns (uint256) {
        return entryPoint.balanceOf(address(this));
    }

    /**
     * Deposit native tokens to pay fees for this paymaster
     */
    function deposit() external payable {
        entryPoint.depositTo{ value: msg.value }(address(this));
    }

    /**
     * Withdraw native tokens to pay fees
     *
     * @param withdrawAddress - Account to send funds to
     * @param withdrawAmount - Amount to withdraw
     */
    function withdrawTo(address payable withdrawAddress, uint256 withdrawAmount) external onlyOwner {
        entryPoint.withdrawTo(withdrawAddress, withdrawAmount);
    }

    /**
     * Add stake on entry point
     *
     * @param unstakeDelaySec - How long the stake will remain locked
     */
    function addStake(uint32 unstakeDelaySec) external payable onlyOwner {
        entryPoint.addStake{ value: msg.value }(unstakeDelaySec);
    }

    /**
     * Unlock the stake to later withdraw it
     *
     * Must wait unstakeDelay before can withdraw
     *
     * Won't be able to use the paymaster with no stake except for some cases outlined on EIP-4337
     */
    function unlockStake() external onlyOwner {
        entryPoint.unlockStake();
    }

    /**
     * Withdraw all the unlocked stake
     *
     * Stake must've been unlocked before
     *
     * @param withdrawAddress - Account to send funds to
     */
    function withdrawStake(address payable withdrawAddress) external onlyOwner {
        entryPoint.withdrawStake(withdrawAddress);
    }
}
