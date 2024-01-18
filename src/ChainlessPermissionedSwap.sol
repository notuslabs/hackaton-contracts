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

import { OwnableUpgradeable } from "openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import { UUPSUpgradeable } from "openzeppelin-contracts/contracts/proxy/utils/UUPSUpgradeable.sol";
import { SafeERC20, IERC20 } from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * A permissioned swap contract for the Chainless Account Abstraction (EIP-4337) app
 */
contract ChainlessPermissionedSwap is UUPSUpgradeable, OwnableUpgradeable {
    using SafeERC20 for IERC20;

    /**
     * Error for when the expected transaction hash doesn't match the computed hash
     */
    error TransactionHashMismatch(bytes32 actual, bytes32 expected);

    /**
     * Error for when the transaction is not pending an execution
     */
    error TransactionNotPending(bytes32 txHash);

    /**
     * Error for when the transaction is already pending an execution
     */
    error TransactionAlreadyPending(bytes32 txHash);

    /**
     * Error for when trying to request swap with random tokens
     */
    error TokenNotAllowed(IERC20 token);

    /**
     * Error for when trying to request a swap with lower than minimum amount
     */
    error AmountSentBelowMinimum(IERC20 token, uint256 sentAmount, uint256 expectedAmount);

    /**
     * @notice Get the current transaction nonce
     *
     * @dev We use an custom nonce so every request by a user is sure to be unique
     */
    uint256 private _txNonce;
    bytes32[] private _pendingTxHashes;
    mapping(bytes32 txHash => uint256 index) private _pendingTxToIndex;
    mapping(bytes32 txHash => bool isPending) private _pendingTxs;
    mapping(address token => uint256 minAmount) private _fiatTokens;
    mapping(address token => uint256 minAmount) private _investTokens;

    /**
     * @dev Emitted when a swap is requested by a user
     */
    event SwapRequested(
        bytes32 indexed txHash,
        address indexed recipient,
        IERC20  indexed receiveToken,
        address         payer,
        IERC20          payWith,
        uint256         payAmount,
        uint256         txNonce
    );

    /**
     * @dev Emitted when a swap is fulfilled0
     */
    event SwapExecuted(
        bytes32 indexed txHash,
        address indexed recipient,
        IERC20  indexed token,
        uint256         amount
    );

    /**
     * Must call on deploy to initialize (constructor of upgradable contracts)
     */
    function initialize() public initializer {
        __Ownable_init(msg.sender);
    }

    /**
     * Allow owner to upgrade implementation
     */
    function _authorizeUpgrade(address) internal override onlyOwner {}

    /**
     * @notice Checks if the transaction is pending
     *
     * @return True if it's pending, False otherwise
     */
    function isTxPending(bytes32 hash) external view returns (bool) {
        return _pendingTxs[hash];
    }

    /**
     * @notice Get the number of transactions that are still pending
     *
     * @return Amount of pending transactions
     */
    function getAmountPendingTx() external view returns (uint256) {
        return _pendingTxHashes.length;
    }

    /**
     * @notice Get a list of hashes from pending transaction
     *
     * @return List of bytes32 hashes
     */
    function getPendingTxHashes(uint256 take, uint256 skip) external view returns (bytes32[] memory) {
        uint256 size = _pendingTxHashes.length;
        uint256 skipNormalized = skip > size ? size : skip;
        uint256 takeNormalized = take + skipNormalized;
        takeNormalized = takeNormalized > size ? size : takeNormalized;

        bytes32[] memory hashes = new bytes32[](takeNormalized - skipNormalized);

        for (uint256 i = skip; i < takeNormalized; i++) {
            hashes[i - skip] = _pendingTxHashes[i];
        }

        return hashes;
    }

    /**
     * Get minimum amount required to queue a transaction
     *
     * A value of zero means the token is not allowed
     *
     * @param token - Token to check minimums
     *
     * @return fiatAmount - Minimum required to call `invest`
     * @return investAmount - Minimum required to call `withdraw`
     */
    function getMinRequest(address token) external view returns (uint256 fiatAmount, uint256 investAmount) {
        return (_fiatTokens[token], _investTokens[token]);
    }

    /**
     * @notice Request an investment on a token Chainless offers as investment
     *
     * @param token - The ERC20 token address to invest into
     * @param recipient - Who will receive the investment token
     * @param payWith - ERC20 token to pay the investment with
     * @param payAmount - Amount of the above token
     */
    function invest(IERC20 token, address recipient, IERC20 payWith, uint256 payAmount) external returns (bytes32) {
        return _txRequest(
            token,
            msg.sender,
            recipient,
            payWith,
            payAmount,
            _fiatTokens[address(payWith)],
            _investTokens[address(token)]
        );
    }

    /**
     * @notice Withdraw a token Chainless considers investment back to a fiat currency
     *
     * @param token - The fiat ERC20 token address to withdraw to
     * @param recipient - Who will receive the fiat token
     * @param payWith - ERC20 investment token address
     * @param payAmount - Amount of the above token
     */
    function withdraw(IERC20 token, address recipient, IERC20 payWith, uint256 payAmount) external returns (bytes32) {
        return _txRequest(
            token,
            recipient,
            msg.sender,
            payWith,
            payAmount,
            _investTokens[address(payWith)],
            _fiatTokens[address(token)]
        );
    }

    /**
     * @notice Request a transaction to be made, invest and withdraws are equal in the eyes of the backend
     *
     * @param token - The ERC20 token address requested by the user
     * @param recipient - Who will receive the token
     * @param payer - Address that will send the exchanged token
     * @param payWith - ERC20 token that the payer will send us
     * @param payAmount - Amount of the above token
     */
    function _txRequest(
        IERC20 token,
        address recipient,
        address payer,
        IERC20 payWith,
        uint256 payAmount,
        uint256 payWithMinimum,
        uint256 receiveTokenMinimum
    ) private returns (bytes32) {
        if (receiveTokenMinimum == 0) {
            revert TokenNotAllowed(token);
        }

        if (payWithMinimum == 0) {
            revert TokenNotAllowed(payWith);
        }

        if (payAmount < payWithMinimum) {
            revert AmountSentBelowMinimum(payWith, payAmount, payWithMinimum);
        }

        bytes32 txHash = keccak256(abi.encodePacked(_txNonce, token, recipient, payer, payWith, payAmount));

        if (_pendingTxs[txHash]) {
            revert TransactionAlreadyPending(txHash);
        }

        _pendingTxs[txHash] = true;
        _pendingTxToIndex[txHash] = _pendingTxHashes.length;
        _pendingTxHashes.push(txHash);

        emit SwapRequested(txHash, recipient, token, payer, payWith, payAmount, _txNonce);
        _txNonce++;

        payWith.safeTransferFrom(payer, address(this), payAmount);

        return txHash;
    }

    /**
     * @notice Accepts a pending transaction (tx) sending the requested tokens
     *
     * @dev The hash is recreated here to make sure it's the correct txHash being fulfilled
     *
     * @param txHash - Hash of the transaction being fulfilled
     * @param txNonce - This contract internal nonce used for this transaction
     * @param receiveAmount - The amount the recipient will receive
     * @param receiveToken - The ERC20 token address to transfer
     * @param recipient - Who will receive the token
     * @param payer - Address that sent the tokens (only used for checking the hash)
     * @param payWith - ERC20 token that was sent to us (only used for checking the hash)
     * @param payAmount - Amount of the above token sent (only used for checking the hash)
     */
    function fulfillTx(
        bytes32 txHash,
        uint256 txNonce,
        uint256 receiveAmount,
        IERC20 receiveToken,
        address recipient,
        address payer,
        IERC20 payWith,
        uint256 payAmount
    ) external onlyOwner {
        if (!_pendingTxs[txHash]) {
            revert TransactionNotPending(txHash);
        }

        bytes32 checkHash = keccak256(abi.encodePacked(txNonce, receiveToken, recipient, payer, payWith, payAmount));

        if (checkHash != txHash) {
            revert TransactionHashMismatch(checkHash, txHash);
        }

        _pendingTxs[txHash] = false;
        uint256 deleteIndex = _pendingTxToIndex[txHash];
        bytes32 lastTx = _pendingTxHashes[_pendingTxHashes.length - 1];
        _pendingTxHashes[deleteIndex] = lastTx;
        _pendingTxToIndex[lastTx] = deleteIndex;
        _pendingTxToIndex[txHash] = 0;
        _pendingTxHashes.pop();

        emit SwapExecuted(txHash, recipient, receiveToken, receiveAmount);

        receiveToken.safeTransfer(recipient, receiveAmount);
    }

    /**
     * @notice Lets the owner send any funds anywhere
     *
     * @param token - The ERC20 token address to transfer
     * @param recipient - Who will receive the token
     * @param amount - The amount the recipient will receive
     */
    function transfer(IERC20 token, address recipient, uint256 amount) external onlyOwner {
        token.safeTransfer(recipient, amount);
    }

    /**
     * @notice Adds a token allowed to pay an investment
     *
     * @dev A minAmount of zero means it's not allowed
     *
     * @param token - Token address
     * @param minAmount - Minimum amount that must be sent for operation to be requested
     */
    function addFiatToken(address token, uint256 minAmount) external onlyOwner {
        _fiatTokens[token] = minAmount;
    }

    /**
     * @notice Adds a token to receive as an investment
     *
     * @dev A minAmount of zero means it's not allowed
     *
     * @param token - Token address
     * @param minAmount - Minimum amount that must be sent for operation to be requested
     */
    function addInvestToken(address token, uint256 minAmount) external onlyOwner {
        _investTokens[token] = minAmount;
    }
}
