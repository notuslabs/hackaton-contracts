// SPDX-License-Identifier: CC0
// solhint-disable func-name-mixedcase
// solhint-disable no-console
pragma solidity ^0.8.18;

import { Test, console2, Vm } from "forge-std/Test.sol";
import { TestERC20 } from "test/mocks/TestERC20.sol";

import { MessageHashUtils } from "openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";

import { ChainlessPaymaster } from "src/Paymaster.sol";
import { UserOperation } from "src/interfaces/UserOperation.sol";
import { IEntryPoint } from "src/interfaces/IEntryPoint.sol";
import { IPaymaster } from "src/interfaces/IPaymaster.sol";

contract PaymasterTest is Test {
    ChainlessPaymaster public paymaster;
    TestERC20 public payingToken;

    function setUp() public {
        paymaster = new ChainlessPaymaster();
        paymaster.initialize(IEntryPoint(address(this)));
        payingToken = new TestERC20("Paymaster Paying Token", "PPT");
    }

    function createUserOperation(
        address sender,
        address payingTokenAddress,
        uint256 exchangeRate,
        uint256 validAfter,
        uint256 validUntil,
        bytes memory initCode,
        bytes memory signature
    ) public pure returns (UserOperation memory userOp) {
        userOp = UserOperation({
            sender: sender,
            nonce: 0,
            initCode: initCode,
            callData: "",
            callGasLimit: 0,
            verificationGasLimit: 0,
            preVerificationGas: 0,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: abi.encodePacked(
                bytes(hex"0011223344556677889900112233445566778899"),
                abi.encode(payingTokenAddress, exchangeRate, validAfter, validUntil),
                signature
                ),
            signature: ""
        });
    }

    function test_reject__UserOpSignatureMismatch(bytes calldata signature) public {
        vm.assume(signature.length != 65);

        UserOperation memory userOp = createUserOperation(address(this), address(payingToken), 0, 0, 0, "", signature);

        vm.expectRevert(
            abi.encodeWithSelector(
                ChainlessPaymaster.PaymasterAndDataLengthMismatch.selector,
                userOp.paymasterAndData.length,
                userOp.paymasterAndData.length - signature.length + 65
            )
        );
        paymaster.validatePaymasterUserOp(userOp, "", 0);
    }

    function test_reject__UserNotAllowedPaymaster(uint256 maxCost) public {
        vm.assume(maxCost > 0);

        bytes memory signature =
            hex"0011223344556677889900112233445566778899001122334455667788990011223344556677889900112233445566778899001122334455667788990011223344";
        UserOperation memory userOp = createUserOperation(address(this), address(payingToken), 0, 0, 0, "", signature);

        vm.expectRevert(
            abi.encodeWithSelector(ChainlessPaymaster.PaymasterNotAllowedERC20.selector, address(payingToken), maxCost)
        );
        paymaster.validatePaymasterUserOp(userOp, "", maxCost);
    }

    function test_reject__PaymasterDataSignedByAnother() public {
        uint256 maxCost = 100_000;
        address payingTokenAddress = address(payingToken);
        uint256 exchangeRate = 12_345;
        uint256 validAfter = 67_890;
        uint256 validUntil = 98_765;

        Vm.Wallet memory maliciousUser = vm.createWallet("maliciousUser");
        bytes32 hash = keccak256(abi.encode(payingTokenAddress, exchangeRate, validAfter, validUntil));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(maliciousUser, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        payingToken.approve(address(paymaster), maxCost);
        UserOperation memory userOp =
            createUserOperation(address(this), payingTokenAddress, exchangeRate, validAfter, validUntil, "", signature);

        (, uint256 validationData) = paymaster.validatePaymasterUserOp(userOp, "", maxCost);

        assertEq(validationData & (1 << 160) - 1, 1);
    }

    function test_accept__PaymasterDataSignedByOwner() public {
        uint256 maxCost = 100_000;
        address payingTokenAddress = address(payingToken);
        uint256 exchangeRate = 12_345;
        uint256 validAfter = 67_890;
        uint256 validUntil = 98_765;
        bytes memory signature;

        {
            Vm.Wallet memory paymasterOwner = vm.createWallet("paymasterOwner");
            bytes32 hash = MessageHashUtils.toEthSignedMessageHash(
                keccak256(abi.encode(payingTokenAddress, exchangeRate, validAfter, validUntil))
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterOwner, hash);
            signature = abi.encodePacked(r, s, v);
            paymaster.transferOwnership(paymasterOwner.addr);
        }

        payingToken.approve(address(paymaster), maxCost);
        UserOperation memory userOp =
            createUserOperation(address(this), payingTokenAddress, exchangeRate, validAfter, validUntil, "", signature);

        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(userOp, "", maxCost);

        uint256 uint48Mask = ((1 << 48) - 1);
        assertEq(validationData & (1 << 160) - 1, 0);
        assertEq(validationData >> 160 & uint48Mask, validUntil);
        assertEq(validationData >> 208 & uint48Mask, validAfter);
        assertEq(context, abi.encode(payingTokenAddress, exchangeRate, address(this)));
    }

    /*
     * actualGasCost up to over 16 million gas
     * exchangeRate up to over 79 million per token
     * txGasPrice up to over 280_000 gwei
     */
    function test_accept__PostOp(uint24 actualGasCost, uint96 exchangeRate, uint48 txGasPrice) public {
        // minimum gas amount allowed
        vm.assume(actualGasCost >= 21_000);
        // that's 0.001 USD per token
        vm.assume(exchangeRate >= 1e3);
        // 1 gwei per gas
        vm.assume(txGasPrice >= 1e9);

        uint256 postOpGasCost = 47_316;
        vm.txGasPrice(txGasPrice);
        bytes memory context = abi.encode(payingToken, exchangeRate, address(this));
        paymaster.transferOwnership(address(payingToken));
        payingToken.approve(address(paymaster), type(uint256).max);
        payingToken.mint(type(uint256).max);

        uint256 gasBefore = gasleft();
        paymaster.postOp(IPaymaster.PostOpMode.opSucceeded, context, actualGasCost);
        console2.log(gasBefore - gasleft());

        // if we are dealing with very low values they could be zero, these should be very rare
        vm.assume(payingToken.balanceOf(address(payingToken)) > 0);

        uint256 payingTokenCost = ((actualGasCost + (postOpGasCost * tx.gasprice)) * exchangeRate) / 1e18;
        assertEq(payingTokenCost, payingToken.balanceOf(address(payingToken)), "Amount we expect should match");
    }
}
