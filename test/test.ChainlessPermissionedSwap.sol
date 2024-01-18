// SPDX-License-Identifier: CC0
// solhint-disable func-name-mixedcase
// solhint-disable no-console
pragma solidity ^0.8.18;

import { Test } from "forge-std/Test.sol";
import { ChainlessPermissionedSwap } from "src/ChainlessPermissionedSwap.sol";
import { TestERC20 } from "test/mocks/TestERC20.sol";

contract SwapTest is Test {
    ChainlessPermissionedSwap public swap;
    TestERC20 public fiat;
    TestERC20 public invest;

    function setUp() public {
        swap = new ChainlessPermissionedSwap();
        swap.initialize();
        fiat = new TestERC20("Fiat", "FIAT");
        invest = new TestERC20("Investment", "STONKS");
    }

    function accept__No_pending_tx_at_start() public {
        uint256 m = swap.getAmountPendingTx();
        assertEq(m, 0);
    }

    function test_revert__Invest_in_token_not_whitelisted() public {
        vm.expectRevert("ERR_INVALID_OUT_TOKEN");
        swap.invest(invest, msg.sender, fiat, 1 ether);
    }

    function test_revert__Invest_out_token_not_whitelisted() public {
        swap.addInvestToken(address(invest), 1 ether);
        swap.addFiatToken(address(fiat), 1 ether);
        vm.expectRevert("ERR_MIN_PAY_TOKEN");
        swap.invest(invest, msg.sender, fiat, 0.1 ether);
    }

    function test_revert__Withdraw_in_token_not_whitelisted() public {
        vm.expectRevert("ERR_INVALID_OUT_TOKEN");
        swap.withdraw(fiat, msg.sender, invest, 1 ether);
    }

    function test_revert__Withdraw_out_token_not_whitelisted() public {
        swap.addInvestToken(address(invest), 1 ether);
        swap.addFiatToken(address(fiat), 1 ether);
        vm.expectRevert("ERR_MIN_PAY_TOKEN");
        swap.withdraw(fiat, msg.sender, invest, 0.1 ether);
    }

    function test_revert__Invest_amount_must_be_positive() public {
        uint256 amount = 0.5 ether;
        swap.addFiatToken(address(fiat), amount);
        swap.addInvestToken(address(invest), amount);

        fiat.approve(address(swap), amount);
        fiat.mint(amount);
        bytes32 investHash = swap.invest(invest, address(this), fiat, amount);

        uint256 m = swap.getAmountPendingTx();
        assertEq(m, 1, "Amount of pending tx doesn't match");

        invest.approve(address(swap), amount);
        invest.mint(amount);
        bytes32 withdrawHash = swap.withdraw(fiat, address(this), invest, amount);

        m = swap.getAmountPendingTx();
        assertEq(m, 2, "Amount of pending tx doesn't match");

        assertEq(swap.isTxPending(investHash), true, "Invest hash not marked as pending");
        assertEq(swap.isTxPending(withdrawHash), true, "Withdraw hash not marked as pending");

        bytes32[] memory hashes = swap.getPendingTxHashes(5, 0);
        assertEq(hashes.length, 2, "Number of hashes obtained doesn't match amount of requests");
        assertEq(hashes[0], investHash, "Invest hash doesn't match");
        assertEq(hashes[1], withdrawHash, "Withdraw hash doesn't match");

        assertEq(fiat.balanceOf(address(this)), 0, "Fiat tokens not sent to contract");
        assertEq(invest.balanceOf(address(this)), 0, "Invest tokens not sent to contract");

        swap.fulfillTx(investHash, 0, amount, invest, address(this), address(this), fiat, amount);

        m = swap.getAmountPendingTx();
        assertEq(m, 1, "Amount of pending tx doesn't match");
        assertEq(fiat.balanceOf(address(this)), 0, "Fiat tokens should've not been received");
        assertEq(invest.balanceOf(address(this)), amount, "Wrong invest tokens amount");
        assertEq(swap.isTxPending(investHash), false, "Invest hash still marked as pending");
        hashes = swap.getPendingTxHashes(5, 0);
        assertEq(hashes.length, 1, "Number of hashes obtained doesn't match amount of requests");
        assertEq(hashes[0], withdrawHash, "Withdraw hash doesn't match");

        swap.fulfillTx(withdrawHash, 1, amount, fiat, address(this), address(this), invest, amount);

        m = swap.getAmountPendingTx();
        assertEq(m, 0, "Amount of pending tx doesn't match");
        assertEq(fiat.balanceOf(address(this)), amount, "Wrong fiat tokens amount");
        assertEq(invest.balanceOf(address(this)), amount, "Invest tokens should've not been received");
        assertEq(swap.isTxPending(investHash), false, "Invest hash still marked as pending");
        hashes = swap.getPendingTxHashes(5, 0);
        assertEq(hashes.length, 0, "Number of hashes obtained doesn't match amount of requests");
    }
}
