// SPDX-License-Identifier: CC0
// solhint-disable func-name-mixedcase
// solhint-disable no-console
pragma solidity ^0.8.18;

import { Test, console2 } from "forge-std/Test.sol";
import { ExternalUpgrader } from "src/abstracts/ExternalUpgrader.sol";
import { TestERC20 } from "test/mocks/TestERC20.sol";

import { ERC1967Proxy } from "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { ERC1967Utils } from "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Utils.sol";
import { OwnableUpgradeable } from "openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";

contract ExternalUpgraderMock is ExternalUpgrader {
    function initialize() public initializer {
        __Ownable_init(msg.sender);
    }

    function getImplementation() public view returns (address) {
        return ERC1967Utils.getImplementation();
    }
}

contract ExternalUpgraderTest is Test {
    ExternalUpgraderMock public eu;

    function setUp() public {
        ExternalUpgraderMock implementation = new ExternalUpgraderMock();
        bytes memory data = abi.encodeWithSelector(ExternalUpgraderMock.initialize.selector);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), data);
        eu = ExternalUpgraderMock(address(proxy));
    }

    function test_accept__Owner_can_upgrade() public {
        address newImplementation = address(new ExternalUpgraderMock());

        vm.expectEmit(true, false, false, false, address(eu));
        emit ERC1967Utils.Upgraded(newImplementation);
        eu.upgradeToAndCall(newImplementation, "");

        assertEq(newImplementation, eu.getImplementation());
    }

    function test_accept__Upgrader_can_upgrade(address upgrader) public {
        assertTrue(upgrader != eu.allowedExternalUpgrader());

        eu.allowExternalUpgrader(upgrader);

        assertEq(upgrader, eu.allowedExternalUpgrader());

        address newImplementation = address(new ExternalUpgraderMock());
        vm.prank(upgrader);
        vm.expectEmit(true, false, false, false, address(eu));
        emit ERC1967Utils.Upgraded(newImplementation);
        eu.upgradeToAndCall(newImplementation, "");

        assertEq(address(0), eu.allowedExternalUpgrader(), "Must reset to zero after upgrade");
    }

    function test_reject__Random_cant_upgrade(address user) public {
        vm.assume(user != address(0) && user != address(this));
        address newImplementation = address(new ExternalUpgraderMock());
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, user));
        eu.upgradeToAndCall(newImplementation, "");
    }
}
