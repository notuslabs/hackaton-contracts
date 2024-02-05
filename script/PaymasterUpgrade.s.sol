// SPDX-License-Identifier: CC0
pragma solidity ^0.8.18;

import { Script } from "forge-std/Script.sol";
import { ChainlessPaymaster } from "src/Paymaster.sol";
import { Upgrades, Options } from "openzeppelin-foundry-upgrades/Upgrades.sol";

contract ChainlessPaymasterUpgradeScript is Script {
    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address uups = 0x0B1d11e34e3e8A6e3958B7657fC335F9505a64A4;
        Options memory opts;
        opts.referenceContract = "Paymaster.old.sol:ChainlessPaymaster";

        vm.startBroadcast(deployerPrivateKey);

        Upgrades.upgradeProxy(uups, "Paymaster.sol:ChainlessPaymaster", "", opts);

        vm.stopBroadcast();
    }
}
