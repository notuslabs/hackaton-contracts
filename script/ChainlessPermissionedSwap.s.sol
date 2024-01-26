// SPDX-License-Identifier: CC0
pragma solidity ^0.8.18;

import { Script } from "forge-std/Script.sol";
import { ERC1967Proxy } from "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { ChainlessPermissionedSwap } from "src/ChainlessPermissionedSwap.sol";

contract ChainlessPermissionedSwapScript is Script {
    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        bytes memory data = abi.encodeWithSelector(ChainlessPermissionedSwap.initialize.selector);

        vm.startBroadcast(deployerPrivateKey);

        ChainlessPermissionedSwap cps = new ChainlessPermissionedSwap();
        address implementation = address(cps);

        ERC1967Proxy uups = new ERC1967Proxy(implementation, data);
        address proxyAddress = address(uups);
        vm.label(proxyAddress, "UUPS Proxy");

        vm.stopBroadcast();
    }
}
