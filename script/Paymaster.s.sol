// SPDX-License-Identifier: CC0
pragma solidity ^0.8.18;

import { Script } from "forge-std/Script.sol";
import { ERC1967Proxy } from
    "openzeppelin-contracts-upgradeable/lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { ChainlessPaymaster } from "src/Paymaster.sol";
import { IEntryPoint } from "src/interfaces/IEntryPoint.sol";

contract ChainlessPaymasterScript is Script {
    function run() public {
        IEntryPoint entryPoint = IEntryPoint(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789);
        bytes memory data = abi.encodeWithSelector(ChainlessPaymaster.initialize.selector, entryPoint);
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        ChainlessPaymaster cpm = new ChainlessPaymaster();
        address implementation = address(cpm);

        ERC1967Proxy uups = new ERC1967Proxy(implementation, data);
        address proxyAddress = address(uups);
        vm.label(proxyAddress, "UUPS Proxy");

        vm.stopBroadcast();
    }
}
