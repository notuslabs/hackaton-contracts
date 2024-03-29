// SPDX-License-Identifier: CC0
pragma solidity ^0.8.18;

import { ERC20 } from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

contract TestERC20 is ERC20 {
    // forgefmt: disable-next-line
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}

    function mint(uint256 value) external {
        _mint(msg.sender, value);
    }
}
