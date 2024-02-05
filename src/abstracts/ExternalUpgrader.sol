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

import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import { OwnableUpgradeable } from "openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";

abstract contract ExternalUpgrader is UUPSUpgradeable, OwnableUpgradeable {
    /**
     * This account is allowed to upgrade the contract once
     */
    address public allowedExternalUpgrader;

    /**
     * The owner and someone else who the owner approved can upgrade the contract
     *
     * If the owner allowed someone than this person can only upgrade once
     */
    function _authorizeUpgrade(address) internal override {
        if (msg.sender != allowedExternalUpgrader && msg.sender != owner()) {
            revert OwnableUpgradeable.OwnableUnauthorizedAccount(msg.sender);
        }

        allowedExternalUpgrader = address(0);
    }

    /**
     * Allow another person to upgrade the contract once
     */
    function allowExternalUpgrader(address upgrader) external onlyOwner {
        // slither-disable-next-line missing-zero-check : owner disallows by sending zero
        allowedExternalUpgrader = upgrader;
    }
}
