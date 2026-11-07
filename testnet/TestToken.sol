// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts@5.1.0/token/ERC20/ERC20.sol";

/// @notice Throwaway open-mint ERC-20 used only for the Sepolia rehearsal. Never use as a real asset.
contract TestToken is ERC20 {
    constructor() ERC20("Test", "TST") {}

    function mint(address to, uint256 amt) external {
        _mint(to, amt);
    }
}