// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts@5.1.0/token/ERC20/ERC20.sol";
import {ERC4626} from "@openzeppelin/contracts@5.1.0/token/ERC20/extensions/ERC4626.sol";
import {IERC20} from "@openzeppelin/contracts@5.1.0/token/ERC20/IERC20.sol";
import {Math} from "@openzeppelin/contracts@5.1.0/utils/math/Math.sol";

/// @title VulnerableVault
/// @notice !!! LAB ONLY. NEVER DEPLOY. Intentionally uses naive share math and has
///         no offset, no zero-share check, no reentrancy guard and no asset validation. !!!
contract VulnerableVault is ERC4626 {
    constructor(IERC20 asset_) ERC20("Vulnerable Vault", "vVULN") ERC4626(asset_) {}

    /// @dev NAIVE: shares = (assets * totalSupply) / totalAssets
    ///
    /// ATTACK WALKTHROUGH (victim deposits V, attacker donates D >= V):
    ///   1. Attacker deposits 1 wei into the empty vault -> `supply == 0` branch -> 1 share.
    ///      State: totalSupply = 1, totalAssets = 1.
    ///   2. Attacker calls asset.transfer(vault, D) DIRECTLY (not via deposit()).
    ///      totalAssets() reads balanceOf(this), so it jumps to 1 + D while totalSupply stays 1.
    ///   3. Victim deposits V <= D:
    ///         shares = floor((V * 1) / (1 + D))
    ///      Since V < 1 + D the quotient is < 1 and integer division TRUNCATES IT TO ZERO.
    ///      <-- the arithmetic vulnerability
    ///   4. No zero-share check exists, so V is pulled in and 0 shares are minted.
    ///   5. Attacker redeems their single share for 1 + D + V (profit = V).
    function _convertToShares(uint256 assets, Math.Rounding rounding)
        internal
        view
        override
        returns (uint256)
    {
        uint256 supply = totalSupply();
        // 1 wei -> 1 share in an empty vault: the attacker's cheap entry point.
        if (supply == 0) return assets;
        // VULNERABLE: floor(assets * supply / totalAssets) can truncate to 0.
        return Math.mulDiv(assets, supply, totalAssets(), rounding);
    }

    function _convertToAssets(uint256 shares, Math.Rounding rounding)
        internal
        view
        override
        returns (uint256)
    {
        uint256 supply = totalSupply();
        if (supply == 0) return shares;
        return Math.mulDiv(shares, totalAssets(), supply, rounding);
    }
}