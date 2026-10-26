// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Build settings (Remix: Compiler -> Advanced Configurations; Foundry: foundry.toml):
//   optimizer = true, runs = 200, via-IR = true, solc >= 0.8.20

import {ERC20} from "@openzeppelin/contracts@5.1.0/token/ERC20/ERC20.sol";
import {ERC4626} from "@openzeppelin/contracts@5.1.0/token/ERC20/extensions/ERC4626.sol";
import {IERC20} from "@openzeppelin/contracts@5.1.0/token/ERC20/IERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts@5.1.0/utils/ReentrancyGuard.sol";

error ZeroAddress();
error ZeroAssets();
error ZeroShares();
error InvalidAsset();
error UnsupportedAsset();
error SlippageExceeded(uint256 actual, uint256 limit);

/// @dev Canonical ERC-1820 registry (same address on every chain it is deployed to).
///      Built from a hex string literal so no address-checksum literal is needed.
address constant ERC1820_REGISTRY = address(bytes20(hex"1820a4b7618bde71dce8cdc73aab6c95905fad24"));
bytes32 constant ERC777_TOKEN_HASH = keccak256("ERC777Token");

/// @dev Runs BEFORE the ERC4626 base constructor (it is evaluated inside the base-constructor
///      argument). OZ's base constructor does NOT revert for address(0) or an EOA: its
///      decimals() probe just falls back to 18. So the validation must live here.
///      Rejects: zero address, EOAs / no-code addresses, contracts without totalSupply(),
///      and (best effort) ERC-777 tokens that registered themselves in ERC-1820.
///      CANNOT be detected on-chain at construction: fee-on-transfer, rebasing, or
///      blacklistable tokens. Vet the asset off-chain before deploying.
function _checkedAsset(IERC20 asset_) view returns (IERC20) {
    address a = address(asset_);
    if (a == address(0)) revert ZeroAddress();
    if (a.code.length == 0) revert InvalidAsset();

    try asset_.totalSupply() returns (uint256) {} catch {
        revert InvalidAsset();
    }

    // ERC-777 MUST register in ERC-1820. If the registry exists on this chain, ask it.
    if (ERC1820_REGISTRY.code.length != 0) {
        (bool ok, bytes memory ret) = ERC1820_REGISTRY.staticcall(
            abi.encodeWithSignature("getInterfaceImplementer(address,bytes32)", a, ERC777_TOKEN_HASH)
        );
        if (ok && ret.length == 32 && abi.decode(ret, (address)) != address(0)) {
            revert UnsupportedAsset();
        }
    }
    return asset_;
}

/// @title SecureVault
/// @notice Immutable ERC-4626 vault with virtual shares/assets (decimals offset = 6).
///
/// @dev CONVERSION MATH (OZ v5.1.0, rounding always favors the vault):
///        shares = floor(assets * (totalSupply + 10**6) / (totalAssets + 1))
///        assets = floor(shares * (totalAssets + 1)   / (totalSupply + 10**6))
///      The virtual reserves make first-depositor inflation uneconomic: to round a victim's
///      deposit V to zero shares the attacker must donate roughly 10**6 * V, and the virtual
///      shares keep a slice of that donation.
///
/// @dev SHARE DECIMALS (offset = 6):  decimals() == assetDecimals + 6
///        - 6-decimal asset (e.g. USDC-like)  -> 12-decimal shares
///        - 8-decimal asset  (e.g. WBTC-like) -> 14-decimal shares
///        - 18-decimal asset (e.g. WETH/DAI)  -> 24-decimal shares
///      1 wei of asset mints 10**6 share-wei at launch, so 1.0 whole asset token == 1.0 whole
///      share token in UI terms (both scale by their own decimals). Integrators MUST read
///      decimals() from the vault and not assume it equals the asset's decimals. Shares
///      never exceed uint256 for any sane supply, since 10**6 is a small multiplier.
///
/// @dev UNSUPPORTED ASSET CLASSES (the vault is immutable, so choose the asset carefully):
///        - Fee-on-transfer tokens: the vault credits `assets` but receives less, so share
///          pricing is inflated and later withdrawers are shorted.
///        - Rebasing / elastic-supply tokens: balanceOf() changes with no deposit or
///          withdrawal, so totalAssets() drifts from share accounting.
///        - ERC-777 / hook tokens (tokensToSend / tokensReceived): enable reentrancy mid-
///          transfer. Detected best-effort at construction, and every entry point is also
///          nonReentrant, but they remain unsupported.
///        - Blacklistable / pausable tokens can freeze withdrawals (e.g. USDC) and are
///          not recommended for an immutable vault.
///      Read-only reentrancy: view functions are not guarded, so external integrators
///      must not read previewX/totalAssets from inside a token callback.
contract SecureVault is ERC4626, ReentrancyGuard {
    constructor(IERC20 asset_, string memory name_, string memory symbol_)
        ERC20(name_, symbol_)
        ERC4626(_checkedAsset(asset_)) // asset is stored as `immutable` inside OZ's ERC4626
    {}

    /// @dev decimals() = assetDecimals + 6 (see contract natspec). Constant, no storage slot.
    function _decimalsOffset() internal pure override returns (uint8) {
        return 6;
    }

    // ───────────────────── Core entry points (all non-reentrant) ─────────────────────

    function deposit(uint256 assets, address receiver) public override nonReentrant returns (uint256) {
        return super.deposit(assets, receiver);
    }

    function mint(uint256 shares, address receiver) public override nonReentrant returns (uint256) {
        return super.mint(shares, receiver);
    }

    function withdraw(uint256 assets, address receiver, address owner)
        public
        override
        nonReentrant
        returns (uint256)
    {
        return super.withdraw(assets, receiver, owner);
    }

    function redeem(uint256 shares, address receiver, address owner)
        public
        override
        nonReentrant
        returns (uint256)
    {
        return super.redeem(shares, receiver, owner);
    }

    // ─────────────── Slippage-protected variants (sandwich / front-run defense) ───────────────

    function depositWithMinShares(uint256 assets, address receiver, uint256 minShares)
        external
        returns (uint256 shares)
    {
        shares = deposit(assets, receiver);
        if (shares < minShares) revert SlippageExceeded(shares, minShares);
    }

    function redeemWithMinAssets(uint256 shares, address receiver, address owner, uint256 minAssets)
        external
        returns (uint256 assets)
    {
        assets = redeem(shares, receiver, owner);
        if (assets < minAssets) revert SlippageExceeded(assets, minAssets);
    }

    // ───────────────────────────── Hardened internal hooks ─────────────────────────────

    /// @dev OZ pulls the asset BEFORE minting on purpose. Minting first would let a hook token
    ///      reenter while shares exist but assets have not arrived (a mispriced state).
    ///      nonReentrant on every entry point covers the remaining surface.
    ///      Emits the ERC-4626 `Deposit` event (inherited).
    function _deposit(address caller, address receiver, uint256 assets, uint256 shares)
        internal
        override
    {
        if (receiver == address(0)) revert ZeroAddress();
        if (assets == 0) revert ZeroAssets();
        if (shares == 0) revert ZeroShares();
        super._deposit(caller, receiver, assets, shares);
    }

    /// @dev OZ burns shares BEFORE transferring assets out (strict CEI on this path).
    ///      Emits the ERC-4626 `Withdraw` event (inherited). The ZeroAssets check means a
    ///      redemption so small that it rounds to 0 assets reverts instead of burning shares.
    function _withdraw(address caller, address receiver, address owner, uint256 assets, uint256 shares)
        internal
        override
    {
        if (receiver == address(0) || owner == address(0)) revert ZeroAddress();
        if (assets == 0) revert ZeroAssets();
        if (shares == 0) revert ZeroShares();
        super._withdraw(caller, receiver, owner, assets, shares);
    }
}