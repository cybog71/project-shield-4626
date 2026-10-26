// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC20} from "@openzeppelin/contracts@5.1.0/token/ERC20/ERC20.sol";
import {SecureVault} from "../src/SecureVault.sol";

/// @dev Open-mint token with configurable decimals (6 = USDC-like, 18 = WETH-like).
contract MockToken is ERC20 {
    uint8 private immutable _dec;

    constructor(uint8 dec_) ERC20("Mock", "MCK") {
        _dec = dec_;
    }

    function decimals() public view override returns (uint8) {
        return _dec;
    }

    function mint(address to, uint256 amt) external {
        _mint(to, amt);
    }
}

/// @notice Drives randomized multi-step sequences against SecureVault and keeps "ghost"
///         accounting. Actor 0 is the ATTACKER (deposits, donates, redeems); actors 1..3 are
///         HONEST users (deposit, redeem). All vault assets enter/leave through this handler,
///         so the ghost totals must always reconcile with the vault's token balance.
contract VaultHandler is Test {
    uint256 internal constant OFFSET = 1e6; // 10 ** _decimalsOffset()
    uint256 internal constant MAX_AMOUNT = 1e24;
    uint256 internal constant START_BALANCE = 1e36;

    SecureVault public immutable vault;
    MockToken public immutable token;
    address public attacker;
    address[] internal _honest;

    // ghost accounting (assets, in wei)
    mapping(address => uint256) public ghostIn; // deposits + donations
    mapping(address => uint256) public ghostOut; // redemption proceeds
    uint256 public ghostTotalIn;
    uint256 public ghostTotalOut;
    uint256 public ghostDonated;

    // violation flags (invariants assert these stay false)
    bool public priceDecreased;
    bool public zeroShareMint;
    bool public depositLossBoundBroken;

    // coverage counters
    uint256 public okDeposits;
    uint256 public okRedeems;
    uint256 public okDonations;
    uint256 public attackSetups;
    uint256 public rejectedDeposits;
    uint256 public rejectedRedeems;

    constructor(SecureVault vault_, MockToken token_) {
        vault = vault_;
        token = token_;

        attacker = makeAddr("attacker");
        _fund(attacker);
        for (uint256 i; i < 3; ++i) {
            address h = makeAddr(string.concat("honest", vm.toString(i)));
            _honest.push(h);
            _fund(h);
        }
    }

    function _fund(address a) internal {
        token.mint(a, START_BALANCE);
        vm.prank(a);
        token.approve(address(vault), type(uint256).max);
    }

    // ────────────────────────────── fuzzed actions ──────────────────────────────

    function deposit(uint256 actorSeed, uint256 amount) external {
        address a = _actor(actorSeed);
        amount = bound(amount, 1, MAX_AMOUNT);
        (uint256 A0, uint256 S0) = _state();

        vm.prank(a);
        try vault.deposit(amount, a) returns (uint256 shares) {
            if (shares == 0) zeroShareMint = true;
            _recordIn(a, amount);
            _checkPrice(A0, S0);

            // Rounding loss on a deposit is at most ONE share-unit of value (+ floor wei),
            // no matter how much was donated: loss <= floor(price) + 2.
            uint256 value = vault.previewRedeem(shares);
            uint256 loss = value >= amount ? 0 : amount - value;
            if (loss > (A0 + 1) / (S0 + OFFSET) + 2) depositLossBoundBroken = true;
            ++okDeposits;
        } catch {
            ++rejectedDeposits; // e.g. ZeroShares: the vault REFUSES rather than minting 0
        }
    }

    /// @dev Only the attacker donates: a direct token transfer that bypasses deposit().
    function donate(uint256 amount) external {
        _donate(amount);
    }

    function redeem(uint256 actorSeed, uint256 bps) external {
        address a = _actor(actorSeed);
        bps = bound(bps, 1, 10_000);
        uint256 shares = (vault.balanceOf(a) * bps) / 10_000;
        if (shares == 0) return;
        (uint256 A0, uint256 S0) = _state();

        vm.prank(a);
        try vault.redeem(shares, a, a) returns (uint256 assetsOut) {
            ghostOut[a] += assetsOut;
            ghostTotalOut += assetsOut;
            _checkPrice(A0, S0);
            ++okRedeems;
        } catch {
            ++rejectedRedeems; // ZeroAssets on dust
        }
    }

    /// @dev Biases sequences toward the real exploit: on an EMPTY vault the attacker
    ///      deposits 1 wei, then donates directly.
    function frontRun(uint256 donation) external {
        if (vault.totalSupply() != 0) return;
        (uint256 A0, uint256 S0) = _state();

        vm.prank(attacker);
        try vault.deposit(1, attacker) returns (uint256 shares) {
            if (shares == 0) zeroShareMint = true;
            _recordIn(attacker, 1);
            _checkPrice(A0, S0);
            ++attackSetups;
            _donate(donation);
        } catch {
            ++rejectedDeposits;
        }
    }

    // ───────────────────────────── views for invariants ─────────────────────────────

    /// @dev Net result for `a`: realized proceeds + current redeemable value - everything put in.
    function netOf(address a) public view returns (int256) {
        uint256 value = ghostOut[a] + vault.previewRedeem(vault.balanceOf(a));
        return int256(value) - int256(ghostIn[a]);
    }

    function attackerNet() external view returns (int256) {
        return netOf(attacker);
    }

    function honestNet() external view returns (int256 sum) {
        for (uint256 i; i < _honest.length; ++i) {
            sum += netOf(_honest[i]);
        }
    }

    function sumActorShares() external view returns (uint256 sum) {
        sum = vault.balanceOf(attacker);
        for (uint256 i; i < _honest.length; ++i) {
            sum += vault.balanceOf(_honest[i]);
        }
    }

    // ──────────────────────────────── internals ────────────────────────────────

    function _donate(uint256 amount) internal {
        amount = bound(amount, 1, MAX_AMOUNT);
        (uint256 A0, uint256 S0) = _state();
        vm.prank(attacker);
        token.transfer(address(vault), amount);
        _recordIn(attacker, amount);
        ghostDonated += amount;
        _checkPrice(A0, S0);
        ++okDonations;
    }

    function _actor(uint256 seed) internal view returns (address) {
        uint256 i = seed % (_honest.length + 1);
        return i == 0 ? attacker : _honest[i - 1];
    }

    function _state() internal view returns (uint256, uint256) {
        return (vault.totalAssets(), vault.totalSupply());
    }

    function _recordIn(address a, uint256 amt) internal {
        ghostIn[a] += amt;
        ghostTotalIn += amt;
    }

    /// @dev Share price p = (A+1)/(S+OFFSET). Compared by cross-multiplication (no truncation):
    ///      price_after >= price_before  <=>  (A1+1)(S0+OFF) >= (A0+1)(S1+OFF).
    ///      Magnitudes stay below ~1e62, so no uint256 overflow.
    function _checkPrice(uint256 A0, uint256 S0) internal {
        (uint256 A1, uint256 S1) = _state();
        if ((A1 + 1) * (S0 + OFFSET) < (A0 + 1) * (S1 + OFFSET)) priceDecreased = true;
    }
}