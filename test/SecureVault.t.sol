// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {ERC20} from "@openzeppelin/contracts@5.1.0/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts@5.1.0/token/ERC20/IERC20.sol";
import {IERC4626} from "@openzeppelin/contracts@5.1.0/interfaces/IERC4626.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts@5.1.0/utils/ReentrancyGuard.sol";

import {VulnerableVault} from "../src/VulnerableVault.sol";
import {
    SecureVault,
    ZeroAddress,
    ZeroAssets,
    ZeroShares,
    InvalidAsset,
    UnsupportedAsset,
    SlippageExceeded,
    ERC1820_REGISTRY
} from "../src/SecureVault.sol";
import {VaultHandler, MockToken} from "./VaultHandler.sol";

/// @dev Pretends every token is registered as an ERC-777 implementer.
contract MockERC1820 {
    function getInterfaceImplementer(address a, bytes32) external pure returns (address) {
        return a;
    }
}

/// @dev Token that tries to re-enter the vault mid-deposit (hook-style callback).
contract ReentrantToken is ERC20 {
    address public target;

    constructor() ERC20("Evil", "EVL") {}

    function setTarget(address t) external {
        target = t;
    }

    function mint(address to, uint256 a) external {
        _mint(to, a);
    }

    function _update(address from, address to, uint256 value) internal override {
        super._update(from, to, value);
        if (target != address(0) && from != address(0) && to == target) {
            SecureVault(target).deposit(1, address(this));
        }
    }
}

// ═══════════════════════════════ Unit + fuzz tests ═══════════════════════════════

contract SecureVaultTest is Test {
    MockToken token;
    VulnerableVault vuln;
    SecureVault secure;

    address attacker = makeAddr("attacker");
    address victim = makeAddr("victim");

    uint256 constant D = 10 ether; // attacker donation
    uint256 constant V = 10 ether; // victim deposit

    function setUp() public {
        token = new MockToken(18);
        vuln = new VulnerableVault(IERC20(address(token)));
        secure = new SecureVault(IERC20(address(token)), "Secure Vault", "sVLT");

        address[2] memory users = [attacker, victim];
        for (uint256 i; i < 2; ++i) {
            token.mint(users[i], 1e30);
            vm.startPrank(users[i]);
            token.approve(address(vuln), type(uint256).max);
            token.approve(address(secure), type(uint256).max);
            vm.stopPrank();
        }
    }

    /// @dev The identical exploit sequence, run against any ERC-4626 vault.
    function _attack(IERC4626 vault, uint256 donation, uint256 victimAmt)
        internal
        returns (uint256 victimShares)
    {
        vm.prank(attacker);
        vault.deposit(1, attacker); // 1 wei

        vm.prank(attacker);
        token.transfer(address(vault), donation); // direct donation inflates price per share

        vm.prank(victim);
        victimShares = vault.deposit(victimAmt, victim);
    }

    // 1) Exploit works on the naive vault
    function test_ReplicateInflationAttack_VulnerableVault() public {
        uint256 attackerBefore = token.balanceOf(attacker);

        uint256 victimShares = _attack(IERC4626(address(vuln)), D, V);
        assertEq(victimShares, 0, "victim receives ZERO shares");
        assertEq(vuln.balanceOf(victim), 0);
        assertEq(token.balanceOf(address(vuln)), 1 + D + V, "victim funds absorbed");

        vm.prank(attacker);
        vuln.redeem(1, attacker, attacker);
        assertEq(token.balanceOf(attacker) - attackerBefore, V, "attacker profit == victim deposit");
    }

    // 2) The same sequence fails on the hardened vault
    function test_InflationAttackFails_SecureVault() public {
        uint256 attackerBefore = token.balanceOf(attacker);
        uint256 victimBefore = token.balanceOf(victim);

        uint256 victimShares = _attack(IERC4626(address(secure)), D, V);
        assertGt(victimShares, 0, "victim must receive shares");

        vm.prank(victim);
        secure.redeem(victimShares, victim, victim);
        assertLe(victimBefore - token.balanceOf(victim), V / 1e5, "victim loss must be negligible");

        uint256 attackerShares = secure.balanceOf(attacker);
        vm.prank(attacker);
        secure.redeem(attackerShares, attacker, attacker);
        assertGt(attackerBefore - token.balanceOf(attacker), 4.9 ether, "attacker takes a large loss");
    }

    // 3) Randomized check over the whole attack sequence (stateless fuzz)
    function testFuzz_SharePriceInvariants(uint256 a, uint256 d, uint256 v) public {
        a = bound(a, 1, 1e24);
        d = bound(d, 0, 1e24);
        v = bound(v, 1, 1e24);

        vm.prank(attacker);
        secure.deposit(a, attacker);
        uint256 attShares = secure.balanceOf(attacker);

        vm.prank(attacker);
        token.transfer(address(secure), d);

        uint256 A1 = secure.totalAssets();
        uint256 S1 = secure.totalSupply();

        // If the donation is so large that the deposit would round to 0 shares,
        // the vault must REFUSE it (revert), never silently keep the funds.
        if (secure.previewDeposit(v) == 0) {
            assertGt(d, v, "zero shares only possible when donation exceeds deposit");
            vm.prank(victim);
            vm.expectRevert(ZeroShares.selector);
            secure.deposit(v, victim);
            assertEq(secure.balanceOf(victim), 0);
            return;
        }

        vm.prank(victim);
        uint256 vShares = secure.deposit(v, victim);

        uint256 A2 = secure.totalAssets();
        uint256 S2 = secure.totalSupply();

        // price (A+1)/(S+1e6) never drops on a deposit
        assertGe((A2 + 1) * (S1 + 1e6), (A1 + 1) * (S2 + 1e6), "price dropped");

        // victim's immediate rounding loss is at most one share-unit of value
        uint256 value = secure.previewRedeem(vShares);
        uint256 loss = value >= v ? 0 : v - value;
        assertLe(loss, (A1 + 1) / (S1 + 1e6) + 2, "loss exceeds one share unit");

        // the attacker can never take out more than they put in
        vm.prank(attacker);
        uint256 out = secure.redeem(attShares, attacker, attacker);
        assertLe(out, a + d, "attacker profited");
    }

    // ───────────────────────── decimals, constructor, guards ─────────────────────────

    function test_ShareDecimals_AssetPlusSix() public {
        assertEq(secure.decimals(), 24, "18-dec asset -> 24-dec shares");
        MockToken usdcLike = new MockToken(6);
        SecureVault v6 = new SecureVault(IERC20(address(usdcLike)), "s", "s");
        assertEq(v6.decimals(), 12, "6-dec asset -> 12-dec shares");
    }

    function test_Constructor_RejectsZeroAddressAndEOA() public {
        vm.expectRevert(ZeroAddress.selector);
        new SecureVault(IERC20(address(0)), "x", "x");

        vm.expectRevert(InvalidAsset.selector);
        new SecureVault(IERC20(makeAddr("eoa")), "x", "x");
    }

    function test_Constructor_RejectsNonTokenContract() public {
        vm.expectRevert(InvalidAsset.selector); // this test contract has no totalSupply()
        new SecureVault(IERC20(address(this)), "x", "x");
    }

    function test_Constructor_RejectsERC777Registered() public {
        vm.etch(ERC1820_REGISTRY, address(new MockERC1820()).code);
        vm.expectRevert(UnsupportedAsset.selector);
        new SecureVault(IERC20(address(token)), "x", "x");
    }

    function test_ZeroAddressReceiver_Reverts() public {
        vm.prank(victim);
        vm.expectRevert(ZeroAddress.selector);
        secure.deposit(1 ether, address(0));

        vm.startPrank(victim);
        secure.deposit(1 ether, victim);
        vm.expectRevert(ZeroAddress.selector);
        secure.withdraw(0.5 ether, address(0), victim);
        vm.stopPrank();
    }

    function test_DustRedeem_RevertsZeroAssets() public {
        vm.startPrank(attacker);
        secure.deposit(1, attacker); // mints 1e6 share-wei
        vm.expectRevert(ZeroAssets.selector); // 1 share-wei redeems to 0 assets
        secure.redeem(1, attacker, attacker);
        vm.stopPrank();
    }

    function test_SlippageGuards() public {
        vm.startPrank(victim);
        uint256 expected = secure.previewDeposit(1 ether);
        vm.expectRevert(abi.encodeWithSelector(SlippageExceeded.selector, expected, expected + 1));
        secure.depositWithMinShares(1 ether, victim, expected + 1);

        uint256 shares = secure.depositWithMinShares(1 ether, victim, expected);
        uint256 out = secure.previewRedeem(shares);
        vm.expectRevert(abi.encodeWithSelector(SlippageExceeded.selector, out, out + 1));
        secure.redeemWithMinAssets(shares, victim, victim, out + 1);
        vm.stopPrank();
    }

    function test_Reentrancy_Blocked() public {
        ReentrantToken evil = new ReentrantToken();
        SecureVault v = new SecureVault(IERC20(address(evil)), "e", "e");
        evil.setTarget(address(v));
        evil.mint(victim, 100);

        vm.startPrank(victim);
        evil.approve(address(v), type(uint256).max);
        vm.expectRevert(ReentrancyGuard.ReentrancyGuardReentrantCall.selector);
        v.deposit(10, victim);
        vm.stopPrank();
    }
}

// ═══════════════════════ Stateful invariant tests (handler-driven) ═══════════════════════

contract SecureVaultInvariantTest is Test {
    MockToken token;
    SecureVault vault;
    VaultHandler handler;

    function setUp() public {
        token = new MockToken(18);
        vault = new SecureVault(IERC20(address(token)), "Secure Vault", "sVLT");
        handler = new VaultHandler(vault, token);

        bytes4[] memory sels = new bytes4[](4);
        sels[0] = VaultHandler.deposit.selector;
        sels[1] = VaultHandler.donate.selector;
        sels[2] = VaultHandler.redeem.selector;
        sels[3] = VaultHandler.frontRun.selector;

        // Only the handler may be fuzzed. Calling the vault/token directly would
        // bypass the handler's accounting and cause false failures.
        excludeContract(address(vault));
        excludeContract(address(token));
        targetSelector(FuzzSelector({addr: address(handler), selectors: sels}));
    }

    /// Deposits, donations and redemptions never lower the share price.
    function invariant_PriceNeverDecreases() public view {
        assertFalse(handler.priceDecreased(), "share price dropped");
    }

    /// The vault never mints 0 shares for a nonzero deposit (it reverts instead).
    function invariant_NoZeroShareMint() public view {
        assertFalse(handler.zeroShareMint(), "zero-share mint");
    }

    /// A depositor's immediate loss is bounded by one share-unit of value, independent of
    /// how much an attacker donated.
    function invariant_DepositLossBoundedByOneShareUnit() public view {
        assertFalse(handler.depositLossBoundBroken(), "deposit loss bound broken");
    }

    /// Redeeming every share can never claim more than the vault holds, and the vault's
    /// token balance reconciles exactly with all ghost inflows/outflows.
    function invariant_Solvency() public view {
        assertLe(vault.convertToAssets(vault.totalSupply()), vault.totalAssets(), "insolvent");
        assertEq(
            token.balanceOf(address(vault)),
            handler.ghostTotalIn() - handler.ghostTotalOut(),
            "asset accounting mismatch"
        );
    }

    /// Share supply equals the sum of all actor balances.
    function invariant_ShareAccounting() public view {
        assertEq(handler.sumActorShares(), vault.totalSupply(), "share accounting mismatch");
    }

    /// No value is created: the attacker's net profit can never exceed honest users' net
    /// loss (attackerNet + honestNet <= 0).
    function invariant_AttackerProfitNeverExceedsVictimLoss() public view {
        assertLe(handler.attackerNet() + handler.honestNet(), 0, "value created from nothing");
    }

    /// Logs how many sequences actually exercised each action.
    function afterInvariant() public view {
        console2.log("deposits ok / rejected", handler.okDeposits(), handler.rejectedDeposits());
        console2.log("redeems  ok / rejected", handler.okRedeems(), handler.rejectedRedeems());
        console2.log("donations / front-run setups", handler.okDonations(), handler.attackSetups());
    }
}