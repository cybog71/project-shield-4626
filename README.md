# project-shield-S-4626

An immutable, security-hardened ERC-4626 tokenized vault, built as a lab to demonstrate and defeat the **first-depositor inflation attack**.

The repository contains two vaults: `VulnerableVault`, which reproduces the attack, and `SecureVault`, which defends against it using OpenZeppelin's virtual shares mechanism. Both are covered by a Foundry test suite with unit tests, fuzz tests and stateful invariant tests.

**Status:** lab project, deployed to the Sepolia testnet. Not audited. Do not deposit real funds.

---

## Overview

An ERC-4626 vault accepts deposits of a single ERC-20 asset and issues shares that represent a proportional claim on everything the vault holds. The price of one share is:

```
share price = totalAssets / totalSupply
```

`SecureVault` has no admin, no proxy and no upgrade path. Its behavior is fixed at deployment. It also has no yield strategy, so the share price only moves through direct donations and rounding. It is a safe vault foundation and a teaching tool, not an investment product.

---

## The vulnerability

In a naive vault, shares are minted with:

```
shares = assets * totalSupply / totalAssets
```

Solidity integer division rounds down. Whoever deposits first can use that to manipulate the share price:

| Step | Action | Result |
|------|--------|--------|
| 1 | Attacker deposits 1 wei | 1 share exists |
| 2 | Attacker transfers 10 tokens directly to the vault (not through `deposit`) | Each share is now worth about 10 tokens |
| 3 | Victim deposits 10 tokens | `10 * 1 / (10 + 1 wei)` rounds down to **0 shares** |
| 4 | Attacker redeems their single share | Takes the victim's tokens along with their own |

The direct transfer in step 2 bypasses `deposit`, so no shares are minted for it. The vault's asset balance rises while the share supply stays at 1. `VulnerableVault.sol` implements exactly this behavior, and `test_ReplicateInflationAttack_VulnerableVault` proves it.

---

## The defense

`SecureVault` uses OpenZeppelin v5.1.0's virtual offset. The vault behaves as if it permanently held an extra 10^6 shares and 1 extra unit of the asset:

```
shares = assets * (totalSupply + 10^6) / (totalAssets + 1)
assets = shares * (totalAssets + 1)   / (totalSupply + 10^6)
```

This changes the economics of the attack:

- The attacker's first 1-wei deposit now mints about 10^6 shares instead of 1.
- To round a victim's deposit down to zero shares, the attacker must donate roughly 10^6 times the victim's deposit.
- The virtual shares absorb a portion of any donation, so the attacker ends up losing money.

Results from the test scenario (10-token donation, 10-token victim deposit):

| | VulnerableVault | SecureVault |
|---|---|---|
| Victim shares received | 0 | 1,999,999 |
| Victim loss | 100% | about 0.000025% |
| Attacker outcome | +10 tokens profit | about 5 tokens loss |

---

## SecureVault design

| Feature | Implementation |
|---|---|
| Virtual offset | `_decimalsOffset()` returns 6 |
| Asset validation | `_checkedAsset` runs before the constructor and rejects the zero address, externally owned accounts, contracts without `totalSupply()`, and ERC-777 tokens registered in ERC-1820 |
| Reentrancy protection | `nonReentrant` on `deposit`, `mint`, `withdraw` and `redeem` |
| Call ordering | `deposit` pulls assets before minting shares. `withdraw` burns shares before sending assets |
| Custom errors | `ZeroAddress`, `ZeroAssets`, `ZeroShares`, `InvalidAsset`, `UnsupportedAsset`, `SlippageExceeded` |
| Zero guards | Zero-share deposits and zero-asset withdrawals revert instead of silently losing funds |
| Slippage protection | `depositWithMinShares` and `redeemWithMinAssets` |
| Immutability | The asset is stored as `immutable`. No admin, proxy or upgrade path |
| Math | OpenZeppelin's `Math.mulDiv`. Rounding always favors the vault |
| Events | Standard ERC-4626 `Deposit` and `Withdraw` events |

### Design decisions

**Deposit pulls before it mints.** Minting first would let a token with transfer callbacks re-enter the vault while shares exist but the assets have not yet arrived, a mispriced state. Pulling first, together with `nonReentrant`, avoids this.

**Withdraw burns before it sends.** This is the standard checks-effects-interactions order for the outgoing path.

**Pre-constructor validation.** OpenZeppelin's `ERC4626` constructor does not revert on the zero address or an address with no code, because its decimals lookup silently falls back to 18. The vault is immutable, so `_checkedAsset` rejects bad assets before anything is deployed.

**Zero checks revert.** A deposit that would mint zero shares reverts, so a victim is refused rather than silently charged. A redemption that rounds down to zero assets reverts too, so shares are never burned for nothing.

### Public interface

| Function | Description |
|---|---|
| `deposit(assets, receiver)` | Deposit assets, receive shares |
| `mint(shares, receiver)` | Mint an exact amount of shares |
| `withdraw(assets, receiver, owner)` | Withdraw an exact amount of assets |
| `redeem(shares, receiver, owner)` | Burn shares for assets |
| `depositWithMinShares(assets, receiver, minShares)` | Deposit, reverting if fewer than `minShares` are received |
| `redeemWithMinAssets(shares, receiver, owner, minAssets)` | Redeem, reverting if fewer than `minAssets` are received |
| `preview*`, `convertTo*`, `max*`, `totalAssets`, `asset`, `decimals` | Standard ERC-4626 views |

---

## Share decimals

With an offset of 6, share decimals equal the asset's decimals plus 6. One whole asset token still corresponds to one whole share token in UI terms.

| Asset decimals | Example | Share decimals |
|---|---|---|
| 6 | USDC-like | 12 |
| 8 | WBTC-like | 14 |
| 18 | WETH, DAI | 24 |

Integrators must read `decimals()` from the vault and must not assume it matches the asset.

---

## Supported assets

The asset is fixed at deployment, so the choice is permanent. Use a plain ERC-20. The following token types are **not supported**:

| Token type | Problem |
|---|---|
| Fee-on-transfer | The vault credits more than it receives, so later withdrawers are shorted |
| Rebasing / elastic supply | Balances change without deposits or withdrawals, which drifts `totalAssets()` from share accounting |
| ERC-777 / hook tokens | Callbacks enable reentrancy. Detected on a best-effort basis at construction |
| Blacklistable or pausable | Withdrawals can be frozen by the token issuer (USDC, for example) |

Fee-on-transfer, rebasing and blacklist behavior cannot be detected on-chain, so the token must be vetted before deployment. View functions are not reentrancy-guarded, so integrators must not read vault state from inside a token callback.

---

## Repository layout

```
src/
  VulnerableVault.sol    Naive ERC-4626 vault. Lab only. Never deploy.
  SecureVault.sol        Hardened vault.
test/
  SecureVault.t.sol      Unit, fuzz and invariant tests
  VaultHandler.sol       Invariant handler and mock token
foundry.toml             Compiler and test configuration
```

---

## Testing

| Suite | Tests | Coverage |
|---|---|---|
| Unit and fuzz | 11 | The attack succeeds on `VulnerableVault` and fails on `SecureVault`; a fuzzed version of the attack sequence; decimals; constructor rejections; zero-address receivers; dust redemption; slippage guards; reentrancy through a hostile token |
| Invariants | 6 | A handler drives one attacker and three honest users through deposits, donations, redemptions and front-running, 256 runs of 100 calls each |

Invariants checked after every call sequence:

1. The share price never decreases.
2. The vault never mints zero shares.
3. A depositor's immediate loss is at most one share-unit of value, however much was donated.
4. The vault is solvent, and its asset balance reconciles exactly with all deposits, donations and redemptions.
5. Total shares equal the sum of all holders' balances.
6. The attacker's profit never exceeds the honest users' loss. No value is created.

---

## Getting started

Requires [Foundry](https://book.getfoundry.sh/) and Git.

```bash
git clone https://github.com/cybog71/project-shield-4626.git
cd project-shield-4626
git submodule update --init --recursive
forge build
forge test -vv
```

`foundry.toml` pins the build configuration:

```toml
solc = "0.8.24"
evm_version = "paris"
via_ir = true
optimizer = true
optimizer_runs = 200
remappings = ["@openzeppelin/contracts@5.1.0/=lib/openzeppelin-contracts/contracts/"]
```

---

## Sepolia deployment

| Item | Value |
|---|---|
| Network | Sepolia (chain ID 11155111) |
| TestToken | [`0x7A6baf79D6E5d1E4B9F2Be92637f5968Ae6d9f5E`](https://sepolia.etherscan.io/address/0x7A6baf79D6E5d1E4B9F2Be92637f5968Ae6d9f5E) |
| SecureVault | [`0x126AC4d34ab2fCC7f35c4F5B9Cfa00bbc535CCE6`](https://sepolia.etherscan.io/address/0x126AC4d34ab2fCC7f35c4F5B9Cfa00bbc535CCE6) |
| Constructor arguments | token address, `"Secure Vault"`, `"sVLT"` |
| Decimals (asset / shares) | 18 / 24 |
| Source verification | Sourcify |

Notes:

- The testnet deployment was compiled in Remix, which does not offer the via-IR option. Its bytecode therefore differs from the Foundry-tested build, although the logic is identical. A production deployment should use `forge create` with `foundry.toml`.
- The verified source is `SecureVault.sol` with the long comments removed.
- `TestToken` is a throwaway open-mint ERC-20 used only for this rehearsal.

---

## Mainnet checklist

Before any mainnet deployment:

- [ ] Choose a plain ERC-20 with no fees, rebasing, pausing or blacklisting, and verify its address from the issuer's official source.
- [ ] Deploy with `forge create` using `foundry.toml` and an encrypted keystore rather than a raw private key.
- [ ] Rehearse the exact command on Sepolia first.
- [ ] Verify the source on Etherscan.
- [ ] Make a small first deposit and redeem part of it.
- [ ] Obtain an independent audit before significant funds are involved.

---

## Security considerations

This project is unaudited. The test results here reflect the tests in this repository and no external review.

Known limitations:

- **No yield:** the vault has no strategy, so it does not earn anything on deposits.
- **Stuck dust:** redemptions that round down to zero assets revert, so very small share balances cannot be redeemed.
- **Virtual reserves:** a small, permanent portion of value is attributed to the virtual shares.
- **Immutability:** any bug or poor asset choice is permanent.

To report a problem, open a GitHub issue.

---

## License

Released under the [MIT License](LICENSE).