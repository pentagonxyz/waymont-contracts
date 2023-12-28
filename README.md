# Waymont: EVM Smart Contracts (built for Safe)

Waymont's EVM smart contracts are built on top of the existing [Safe contracts](https://github.com/safe-global/safe-contracts). Waymont's smart contracts enable specialized functionality, mainly security features, such as using Waymont's off-chain transaction policy guardians removable after a timelock (achieved using a custom signing contract as one of the signers on the `Safe`) as well as Waymont's social recovery system (achieved using a module attached to the `Safe`). Waymont's contracts also support (via another custom Safe signer contract) signing and sending transactions with non-incremental nonces (i.e., transactions that can be sent in any order after signing) with deadlines as well the ability to sign multiple non-incremental transactions at once (including signing transactions on multiple chains at once).

## Structure

The following contracts should be used with Safe contracts [v1.4.1](https://github.com/safe-global/safe-contracts/tree/v1.4.1). (Despite the fact that this repo uses Safe contracts `v1.4.0` as a dependency, Waymont's contracts should be used with `v1.4.1` Safes because `v1.4.0` includes a bug fix in the `Safe` contract.)

- **`WaymontSafePolicyGuardianSigner`**: Smart contract signer (via ERC-1271) for Safes wrapping an EOA and supporting changing the EOA or bypassing this signer (for all Safes) from a global manager address as well as bypassing this signer after a timelock on a specific Safe.
- **`WaymontSafeFactory`**: Creates EIP-1167 minimal proxy contract clones of `WaymontSafeAdvancedSigner` and `WaymontSafeTimelockedRecoveryModule`.
- **`WaymontSafeAdvancedSigner`**: Smart contract signer (via ERC-1271) to support a subgroup of signers (with their own threshold) attached as a signer on a Safe.
- **`WaymontSafeTimelockedRecoveryModule`**: Safe module supporting timelocked recovery by an alternate group of signers.
- **`WaymontSafeExternalSignerFactory`**: Creates EIP-1167 minimal proxy contract clones of `WaymontSafeExternalSigner`.
- **`WaymontSafeExternalSigner`**`: Smart contract signer (via ERC-1271) for Safes allowing execution of transactions signed together through merkle trees and/or without incremental nonces.

## Installation

Simply [install Foundry](https://book.getfoundry.sh/getting-started/installation) to get started.

## Compiling

`npm run build` or `forge build`

## Testing

`npm t` or `forge test`

## Coverage

`npm run coverage` or `forge coverage --ir-minimum`

*Note that there seems to be a bug in `forge coverage --ir-minimum` resulting in false readings--specifically, the test coverage should show 100%, but the coverage for `WaymontSafePolicyGuardianSigner.sol` is slightly understated. [This issue has been reported on Foundry's GitHub here.](https://github.com/foundry-rs/foundry/issues/6156)*

## History

An overview of Waymont's smart contracts' history is as follows:

1. Waymont made the choice to use smart contracts over MPC for its wallet software around early December 2022.
2. Waymont's contracts originally started as fully custom-made. Development continued until April 2023.
3. Eventually, in early May 2023, Waymont redesigned its contracts to use Safe as a base.
4. Then, in late May 2023, redesigned the contracts again to be more modular (still using Safe as a base).
5. In September and October 2023, Waymont created the `WaymontSafeExternalSigner` and its factory to support non-incremental transactions and multi-TX signing.

### Early May 2023 Redesign

In early May 2023, Waymont redesigned its smart contracts to be based on top of the existing [Safe contracts](https://github.com/safe-global/safe-contracts). Previously, Waymont's contracts included entirely custom-made smart contract wallet code. However, Waymont switched to using Safe as a base in an effort to increase security, simplicity, interoperability, composability, and functionality.

### V1.0.0: Late May 2023 Redesign

In late May 2023, Waymont redesigned its smart contracts again (still on top of Safe) to be more modular in an effort to maximize security and simplicity.

#### Goals

Goals achieved by the new structure:

1. Separate the code for the different features to isolate them from one another so that:
    - Users are only exposed to the smart contract risk of the features they are actually using.
    - Code is more clear and easier to safely audit since it is more organized.
2. Keep the user's signing devices as actual signers on the Safe itself wherever/whenever possible in an effort to:
    - Decrease smart contract attack surface significantly.
    - Ensure the structure is more clear and easier to understand for users.

#### Overview

As of 5/21/2023, the contracts have been updated to work as follows:

1. In the default user wallet deployment scenario: instead of being a 1-of-1 `Safe` with an underlying custom signer managing all signers, wallets will be 2-of-2 between `Safe`s with the user's actual primary Waymont mobile app signing device key and a custom signer contract (`WaymontSafePolicyGuardianSigner`) overlaying/representing the policy guardian (so the policy guardian key can be switched out by the policy guardian manager and so the policy guardian can be disabled after a timelock).
    - WARNING: Do not use this configuration with an x-of-n wallet where x is less than n--users should use the `WaymontSafeAdvancedSigner` for this as described below.
    - NOTE: As of 11/20/2023, Waymont's production API currently does NOT use this pattern: instead, Waymont's production API ALWAYS uses the `WaymontSafeAdvancedSigner`, even if the user has only one signing device on their Safe.
    - *Down the line with this contract setup, the Waymont app could eventually allow users to require multiple of their Waymont mobile app signing devices by making the `Safe` a 3-of-3, 4-of-4, etc. (But for now, this will not be a supported feature in the app.)*
        - *Even further down the line, Waymont could even allow these signers to be removed after a timelock with something like `WaymontSafeOverridableSigner`. (This will of course not be built or audited now.)*

2. If the user desires an x-of-n wallet where x is less than n (and wants to use the off-chain transaction policy guardian, which currently all users do since SSO is a part of that)--they will need to use the `WaymontSafeAdvancedSigner` to represent their signing devices.
    - The `WaymontSafeAdvancedSigner` is a single custom signer contract that will validate the specified threshold of underlying user signing devices; this contract, along with the `WaymontSafePolicyGuardianSigner`, will be the only signers on a 2-of-2 `Safe`.
    - This contract will be an extension of both the `OwnerManager` contract (with an override for the `authorized` modifier) and `Safe.checkSignatures`.
    - The most likely use cases here are adding additional or backup personal signing devices as well as, down the line, multiplayer support (for wallets where not all users are needed to sign transactions).
    - A custom signer contract was chosen here as it seems there are only gas advantages (and no disadvantages).
    - *Down the line, if users really want, Waymont could support configurable weighted vote counts per signer down the line via a contract called something like `WaymontSafeWeightedSigner`. (For now, Waymont will not be building or auditing this it seems very unlikely to be a necessity at this time.)*

3. Timelocked social recovery guardians will not be signers on the `Safe`: instead, they will be a module called `WaymontSafeTimelockedRecoveryModule`, which allows setting up recovery signers with timelocked signing and validating their signatures after the timelock (queued before the timelock with `queueSignature`) and the policy guardian signature (instead of the actual signers on the `Safe` itself).
    - This contract will be an extension of both the `OwnerManager` contract (with an override for the `authorized` modifier) and `Safe.checkSignatures`.
    - *Down the line, Waymont could support using `Safe`s and other smart contract wallets as recovery signers by creating a modified version of the `WaymontSafeTimelockedRecoveryModule` that uses a modified `IsolatedOwnerManager`. For now, due to privacy concerns with using recovery signers within Waymont, Waymont will not building or auditing this.*
    - *Down the line, Waymont could support unequal recovery signer voting power (i.e., signers could have multiple votes) and/or unequal recovery signing timelocks (i.e., some signers could queue their signature more quickly than others) by creating a modified version of the `WaymontSafeTimelockedRecoveryModule` that uses a modified `IsolatedOwnerManager`. For now, due to lack of necessity, Waymont will not building or auditing this.*

4. The nonceless/scheduled transaction plugin will now be a part of Sling as the other plugins are likely more useful. (Waymont won't be building or auditing this initially.)

### V2.0.0: September/October 2023 Additions

In September and October 2023, Waymont added the `WaymontSafeExternalSigner` and its factory to support non-incremental transactions and multi-TX signing. This contract supports signing and sending transactions with non-incremental nonces (i.e., transactions that can be sent in any order after signing) with deadlines as well the ability to sign multiple non-incremental transactions at once (including signing transactions on multiple chains at once).
