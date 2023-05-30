# Waymont: May 2023 Smart Contract Redesign

Waymont has chosen to redesign its smart contracts to be built on top of the existing [Safe contracts](https://github.com/safe-global/safe-contracts). Waymont's smart contracts will enable specialized functionality, mainly security features, such as using Waymont's off-chain transaction policy guardians removable after a timelock (achieved using a custom signing contract as one of the signers on the `Safe`) as well as Waymont's social recovery system (achieved using a module attached to the `Safe`).

## Goals

Goals achieved by the new structure:

1. Separate the code for the different features to isolate them from one another so that:
    - Users are only exposed to the smart contract risk of the features they are actually using.
    - Code is more clear and easier to safely audit since it is more organized.
2. Keep the user's signing devices as actual signers on the Safe itself wherever/whenever possible in an effort to:
    - Decrease smart contract attack surface significantly.
    - Ensure the structure is more clear and easier to understand for users.

## Overview

As of 5/21/2023, the contracts have been updated to work as follows:

1. In the default user wallet deployment scenario: instead of being a 1-of-1 `Safe` with an underlying custom signer managing all signers, wallets will be 2-of-2 between `Safe`s with the user's actual primary Waymont mobile app signing device key and a custom signer contract (`WaymontPolicyGuardianSafeSigner`) overlaying/representing the policy guardian (so the policy guardian key can be switched out by the policy guardian manager and so the policy guardian can be disabled after a timelock).
    - WARNING: Do not use this configuration with an x-of-n wallet where x is less than n--users should use the `WaymontAdvancedSafeSigner` for this as described below.
    - *Down the line with this contract setup, the Waymont app could eventually allow users to require multiple of their Waymont mobile app signing devices by making the `Safe` a 3-of-3, 4-of-4, etc. (But for now, this will not be a supported feature in the app.)*
        - *Even further down the line, Waymont could even allow these signers to be removed after a timelock with something like `WaymontOverridableSafeSigner`. (This will of course not be built or audited now.)*

2. If the user desires an x-of-n wallet where x is less than n (and wants to use the off-chain transaction policy guardian, which currently all users do since SSO is a part of that)--they will need to use the `WaymontAdvancedSafeSigner` to represent their signing devices.
    - The `WaymontAdvancedSafeSigner` is a single custom signer contract that will validate the specified threshold of underlying user signing devices; this contract, along with the `WaymontPolicyGuardianSafeSigner`, will be the only signers on a 2-of-2 `Safe`.
    - This contract will be an extension of both the `OwnerManager` contract (with an override for the `authorized` modifier) and `Safe.checkSignatures`.
    - The most likely use cases here are adding additional or backup personal signing devices as well as, down the line, multiplayer support (for wallets where not all users are needed to sign transactions).
    - A custom signer contract was chosen here as it seems there are only gas advantages (and no disadvantages).
    - *Down the line, if users really want, Waymont could support configurable weighted vote counts per signer down the line via a contract called something like `WaymontWeightedSafeSigner`. (For now, Waymont will not be building or auditing this it seems very unlikely to be a necessity at this time.)*

3. Timelocked social recovery guardians will not be signers on the `Safe`: instead, they will be a module called `WaymontTimelockedBackupSignerSafeModule`, which allows setting up recovery signers with timelocked signing and validating their signatures after the timelock (queued before the timelock with `queueSignature`) and the policy guardian signature (instead of the actual signers on the `Safe` itself).
    - This contract will be an extension of both the `OwnerManager` contract (with an override for the `authorized` modifier) and `Safe.checkSignatures`.
    - *Down the line, Waymont could support using `Safe`s and other smart contract wallets as recovery signers by creating a modified version of the `WaymontTimelockedBackupSignerSafeModule` that uses a modified `IsolatedOwnerManager`. For now, due to privacy concerns with using recovery signers within Waymont, Waymont will not building or auditing this.*
    - *Down the line, Waymont could support unequal recovery signer voting power (i.e., signers could have multiple votes) and/or unequal recovery signing timelocks (i.e., some signers could queue their signature more quickly than others) by creating a modified version of the `WaymontTimelockedBackupSignerSafeModule` that uses a modified `IsolatedOwnerManager`. For now, due to lack of necessity, Waymont will not building or auditing this.*

4. The nonceless/scheduled transaction plugin will now be a part of Sling as the other plugins are likely more useful. (Waymont won't be building or auditing this initially.)
