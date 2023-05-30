# Waymont May 2023 Smart Contracts: Integration

The following explains how Waymont's API should use the `WaymontSafePolicyGuardianSigner`, the `WaymontSafeAdvancedSigner`, and the `WaymontSafeTimelockedBackupSignerModule`:

## Preventing transactions from `Safe`s 

**WARNING: Make sure to block transactions sent from `Safe`s to the deployed `WaymontSafePolicyGuardianSigner`, any of the deployed `WaymontSafeAdvancedSigner`s, or any of the deployed `WaymontSafeTimelockedBackupSignerModule`s (validate this in the Waymont API's `createWalletSigningRequest` endpoint before generating the policy guardian signature).**

## Enabling and using the `WaymontSafePolicyGuardianSigner`

The `WaymontSafePolicyGuardianSigner` is only deployed once per `WaymontSafeFactory`, meaning that all Waymont `Safe`s will use it (*unless a new version of the `WaymontSafeFactory` and/or `WaymontSafePolicyGuardianSigner` is built and audited down the line*).

### Enabling the policy guardian signer on a `Safe`

1. Add the `WaymontSafePolicyGuardianSigner` as a signer on a `Safe` that would like to use the policy guardian (for now, all `Safe`s).
    - **WARNING: If the user would like an x-of-n `Safe` where x is less than n (i.e., if the user wants to use one of multiple signing devices to sign transactions), the `WaymontSafeAdvancedSigner` and `WaymontSafePolicyGuardianSigner` must be used as the two signers on a 2-of-2 `Safe` (with the actual signers underlying the `WaymontSafeAdvancedSigner`), [as described below](#deploying-enabling-and-using-a-waymontsafeadvancedsigner).**
    - To add the `WaymontSafePolicyGuardianSigner` to the `Safe` as part of the initial `Safe` deployment, simply include the `WaymontSafePolicyGuardianSigner` address in the `_owners` array parameter when deploying and initializing the `Safe` (and use a maxed-out threshold equal to the number of signers on the `Safe` including the policy guardian).
    - To add the `WaymontSafePolicyGuardianSigner` to the `Safe` down the line, simply call `Safe.addOwnerWithThreshold` (or if using the Protocol Kit, `createAddOwnerTx`) with the `WaymontSafePolicyGuardianSigner` address (and a maxed-out threshold equal to the number of signers on the `Safe` including the policy guardian).
        - **WARNING: Once again, note that if the `Safe` requires less than all signers, the `WaymontSafeAdvancedSigner` and `WaymontSafePolicyGuardianSigner` must be used as the two signers on a 2-of-2 `Safe` (with the actual signers underlying the `WaymontSafeAdvancedSigner`), [as described below](#deploying-enabling-and-using-a-waymontsafeadvancedsigner).**

### Signing transactions with the `WaymontSafePolicyGuardianSigner`

**WARNING: Do not use the policy guardian key for ANYTHING ELSE other than generating signatures for use with the `WaymontSafePolicyGuardianSigner` as described directly below (or to generate policy guardian signatures for the `WaymontSafeTimelockedBackupSignerModule` [as described further below](#recovering-a-safe)). Specifically, do not send any funds to its address. (The reasoning here is simply to isolate the use of the account as much as possible with the goal of reducing collateral attack surface.)**

Normally, when using the Safe TypeScript Protocol Kit to sign the second signature (i.e., the policy guardian's signature) on a proposed transaction [as described here](https://docs.safe.global/learn/safe-core/safe-core-account-abstraction-sdk/protocol-kit#confirm-the-transaction-second-confirmation), the `Safe.signTransactionHash` method is used to instantiate a `new EthSafeSignature` object in order to pass the instantiated object's `data` param as the second argument to `SafeApiKit.confirmTransaction`. In this case, instead of using `Safe.signTransactionHash` to get the signature, one should generate a new wrapped signature to pass as the second argument to `SafeApiKit.confirmTransaction`--this new signature param should be the concatenation of the following three items:

1. A "fake signature" made up of pointers to the "actual underlying signature." In the "fake signature":
    - `r` is the `WaymontGnosisSafeSigner` contract address, `s == 65` (which is the offset of the contract signature length `bytes32` concatenated with the "actual underlying signature"), and `v == 0` (indicating that this is a smart contract signature).
    - *As usual, `r`, `s`, and `v` are concatenated into a bytestring of length 65 where the first 32 bytes are `r`, the next 32 bytes are `s`, and the last byte is `v`.*
2. The length of the "actual underlying signature" as a `bytes32`.
3. The "actual underlying signature" from the policy guardian key--this can be calculated as: `(new ethers.utils.SigningKey(hexEncodedPolicyGuardianPrivateKey)).signDigest(safeTxHash).serialized` where `safeTxHash` is calculated as `await safeSdk.getTransactionHash(safeTransaction)` (where `safeTransaction` is created by the Safe Protocol Kit's `Safe.createTransaction` method).

### Tracking policy guardian removal requests

**WARNING: The following is important to implement for security!**

Waymont should track all `WaymontSafePolicyGuardianSigner.DisablePolicyGuardianQueued` events and immediately notify users if the disabling of the policy guardian on their `Safe` has been queued.

### Tracking policy guardian removal and timelock changes

**The following security feature is not NEARLY as important as tracking the queueing of disabling the policy guardian on `Safe`s [as described above](#tracking-policy-guardian-removal-requests).**

The policy guardian cannot be disabled via the `WaymontSafePolicyGuardianSigner` without either the policy guardian's approval or the user queueing it and waiting for the timelock to pass. The policy guardian timelock also cannot be changed without the without the policy guardian's approval. Nevertheless, given the risk of the policy guardian key being compromised, Waymont should still track `WaymontSafePolicyGuardianSigner.PolicyGuardianDisabledOnSafe` and `WaymontSafePolicyGuardianSigner.PolicyGuardianTimelockChanged` events and emit notifications to users (unless a notification was already emitted because Waymont approved the action).

### Extra stuff (not to be implemented now)

*Down the line, to enable users to set a custom policy guardian timelock, use `WaymontSafePolicyGuardianSigner.setPolicyGuardianTimelock` (can batch this using Safe's `MultiSendCallOnly` contract [as described below](#using-safes-multisendcallonly-contract)).*

## Deploying, enabling and using a `WaymontSafeAdvancedSigner`

- A new `WaymontSafeAdvancedSigner` is deployed any time a `Safe` decides it would like to use a `WaymontSafeAdvancedSigner`.
- If the user removes the `WaymontSafeAdvancedSigner` from their `Safe` and decides to add it back, a `WaymontSafeAdvancedSigner` should be deployed to avoid having to clean up the signers on the old `WaymontSafeAdvancedSigner`.

### Deploying and enabling

If the user would like an x-of-n `Safe` where x is less than n (i.e., if the user wants to use one of multiple signing devices to sign transactions), the user's signing devices should not be added as signers on the actual `Safe` itself, but should be added as underlying signers on a new `WaymontSafeAdvancedSigner` contract. Then, add the `WaymontSafeAdvancedSigner` and `WaymontSafePolicyGuardianSigner` as the only two signers on the `Safe` (will be a 2-of-2 `Safe` at the `Safe` level) .
    - Deployment of the signer and the addition of the signer to the `Safe` should be done in reverse order (using the `MultiSendCallOnly` contract [as described below](#using-safes-multisendcallonly-contract)):
        1. To add the signer to the `Safe`, simply call `Safe.addOwnerWithThreshold(address(waymontSafeAdvancedSigner), 1)`.
            - The address of the module can be computed as the last 20 bytes of `0xff${waymontSafeFactoryAddress}${salt}${minimalProxyCreationCodeHash}` where `salt` is `keccak256(abi.encode(safe, signers, threshold, signingTimelock, requirePolicyGuardian, deploymentNonce))` and `minimalProxyCreationCodeHash` is `keccak256(0x3d602d80600a3d3981f3363d3d373d3d3d363d73${advancedSignerImplementation}5af43d82803e903d91602b57fd5bf3)`.
                - The `advancedSignerImplementation` is immutable for a given `WaymontSafeFactory` and can be found by calling `WaymontSafeFactory.advancedSignerImplementation()`.
        2. To deploy the signer, call `WaymontSafeFactory.createAdvancedSigner(Safe safe, address[] signers, uint256 threshold, uint256 deploymentNonce)`.
            - `signers` will be the underlying mobile signer keys, as has been done in the past, but without the social recovery guardian keys.

### Signing transactions with the `WaymontSafeAdvancedSigner`

Normally, when using the Safe TypeScript Protocol Kit to sign the first signature (i.e., the user's signing device's signature) on a proposed transaction [as described here](https://docs.safe.global/learn/safe-core/safe-core-account-abstraction-sdk/protocol-kit#confirm-the-transaction-second-confirmation), the `Safe.signTransactionHash` method is used to instantiate a `new EthSafeSignature` object in order to pass the instantiated object's `data` param as the second argument to `SafeApiKit.confirmTransaction`. In this case, instead of passing in the `EthSafeSignature.data` param directly into `SafeApiKit.confirmTransaction`, it should be wrapped into a new signature param--this new signature param should be the concatenation of:

1. A "fake signature" made up of pointers to the "actual underlying signature." In the "fake signature":
    - `r` is the `WaymontGnosisSafeSigner` contract address, `s == 65` (which is the offset of the contract signature length `bytes32` concatenated with the "actual underlying signature"), and `v == 0` (indicating that this is a smart contract signature).
    - *As usual, `r`, `s`, and `v` are concatenated into a bytestring of length 65 where the first 32 bytes are `r`, the next 32 bytes are `s`, and the last byte is `v`.*
2. The length of the "actual underlying signature" as a `bytes32`.
3. The "actual underlying signature" from the user's signing device generated with `Safe.signTransactionHash`.

## Deploying, enabling, and using a `WaymontSafeTimelockedBackupSignerModule`

- A new `WaymontSafeTimelockedBackupSignerModule` is deployed any time a `Safe` decides it would like to use a `WaymontSafeTimelockedBackupSignerModule`.
- If the user removes the `WaymontSafeTimelockedBackupSignerModule` from their `Safe` and decides to add it back, a `WaymontSafeTimelockedBackupSignerModule` should be deployed to avoid having to clean up the signers on the old module.

### Deploying and enabling

Add the `WaymontSafeTimelockedBackupSignerModule` to the `Safe` to enable timelocked social recovery guardians.

- Timelocked social recovery guardians will not be signers on the `Safe`: instead, they will be a module called `WaymontTimelockedBackupSignerSafeModule`, which allows setting up recovery signers with timelocked signing and validating their signatures after the timelock (queued before the timelock with `queueSignature`) and the policy guardian signature (instead of the actual signers on the `Safe` itself).
- Deployment of the module and the enabling of the module should be done in reverse order (using the `MultiSendCallOnly` contract [as described below](#using-safes-multisendcallonly-contract)):
    1. To enable the module, simply call `Safe.enableModule(address(waymontTimelockedBackupSignerSafeModule))`.
        - The address of the module can be computed as the last 20 bytes of `0xff${waymontSafeFactoryAddress}${salt}${minimalProxyCreationCodeHash}` where `salt` is `keccak256(abi.encode(safe, signers, threshold, signingTimelock, requirePolicyGuardian, deploymentNonce))` and `minimalProxyCreationCodeHash` is `keccak256(0x3d602d80600a3d3981f3363d3d373d3d3d363d73${timelockedBackupSignerModuleImplementation}5af43d82803e903d91602b57fd5bf3)`.
            - The `timelockedBackupSignerModuleImplementation` is immutable for a given `WaymontSafeFactory` and can be found by calling `WaymontSafeFactory.timelockedBackupSignerModuleImplementation()`.
    2. To deploy the module, call `WaymontSafeFactory.createTimelockedBackupSignerModule(Safe safe, address[] signers, uint256 threshold, uint256 signingTimelock, bool requirePolicyGuardian, uint256 deploymentNonce)`.
        - `signers` will be an array of social recovery guardian signing keys and `threshold` should equal the ceiling of 51% of the number of signers.
        - `signingTimelock` should be the quantity of time in seconds that must pass after queuing a signature in order to use it to execute a recovery transaction.
        - `requirePolicyGuardian` indicated whether or not the policy guardian should be required for recovery: for now, this will be enabled on all wallets.
        - Ideally, `deploymentNonce` is incremental for each `Safe`, but it can also be based on a global counter (not localized to any `Safe`) or a random number.

### Recovering a `Safe`

**WARNING: Do not use the policy guardian key for ANYTHING ELSE other than generating signatures for use with the `WaymontSafePolicyGuardianSigner` [as described above](#signing-transactions-with-the-waymontsafepolicyguardiansigner) or to generate policy guardian signatures for the `WaymontSafeTimelockedBackupSignerModule` as described directly below. Specifically, do not send any funds to its address. (The reasoning here is simply to isolate the use of the account as much as possible with the goal of reducing collateral attack surface.)**

#### Beginning the recovery request timelock

To begin the timelock, each of the necessary threshold of recovery signers must call `WaymontSafeTimelockedBackupSignerModule.queueSignature(bytes32 underlyingHash, bytes signature, bytes policyGuardianSignature)`.

- Param `underlyingHash` is computed as `keccak256(abi.encode(EXEC_TRANSACTION_TYPEHASH, safe, waymontSafeTimelockedBackupSignerModule.nonce(), to, value, keccak256(data), operation))` where `EXEC_TRANSACTION_TYPEHASH == 0x60c023ac5b12ccfb6346228598efbab110f9f06cd102f7009adbf0dbb8b8c240` and `value == 0`.
    - Fill in `to`, `data`, and `operation` with the values returned from the Protocol Kit's `Safe.createSwapOwnerTx` method (to replace the lost signer on the wallet with a working one) or the `Safe.createAddOwnerTx` method (to just add a new working signer on the wallet).
- Param `signature` is the recovery guardian's 65-byte packed signature on `keccak256(txHashData)` (or `keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(txHashData)))` with `4` added to the `signature` param's `v` param if `signTypedData` is not available on the recovery signer, [as is the case with WalletConnect](https://docs.walletconnect.com/2.0/advanced/rpc-reference/ethereum-rpc#eth_signtypeddata)) where `txHashData` is `abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator(), underlyingHash)`.
    - `domainSeparator()` is defined as `keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, getChainId(), waymontSafeTimelockedBackupSignerModule))` where `DOMAIN_SEPARATOR_TYPEHASH == 0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218` and `getChainId()` is a 32-byte `uint256`.
    - To calculate this signature, follow [the instructions below to use `ethers.Signer._signTypedData` (with ethers.js) to generate the recovery guardian signature](#generating-the-recovery-guardian-signature-using-ethersjs-for-use-with-both-queuesignature-and-exectransaction).
- Param `policyGuardianSignature` is the policy guardian's 65-byte packed signature on `keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator(), queueSignatureUnderlyingHash)` where `queueSignatureUnderlyingHash` is `keccak256(abi.encode(QUEUE_SIGNATURE_TYPEHASH, keccak256(signature)))` (where `signature` is the `signature` param, the recovery guardian's 65-byte packed signature).
    - To calculate this signature, follow [the instructions below to use `ethers.Signer._signTypedData` (with ethers.js) to generate the policy guardian signature](#generating-the-policy-guardian-signature-for-use-with-queuesignature-using-ethersjs).

##### Generating the recovery guardian signature using ethers.js (for use with both `queueSignature` and `execTransaction`)

To use `ethers.Signer._signTypedData` (with ethers.js) to generate the policy guardian signature (for use with both `WaymontSafeTimelockedBackupSignerModule.queueSignature` and `WaymontSafeTimelockedBackupSignerModule.execTransaction`):

```
const domain = {
    chainId: 1,
    verifyingContract: timelockedBackupSignerModule.address
};

const types = {
    ExecTransaction: [
        { name: 'safe', type: 'address' }
        { name: 'nonce', type: 'uint256' }
        { name: 'to', type: 'address' }
        { name: 'value', type: 'uint256' }
        { name: 'data', type: 'bytes' }
        { name: 'operation', type: 'uint8' }
    ]
};

const swapOwnerTx = await safeSdk.createSwapOwnerTx({ oldOwnerAddress, newOwnerAddress });

const value = {
    safe: safe.address,
    nonce: await waymontSafeTimelockedBackupSignerModule.nonce(),
    to: swapOwnerTx.data.to,
    value: '0',
    data: swapOwnerTx.data.data,
    operation: swapOwnerTx.data.operation,
};

const signature = await recoveryGuardianEthersWallet.signTypedData(domain, types, value);
```

As mentioned above, fill in `to`, `data`, and `operation` with the values returned from the Protocol Kit's `Safe.createSwapOwnerTx` method or the `Safe.createAddOwnerTx` method.

##### Generating the policy guardian signature for use with `queueSignature` using ethers.js

To use `ethers.Signer._signTypedData` (with ethers.js) to generate the policy guardian signature for use with `WaymontSafeTimelockedBackupSignerModule.queueSignature`:

```
const domain = {
    chainId: 1,
    verifyingContract: timelockedBackupSignerModule.address
};

const types = {
    QueueSignature: [
        { name: 'signature', type: 'bytes' }
    ]
};

const value = {
    signature: recoveryGuardianSignatureHex
};

const policyGuardianSignatureHex = await policyGuardianEthersWallet.signTypedData(domain, types, value);
```

#### Executing the recovery request

After the signing timelock has passed, to execute the recovery request, call `WaymontSafeTimelockedBackupSignerModule.execTransaction(address to, uint256 value, bytes data, Enum.Operation operation, bytes signatures)`.

- Fill in `to`, `data`, and `operation` with the values returned from the Protocol Kit's `Safe.createSwapOwnerTx` method or the `Safe.createAddOwnerTx` method.
- `value == 0` again obviously.
- `signatures` should be the packed concatenation of the 65-byte recovery guardian signatures queued earlier, in ascending order of signer address, concatenated with the 65-byte policy guardian signature at the end.
    - Follow [the instructions below to generate the policy guardian signature for use with `execTransaction` below](#generating-the-policy-guardian-signature-for-use-with-waymontsafetimelockedbackupsignermoduleexectransaction-using-ethersjs).

##### Generating the policy guardian signature for use with `WaymontSafeTimelockedBackupSignerModule.execTransaction` using ethers.js

To use `ethers.Signer._signTypedData` (with ethers.js) to generate the policy guardian signature for use with `WaymontSafeTimelockedBackupSignerModule.execTransaction`:

```
const domain = {
    chainId: 1,
    verifyingContract: timelockedBackupSignerModule.address
};

const types = {
    ExecTransaction: [
        { name: 'safe', type: 'address' }
        { name: 'nonce', type: 'uint256' }
        { name: 'to', type: 'address' }
        { name: 'value', type: 'uint256' }
        { name: 'data', type: 'bytes' }
        { name: 'operation', type: 'uint8' }
    ]
};

const swapOwnerTx = await safeSdk.createSwapOwnerTx({ oldOwnerAddress, newOwnerAddress });

const value = {
    safe: safe.address,
    nonce: await waymontSafeTimelockedBackupSignerModule.nonce(),
    to: swapOwnerTx.data.to,
    value: '0',
    data: swapOwnerTx.data.data,
    operation: swapOwnerTx.data.operation,
};

const signature = await policyGuardianEthersWallet.signTypedData(domain, types, value);
```

Note that this code is identical to [the code above](#generating-the-recovery-guardian-signature-using-ethersjs), but the `policyGuardianEthersWallet` is used to sign instead of the `recoveryGuardianEthersWallet`. *As above, fill in `to`, `data`, and `operation` with the values returned from the Protocol Kit's `Safe.createSwapOwnerTx` method or the `Safe.createAddOwnerTx` method.*

### Tracking queueing of social recovery signatures

**The following security feature is not NEARLY as important as tracking the queueing of disabling the policy guardian on `Safe`s [as described above](#tracking-policy-guardian-removal-requests).**

For `WaymontSafeTimelockedBackupSignerModule` instances that have been deployed without a policy guardian attached cannot queue signatures from recovery signers without the policy guardian's approval. Nevertheless, given the risk of the policy guardian key being compromised, Waymont should still track `WaymontSafeTimelockedBackupSignerModule.SignatureQueued` events and emit notifications to users (unless a notification was already emitted because Waymont did approve the queueing of the recovery guardian signature). And of course, if the policy guardian were ever to be disabled, then this notification system becomes extremely important.

## Using Safe's `MultiSendCallOnly` contract

Call `MultiSendCallOnly(0x40A2aCCbd92BCA938b02010E17A5b8929b49130D).multiSend(transactions)` where `transactions` is the concatenation (for each transaction) of `abi.encodePacked(uint8(0), to, value, data.length, data)` where `to` is a 20-byte `address`, `value`, is a 32-byte `uint256` (which will always be set to `0`), and `data.length` is a 32-byte `uint256`.

The source code can be found here (note that we are using the `v1.3.0` version since the `v1.4.0` version has not yet been deployed):

- https://github.com/safe-global/safe-contracts/blob/v1.3.0/contracts/libraries/MultiSendCallOnly.sol
- https://etherscan.io/address/0x40A2aCCbd92BCA938b02010E17A5b8929b49130D#code
