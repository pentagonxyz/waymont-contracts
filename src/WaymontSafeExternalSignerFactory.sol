// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "lib/openzeppelin-contracts/contracts/proxy/Clones.sol";

import "lib/safe-contracts/contracts/Safe.sol";

import "./WaymontSafeExternalSigner.sol";
import "./WaymontSafePolicyGuardianSigner.sol";

/// @title WaymontSafeExternalSignerFactory
/// @notice Creates EIP-1167 minimal proxy contract clones of `WaymontSafeExternalSigner`.
/// These contracts are meant to be used with Safe contracts v1.4.1 (https://github.com/safe-global/safe-contracts/tree/v1.4.1). It can also be used with v1.4.0.
/// @dev Using the Safe Singleton Factory is recommended method of deployment of this factory: https://github.com/safe-global/safe-singleton-factory
contract WaymontSafeExternalSignerFactory {
    /// @notice Address of the `WaymontSafePolicyGuardianSigner` contract.
    WaymontSafePolicyGuardianSigner public immutable policyGuardianSigner;

    /// @dev `WaymontSafeExternalSigner` implementation/logic contract address.
    address public immutable externalSignerImplementation;

    /// @dev Constructor to initialize the factory by validating and setting the `WaymontSafePolicyGuardianSigner` and deploying the `WaymontSafeExternalSigner`.
    constructor(WaymontSafePolicyGuardianSigner _policyGuardianSigner) {
        _policyGuardianSigner.policyGuardian();
        policyGuardianSigner = _policyGuardianSigner;
        externalSignerImplementation = address(new WaymontSafeExternalSigner());
    }

    /// @notice Deploys a (non-upgradeable) minimal proxy contract over `WaymontSafeExternalSigner`.
    /// @dev See `WaymontSafeExternalSigner` for other params.
    /// @param requirePolicyGuardianForReusableCalls Whether or not the contract should ensure that the policy guardian is enabled on the Safe when making reusable function calls. Currently there are no plans to ever set this to false but keeping it as an option keeps the contracts flexible (so they can be used without the policy guardian if desired in the future).
    /// @param deploymentNonce The unique nonce for the deployed signer contract. If the contract address of the `WaymontSafeExternalSignerFactory` is the same across each chain (which it will be if the same private key deploys them with the same nonce), then the contract addresses of the `WaymontSafeExternalSigner` instances created will also be the same across all chains according to the combination of initialization parameters (`safe`, `signers`, `threshold`, `requirePolicyGuardian`, and `deploymentNonce`).
    /// @return `WaymontSafeExternalSigner` interface for the deployed proxy.
    function createExternalSigner(
        Safe safe,
        address[] calldata signers,
        uint256 threshold,
        bool requirePolicyGuardianForReusableCalls,
        uint256 deploymentNonce
    ) external returns (WaymontSafeExternalSigner) {
        WaymontSafeExternalSigner instance;
        {
            bytes32 salt = keccak256(abi.encode(safe, signers, threshold, requirePolicyGuardianForReusableCalls, deploymentNonce));
            instance = WaymontSafeExternalSigner(payable(Clones.cloneDeterministic(externalSignerImplementation, salt)));
        }
        instance.initialize(safe, signers, threshold, requirePolicyGuardianForReusableCalls ? policyGuardianSigner : WaymontSafePolicyGuardianSigner(address(0)));
        return instance;
    }
}
