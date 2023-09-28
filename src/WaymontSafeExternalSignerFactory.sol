// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "lib/openzeppelin-contracts/contracts/proxy/Clones.sol";

import "lib/safe-contracts/contracts/Safe.sol";

import "./WaymontSafeExternalSigner.sol";

/// @title WaymontSafeFactory
/// @notice Creates EIP-1167 minimal proxy contract clones of `WaymontSafeExternalSigner`.
contract WaymontSafeFactory {
    /// @dev `WaymontSafeExternalSigner` implementation/logic contract address.
    address public immutable externalSignerImplementation;

    /// @dev Constructor to initialize the factory by deploying the 3 other Waymont contracts.
    constructor() {
        externalSignerImplementation = address(new WaymontSafeExternalSigner());
    }

    /// @notice Deploys a (non-upgradeable) minimal proxy contract over `WaymontSafeExternalSigner`.
    /// @dev See `WaymontSafeExternalSigner` for other params.
    /// @param deploymentNonce The unique nonce for the deployed signer contract. If the contract address of the `WaymontSafeFactory` and the `WaymontSafeAdvancedSigner` implementation is the same across each chain (which it will be if the same private key deploys them with the same nonces), then the contract addresses of the `WaymontSafeAdvancedSigner` instances created will also be the same across all chains according to the combination of initialization parameters (`safe`, `signers`, `threshold`, and `deploymentNonce`).
    /// @return `WaymontSafeExternalSigner` interface for the deployed proxy.
    function createExternalSigner(
        Safe safe,
        address[] calldata signers,
        uint256 threshold,
        uint256 deploymentNonce
    ) external returns (WaymontSafeExternalSigner) {
        WaymontSafeExternalSigner instance;
        {
            bytes32 salt = keccak256(abi.encode(safe, signers, threshold, deploymentNonce));
            instance = WaymontSafeExternalSigner(payable(Clones.cloneDeterministic(externalSignerImplementation, salt)));
        }
        instance.initialize(safe, signers, threshold, deploymentNonce);
        return instance;
    }
}
