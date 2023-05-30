// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "./WaymontSafePolicyGuardianSigner.sol";
import "./WaymontSafeAdvancedSigner.sol";
import "./WaymontSafeTimelockedBackupSignerModule.sol";

import "lib/openzeppelin-contracts-upgradeable/contracts/proxy/ClonesUpgradeable.sol";

/// @title WaymontSafeFactory
/// @notice Creates EIP-1167 minimal proxy contract clones of `WaymontSafeAdvancedSigner` and `WaymontSafeTimelockedBackupSignerModule`.
contract WaymontSafeFactory {
    /// @notice `WaymontSafePolicyGuardianSigner` contract.
    WaymontSafePolicyGuardianSigner public immutable policyGuardianSigner;

    /// @dev `WaymontSafeAdvancedSigner` implementation/logic contract address.
    address public immutable advancedSignerImplementation;

    /// @dev `WaymontSafeTimelockedBackupSignerModule` implementation/logic contract address.
    address public immutable timelockedBackupSignerModuleImplementation;

    /// @dev Constructor to initialize the factory by deploying the 3 other Waymont contracts.
    constructor(address _policyGuardianManager) {
        policyGuardianSigner = new WaymontSafePolicyGuardianSigner(_policyGuardianManager);
        advancedSignerImplementation = new WaymontSafeAdvancedSigner();
        timelockedBackupSignerModuleImplementation = new WaymontSafeTimelockedBackupSignerModule();
    }

    /// @notice Deploys a (non-upgradeable) minimal proxy contract over `WaymontSafeAdvancedSigner`.
    /// @dev See `WaymontSafeAdvancedSigner` for other params.
    /// @param deploymentNonce The unique nonce for the deployed signer contract. If the contract address of the `WaymontSafeFactory` and the `WaymontSafeAdvancedSigner` implementation is the same across each chain (which it will be if the same private key deploys them with the same nonces), then the contract addresses of the `WaymontSafeAdvancedSigner` instances created will also be the same across all chains according to the combination of initialization parameters (`safe`, `signers`, `threshold`, and `deploymentNonce`).
    /// @return `WaymontSafeAdvancedSigner` interface for the deployed proxy.
    function createAdvancedSigner(
        Safe safe,
        address[] calldata signers,
        uint256 threshold,
        uint256 deploymentNonce
    ) external returns (WaymontSafeAdvancedSigner) {
        WaymontSafeAdvancedSigner instance;
        {
            bytes32 salt = keccak256(abi.encode(safe, signers, threshold, deploymentNonce));
            instance = WaymontSafeAdvancedSigner(payable(ClonesUpgradeable.cloneDeterministic(advancedSafeSignerImplementation, salt)));
        }
        instance.initialize(safe, signers, threshold);
        return instance;
    }

    /// @notice Deploys a (non-upgradeable) minimal proxy contract over `WaymontSafeTimelockedBackupSignerModule`.
    /// @dev See `WaymontSafeTimelockedBackupSignerModule` for other params.
    /// @param deploymentNonce The unique nonce for the deployed signer contract. If the contract address of the `WaymontSafeFactory` and the `WaymontSafeTimelockedBackupSignerModule` implementation is the same across each chain (which it will be if the same private key deploys them with the same nonces), then the contract addresses of the `WaymontSafeTimelockedBackupSignerModule` instances created will also be the same across all chains according to the combination of initialization parameters (`safe`, `signers`, `threshold`, `signingTimelock`, `requirePolicyGuardian`, and `deploymentNonce`).
    /// @return `WaymontSafeTimelockedBackupSignerModule` interface for the deployed proxy.
    function createTimelockedBackupSignerModule(
        Safe safe,
        address[] calldata signers,
        uint256 threshold,
        uint256 signingTimelock,
        bool requirePolicyGuardian,
        uint256 deploymentNonce
    ) external returns (WaymontSafeTimelockedBackupSignerModule) {
        WaymontSafeTimelockedBackupSignerModule instance;
        {
            bytes32 salt = keccak256(abi.encode(safe, signers, threshold, signingTimelock, requirePolicyGuardian, deploymentNonce));
            instance = WaymontSafeTimelockedBackupSignerModule(payable(ClonesUpgradeable.cloneDeterministic(timelockedBackupSignerModuleImplementation, salt)));
        }
        instance.initialize(safe, signers, threshold, signingTimelock, requirePolicyGuardian ? policyGuardianSigner : address(0));
        return instance;
    }

    /// @dev Event emitted when a signature is queued on a `Safe`.
    /// Useful for sending security notifications to `Safe` owners if the policy guardian cannot find record of itself sending the transaction hash associated with a `SignatureQueued` event.
    /// Only contains the signer as a parameter because that is all that is needed to know if an extra signature was queued and which signer it was from (so that signer can be removed).
    /// WARNING: The function that emits this event is not access-gated (in the interest of reducing gas costs and avoiding unnecessary smart contract complexity), so make sure to check underlying `Safe` addresses for validity. If events are spammed on a chain and `eth_getLogs` times out, `Safe`s can be checked individually (in descending order of net worth on that chain).
    event SignatureQueued(Safe indexed safe, WaymontSafeTimelockedBackupSignerModule indexed timelockedBackupSignerModule, address indexed signer, bytes32 signedDataHash);

    /// @dev Emits a `SignatureQueued` event.
    function emitSignatureQueued(address signer, bytes32 signedDataHash) external {
        WaymontSafeTimelockedBackupSignerModule timelockedBackupSignerModule = WaymontSafeTimelockedBackupSignerModule(msg.sender);
        Safe safe = timelockedBackupSignerModule.safe();
        require(safe.isModuleEnabled(timelockedBackupSignerModule), "The Safe does not have this Waymont module enabled.");
        emit SignatureQueued(Safe(msg.sender), timelockedBackupSignerModule, signer, signedDataHash);
    }
}
