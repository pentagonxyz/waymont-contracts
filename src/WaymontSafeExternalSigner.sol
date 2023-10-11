// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "lib/safe-contracts/contracts/Safe.sol";
import "lib/safe-contracts/contracts/EIP712DomainSeparator.sol";
import "lib/safe-contracts/contracts/CheckSignaturesEIP1271.sol";
import "lib/safe-contracts/contracts/common/Enum.sol";

import "lib/openzeppelin-contracts/contracts/utils/cryptography/MerkleProof.sol";

import "./WaymontSafePolicyGuardianSigner.sol";

/// @title WaymontSafeExternalSigner
/// @notice Smart contract signer (via ERC-1271) for Safe contracts v1.4.0 (https://github.com/safe-global/safe-contracts).
contract WaymontSafeExternalSigner is EIP712DomainSeparator, CheckSignaturesEIP1271 {
    // @dev Equivalent of `Safe.SAFE_TX_TYPEHASH` but for transactions verified by this contract specifically.
    // Computed as: `keccak256("WaymontSafeExternalSignerTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 uniqueId,uint256 groupUniqueId,uint256 deadline)");`
    bytes32 private constant EXTERNAL_SIGNER_SAFE_TX_TYPEHASH = 0xf641ab1aa14257ef40a4f6202602bc27847e79f0aa3bac95aa170c03c99d6290;

    /// @notice Address of the `WaymontSafePolicyGuardianSigner` contract.
    WaymontSafePolicyGuardianSigner public policyGuardianSigner;

    /// @notice Blacklist for function calls that have already been dispatched or that have been revoked.
    mapping(uint256 => bool) public functionCallUniqueIdBlacklist;

    /// @notice Quantity of gas allocated to reusable smart actions.
    uint256 public reuseableFunctionCallGasTank;

    /// @dev Initializes the contract by setting the `Safe`, signers, and threshold.
    /// @param _safe The `Safe` of which this signer contract will be an owner.
    /// @param signers The signers underlying this signer contract.
    /// @param threshold The threshold required of signers underlying this signer contract.
    /// Can only be called once (because `setupOwners` can only be called once).
    function initialize(Safe _safe, address[] calldata signers, uint256 threshold, WaymontSafePolicyGuardianSigner _policyGuardianSigner) external {
        // Input validation
        require(_safe.isOwner(address(this)), "The Safe is not owned by this Waymont signer contract.");

        // Call `setupOwners` (can only be called once)
        setupOwners(signers, threshold);

        // Set the `Safe` and `WaymontSafePolicyGuardianSigner`
        safe = _safe;
        policyGuardianSigner = _policyGuardianSigner;
    }

    /// @notice Blacklists a function call unique ID.
    /// @param uniqueId The function call unique ID to be blacklisted.
    function blacklistFunctionCall(uint256 uniqueId) external {
        require(msg.sender == address(safe), "Sender is not the safe.");
        functionCallUniqueIdBlacklist[uniqueId] = true;
    }

    /// @notice Sets the gas tank available to reusable function calls.
    /// @param value The amount of ETH that should be in the gas tank.
    function setGasTank(uint256 value) external {
        require(msg.sender == address(safe), "Sender is not the safe.");
        reuseableFunctionCallGasTank = value;
    }

    /// @notice Signature validation function used by the `Safe` overlying this contract to validate underlying signers attached to this contract.
    /// @param _data Data signed in `_signature`.
    /// @param _signature Signature byte array associated with `_data`.
    /// @dev MUST return the bytes4 magic value 0x20c13b0b when function passes.
    /// MUST NOT modify state (using STATICCALL for solc < 0.5, view modifier for solc > 0.5).
    /// MUST allow external calls.
    function isValidSignature(bytes calldata _data, bytes memory _signature) external view returns (bytes4) {
        // Check signatures
        checkSignatures(keccak256(_data), _signature);

        // Return success by default
        return bytes4(0x20c13b0b);
    }

    /// @notice Additional parameters used by `WaymontSafeExternalSigner.execTransaction` (that are not part of `Safe.execTransaction`).
    struct AdditionalExecTransactionParams {
        bytes externalSignatures;
        uint256 uniqueId;
        uint256 groupUniqueId;
        uint256 deadline;
        bytes32[] merkleProof;
    }

    /// @notice Proxy for `Safe.execTransaction` allowing execution of transactions signed through merkle trees and without incremental nonces.
    /// @param additionalParams See struct type for more info. WARNING: If using a merkle tree, make sure to use random `uniqueId` values to prevent the unauthorized submission of transactions using signatures and merkle proofs that have already been revealed.
    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory safeSignatures,
        AdditionalExecTransactionParams memory additionalParams
    ) external returns (bool success) {
        // Validate deadline
        require(block.timestamp <= additionalParams.deadline, "This TX is expired/past its deadline.");

        // If specified, validate unique ID not used/blacklisted; if not specified and policy guardian is required, validate that policy guardian signature is required; if group unique ID specified, validate not blacklisted
        require(additionalParams.uniqueId > 0 || additionalParams.groupUniqueId > 0, "Must specify either a unique ID or group unique ID to have the ability to prevent the repeat use of this function call.");
        if (additionalParams.uniqueId > 0) require(!functionCallUniqueIdBlacklist[additionalParams.uniqueId], "Function call unique ID has already been used or has been blacklisted.");
        else if (address(policyGuardianSigner) != address(0)) require(safe.isOwner(address(policyGuardianSigner)) && safe.getThreshold() == safe.getOwners().length && policyGuardianSigner.policyGuardian() != address(0) && !policyGuardianSigner.policyGuardianDisabled(safe), "Policy guardian must be enabled to submit reusable transactions.");
        if (additionalParams.groupUniqueId > 0) require(!functionCallUniqueIdBlacklist[additionalParams.groupUniqueId], "Function call group unique ID has been blacklisted.");

        // Scope to avoid "stack too deep"
        {
            // Compute newTxHash
            bytes32 newSafeTxHash = keccak256(abi.encode(EXTERNAL_SIGNER_SAFE_TX_TYPEHASH, to, value, keccak256(data), operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, additionalParams.uniqueId, additionalParams.groupUniqueId, additionalParams.deadline));
            bytes32 newTxHash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator(), newSafeTxHash));

            // Process merkle proof
            newTxHash = MerkleProof.processProof(additionalParams.merkleProof, newTxHash);

            // Check signatures
            checkSignatures(newTxHash, additionalParams.externalSignatures);
        }

        // If uniqueId is reusable, subtract from gas tank (checked math will revert if not enough)
        if (additionalParams.uniqueId == 0) reuseableFunctionCallGasTank -= (baseGas + safeTxGas) * (gasPrice < tx.gasprice || gasToken != address(0) ? gasPrice : tx.gasprice);
        // If uniqueId is not reuseable, blacklist unique ID's future use
        else functionCallUniqueIdBlacklist[additionalParams.uniqueId] = true;

        // Execute the transaction
        // Hashes are automatically approved by the sender with v == 1 and r == approver (this contract)
        // See line 316-321 of safe-contracts v1.4.0 Safe.sol: https://github.com/safe-global/safe-contracts/blob/v1.4.0/contracts/Safe.sol#L316-L321
        return safe.execTransaction(to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, safeSignatures);
    }
}
