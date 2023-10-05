// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "lib/safe-contracts/contracts/Safe.sol";
import "lib/safe-contracts/contracts/CheckSignatures.sol";
import "lib/safe-contracts/contracts/common/Enum.sol";

import "lib/openzeppelin-contracts/contracts/utils/cryptography/MerkleProofEfficientHash.sol";

/// @title WaymontSafeExternalSigner
/// @notice Smart contract signer (via ERC-1271) for Safe contracts v1.4.0 (https://github.com/safe-global/safe-contracts).
contract WaymontSafeExternalSigner is CheckSignatures {
    /// @dev Domain separator typehash with salt as the only parameter.
    /// Computed as `keccak256("EIP712Domain(bytes32 salt)");`
    bytes32 private constant DOMAIN_SEPARATOR_TYPEHASH = 0xed46087c30783a9d27be533e9e6a1f834cec6daf2cfb016c9ab60d791039f983;

    // @dev Equivalent of `Safe.SAFE_TX_TYPEHASH` but for transactions verified by this contract specifically.
    // Computed as: `keccak256("WaymontSafeExternalSignerTx(bytes data)");`
    bytes32 private constant EXTERNAL_SIGNER_SAFE_TX_TYPEHASH = 0x889a7153169f421ec4278295c8c28df6cec258e8ce92727f0de29d5028d297e4;

    // @dev `SAFE_TX_TYPEHASH` copied from `Safe` contract.
    // Computed as: `keccak256("SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)");`
    bytes32 private constant SAFE_TX_TYPEHASH = 0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8;

    /// @notice Blacklist for function calls that have already been dispatched or that have been revoked.
    mapping(uint256 => bool) public functionCallUniqueIdBlacklist;

    /// @notice Deployment nonce/initialization vector for this contract. Used to ensure signatures created are unique.
    /// @dev TODO: Remove `signers`/`threshold` from contract CREATE2 address instead to save gas?
    bytes32 public iv;

    /// @dev Initializes the contract by setting the `Safe`, signers, and threshold.
    /// @param _safe The `Safe` of which this signer contract will be an owner.
    /// @param signers The signers underlying this signer contract.
    /// @param threshold The threshold required of signers underlying this signer contract.
    /// @param deploymentNonce Deployment nonce used as a seed for the initialization vector for this contract. Used to ensure signatures created are unique.
    /// Can only be called once (because `setupOwners` can only be called once).
    function initialize(Safe _safe, address[] calldata signers, uint256 threshold, uint256 deploymentNonce) external {
        // Input validation
        require(_safe.isOwner(address(this)), "The Safe is not owned by this Waymont signer contract.");

        // Call `setupOwners` (can only be called once)
        setupOwners(signers, threshold);

        // Set the `Safe` and IV
        safe = _safe;
        iv = MerkleProofEfficientHash._efficientHash(bytes32(bytes20(address(safe))), bytes32(deploymentNonce));
    }

    /// @notice Blacklists a function call unique ID.
    /// @param uniqueId The function call unique ID to be blacklisted.
    function blacklistFunctionCall(uint256 uniqueId) external {
        require(msg.sender == address(safe), "Sender is not the safe.");
        functionCallUniqueIdBlacklist[uniqueId] = true;
    }

    /// @dev Returns the EIP-712 domain separator hash for this contract.
    /// @dev TODO: Need to specify virtual/override or change name.
    /// TODO: Keep this contract in same repo or use new repo/subrepo/subfolder to differentiate between contract releases/versions?
    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, iv));
    }

    /// @notice Signature validation function used by the `Safe` overlying this contract to validate underlying signers attached to this contract.
    /// @param _data Data signed in `_signature`.
    /// @param _signature Signature byte array associated with `_data`.
    /// @dev MUST return the bytes4 magic value 0x20c13b0b when function passes.
    /// MUST NOT modify state (using STATICCALL for solc < 0.5, view modifier for solc > 0.5).
    /// MUST allow external calls.
    /// TODO: Pretty sure `_signature` is better kept as `memory` rather than `calldata` because it would waste gas to perform a large number of `calldatacopy` operations, right?
    function isValidSignature(bytes calldata _data, bytes memory _signature) external view returns (bytes4) {
        // Cache to save gas
        uint256 execTransactionDataLengthOffset = threshold * 65;

        // Check if signatures only
        if (_signature.length > execTransactionDataLengthOffset) {
            // Extract execTransaction data length
            // Checked _signature.length above
            uint256 execTransactionDataOffset = execTransactionDataLengthOffset + 32;
            bytes memory execTransactionDataLength;

            assembly {
                execTransactionDataLength := mload(add(_signature, execTransactionDataOffset))
            }

            // Cache to save gas
            uint256 merkleTreeOffset = execTransactionDataOffset + execTransactionDataLength;

            // Get merkle tree exponent
            uint256 merkleTreeExponent = (_signature.length - merkleTreeOffset) / 32;

            // Only reformat transaction data if requested
            bytes32 newTxHash;

            if (execTransactionDataLength > 0) {
                // Extract execTransaction data
                // Checked _signature.length above
                bytes memory execTransactionData;

                assembly {
                    execTransactionData := add(_signature, execTransactionDataOffset)
                }

                // Decode execTransactionData
                (address to, uint256 value, bytes32 dataHash, Enum.Operation operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address payable refundReceiver, uint256 uniqueId) =
                    abi.decode(execTransactionData, (address, uint256, bytes32, Enum.Operation, uint256, uint256, uint256, address, address, uint256));

                // Validate unique ID
                require(!functionCallUniqueIdBlacklist[uniqueId], "Function call unique ID has been blacklisted.");
                
                // Ensure hash of execTransactionData matches data passed from Safe
                // TODO: Does it waste gas to store txHashData as a memory variable as opposed to only declaring a variable for its hash?
                bytes32 safeTxHash = keccak256(abi.encode(SAFE_TX_TYPEHASH, to, value, dataHash, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, safe.nonce()));
                bytes memory txHashData = abi.encodePacked(bytes1(0x19), bytes1(0x01), safe.domainSeparator(), safeTxHash);
                require(keccak256(_data) == keccak256(txHashData), "Mismatch between execTransactionData and data passed from Safe.");

                // Compute newTxHash
                bytes memory newTxHashData = abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator(), keccak256(abi.encode(EXTERNAL_SIGNER_SAFE_TX_TYPEHASH, execTransactionData)));
                newTxHash = keccak256(newTxHashData);

                // Blacklist unique ID's future use
                functionCallUniqueIdBlacklist[uniqueId] = true;
            } else {
                newTxHash = keccak256(_data);
            }

            // If using merkle tree:
            if (merkleTreeExponent > 0) {
                // Ensure merkle tree is in bounds
                require(_signature.length >= merkleTreeOffset + (32 * merkleTreeExponent), "Merkle tree out of bounds in WaymontSafeExternalSigner.isValidSignature.");

                // Extract siblings
                for (uint256 i = 1; i <= merkleTreeExponent; i++) {
                    // No need for checked math because already done above
                    // Checked _signature.length above
                    bytes32 node;

                    assembly {
                        node := mload(add(_signature, add(merkleTreeOffset, mul(32, i))))
                    }

                    newTxHash = node > newTxHash ? MerkleProofEfficientHash._efficientHash(newTxHash, node) : MerkleProofEfficientHash._efficientHash(node, newTxHash);
                }
            }

            // Check signatures
            checkSignatures(newTxHash, _signature);
        } else {
            // Check signatures
            checkSignatures(keccak256(_data), _signature);
        }

        // Return success by default
        return bytes4(0x20c13b0b);
    }
}
