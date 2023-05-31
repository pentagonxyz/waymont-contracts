// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import "lib/safe-contracts/contracts/Safe.sol";
import "lib/safe-contracts/contracts/common/Enum.sol";
import "lib/safe-contracts/contracts/handler/CompatibilityFallbackHandler.sol";
import "lib/safe-contracts/contracts/proxies/SafeProxyFactory.sol";

import "../src/WaymontSafeFactory.sol";

contract WaymontSafeFactoryTest is Test {
    // Waymont accounts
    address public constant POLICY_GUARDIAN_MANAGER = 0x1111a407ca07005b696eD702E163955f27445394;
    address public constant POLICY_GUARDIAN = 0x2222939748d8F58b0e9EeFC257676EF4c560cBf4;
    address public constant POLICY_GUARDIAN_PRIVATE = 0x1f5a13350de3ffcf43c1bdb898d5ce85582526534eb07be613aed1e86fc519a2;
    address public constant SECONDARY_POLICY_GUARDIAN = 0x3333FB4491fE1b2983a080399b1B31bed05c077F;
    address public constant SECONDARY_POLICY_GUARDIAN_PRIVATE = 0x99ac8e048e51812694c4d4678bc461c141388ef5d8dbc73b56654753704bf1d8;

    // User signing devices
    address constant public ALICE = 0xA11CE2B5F21712C12C7FE9f426132396B0CFf833;
    uint256 constant public ALICE_PRIVATE = 0x45759107ecc4488d2346a3b970603914bedda4d5b7b4446cb3f048ae7ae14b91;
    address constant public BOB = 0xB0BcbA77455A98813C3a4194b284FB25607DE9A5;
    uint256 constant public BOB_PRIVATE = 0x992b834bb9d4af04b3c03be0a8968ce7e8a380d7832c6f73997eed358929a8b0;
    address constant public JOE = 0x12341f365ee78AC432C4c5340e318E35F1A60655;
    uint256 constant public JOE_PRIVATE = 0x879b74cdb4a972d577f27f60e94fe225019d352b6a2848d4eb3af327303b7e38;
    address constant public JOE = 0x12341f365ee78AC432C4c5340e318E35F1A60655;
    uint256 constant public JOE_PRIVATE = 0x879b74cdb4a972d577f27f60e94fe225019d352b6a2848d4eb3af327303b7e38;

    // Replacement user signing device
    address constant public JOE_REPLACEMENT = 0xFFFF15bd7Fe7890D078bb4FB74CF1C44213dC9BC;
    uint256 constant public JOE_REPLACEMENT_PRIVATE = 0x9ccb727a5e6438f5ed866a13c44a1cb7b801e09808c21e73dad3da2a6363abd3;

    // Social recovery signers
    address constant public FRIEND_ONE = 0x567861AcfBd3a0b3767d879ED48C030D02ba1c66;
    uint256 constant public FRIEND_ONE_PRIVATE = 0x40fd712cc644643fe42e2df5297fdb042db760c95a1d5642970c186d40987a56;
    address constant public FRIEND_TWO = 0x999963E1D8b0f7751aC958092942EE900d72490c;
    uint256 constant public FRIEND_TWO_PRIVATE = 0x46c2774c7dc2973c5d92b56ca99ef0b8b1f96f1e7e9f6dd7cd432b1a46b1f0f4;
    address constant public FRIEND_THREE = 0x00003d5936c2cb0dc8F04DBF8a4daC5195550E8a;
    uint256 constant public FRIEND_THREE_PRIVATE = 0x29a7553c21c0f021eb6aa4e31df307d3ff9ea4f50769c77684985e3c0c97c649;

    // Random addresses for tests
    uint256 constant public RANDOM_ADDRESS = 0xF72365D0eac98fFD5c8ddcA0CB9A06b28ab67C14;
    uint256 constant public RANDOM_ADDRESS_2 = 0xB72D54CF221d71dA98550Fb516F6A3219759b4DD;

    // Wrong private key for failing tests
    uint256 constant public WRONG_PRIVATE = 0x992b834bb9d4af04b3c03be0a8968ce7e8a380d7832c6f73997eed358929a8b1;

    // Waymont contracts
    WaymontSafeFactory public waymontSafeFactory;
    WaymontSafeAdvancedSigner public advancedSignerInstance;
    WaymontSafeTimelockedRecoveryModule public timelockedRecoveryModuleInstance;

    // Safe contracts
    SafeProxyFactory public safeProxyFactory;
    Safe public safeInstance;
    address public safeImplementation;
    CompatibilityFallbackHandler public compatibilityFallbackHandler;

    // Dummy variable to be manipulated by the example test Safe
    uint256 public dummy;

    function setUp() public {
        setUpSafeProxyFactory();
        setUpWaymontSafeFactory();
        setUpWaymontSafe();
    }

    function setUpSafeProxyFactory() public {
        // Set up the SafeProxyFactory and Safe implementation/singleton
        safeProxyFactory = new SafeProxyFactory();
        safeImplementation = address(new Safe());
        compatibilityFallbackHandler = new CompatibilityFallbackHandler();
    }

    function setUpWaymontSafeFactory() public {
        // Fail to use zero address for policy guardian manager
        vm.expectRevert("Invalid policy guardian manager.");
        waymontSafeFactory = new WaymontSafeFactory(address(0));

        // Successfully create WaymontSafeFactory
        waymontSafeFactory = new WaymontSafeFactory(POLICY_GUARDIAN_MANAGER);
        
        // Check 3 deployed contracts exist
        WaymontSafePolicyGuardianSigner policyGuardianSigner = waymontSafeFactory.policyGuardianSigner();
        assert(policyGuardianSigner != address(0));
        assert(waymontSafeFactory.advancedSignerImplementation() != address(0));
        assert(waymontSafeFactory.timelockedRecoveryModuleImplementation() != address(0));

        // Check policy guardian manager
        assert(policyGuardianSigner.policyGuardianManager() == POLICY_GUARDIAN_MANAGER);

        // Check implementation singleton thresholds
        assert(WaymontSafeAdvancedSigner(waymontSafeFactory.advancedSignerImplementation()).threshold() == 1);
        assert(WaymontSafeAdvancedSigner(waymontSafeFactory.timelockedRecoveryModuleImplementation()).threshold() == 1);

        // Fail to call onlyPolicyGuardianManager functions from an address that is not the manager
        vm.expectRevert("Sender is not the policy guardian manager.");
        policyGuardianSigner.setPolicyGuardian(POLICY_GUARDIAN);

        // Set the policy guardian
        vm.prank(POLICY_GUARDIAN_MANAGER);
        policyGuardianSigner.setPolicyGuardian(POLICY_GUARDIAN);
        assert(policyGuardianSigner.policyGuardian() == POLICY_GUARDIAN);
    }

    function setUpWaymontSafe() {
        // WaymontAdvancedSigner params
        address[] memory underlyingOwners = new address[](3);
        owners[0] = ALICE;
        owners[1] = BOB;
        owners[2] = JOE;
        uint256 underlyingThreshold = 2;
        uint256 deploymentNonce = 4444;

        // Predict WaymontSafeAdvancedSigner address
        bytes32 salt = keccak256(abi.encode(safe, signers, threshold, deploymentNonce));
        address predictedAdvancedSignerInstanceAddress = ClonesUpgradeable.predictDeterministicAddress(waymontSafeFactory.advancedSignerImplementation(), salt, address(waymontSafeFactory));

        // WaymontSafeTimelockedRecoveryModule params (use same deploymentNonce)
        address[] memory recoverySigners = new address[](3);
        recoverySigners[0] = FRIEND_ONE;
        recoverySigners[1] = FRIEND_TWO;
        recoverySigners[2] = FRIEND_THREE;
        uint256 recoveryThreshold = 2;
        uint256 signingTimelock = 3 days;
        uint256 requirePolicyGuardian = true;

        // Preduct WaymontSafeTimelockedRecoveryModule address
        salt = keccak256(abi.encode(safe, signers, threshold, signingTimelock, requirePolicyGuardian, deploymentNonce));
        address predictedTimelockedRecoveryModuleInstanceAddress = ClonesUpgradeable.predictDeterministicAddress(waymontSafeFactory.timelockedRecoveryModuleImplementation(), salt, address(waymontSafeFactory));

        // Safe params
        address[] memory overlyingSigners = new address[](2);
        overlyingSigners[0] = predictedAdvancedSignerInstanceAddress;
        overlyingSigners[1] = address(waymontSafeFactory.policyGuardianSigner());
        uint256 overlyingThreshold = 2;
        
        // Deploy safe (enabling the module simultaneously)
        bytes memory intializer = abi.encodeWithSelector(
            Safe.setup,
            overlyingSigners,
            overlyingThreshold,
            safeImplementation,
            abi.encodeWithSelector(Safe.enableModule, predictedTimelockedRecoveryModuleInstanceAddress),
            address(compatibilityFallbackHandler),
            address(0),
            0,
            address(0)
        );
        bytes32 saltNonce = 0x8888888888888888888888888888888888888888888888888888888888888888;
        safeInstance = Safe(address(safeProxyFactory.createProxyWithNonce(safeImplementation, initializer, saltNonce)));

        // Assert Safe deployed correctly
        for (uint256 i = 0; i < overlyingSigners.length; i++) assert(safeInstance.isOwner(overlyingSigners[i]));
        assert(safeInstance.threshold() == overlyingThreshold);

        // Deploy WaymontAdvancedSigner
        advancedSignerInstance = waymontSafeFactory.createAdvancedSigner(safeInstance, underlyingOwners, underlyingThreshold, deploymentNonce);

        // Assert deployed correctly
        assert(address(advancedSignerInstance) == predictedAdvancedSignerInstanceAddress);
        for (uint256 i = 0; i < underlyingOwners.length; i++) assert(advancedSignerInstance.isOwner(underlyingOwners[i]));
        assert(address(advancedSignerInstance.safe()) == address(safeInstance));
        assert(advancedSignerInstance.threshold() == underlyingThreshold);

        // Deploy WaymontSafeTimelockedRecoveryModule
        timelockedRecoveryModuleInstance = waymontSafeFactory.createTimelockedRecoveryModule(
            safeInstance,
            recoverySigners,
            recoveryThreshold,
            signingTimelock,
            requirePolicyGuardian ? waymontSafeFactory.policyGuardianSigner() : WaymontSafePolicyGuardianSigner(address(0)),
            deploymentNonce
        );

        // Assert deployed correctly
        assert(address(timelockedRecoveryModuleInstance) == predictedTimelockedRecoveryModuleInstanceAddress);
        assert(address(advancedSignerInstance.safe()) == address(safeInstance));
        for (uint256 i = 0; i < recoverySigners.length; i++) assert(timelockedRecoveryModuleInstance.isOwner(recoverySigners[i]));
        assert(advancedSignerInstance.threshold() == recoveryThreshold);
        assert(timelockedRecoveryModuleInstance.signingTimelock() == signingTimelock);
        assert(address(timelockedRecoveryModuleInstance.waymontSafeFactory()) == address(waymontSafeFactory));
        assert(address(timelockedRecoveryModuleInstance.policyGuardianSigner()) == requirePolicyGuardian ? address(policyGuardianSigner) : address(0));
    }

    function testCannotSetPolicyGuardianIfNotManager() public {
        // Fail to set the policy guardian to a random address
        vm.expectRevert("Sender is not the policy guardian manager.");
        policyGuardianSigner.setPolicyGuardian(RANDOM_ADDRESS);
    }

    function testCannotSetPolicyGuardianToZeroAddress() public {
        // Fail to set the policy guardian to the zero address
        vm.prank(POLICY_GUARDIAN_MANAGER);
        vm.expectRevert("Cannot set policy guardian to the zero address. Use the disablePolicyGuardianGlobally function instead.");
        policyGuardianSigner.setPolicyGuardian(address(0));
    }

    function testCannotSetPolicyGuardianIfPermanentlyDisabled() public {
        // Fail to set the policy guardian to the zero address
        vm.prank(POLICY_GUARDIAN_MANAGER);
        policyGuardianSigner.disablePolicyGuardianPermanently();
        vm.prank(POLICY_GUARDIAN_MANAGER);
        vm.expectRevert("Policy guardian has been permanently disabled.");
        policyGuardianSigner.setPolicyGuardian(RANDOM_ADDRESS);
    }

    function testDisablePolicyGuardianPermanently() public {
        // Disable the policy guardian permanently
        vm.prank(POLICY_GUARDIAN_MANAGER);
        policyGuardianSigner.disablePolicyGuardianPermanently();
        assert(policyGuardianSigner.policyGuardianPermanentlyDisabled());
        assert(policyGuardianSigner.policyGuardian() == address(0));
    }

    function testSetPolicyGuardianManager() public {
        // Call setPendingPolicyGuardianManager
        vm.prank(POLICY_GUARDIAN_MANAGER);
        policyGuardianSigner.setPendingPolicyGuardianManager(RANDOM_ADDRESS);
        assert(policyGuardianSigner.pendingPolicyGuardianManager() == RANDOM_ADDRESS);

        // Call acceptPolicyGuardianManager
        vm.prank(RANDOM_ADDRESS);
        policyGuardianSigner.acceptPolicyGuardianManager();
        assert(policyGuardianSigner.policyGuardianManager() == RANDOM_ADDRESS);
        assert(policyGuardianSigner.pendingPolicyGuardianManager() == address(0));
    }

    function testCannotAcceptPolicyGuardianManagerIfNotPendingManager() public {
        // Call setPendingPolicyGuardianManager
        vm.prank(POLICY_GUARDIAN_MANAGER);
        policyGuardianSigner.setPendingPolicyGuardianManager(RANDOM_ADDRESS);
        assert(policyGuardianSigner.pendingPolicyGuardianManager() == RANDOM_ADDRESS);

        // Call acceptPolicyGuardianManager
        vm.prank(RANDOM_ADDRESS_2);
        vm.expectRevert("Sender is not the pending policy guardian manager.");
        policyGuardianSigner.acceptPolicyGuardianManager();
    }

    function testCannotDisablePolicyGuardianPermanentlyIfAlreadyDisabledPermanently() public {
        // Disable the policy guardian permanently
        vm.prank(POLICY_GUARDIAN_MANAGER);
        policyGuardianSigner.disablePolicyGuardianPermanently();

        // Fail to do it again
        vm.prank(POLICY_GUARDIAN_MANAGER);
        vm.expectRevert("Policy guardian already permanently disabled.");
        policyGuardianSigner.disablePolicyGuardianPermanently();
    }

    function testExecTransaction() public {
        // Transaction params
        address to = address(this);
        uint256 value = 1337;
        bytes memory data = abi.encodeWithSelector(this.sampleWalletOnlyFunction, 22222222);

        // Standard params
        Enum.Operation operation = Enum.Operation.Call;
        uint256 safeTxGas = 0;
        uint256 baseGas = 0;
        uint256 gasPrice = 0;
        address gasToken = address(0);
        address refundReceiver = address(0);
        
        // Generate data hash for transaction
        bytes32 txHash = keccak256(encodeTransactionData(to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, safeInstance.nonce()));

        // Generate user signing device signature #1
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE, txHash);
        bytes memory userSignature1 = abi.encodePacked(r, s, v);

        // Generate user signing device signature #2
        (v, r, s) = vm.sign(BOB_PRIVATE, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", txHash)));
        bytes memory userSignature2 = abi.encodePacked(r, s, v + 4);

        // Pack user signatures
        bytes memory packedUserSignatures = abi.encodePacked(userSignature1, userSignature2);

        // Generate overlying policy guardian signature
        bytes memory advancedSignerOverlyingSignature = abi.encodePacked(
            bytes32(uint256(uint160(address(advancedSignerInstance)))),
            uint256(65),
            uint256(0),
            uint256(65),
            packedUserSignatures
        );

        // Generate policy guardian signatures
        (v, r, s) = vm.sign(POLICY_GUARDIAN_PRIVATE, txHash);
        bytes memory policyGuardianUnderlyingSignature = abi.encodePacked(r, s, v);

        // Generate overlying policy guardian signature
        bytes memory policyGuardianOverlyingSignature = abi.encodePacked(
            bytes32(uint256(uint160(address(waymontSafeFactory.policyGuardianSigner())))),
            uint256(65),
            uint256(0),
            uint256(65),
            policyGuardianUnderlyingSignature
        );

        // Pack all overlying signatures
        bytes memory packedOverlyingSignatures = abi.encodePacked(advancedSignerOverlyingSignature, policyGuardianOverlyingSignature);

        // Safe.execTransaction
        safeInstance.execTranasction(to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, packedOverlyingSignatures);

        // Assert TX succeeded
        assert(dummy == 22222222);
    }

    function testDisablePolicyGuardianWithoutPolicyGuardian() public {
        // Generate underlying hash + overlying signed data (to queue disabling)
        WaymontSafePolicyGuardianSigner policyGuardianSigner = waymontSafeFactory.policyGuardianSigner();
        uint256 signerNonce = policyGuardianSigner.nonces(safeInstance);
        bytes32 underlyingHash = keccak256(abi.encode(QUEUE_DISABLE_POLICY_GUARDIAN_TYPEHASH, safeInstance, signerNonce));
        bytes memory txHash = abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator(), underlyingHash);

        // Generate user signing device signature #1 (to queue disabling)
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE, txHash);
        bytes memory userSignature1 = abi.encodePacked(r, s, v);

        // Generate user signing device signature #2 (to queue disabling)
        (v, r, s) = vm.sign(BOB_PRIVATE, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", txHash)));
        bytes memory userSignature2 = abi.encodePacked(r, s, v + 4);

        // Pack user signatures (to queue disabling)
        bytes memory packedUserSignaturesForQueueing = abi.encodePacked(userSignature1, userSignature2);

        // Generate underlying hash + overlying signed data (to execute disabling)
        underlyingHash = keccak256(abi.encode(DISABLE_POLICY_GUARDIAN_TYPEHASH, safeInstance, signerNonce));
        txHash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator(), underlyingHash));

        // Generate user signing device signature #1 (to execute disabling)
        (v, r, s) = vm.sign(ALICE_PRIVATE, txHash);
        userSignature1 = abi.encodePacked(r, s, v);

        // Generate user signing device signature #2 (to execute disabling)
        (v, r, s) = vm.sign(BOB_PRIVATE, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", txHash)));
        userSignature2 = abi.encodePacked(r, s, v + 4);

        // Pack user signatures (to execute disabling)
        bytes memory packedUserSignatures = abi.encodePacked(userSignature1, userSignature2);

        // Fail to disable the policy guardian since not yet queued
        vm.expectRevert("Action not queued.");
        policyGuardianSigner.disablePolicyGuardianWithoutPolicyGuardian(safeInstance, packedUserSignatures);

        // Queue the disabling of the policy guardian
        policyGuardianSigner.queueDisablePolicyGuardian(safeInstance, packedUserSignaturesForQueueing);
        assert(policyGuardianSigner.nonces(safeInstance) == ++signerNonce);
        assert(policyGuardianSigner.disablePolicyGuardianQueueTimestamps[safeInstance] == block.timestamp);

        // Wait almost for the timelock to pass
        vm.warp(block.timestamp + 3 days - 1 seconds);

        // Fail to disable the policy guardian
        vm.expectRevert("Timelock not satisfied.");
        policyGuardianSigner.disablePolicyGuardianWithoutPolicyGuardian(safeInstance, packedUserSignatures);

        // Wait for the timelock to pass in full
        vm.warp(block.timestamp + 1 seconds);

        // Disable the policy guardian
        policyGuardianSigner.disablePolicyGuardianWithoutPolicyGuardian(safeInstance, packedUserSignatures);
        assert(policyGuardianSigner.nonces(safeInstance) == ++signerNonce);
        assert(policyGuardianSigner.policyGuardianDisabled(safeInstance));
    }

    function testSocialRecovery() public {
        // Underlying transaction params
        address to = address(safeInstance);
        bytes memory data = abi.encodeWithSelector(safeInstance.addOwnerWithThreshold, JOE_REPLACEMENT, 2);

        // Standard params
        uint256 value = 0;
        Enum.Operation operation = Enum.Operation.Call;
        
        // Generate data hash for underlying transaction
        uint256 moduleNonce = timelockedRecoveryModuleInstance.nonce();
        bytes32 underlyingHash = keccak256(abi.encode(EXEC_TRANSACTION_TYPEHASH, safe, moduleNonce, to, value, keccak256(data), operation));
        timelockedRecoveryModuleInstance.queueSignature(underlyingHash);
        bytes memory txHash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator(), underlyingHash));

        // Generate recovery guardian signature #1
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(FRIEND_ONE_PRIVATE, txHash);
        bytes memory friendSignature1 = abi.encodePacked(r, s, v);

        // Generate policy guardian signature for recovery guardian #1 for queueSignature
        bytes memory queueSignatureUnderlyingHash = keccak256(abi.encode(QUEUE_SIGNATURE_TYPEHASH, keccak256(friendSignature1)));
        bytes memory queueSignatureMsgHash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator(), queueSignatureUnderlyingHash));
        (v, r, s) = vm.sign(FRIEND_ONE_PRIVATE, queueSignatureMsgHash);
        bytes memory friend1PolicyGuardianSignature = abi.encodePacked(r, s, v);

        // Queue signature #1
        timelockedRecoveryModuleInstance.queueSignature(underlyingHash, friendSignature1, friend1PolicyGuardianSignature);
        assert(timelockedRecoveryModuleInstance.pendingSignatures(keccak256(friendSignature1)) == block.timestamp);

        // Generate user signing device signature #2
        (v, r, s) = vm.sign(FRIEND_TWO_PRIVATE, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", txHash)));
        bytes memory friendSignature2 = abi.encodePacked(r, s, v + 4);

        // Generate policy guardian signature for recovery guardian #2 for queueSignature
        queueSignatureUnderlyingHash = keccak256(abi.encode(QUEUE_SIGNATURE_TYPEHASH, keccak256(friendSignature2)));
        queueSignatureMsgHash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator(), queueSignatureUnderlyingHash));
        (v, r, s) = vm.sign(FRIEND_ONE_PRIVATE, queueSignatureMsgHash);
        bytes memory friend2PolicyGuardianSignature = abi.encodePacked(r, s, v);

        // Queue signature #2
        timelockedRecoveryModuleInstance.queueSignature(underlyingHash, friendSignature2, friend2PolicyGuardianSignature);
        assert(timelockedRecoveryModuleInstance.pendingSignatures(keccak256(friendSignature2)) == block.timestamp);

        // Pack friend signatures
        bytes memory packedFriendSignatures = abi.encodePacked(friendSignature1, friendSignature2);

        // Generate policy guardian signature for execTransaction
        (v, r, s) = vm.sign(POLICY_GUARDIAN_PRIVATE, txHash);
        bytes memory finalPolicyGuardianSignature = abi.encodePacked(r, s, v);

        // Wait almost for the timelock to pass
        vm.warp(block.timestamp + 3 days - 1 seconds);

        // WaymontSafeTimelockedRecoveryModule.execTransaction
        vm.expectRevert("Timelock not satisfied.");
        timelockedRecoveryModuleInstance.execTranasction(to, value, data, operation, packedFriendSignatures, finalPolicyGuardianSignature);

        // Wait for the timelock to pass in full
        vm.warp(block.timestamp + 1 seconds);

        // WaymontSafeTimelockedRecoveryModule.execTransaction
        timelockedRecoveryModuleInstance.execTranasction(to, value, data, operation, packedFriendSignatures, finalPolicyGuardianSignature);

        // Assert TX succeeded
        assert(timelockedRecoveryModuleInstance.nonce() == moduleNonce + 1);
        assert(safeInstance.isOwner(JOE_REPLACEMENT));
    }

    function sampleWalletOnlyFunction(uint256 arg) public payable {
        // Example function to be called by the Safe
        assert(msg.sender == address(safeInstance));
        assert(msg.value == 1337);
        dummy = arg;
    }
}
