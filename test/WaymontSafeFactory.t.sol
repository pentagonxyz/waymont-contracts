// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import "lib/openzeppelin-contracts/contracts/proxy/Clones.sol";

import "lib/safe-contracts/contracts/Safe.sol";
import "lib/safe-contracts/contracts/common/Enum.sol";
import "lib/safe-contracts/contracts/handler/CompatibilityFallbackHandler.sol";
import "lib/safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import "lib/safe-contracts/contracts/libraries/MultiSend.sol";

import "../src/WaymontSafeFactory.sol";
import "../src/WaymontSafePolicyGuardianSigner.sol";
import "../src/WaymontSafeAdvancedSigner.sol";
import "../src/WaymontSafeTimelockedRecoveryModule.sol";

contract WaymontSafeFactoryTest is Test {
    // Typehashes copied from contracts
    bytes32 private constant QUEUE_SIGNATURE_TYPEHASH = 0x56f7b592467518044b02545f1b4518cd51c746d04978afb6a3b9d05895cb79cf;
    bytes32 private constant EXEC_TRANSACTION_TYPEHASH = 0x017ac7ed7bb44ab92aef10c445ff46b9a95c18bfa2bf271178886356daa01e9c;
    bytes32 private constant QUEUE_DISABLE_POLICY_GUARDIAN_TYPEHASH = 0xd5fa5ce164fba34243c3b3b9c5346acc2eae6f31655b86516d465566d0ba53f7;
    bytes32 private constant UNQUEUE_DISABLE_POLICY_GUARDIAN_TYPEHASH = 0x16dda714d491dced303c8770c04d1539fd0000764e8745d3fe40945bb0d59dcf;
    bytes32 private constant DISABLE_POLICY_GUARDIAN_TYPEHASH = 0x1fa738809572ae202e6e8b28ae7d08f5972c3ae85e70f8bc386515bb47925975;
    
    // Waymont accounts
    address public constant POLICY_GUARDIAN_MANAGER = 0x1111a407ca07005b696eD702E163955f27445394;
    address public constant POLICY_GUARDIAN = 0x2222939748d8F58b0e9EeFC257676EF4c560cBf4;
    uint256 public constant POLICY_GUARDIAN_PRIVATE = 0x1f5a13350de3ffcf43c1bdb898d5ce85582526534eb07be613aed1e86fc519a2;
    address public constant SECONDARY_POLICY_GUARDIAN = 0x3333FB4491fE1b2983a080399b1B31bed05c077F;
    uint256 public constant SECONDARY_POLICY_GUARDIAN_PRIVATE = 0x99ac8e048e51812694c4d4678bc461c141388ef5d8dbc73b56654753704bf1d8;

    // User signing devices
    address constant public ALICE = 0xA11CE2B5F21712C12C7FE9f426132396B0CFf833;
    uint256 constant public ALICE_PRIVATE = 0x45759107ecc4488d2346a3b970603914bedda4d5b7b4446cb3f048ae7ae14b91;
    address constant public BOB = 0xB0BcbA77455A98813C3a4194b284FB25607DE9A5;
    uint256 constant public BOB_PRIVATE = 0x992b834bb9d4af04b3c03be0a8968ce7e8a380d7832c6f73997eed358929a8b0;
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
    address constant public RANDOM_ADDRESS = 0xF72365D0eac98fFD5c8ddcA0CB9A06b28ab67C14;
    address constant public RANDOM_ADDRESS_2 = 0xB72D54CF221d71dA98550Fb516F6A3219759b4DD;

    // Wrong private key for failing tests
    uint256 constant public WRONG_PRIVATE = 0x992b834bb9d4af04b3c03be0a8968ce7e8a380d7832c6f73997eed358929a8b1;

    // Waymont contracts
    WaymontSafeFactory public waymontSafeFactory;
    WaymontSafePolicyGuardianSigner public policyGuardianSigner;
    WaymontSafeAdvancedSigner public advancedSignerInstance;
    WaymontSafeTimelockedRecoveryModule public timelockedRecoveryModuleInstance;

    // Safe contracts
    SafeProxyFactory public safeProxyFactory;
    Safe public safeInstance;
    address public safeImplementation;
    CompatibilityFallbackHandler public compatibilityFallbackHandler;
    MultiSend public multiSend;

    // Dummy variable to be manipulated by the example test Safe
    uint256 public dummy;

    function setUp() public {
        setUpSafeProxyFactory();
        multiSend = new MultiSend();
        setUpWaymontSafeFactory();
        setUpWaymontSafe();
    }

    function testSetUpTwice() public {
        setUp();
    }

    function setUpSafeProxyFactory() public {
        // Set up the SafeProxyFactory and Safe implementation/singleton
        safeProxyFactory = new SafeProxyFactory();
        safeImplementation = address(new Safe());
        compatibilityFallbackHandler = new CompatibilityFallbackHandler();
    }

    event PolicyGuardianChanged(address _policyGuardian);

    function setUpWaymontSafeFactory() public {
        // Fail to use zero address for policy guardian manager
        vm.expectRevert("Invalid policy guardian manager.");
        waymontSafeFactory = new WaymontSafeFactory(address(0));

        // Successfully create WaymontSafeFactory
        waymontSafeFactory = new WaymontSafeFactory(POLICY_GUARDIAN_MANAGER);
        
        // Set policyGuardianSigner in state for easy access
        policyGuardianSigner = waymontSafeFactory.policyGuardianSigner();

        // Check 3 deployed contracts exist
        assert(address(policyGuardianSigner) != address(0));
        assert(waymontSafeFactory.advancedSignerImplementation() != address(0));
        assert(waymontSafeFactory.timelockedRecoveryModuleImplementation() != address(0));

        // Check policy guardian manager
        assert(policyGuardianSigner.policyGuardianManager() == POLICY_GUARDIAN_MANAGER);

        // Check implementation singleton thresholds
        assert(WaymontSafeAdvancedSigner(waymontSafeFactory.advancedSignerImplementation()).getThreshold() == 1);
        assert(WaymontSafeTimelockedRecoveryModule(waymontSafeFactory.timelockedRecoveryModuleImplementation()).getThreshold() == 1);

        // Fail to call onlyPolicyGuardianManager functions from an address that is not the manager
        vm.expectRevert("Sender is not the policy guardian manager.");
        policyGuardianSigner.setPolicyGuardian(POLICY_GUARDIAN);

        // Set the policy guardian
        vm.prank(POLICY_GUARDIAN_MANAGER);
        vm.expectEmit(false, false, false, true, address(policyGuardianSigner));
        emit PolicyGuardianChanged(POLICY_GUARDIAN);
        policyGuardianSigner.setPolicyGuardian(POLICY_GUARDIAN);
        assert(policyGuardianSigner.policyGuardian() == POLICY_GUARDIAN);
    }

    struct CreateTimelockedRecoveryModuleParams {
        address[] recoverySigners;
        uint256 recoveryThreshold;
        uint256 recoverySigningTimelock;
        bool requirePolicyGuardianForRecovery;
    }

    function _packSignaturesOrderedBySigner(bytes[] memory signatures, address[] memory signers) internal pure returns (bytes memory packedOrderedSignatures) {
        // Assertions
        assert(signatures.length == signers.length);
        assert(signatures.length > 0);

        // Handle simple case of only one signature
        if (signatures.length == 1) return signatures[0];

        // Copy input arrays to avoid messing them up
        address[] memory _signers = new address[](signers.length);
        bytes[] memory _signatures = new bytes[](signatures.length);

        for (uint256 i = 0; i < signers.length; i++) {
            _signers[i] = signers[i];
            _signatures[i] = signatures[i];
        }

        // Sort signatures by signer
        for (uint256 i = 1; i < _signers.length; i++) {
            address signer = _signers[i];
            bytes memory signature = _signatures[i];
            uint256 j;
            for (j = i; j > 0 && signer < signers[j - 1]; j--) {
                _signers[j] = _signers[j - 1];
                _signatures[j] = _signatures[j - 1];
            }
            _signers[j] = signer;
            _signatures[j] = signature;
        }

        // Pack ordered signatures
        packedOrderedSignatures = _signatures[0];
        for (uint256 i = 1; i < signatures.length; i++) packedOrderedSignatures = abi.encodePacked(packedOrderedSignatures, _signatures[i]);
    }

    function _execInitialConfigOnSafe(
        address[] memory underlyingOwners,
        uint256 underlyingThreshold,
        CreateTimelockedRecoveryModuleParams memory moduleCreationParams,
        address predictedAdvancedSignerInstanceAddress,
        address predictedTimelockedRecoveryModuleInstanceAddress,
        uint256 deploymentNonce,
        bool expectRevert
    ) internal {
        // Get Safe.execTransaction params
        address to;
        bytes memory data;
        Enum.Operation operation = Enum.Operation.DelegateCall;
        {
            // Set new threshold for after the WaymontSafeAdvancedSigner is added
            uint256 finalOverlyingThreshold = 2;

            // Add WaymontSafeAdvancedSigner to Safe as signer using Safe.addOwner
            to = address(safeInstance);
            data = abi.encodeWithSelector(safeInstance.addOwnerWithThreshold.selector, predictedAdvancedSignerInstanceAddress, finalOverlyingThreshold);
            bytes memory multiSendTransactions = abi.encodePacked(uint8(0), to, uint256(0), data.length, data);

            // Enable WaymontSafeTimelockedRecoveryModule on the Safe
            to = address(safeInstance);
            data = abi.encodeWithSelector(safeInstance.enableModule.selector, predictedTimelockedRecoveryModuleInstanceAddress);
            multiSendTransactions = abi.encodePacked(multiSendTransactions, uint8(0), to, uint256(0), data.length, data);

            // Deploy WaymontSafeAdvancedSigner
            to = address(waymontSafeFactory);
            data = abi.encodeWithSelector(waymontSafeFactory.createAdvancedSigner.selector, safeInstance, underlyingOwners, underlyingThreshold, deploymentNonce);
            multiSendTransactions = abi.encodePacked(multiSendTransactions, uint8(0), to, uint256(0), data.length, data);

            // Deploy WaymontSafeTimelockedRecoveryModule
            to = address(waymontSafeFactory);
            data = abi.encodeWithSelector(
                waymontSafeFactory.createTimelockedRecoveryModule.selector,
                safeInstance,
                moduleCreationParams.recoverySigners,
                moduleCreationParams.recoveryThreshold,
                moduleCreationParams.recoverySigningTimelock,
                moduleCreationParams.requirePolicyGuardianForRecovery,
                deploymentNonce
            );
            multiSendTransactions = abi.encodePacked(multiSendTransactions, uint8(0), to, uint256(0), data.length, data);

            // Params for Safe.execTransaction
            to = address(multiSend);
            data = abi.encodeWithSelector(multiSend.multiSend.selector, multiSendTransactions);
        }

        // Get, order, and pack all overlying signatures
        bytes memory packedOverlyingSignatures;
        {
            // Get overlying signatures
            (, , bytes memory policyGuardianOverlyingSignaturePointer, bytes memory policyGuardianOverlyingSignatureData) = _getUserSignaturesAndOverlyingPolicyGuardianSignature(to, 0, data, operation, 0, false);

            // Pack overlying signatures
            packedOverlyingSignatures = abi.encodePacked(policyGuardianOverlyingSignaturePointer, policyGuardianOverlyingSignatureData);
        }

        // Safe.execTransaction
        if (expectRevert) vm.expectRevert("GS013");
        safeInstance.execTransaction(to, 0, data, operation, 0, 0, 0, address(0), payable(address(0)), packedOverlyingSignatures);
    }

    function setUpWaymontSafe() public {
        // WaymontAdvancedSigner params
        address[] memory underlyingOwners = new address[](3);
        underlyingOwners[0] = ALICE;
        underlyingOwners[1] = BOB;
        underlyingOwners[2] = JOE;
        uint256 underlyingThreshold = 2;
        uint256 deploymentNonce = 4444;

        // Safe params--initiating signers are the signers that will remove themselves in favor of the `AdvancedSigner` (but the WaymontSafePolicyGuardianSigner will stay)
        address[] memory initialOverlyingSigners;
        {
            uint256 initialOverlyingThreshold = 1;
            initialOverlyingSigners = new address[](initialOverlyingThreshold);
            initialOverlyingSigners[0] = address(policyGuardianSigner);
            
            // Deploy Safe
            {
                bytes memory initializer = abi.encodeWithSelector(
                    Safe.setup.selector,
                    initialOverlyingSigners,
                    initialOverlyingThreshold,
                    address(0),
                    hex'',
                    address(compatibilityFallbackHandler),
                    address(0),
                    0,
                    address(0)
                );
                uint256 saltNonce = 0x8888888888888888888888888888888888888888888888888888888888888888;
                safeInstance = Safe(payable(address(safeProxyFactory.createProxyWithNonce(safeImplementation, initializer, saltNonce))));
            }

            // Assert Safe deployed correctly
            for (uint256 i = 0; i < initialOverlyingSigners.length; i++) assert(safeInstance.isOwner(initialOverlyingSigners[i]));
            assert(safeInstance.getThreshold() == initialOverlyingThreshold);
        }

        // Predict WaymontSafeAdvancedSigner address
        address predictedAdvancedSignerInstanceAddress;
        {
            bytes32 salt = keccak256(abi.encode(safeInstance, underlyingOwners, underlyingThreshold, deploymentNonce));
            predictedAdvancedSignerInstanceAddress = Clones.predictDeterministicAddress(waymontSafeFactory.advancedSignerImplementation(), salt, address(waymontSafeFactory));
        }

        // Try and fail to deploy WaymontSafeAdvancedSigner (since it has not yet been added to the Safe)
        vm.expectRevert("The Safe is not owned by this Waymont signer contract.");
        advancedSignerInstance = waymontSafeFactory.createAdvancedSigner(safeInstance, underlyingOwners, underlyingThreshold, deploymentNonce);

        // WaymontSafeTimelockedRecoveryModule params (use same deploymentNonce)
        CreateTimelockedRecoveryModuleParams memory moduleCreationParams;
        {
            address[] memory recoverySigners = new address[](3);
            recoverySigners[0] = FRIEND_ONE;
            recoverySigners[1] = FRIEND_TWO;
            recoverySigners[2] = FRIEND_THREE;
            moduleCreationParams = CreateTimelockedRecoveryModuleParams({
                recoverySigners: recoverySigners,
                recoveryThreshold: 2,
                recoverySigningTimelock: 3 days,
                requirePolicyGuardianForRecovery: true
            });
        }

        // Predict WaymontSafeTimelockedRecoveryModule address
        address predictedTimelockedRecoveryModuleInstanceAddress;
        {
            bytes32 salt = keccak256(abi.encode(safeInstance, moduleCreationParams.recoverySigners, moduleCreationParams.recoveryThreshold, moduleCreationParams.recoverySigningTimelock, moduleCreationParams.requirePolicyGuardianForRecovery, deploymentNonce));
            predictedTimelockedRecoveryModuleInstanceAddress = Clones.predictDeterministicAddress(waymontSafeFactory.timelockedRecoveryModuleImplementation(), salt, address(waymontSafeFactory));
        }

        // Try and fail to deploy WaymontSafeTimelockedRecoveryModule before enabling
        vm.expectRevert("The Safe does not have this Waymont module enabled.");
        timelockedRecoveryModuleInstance = waymontSafeFactory.createTimelockedRecoveryModule(
            safeInstance,
            moduleCreationParams.recoverySigners,
            moduleCreationParams.recoveryThreshold,
            moduleCreationParams.recoverySigningTimelock,
            moduleCreationParams.requirePolicyGuardianForRecovery,
            deploymentNonce
        );

        // Try and fail to deploy WaymontSafeTimelockedRecoveryModule with a bad config
        moduleCreationParams.recoveryThreshold = 3;
        _execInitialConfigOnSafe(
            underlyingOwners,
            underlyingThreshold,
            moduleCreationParams,
            predictedAdvancedSignerInstanceAddress,
            predictedTimelockedRecoveryModuleInstanceAddress,
            deploymentNonce,
            true
        );
        moduleCreationParams.recoveryThreshold = 2;

        // Try and fail to deploy WaymontSafeTimelockedRecoveryModule with a bad signing timelock
        moduleCreationParams.recoverySigningTimelock = 14 minutes;
        address badPredictedTimelockedRecoveryModuleInstanceAddress;
        {
            bytes32 salt = keccak256(abi.encode(safeInstance, moduleCreationParams.recoverySigners, moduleCreationParams.recoveryThreshold, 14 minutes, moduleCreationParams.requirePolicyGuardianForRecovery, deploymentNonce));
            badPredictedTimelockedRecoveryModuleInstanceAddress = Clones.predictDeterministicAddress(waymontSafeFactory.timelockedRecoveryModuleImplementation(), salt, address(waymontSafeFactory));
        }
        _execInitialConfigOnSafe(
            underlyingOwners,
            underlyingThreshold,
            moduleCreationParams,
            predictedAdvancedSignerInstanceAddress,
            badPredictedTimelockedRecoveryModuleInstanceAddress,
            deploymentNonce,
            true
        );
        moduleCreationParams.recoverySigningTimelock = 3 days;

        // Use Safe.execTransaction to call MultiSend.multiSend to add WaymontSafeAdvancedSigner to the Safe as a signer using Safe.swapOwner, remove the extra signer(s) from the Safe with Safe.removeOwner, enable the WaymontSafeTimelockedRecoveryModule on the Safe, deploy the WaymontSafeAdvancedSigner, and deploy the WaymontSafeTimelockedRecoveryModule
        _execInitialConfigOnSafe(
            underlyingOwners,
            underlyingThreshold,
            moduleCreationParams,
            predictedAdvancedSignerInstanceAddress,
            predictedTimelockedRecoveryModuleInstanceAddress,
            deploymentNonce,
            false
        );

        // Set WaymontSafeAdvancedSigner
        advancedSignerInstance = WaymontSafeAdvancedSigner(predictedAdvancedSignerInstanceAddress);

        // Assert WaymontSafeAdvancedSigner deployed correctly
        assert(address(advancedSignerInstance) == predictedAdvancedSignerInstanceAddress);
        for (uint256 i = 0; i < underlyingOwners.length; i++) assert(advancedSignerInstance.isOwner(underlyingOwners[i]));
        assert(address(advancedSignerInstance.safe()) == address(safeInstance));
        assert(advancedSignerInstance.getThreshold() == underlyingThreshold);

        // Assert signers configured correctly now
        {
            address[] memory finalOverlyingSigners = new address[](2);
            finalOverlyingSigners[0] = address(policyGuardianSigner);
            finalOverlyingSigners[1] = address(advancedSignerInstance);
            for (uint256 i = 0; i < finalOverlyingSigners.length; i++) assert(safeInstance.isOwner(finalOverlyingSigners[i]));
            assert(safeInstance.getOwners().length == finalOverlyingSigners.length);
            assert(safeInstance.getThreshold() == 2);
        }

        // Set WaymontSafeTimelockedRecoveryModule
        timelockedRecoveryModuleInstance = WaymontSafeTimelockedRecoveryModule(predictedTimelockedRecoveryModuleInstanceAddress);

        // Assert deployed correctly
        assert(address(timelockedRecoveryModuleInstance) == predictedTimelockedRecoveryModuleInstanceAddress);
        assert(address(timelockedRecoveryModuleInstance.safe()) == address(safeInstance));
        for (uint256 i = 0; i < moduleCreationParams.recoverySigners.length; i++) assert(timelockedRecoveryModuleInstance.isOwner(moduleCreationParams.recoverySigners[i]));
        assert(timelockedRecoveryModuleInstance.getThreshold() == moduleCreationParams.recoveryThreshold);
        assert(timelockedRecoveryModuleInstance.signingTimelock() == moduleCreationParams.recoverySigningTimelock);
        assert(address(timelockedRecoveryModuleInstance.waymontSafeFactory()) == address(waymontSafeFactory));
        assert(address(timelockedRecoveryModuleInstance.policyGuardianSigner()) == (moduleCreationParams.requirePolicyGuardianForRecovery ? address(policyGuardianSigner) : address(0)));
        assert(safeInstance.isModuleEnabled(address(timelockedRecoveryModuleInstance)));
    }

    function testCannotCreateAdvancedSignerWithMismatchingDeploymentNonce() public {
        // WaymontSafeAdvancedSigner params
        address[] memory underlyingOwners = new address[](3);
        underlyingOwners[0] = ALICE;
        underlyingOwners[1] = BOB;
        underlyingOwners[2] = JOE;
        uint256 underlyingThreshold = 2;
        uint256 deploymentNonce = 5555;

        // Failure
        vm.expectRevert("The Safe is not owned by this Waymont signer contract.");
        waymontSafeFactory.createAdvancedSigner(safeInstance, underlyingOwners, underlyingThreshold, deploymentNonce);
    }

    function testCannotCreateTimelockedRecoveryModuleWithMismatchingDeploymentNonce() public {
        // WaymontSafeTimelockedRecoveryModule params
        address[] memory recoverySigners = new address[](3);
        recoverySigners[0] = FRIEND_ONE;
        recoverySigners[1] = FRIEND_TWO;
        recoverySigners[2] = FRIEND_THREE;
        uint256 recoveryThreshold = 2;
        uint256 recoverySigningTimelock = 3 days;
        bool requirePolicyGuardianForRecovery = false;
        uint256 deploymentNonce = 5555;

        // Failure
        vm.expectRevert("The Safe does not have this Waymont module enabled.");
        waymontSafeFactory.createTimelockedRecoveryModule(
            safeInstance,
            recoverySigners,
            recoveryThreshold,
            recoverySigningTimelock,
            requirePolicyGuardianForRecovery,
            deploymentNonce
        );
    }

    function testCannotCreateAdvancedSignerWithSameParamsTwice() public {
        // WaymontSafeAdvancedSigner params
        address[] memory underlyingOwners = new address[](3);
        underlyingOwners[0] = ALICE;
        underlyingOwners[1] = BOB;
        underlyingOwners[2] = JOE;
        uint256 underlyingThreshold = 2;
        uint256 deploymentNonce = 4444;

        // Failure
        vm.expectRevert();
        waymontSafeFactory.createAdvancedSigner(safeInstance, underlyingOwners, underlyingThreshold, deploymentNonce);
    }

    function testCannotCreateTimelockedRecoveryModuleWithSameParamsTwice() public {
        // WaymontSafeTimelockedRecoveryModule params
        address[] memory recoverySigners = new address[](3);
        recoverySigners[0] = FRIEND_ONE;
        recoverySigners[1] = FRIEND_TWO;
        recoverySigners[2] = FRIEND_THREE;
        uint256 recoveryThreshold = 2;
        uint256 recoverySigningTimelock = 3 days;
        bool requirePolicyGuardianForRecovery = false;
        uint256 deploymentNonce = 4444;

        // Failure
        vm.expectRevert();
        waymontSafeFactory.createTimelockedRecoveryModule(
            safeInstance,
            recoverySigners,
            recoveryThreshold,
            recoverySigningTimelock,
            requirePolicyGuardianForRecovery,
            deploymentNonce
        );
    }

    function testCannotReinitializeAdvancedSigner() public {
        // WaymontSafeAdvancedSigner params
        address[] memory underlyingOwners = new address[](3);
        underlyingOwners[0] = ALICE;
        underlyingOwners[1] = BOB;
        underlyingOwners[2] = JOE;
        uint256 underlyingThreshold = 2;

        // Try and fail to re-initialize the WaymontSafeAdvancedSigner instance
        vm.expectRevert("GS200");
        advancedSignerInstance.initialize(safeInstance, underlyingOwners, underlyingThreshold);
    }

    function testCannotReinitializeTimelockedRecoveryModule() public {
        // WaymontSafeTimelockedRecoveryModule params (use same deploymentNonce)
        CreateTimelockedRecoveryModuleParams memory moduleCreationParams;
        {
            address[] memory recoverySigners = new address[](3);
            recoverySigners[0] = FRIEND_ONE;
            recoverySigners[1] = FRIEND_TWO;
            recoverySigners[2] = FRIEND_THREE;
            moduleCreationParams = CreateTimelockedRecoveryModuleParams({
                recoverySigners: recoverySigners,
                recoveryThreshold: 2,
                recoverySigningTimelock: 3 days,
                requirePolicyGuardianForRecovery: true
            });
        }

        // Try and fail to re-initialize the WaymontSafeTimelockedRecoveryModule instance
        vm.expectRevert("GS200");
        timelockedRecoveryModuleInstance.initialize(
            safeInstance,
            moduleCreationParams.recoverySigners,
            moduleCreationParams.recoveryThreshold,
            moduleCreationParams.recoverySigningTimelock,
            policyGuardianSigner
        );
    }

    function testSetPolicyGuardian() public {
        // Set the policy guardian to a random address (checking events)
        vm.prank(POLICY_GUARDIAN_MANAGER);
        vm.expectEmit(false, false, false, true, address(policyGuardianSigner));
        emit PolicyGuardianChanged(RANDOM_ADDRESS);
        policyGuardianSigner.setPolicyGuardian(RANDOM_ADDRESS);
        assert(policyGuardianSigner.policyGuardian() == RANDOM_ADDRESS);
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

    event SecondaryPolicyGuardianChanged(address _policyGuardian);

    function testSetSecondaryPolicyGuardian() public {
        // Set the secondary policy guardian (checking events)
        vm.prank(POLICY_GUARDIAN_MANAGER);
        vm.expectEmit(false, false, false, true, address(policyGuardianSigner));
        emit SecondaryPolicyGuardianChanged(SECONDARY_POLICY_GUARDIAN);
        policyGuardianSigner.setSecondaryPolicyGuardian(SECONDARY_POLICY_GUARDIAN);
        assert(policyGuardianSigner.secondaryPolicyGuardian() == SECONDARY_POLICY_GUARDIAN);
    }

    function testSetSecondaryPolicyGuardianTwice() public {
        // Set the secondary policy guardian once
        testSetSecondaryPolicyGuardian();

        // Set the secondary policy guardian again but to a random address (checking events)
        vm.prank(POLICY_GUARDIAN_MANAGER);
        vm.expectEmit(false, false, false, true, address(policyGuardianSigner));
        emit SecondaryPolicyGuardianChanged(RANDOM_ADDRESS);
        policyGuardianSigner.setSecondaryPolicyGuardian(RANDOM_ADDRESS);
        assert(policyGuardianSigner.secondaryPolicyGuardian() == RANDOM_ADDRESS);
    }

    function testCannotSetSecondaryPolicyGuardianIfNotManager() public {
        // Fail to set the secondary policy guardian to a random address
        vm.expectRevert("Sender is not the policy guardian manager.");
        policyGuardianSigner.setSecondaryPolicyGuardian(RANDOM_ADDRESS);
    }

    function testDisablePolicyGuardianPermanently() public {
        // Disable the policy guardian permanently
        vm.prank(POLICY_GUARDIAN_MANAGER);
        vm.expectEmit(false, false, false, true, address(policyGuardianSigner));
        emit PolicyGuardianDisabledGlobally(true);
        policyGuardianSigner.disablePolicyGuardianPermanently();
        assert(policyGuardianSigner.policyGuardianPermanentlyDisabled());
        assert(policyGuardianSigner.policyGuardian() == address(0));
    }

    event PolicyGuardianManagerChanged(address _policyGuardianManager);
    event PendingPolicyGuardianManagerChanged(address _pendingPolicyGuardianManager);

    function testSetPolicyGuardianManager() public {
        // Call setPendingPolicyGuardianManager
        vm.prank(POLICY_GUARDIAN_MANAGER);
        vm.expectEmit(false, false, false, true, address(policyGuardianSigner));
        emit PendingPolicyGuardianManagerChanged(RANDOM_ADDRESS);
        policyGuardianSigner.setPendingPolicyGuardianManager(RANDOM_ADDRESS);
        assert(policyGuardianSigner.pendingPolicyGuardianManager() == RANDOM_ADDRESS);

        // Call acceptPolicyGuardianManager
        vm.prank(RANDOM_ADDRESS);
        vm.expectEmit(false, false, false, true, address(policyGuardianSigner));
        emit PolicyGuardianManagerChanged(RANDOM_ADDRESS);
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

    event PolicyGuardianDisabledGlobally(bool permanently);

    function testDisablePolicyGuardianGlobally() public {
        // Disable the policy guardian globally
        vm.prank(POLICY_GUARDIAN_MANAGER);
        vm.expectEmit(false, false, false, true, address(policyGuardianSigner));
        emit PolicyGuardianDisabledGlobally(false);
        policyGuardianSigner.disablePolicyGuardianGlobally();
        assert(!policyGuardianSigner.policyGuardianPermanentlyDisabled());
        assert(policyGuardianSigner.policyGuardian() == address(0));
    }

    function testCannotDisablePolicyGuardianGloballyIfAlreadyDisabledGlobally() public {
        // Disable the policy guardian globally
        vm.prank(POLICY_GUARDIAN_MANAGER);
        policyGuardianSigner.disablePolicyGuardianGlobally();

        // Fail to do it again
        vm.prank(POLICY_GUARDIAN_MANAGER);
        vm.expectRevert("Policy guardian already disabled.");
        policyGuardianSigner.disablePolicyGuardianGlobally();
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

    function testDisablePolicyGuardian() public {
        // Transaction params
        address to = address(policyGuardianSigner);
        uint256 value = 0;
        bytes memory data = abi.encodeWithSelector(policyGuardianSigner.disablePolicyGuardian.selector);

        // Safe.execTransaction
        _execTransaction(to, value, data, TestExecTransactionOptions(false, false, false, false, false, true, false, 0));

        // Assert TX succeeded
        assert(policyGuardianSigner.policyGuardianDisabled(safeInstance));
    }

    function testSetPolicyGuardianTimelock() public {
        // Transaction params
        address to = address(policyGuardianSigner);
        uint256 value = 0;
        bytes memory data = abi.encodeWithSelector(policyGuardianSigner.setPolicyGuardianTimelock.selector, 7 days);

        // Safe.execTransaction
        _execTransaction(to, value, data, TestExecTransactionOptions(false, false, false, false, false, false, true, 7 days));

        // Assert TX succeeded
        assert(policyGuardianSigner.getPolicyGuardianTimelock(safeInstance) == 7 days);
        assert(policyGuardianSigner.customPolicyGuardianTimelocks(safeInstance) == 7 days);
    }

    function testCannotSetPolicyGuardianTimelockBelowMin() public {
        // Transaction params
        address to = address(policyGuardianSigner);
        uint256 value = 0;
        bytes memory data = abi.encodeWithSelector(policyGuardianSigner.setPolicyGuardianTimelock.selector, 14 minutes);

        // Safe.execTransaction expecting revert
        _execTransaction(to, value, data, TestExecTransactionOptions(false, true, false, false, false, false, false, 0));
    }

    function testCannotSetPolicyGuardianTimelockAboveMax() public {
        // Transaction params
        address to = address(policyGuardianSigner);
        uint256 value = 0;
        bytes memory data = abi.encodeWithSelector(policyGuardianSigner.setPolicyGuardianTimelock.selector, 181 days);

        // Safe.execTransaction expecting revert
        _execTransaction(to, value, data, TestExecTransactionOptions(false, true, false, false, false, false, false, 0));
    }

    function testExecTransaction() public {
        // Send ETH to Safe
        vm.deal(address(safeInstance), 1337);

        // Transaction params
        address to = address(this);
        uint256 value = 1337;
        bytes memory data = abi.encodeWithSelector(this.sampleWalletOnlyFunction.selector, 22222222);

        // Safe.execTransaction expecting revert
        _execTransaction(to, value, data, TestExecTransactionOptions(false, false, true, false, false, false, false, 0));
        _execTransaction(to, value, data, TestExecTransactionOptions(false, false, false, true, false, false, false, 0));
        _execTransaction(to, value, data, TestExecTransactionOptions(false, false, false, false, true, false, false, 0));

        // Safe.execTransaction
        _execTransaction(to, value, data);

        // Assert TX succeeded
        assert(dummy == 22222222);
    }

    function testExecTransactionUsingSecondaryPolicyGuardian() public {
        // Set the secondary policy guardian
        testSetSecondaryPolicyGuardian();

        // Send ETH to Safe
        vm.deal(address(safeInstance), 1337);

        // Transaction params
        address to = address(this);
        uint256 value = 1337;
        bytes memory data = abi.encodeWithSelector(this.sampleWalletOnlyFunction.selector, 22222222);

        // Safe.execTransaction expecting revert
        _execTransaction(to, value, data, TestExecTransactionOptions(true, false, true, false, false, false, false, 0));
        _execTransaction(to, value, data, TestExecTransactionOptions(true, false, false, true, false, false, false, 0));
        _execTransaction(to, value, data, TestExecTransactionOptions(true, false, false, false, true, false, false, 0));

        // Safe.execTransaction
        _execTransaction(to, value, data, TestExecTransactionOptions(true, false, false, false, false, false, false, 0));

        // Assert TX succeeded
        assert(dummy == 22222222);
    }

    function _getUserSignaturesAndOverlyingPolicyGuardianSignature(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 overlyingSignaturesBeforePolicyGuardian,
        bool useSecondaryPolicyGuardian
    ) internal view returns (
        bytes memory userSignature1,
        bytes memory userSignature2,
        bytes memory policyGuardianOverlyingSignaturePointer,
        bytes memory policyGuardianOverlyingSignatureData
    ) {
        // Generate data hash for the new transaction
        bytes32 txHash = keccak256(safeInstance.encodeTransactionData(to, value, data, operation, 0, 0, 0, address(0), payable(address(0)), safeInstance.nonce()));

        // Generate user signing device signature #1
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE, txHash);
        userSignature1 = abi.encodePacked(r, s, v);

        // Generate user signing device signature #2
        (v, r, s) = vm.sign(BOB_PRIVATE, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", txHash)));
        userSignature2 = abi.encodePacked(r, s, v + 4);

        // Generate underlying/actual policy guardian signature
        (v, r, s) = vm.sign(useSecondaryPolicyGuardian ? SECONDARY_POLICY_GUARDIAN_PRIVATE : POLICY_GUARDIAN_PRIVATE, txHash);
        bytes memory policyGuardianUnderlyingSignature = abi.encodePacked(r, s, v);

        // Generate overlying policy guardian smart contract signature
        policyGuardianOverlyingSignaturePointer = abi.encodePacked(
            bytes32(uint256(uint160(address(policyGuardianSigner)))),
            uint256((overlyingSignaturesBeforePolicyGuardian + 1) * 65),
            uint8(0)
        );
        policyGuardianOverlyingSignatureData = abi.encodePacked(
            uint256(65),
            policyGuardianUnderlyingSignature
        );
    }

    event PolicyGuardianDisabledOnSafe(Safe indexed safe, bool withoutPolicyGuardian);
    event PolicyGuardianTimelockChanged(Safe indexed safe, uint256 policyGuardianTimelock);

    struct TestExecTransactionOptions {
        bool useSecondaryPolicyGuardian;
        bool expectRevert;
        bool testInvalidUserSignature;
        bool testInvalidPolicyGuardianSignature;
        bool testShortPolicyGuardianSignature;
        bool expectEmitPolicyGuardianDisabledOnSafe;
        bool expectEmitPolicyGuardianTimelockChanged;
        uint256 newPolicyGuardianTimelock;
    }

    function _execTransaction(address to, uint256 value, bytes memory data, TestExecTransactionOptions memory options) internal {
        // Get signature data:
        bytes memory packedOverlyingSignatures;
        {
            // Get signatures
            (bytes memory userSignature1, bytes memory userSignature2, bytes memory policyGuardianOverlyingSignaturePointer, bytes memory policyGuardianOverlyingSignatureData) = _getUserSignaturesAndOverlyingPolicyGuardianSignature(to, value, data, Enum.Operation.Call, 1, options.useSecondaryPolicyGuardian);
            if (options.testInvalidUserSignature) userSignature1[50] = userSignature1[50] == bytes1(0x55) ? bytes1(0x66) : bytes1(0x55);
            else if (options.testInvalidPolicyGuardianSignature) policyGuardianOverlyingSignatureData[50] = policyGuardianOverlyingSignatureData[50] == bytes1(0x55) ? bytes1(0x66) : bytes1(0x55);
            else if (options.testShortPolicyGuardianSignature) policyGuardianOverlyingSignatureData = abi.encodePacked(uint256(64), hex'12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678');

            // Pack user signatures
            bytes memory packedUserSignatures = BOB > ALICE ? abi.encodePacked(userSignature1, userSignature2) : abi.encodePacked(userSignature2, userSignature1);

            // Generate overlying WaymontSafeAdvancedSigner signature
            bytes memory advancedSignerOverlyingSignaturePointer = abi.encodePacked(
                bytes32(uint256(uint160(address(advancedSignerInstance)))),
                uint256((65 * 2) + 32 + (options.testShortPolicyGuardianSignature ? 64 : 65)),
                uint8(0)
            );
            bytes memory advancedSignerOverlyingSignatureData = abi.encodePacked(
                uint256(65 * 2),
                packedUserSignatures
            );

            // Pack all overlying signatures (in correct order)
            if (address(advancedSignerInstance) > address(policyGuardianSigner)) {
                packedOverlyingSignatures = abi.encodePacked(policyGuardianOverlyingSignaturePointer, advancedSignerOverlyingSignaturePointer, policyGuardianOverlyingSignatureData, advancedSignerOverlyingSignatureData);
            } else {
                packedOverlyingSignatures = abi.encodePacked(advancedSignerOverlyingSignaturePointer, policyGuardianOverlyingSignaturePointer, policyGuardianOverlyingSignatureData, advancedSignerOverlyingSignatureData);
            }
        }

        // Safe.execTransaction
        if (options.testInvalidUserSignature) vm.expectRevert("GS026");
        else if (options.testInvalidPolicyGuardianSignature) vm.expectRevert("Invalid policy guardian signature.");
        else if (options.testShortPolicyGuardianSignature) vm.expectRevert("Invalid signature length.");
        else if (options.expectRevert) vm.expectRevert("GS013");
        else if (options.expectEmitPolicyGuardianDisabledOnSafe) {
            vm.expectEmit(true, false, false, true, address(policyGuardianSigner));
            emit PolicyGuardianDisabledOnSafe(safeInstance, false);
        } else if (options.expectEmitPolicyGuardianTimelockChanged) {
            vm.expectEmit(true, false, false, true, address(policyGuardianSigner));
            emit PolicyGuardianTimelockChanged(safeInstance, options.newPolicyGuardianTimelock);
        }
        safeInstance.execTransaction(to, value, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), packedOverlyingSignatures);
    }

    function _execTransaction(address to, uint256 value, bytes memory data) internal {
        _execTransaction(to, value, data, TestExecTransactionOptions(false, false, false, false, false, false, false, 0));
    }

    event DisablePolicyGuardianQueued(Safe indexed safe);
    event DisablePolicyGuardianUnqueued(Safe indexed safe);

    function testDisablePolicyGuardianWithoutPolicyGuardian() public {
        _testDisablePolicyGuardianWithoutPolicyGuardian(false);
    }

    function testUnqueueDisablePolicyGuardian() public {
        _testDisablePolicyGuardianWithoutPolicyGuardian(true);
    }

    function _testDisablePolicyGuardianWithoutPolicyGuardian(bool testUnqueueingInstead) internal {
        // Generate underlying hash + overlying signed data (to queue disabling)
        uint256 signerNonce = policyGuardianSigner.nonces(safeInstance);
        bytes32 underlyingHash = keccak256(abi.encode(QUEUE_DISABLE_POLICY_GUARDIAN_TYPEHASH, safeInstance, signerNonce));
        bytes32 txHash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), policyGuardianSigner.domainSeparator(), underlyingHash));

        // Generate user signing device signature #1 (to queue disabling)
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE, txHash);
        bytes memory userSignature1 = abi.encodePacked(r, s, v);

        // Generate user signing device signature #2 (to queue disabling)
        (v, r, s) = vm.sign(BOB_PRIVATE, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", txHash)));
        bytes memory userSignature2 = abi.encodePacked(r, s, v + 4);

        // Generate overlying policy guardian smart contract signature (used both to queue disabling and to execute disabling)
        bytes memory policyGuardianOverlyingSignaturePointer = abi.encodePacked(
            bytes32(uint256(uint160(address(policyGuardianSigner)))),
            uint256(2 * 65),
            uint8(0)
        );
        bytes memory policyGuardianOverlyingSignatureData = abi.encodePacked(
            uint256(65),
            hex'0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        );

        // Pack user signatures (to queue disabling)
        bytes memory packedUserSignatures = BOB > ALICE ? abi.encodePacked(userSignature1, userSignature2) : abi.encodePacked(userSignature2, userSignature1);

        // Generate overlying WaymontSafeAdvancedSigner signature (to queue disabling)
        bytes memory advancedSignerOverlyingSignaturePointer = abi.encodePacked(
            bytes32(uint256(uint160(address(advancedSignerInstance)))),
            uint256((65 * 2) + 32 + 65),
            uint8(0)
        );
        bytes memory advancedSignerOverlyingSignatureData = abi.encodePacked(
            uint256(65 * 2),
            packedUserSignatures
        );

        // Pack all overlying signatures in correct order (to queue disabling)
        bytes memory packedOverlyingSignaturesForQueueing;

        if (address(advancedSignerInstance) > address(policyGuardianSigner)) {
            packedOverlyingSignaturesForQueueing = abi.encodePacked(policyGuardianOverlyingSignaturePointer, advancedSignerOverlyingSignaturePointer, policyGuardianOverlyingSignatureData, advancedSignerOverlyingSignatureData);
        } else {
            packedOverlyingSignaturesForQueueing = abi.encodePacked(advancedSignerOverlyingSignaturePointer, policyGuardianOverlyingSignaturePointer, policyGuardianOverlyingSignatureData, advancedSignerOverlyingSignatureData);
        }

        // Generate underlying hash + overlying signed data (to execute disabling)
        underlyingHash = keccak256(abi.encode(DISABLE_POLICY_GUARDIAN_TYPEHASH, safeInstance, signerNonce));
        txHash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), policyGuardianSigner.domainSeparator(), underlyingHash));

        // Generate user signing device signature #1 (to execute disabling)
        (v, r, s) = vm.sign(ALICE_PRIVATE, txHash);
        userSignature1 = abi.encodePacked(r, s, v);

        // Generate user signing device signature #2 (to execute disabling)
        (v, r, s) = vm.sign(BOB_PRIVATE, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", txHash)));
        userSignature2 = abi.encodePacked(r, s, v + 4);

        // Pack user signatures
        packedUserSignatures = BOB > ALICE ? abi.encodePacked(userSignature1, userSignature2) : abi.encodePacked(userSignature2, userSignature1);

        // Generate overlying WaymontSafeAdvancedSigner signature
        advancedSignerOverlyingSignaturePointer = abi.encodePacked(
            bytes32(uint256(uint160(address(advancedSignerInstance)))),
            uint256((65 * 2) + 32 + 65),
            uint8(0)
        );
        advancedSignerOverlyingSignatureData = abi.encodePacked(
            uint256(65 * 2),
            packedUserSignatures
        );

        {
            // Pack all overlying signatures in correct order (to execute disabling)
            bytes memory packedOverlyingSignatures;

            if (address(advancedSignerInstance) > address(policyGuardianSigner)) {
                packedOverlyingSignatures = abi.encodePacked(policyGuardianOverlyingSignaturePointer, advancedSignerOverlyingSignaturePointer, policyGuardianOverlyingSignatureData, advancedSignerOverlyingSignatureData);
            } else {
                packedOverlyingSignatures = abi.encodePacked(advancedSignerOverlyingSignaturePointer, policyGuardianOverlyingSignaturePointer, policyGuardianOverlyingSignatureData, advancedSignerOverlyingSignatureData);
            }

            // Fail to disable the policy guardian since not yet queued
            vm.expectRevert("Action not queued.");
            policyGuardianSigner.disablePolicyGuardianWithoutPolicyGuardian(safeInstance, packedOverlyingSignatures);
        }

        // Queue the disabling of the policy guardian
        vm.expectEmit(true, false, false, false, address(policyGuardianSigner));
        emit DisablePolicyGuardianQueued(safeInstance);
        policyGuardianSigner.queueDisablePolicyGuardian(safeInstance, packedOverlyingSignaturesForQueueing);
        assert(policyGuardianSigner.nonces(safeInstance) == ++signerNonce);
        assert(policyGuardianSigner.disablePolicyGuardianQueueTimestamps(safeInstance) == block.timestamp);

        // If testing unqueueing
        if (testUnqueueingInstead) {
            // Generate underlying hash + overlying signed data (to queue disabling)
            underlyingHash = keccak256(abi.encode(UNQUEUE_DISABLE_POLICY_GUARDIAN_TYPEHASH, safeInstance, signerNonce));
            txHash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), policyGuardianSigner.domainSeparator(), underlyingHash));

            // Generate user signing device signature #1 (to queue disabling)
            (v, r, s) = vm.sign(ALICE_PRIVATE, txHash);
            userSignature1 = abi.encodePacked(r, s, v);

            // Generate user signing device signature #2 (to queue disabling)
            (v, r, s) = vm.sign(BOB_PRIVATE, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", txHash)));
            userSignature2 = abi.encodePacked(r, s, v + 4);

            // Pack user signatures (to queue disabling)
            packedUserSignatures = BOB > ALICE ? abi.encodePacked(userSignature1, userSignature2) : abi.encodePacked(userSignature2, userSignature1);

            // Generate overlying WaymontSafeAdvancedSigner signature (to queue disabling)
            advancedSignerOverlyingSignatureData = abi.encodePacked(
                uint256(65 * 2),
                packedUserSignatures
            );

            // Pack all overlying signatures in correct order (to queue disabling)
            bytes memory packedOverlyingSignaturesForUnqueueing;

            if (address(advancedSignerInstance) > address(policyGuardianSigner)) {
                packedOverlyingSignaturesForUnqueueing = abi.encodePacked(policyGuardianOverlyingSignaturePointer, advancedSignerOverlyingSignaturePointer, policyGuardianOverlyingSignatureData, advancedSignerOverlyingSignatureData);
            } else {
                packedOverlyingSignaturesForUnqueueing = abi.encodePacked(advancedSignerOverlyingSignaturePointer, policyGuardianOverlyingSignaturePointer, policyGuardianOverlyingSignatureData, advancedSignerOverlyingSignatureData);
            }

            // Unqueue the disabling of the policy guardian
            vm.expectEmit(true, false, false, false, address(policyGuardianSigner));
            emit DisablePolicyGuardianUnqueued(safeInstance);
            policyGuardianSigner.unqueueDisablePolicyGuardian(safeInstance, packedOverlyingSignaturesForUnqueueing);
            assert(policyGuardianSigner.nonces(safeInstance) == ++signerNonce);
            assert(policyGuardianSigner.disablePolicyGuardianQueueTimestamps(safeInstance) == 0);
        }

        // AGAIN WITH NEW NONCE: Generate underlying hash + overlying signed data (to execute disabling)
        underlyingHash = keccak256(abi.encode(DISABLE_POLICY_GUARDIAN_TYPEHASH, safeInstance, signerNonce));
        txHash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), policyGuardianSigner.domainSeparator(), underlyingHash));

        // AGAIN WITH NEW NONCE: Generate user signing device signature #1 (to execute disabling)
        (v, r, s) = vm.sign(ALICE_PRIVATE, txHash);
        userSignature1 = abi.encodePacked(r, s, v);

        // AGAIN WITH NEW NONCE: Generate user signing device signature #2 (to execute disabling)
        (v, r, s) = vm.sign(BOB_PRIVATE, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", txHash)));
        userSignature2 = abi.encodePacked(r, s, v + 4);

        // AGAIN WITH NEW NONCE: Pack user signatures
        packedUserSignatures = BOB > ALICE ? abi.encodePacked(userSignature1, userSignature2) : abi.encodePacked(userSignature2, userSignature1);

        // AGAIN WITH NEW NONCE: Generate overlying WaymontSafeAdvancedSigner signature
        advancedSignerOverlyingSignatureData = abi.encodePacked(
            uint256(65 * 2),
            packedUserSignatures
        );

        // AGAIN WITH NEW NONCE: Pack all overlying signatures in correct order (to execute disabling)
        bytes memory packedOverlyingSignatures2;

        if (address(advancedSignerInstance) > address(policyGuardianSigner)) {
            packedOverlyingSignatures2 = abi.encodePacked(policyGuardianOverlyingSignaturePointer, advancedSignerOverlyingSignaturePointer, policyGuardianOverlyingSignatureData, advancedSignerOverlyingSignatureData);
        } else {
            packedOverlyingSignatures2 = abi.encodePacked(advancedSignerOverlyingSignaturePointer, policyGuardianOverlyingSignaturePointer, policyGuardianOverlyingSignatureData, advancedSignerOverlyingSignatureData);
        }

        // Wait almost for the timelock to pass
        vm.warp(block.timestamp + 14 days - 1 seconds);

        // Only run the following negative test if we aren't testing unqueueing
        if (!testUnqueueingInstead) {
            // Fail to disable the policy guardian
            vm.expectRevert("Timelock not satisfied.");
            policyGuardianSigner.disablePolicyGuardianWithoutPolicyGuardian(safeInstance, packedOverlyingSignatures2);
        }

        // Wait for the timelock to pass in full
        vm.warp(block.timestamp + 1 seconds);

        // Expect success unless testUnqueueingInstead
        if (testUnqueueingInstead) {
            vm.expectRevert("Action not queued.");
            policyGuardianSigner.disablePolicyGuardianWithoutPolicyGuardian(safeInstance, packedOverlyingSignatures2);
        } else {
            // Disable the policy guardian
            vm.expectEmit(true, false, false, true, address(policyGuardianSigner));
            emit PolicyGuardianDisabledOnSafe(safeInstance, true);
            policyGuardianSigner.disablePolicyGuardianWithoutPolicyGuardian(safeInstance, packedOverlyingSignatures2);
            assert(policyGuardianSigner.nonces(safeInstance) == ++signerNonce);
            assert(policyGuardianSigner.policyGuardianDisabled(safeInstance));
        }
    }

    event ExecutionSuccess(bytes32 indexed txHash);
    event ExecutionFailure(bytes32 indexed txHash);

    struct TestSocialRecoveryOptions {
        bool testSignatureNotQueued;
        bool testExpiringQueuedSignatures;
        bool testRevertingUnderlyingTransaction;
        bool expectPolicyGuardianSignatureValidationFailure;
    }

    function testSocialRecovery() public {
        _testSocialRecovery(TestSocialRecoveryOptions(false, false, false, false));
    }

    function testCannotSocialRecoveryIfNotAllSignaturesAreQueued() public {
        _testSocialRecovery(TestSocialRecoveryOptions(true, false, false, false));
    }

    function testCannotSocialRecoveryAfterQueuedSignaturesExpired() public {
        _testSocialRecovery(TestSocialRecoveryOptions(false, true, false, false));
    }

    function testCannotSocialRecoveryWithRevertingUnderlyingTransaction() public {
        _testSocialRecovery(TestSocialRecoveryOptions(false, false, true, false));
    }

    function testCannotSocialRecoveryWithNonfunctionalPolicyGuardianSigner() public {
        // Create mock WaymontSafePolicyGuardianSigner
        WaymontSafePolicyGuardianSigner mockPolicyGuardianSigner = WaymontSafePolicyGuardianSigner(address(7539));
        vm.mockCall(
            address(mockPolicyGuardianSigner),
            abi.encodeWithSelector(policyGuardianSigner.isValidSignature.selector),
            abi.encode(bytes4(0xffffffff))
        );

        // WaymontSafeTimelockedRecoveryModule params (use alternate deploymentNonce)
        address[] memory recoverySigners = new address[](3);
        recoverySigners[0] = FRIEND_ONE;
        recoverySigners[1] = FRIEND_TWO;
        recoverySigners[2] = FRIEND_THREE;
        uint256 recoveryThreshold = 2;
        uint256 recoverySigningTimelock = 3 days;

        // Predict WaymontSafeTimelockedRecoveryModule address
        bytes32 salt = bytes32(uint256(9117));
        address predictedTimelockedRecoveryModuleInstanceAddress = Clones.predictDeterministicAddress(waymontSafeFactory.timelockedRecoveryModuleImplementation(), salt, address(this));
        
        // Transaction params
        address to = address(safeInstance);
        uint256 value = 0;
        bytes memory data = abi.encodeWithSelector(safeInstance.enableModule.selector, predictedTimelockedRecoveryModuleInstanceAddress);

        // Safe.execTransaction
        _execTransaction(to, value, data, TestExecTransactionOptions(false, false, false, false, false, false, false, 0));

        // Assert TX succeeded
        assert(safeInstance.isModuleEnabled(predictedTimelockedRecoveryModuleInstanceAddress));

        // Deploy WaymontSafeTimelockedRecoveryModule
        timelockedRecoveryModuleInstance = WaymontSafeTimelockedRecoveryModule(payable(Clones.cloneDeterministic(waymontSafeFactory.timelockedRecoveryModuleImplementation(), salt)));
        timelockedRecoveryModuleInstance.initialize(safeInstance, recoverySigners, recoveryThreshold, recoverySigningTimelock, mockPolicyGuardianSigner);

        // Test social recovery
        _testSocialRecovery(TestSocialRecoveryOptions(false, false, false, true));
    }

    function testSocialRecoveryWithoutPolicyGuardianSigner() public {
        // WaymontSafeTimelockedRecoveryModule params (use alternate deploymentNonce)
        address[] memory recoverySigners = new address[](3);
        recoverySigners[0] = FRIEND_ONE;
        recoverySigners[1] = FRIEND_TWO;
        recoverySigners[2] = FRIEND_THREE;
        uint256 recoveryThreshold = 2;
        uint256 recoverySigningTimelock = 3 days;
        bool requirePolicyGuardianForRecovery = false;
        uint256 alternateDeploymentNonce = 5555;

        // Predict WaymontSafeTimelockedRecoveryModule address
        bytes32 salt = keccak256(abi.encode(safeInstance, recoverySigners, recoveryThreshold, recoverySigningTimelock, requirePolicyGuardianForRecovery, alternateDeploymentNonce));
        address predictedTimelockedRecoveryModuleInstanceAddress = Clones.predictDeterministicAddress(waymontSafeFactory.timelockedRecoveryModuleImplementation(), salt, address(waymontSafeFactory));
        
        // Transaction params
        address to = address(safeInstance);
        uint256 value = 0;
        bytes memory data = abi.encodeWithSelector(safeInstance.enableModule.selector, predictedTimelockedRecoveryModuleInstanceAddress);

        // Safe.execTransaction
        _execTransaction(to, value, data, TestExecTransactionOptions(false, false, false, false, false, false, false, 0));

        // Assert TX succeeded
        assert(safeInstance.isModuleEnabled(address(timelockedRecoveryModuleInstance)));

        // Deploy WaymontSafeTimelockedRecoveryModule
        timelockedRecoveryModuleInstance = waymontSafeFactory.createTimelockedRecoveryModule(
            safeInstance,
            recoverySigners,
            recoveryThreshold,
            recoverySigningTimelock,
            requirePolicyGuardianForRecovery,
            alternateDeploymentNonce
        );

        // Test social recovery
        _testSocialRecovery(TestSocialRecoveryOptions(false, false, false, false));
    }

    function _testSocialRecovery(TestSocialRecoveryOptions memory options) internal {
        // Underlying transaction params
        address to = address(advancedSignerInstance);
        bytes memory data = abi.encodeWithSelector(advancedSignerInstance.swapOwner.selector, options.testRevertingUnderlyingTransaction ? ALICE : BOB, JOE, JOE_REPLACEMENT);

        // Standard params
        uint256 value = 0;
        Enum.Operation operation = Enum.Operation.Call;
        
        // Generate data hash for underlying transaction
        uint256 moduleNonce = timelockedRecoveryModuleInstance.nonce();
        bytes32 underlyingHash = keccak256(abi.encode(EXEC_TRANSACTION_TYPEHASH, safeInstance, moduleNonce, to, value, keccak256(data), operation));
        bytes32 txHash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), timelockedRecoveryModuleInstance.domainSeparator(), underlyingHash));

        // To queue signature #1:
        bytes memory friendSignature1;
        {
            // Generate recovery guardian signature #1
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(FRIEND_ONE_PRIVATE, txHash);
            friendSignature1 = abi.encodePacked(r, s, v);

            // Generate policy guardian signature for recovery guardian #1 for queueSignature
            bytes32 queueSignatureUnderlyingHash = keccak256(abi.encode(QUEUE_SIGNATURE_TYPEHASH, keccak256(friendSignature1)));
            bytes32 queueSignatureMsgHash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), timelockedRecoveryModuleInstance.domainSeparator(), queueSignatureUnderlyingHash));
            (v, r, s) = vm.sign(POLICY_GUARDIAN_PRIVATE, queueSignatureMsgHash);
            bytes memory friend1PolicyGuardianSignature = abi.encodePacked(r, s, v);

            // Expect revert if given wrong underlyingHash
            vm.expectRevert("Invalid signature.");
            timelockedRecoveryModuleInstance.queueSignature(bytes32(uint256(underlyingHash) + 1), friendSignature1, friend1PolicyGuardianSignature);

            // Expect revert if given wrong signature
            vm.expectRevert("Invalid signature.");
            bytes memory friendSignature1Corrupted = abi.encodePacked(friendSignature1);
            friendSignature1Corrupted[50] = friendSignature1Corrupted[50] == bytes1(0x55) ? bytes1(0x66) : bytes1(0x55);
            timelockedRecoveryModuleInstance.queueSignature(underlyingHash, friendSignature1Corrupted, friend1PolicyGuardianSignature);

            // If option is set, test nonfunctional WaymontSafePolicyGuardianSigner
            if (options.expectPolicyGuardianSignatureValidationFailure) {
                vm.expectRevert("Policy guardian signature validation failed.");
                timelockedRecoveryModuleInstance.queueSignature(underlyingHash, friendSignature1, friend1PolicyGuardianSignature);
                return;
            }

            // Queue signature #1
            timelockedRecoveryModuleInstance.queueSignature(underlyingHash, friendSignature1, friend1PolicyGuardianSignature);
            assert(timelockedRecoveryModuleInstance.pendingSignatures(keccak256(friendSignature1)) == block.timestamp);

            // Expect revert if signature already queued
            vm.expectRevert("Signature already queued.");
            timelockedRecoveryModuleInstance.queueSignature(underlyingHash, friendSignature1, friend1PolicyGuardianSignature);
        }

        // Prep to queue signature #2 but don't queue yet:
        bytes memory friendSignature2;
        {
            // Generate user signing device signature #2
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(FRIEND_TWO_PRIVATE, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", txHash)));
            friendSignature2 = abi.encodePacked(r, s, v + 4);

            // Generate policy guardian signature for recovery guardian #2 for queueSignature
            bytes32 queueSignatureUnderlyingHash = keccak256(abi.encode(QUEUE_SIGNATURE_TYPEHASH, keccak256(friendSignature2)));
            bytes32 queueSignatureMsgHash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), timelockedRecoveryModuleInstance.domainSeparator(), queueSignatureUnderlyingHash));
            (v, r, s) = vm.sign(POLICY_GUARDIAN_PRIVATE, queueSignatureMsgHash);
            bytes memory friend2PolicyGuardianSignature = abi.encodePacked(r, s, v);

            // Queue signature #2 (unless we are testing not queueing it)
            if (!options.testSignatureNotQueued) {
                timelockedRecoveryModuleInstance.queueSignature(underlyingHash, friendSignature2, friend2PolicyGuardianSignature);
                assert(timelockedRecoveryModuleInstance.pendingSignatures(keccak256(friendSignature2)) == block.timestamp);
            }
        }

        // Pack friend signatures
        bytes memory packedFriendSignatures = FRIEND_TWO > FRIEND_ONE ? abi.encodePacked(friendSignature1, friendSignature2) : abi.encodePacked(friendSignature2, friendSignature1);

        // Generate policy guardian signature for execTransaction
        bytes memory finalPolicyGuardianSignature;
        {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(POLICY_GUARDIAN_PRIVATE, txHash);
            finalPolicyGuardianSignature = abi.encodePacked(r, s, v);
        }

        // Wait almost for the timelock to pass
        vm.warp(block.timestamp + 3 days - 1 seconds);

        // WaymontSafeTimelockedRecoveryModule.execTransaction
        vm.expectRevert("Timelock not satisfied.");
        timelockedRecoveryModuleInstance.execTransaction(to, value, data, operation, packedFriendSignatures, finalPolicyGuardianSignature);

        // Wait for the timelock to pass in full
        vm.warp(block.timestamp + 1 seconds);

        // Switch logic based on test case
        if (options.testSignatureNotQueued) {
            // Ensure cannot execute without queueing signature #2
            vm.expectRevert("Signature not queued.");
            timelockedRecoveryModuleInstance.execTransaction(to, value, data, operation, packedFriendSignatures, finalPolicyGuardianSignature);
        } else if (options.testExpiringQueuedSignatures) {
            // Wait for the signature to expire
            vm.warp(block.timestamp + 1 weeks + 1 seconds);

            // WaymontSafeTimelockedRecoveryModule.execTransaction
            vm.expectRevert("Queued signatures are only usable for 1 week until they expire.");
            timelockedRecoveryModuleInstance.execTransaction(to, value, data, operation, packedFriendSignatures, finalPolicyGuardianSignature);
        } else {
            // WaymontSafeTimelockedRecoveryModule.execTransaction
            vm.expectEmit(true, false, false, false, address(timelockedRecoveryModuleInstance));
            if (options.testRevertingUnderlyingTransaction) emit ExecutionFailure(txHash);
            else emit ExecutionSuccess(txHash);
            timelockedRecoveryModuleInstance.execTransaction(to, value, data, operation, packedFriendSignatures, finalPolicyGuardianSignature);

            // Assert TX succeeded
            assert(timelockedRecoveryModuleInstance.nonce() == moduleNonce + 1);

            if (!options.testRevertingUnderlyingTransaction) {
                assert(advancedSignerInstance.isOwner(JOE_REPLACEMENT));
                assert(!advancedSignerInstance.isOwner(JOE));
            }
        }
    }

    function testCannotEmitSignatureQueuedFromMaliciousModule() public {
        // Mock call to WaymontSafeTimelockedRecoveryModule.safe at address 0xBAD
        vm.mockCall(
            address(0xBAD),
            abi.encodeWithSignature("safe()"),
            abi.encode(safeInstance)
        );
        assert(address(WaymontSafeTimelockedRecoveryModule(address(0xBAD)).safe()) == address(safeInstance));

        // Fail to call WaymontSafeFactory.emitSignatureQueued
        vm.prank(address(0xBAD));
        vm.expectRevert("The Safe does not have this Waymont module enabled.");
        waymontSafeFactory.emitSignatureQueued(JOE, 0x1234123412341234123412341234123412341234123412341234123412341234);
    }

    function sampleWalletOnlyFunction(uint256 arg) public payable {
        // Example function to be called by the Safe
        assert(msg.sender == address(safeInstance));
        assert(msg.value == 1337);
        dummy = arg;
    }
}
