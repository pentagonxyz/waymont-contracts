// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import "lib/openzeppelin-contracts/contracts/proxy/Clones.sol";

import "lib/safe-contracts/contracts/Safe.sol";
import "lib/safe-contracts/contracts/common/Enum.sol";
import "lib/safe-contracts/contracts/handler/CompatibilityFallbackHandler.sol";
import "lib/safe-contracts/contracts/proxies/SafeProxyFactory.sol";

import "../src/WaymontSafeFactory.sol";
import "../src/WaymontSafePolicyGuardianSigner.sol";
import "../src/WaymontSafeAdvancedSigner.sol";
import "../src/WaymontSafeTimelockedRecoveryModule.sol";

contract WaymontSafeFactoryTest is Test {
    // Typehashes copied from contracts
    bytes32 private constant QUEUE_SIGNATURE_TYPEHASH = 0x56f7b592467518044b02545f1b4518cd51c746d04978afb6a3b9d05895cb79cf;
    bytes32 private constant EXEC_TRANSACTION_TYPEHASH = 0x60c023ac5b12ccfb6346228598efbab110f9f06cd102f7009adbf0dbb8b8c240;
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
        assert(WaymontSafeAdvancedSigner(waymontSafeFactory.timelockedRecoveryModuleImplementation()).getThreshold() == 1);

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
        assert(signatures.length == signers.length);
        assert(signatures.length > 0);
        if (signatures.length == 1) return signatures[0];

        for (uint256 i = 1; i < signers.length; i++) {
            address signer = signers[i];
            bytes memory signature = signatures[i];
            uint256 j;
            for (j = i; j > 0 && signer < signers[j - 1]; j--) {
                signers[j] = signers[j - 1];
                signatures[j] = signatures[j - 1];
            }
            signers[j] = signer;
            signatures[j] = signature;
        }

        packedOrderedSignatures = signatures[0];
        for (uint256 i = 1; i < signatures.length; i++) packedOrderedSignatures = abi.encodePacked(packedOrderedSignatures, signatures[i]);
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
        uint256 initialOverlyingThreshold = underlyingThreshold + 1;
        address[] memory initialOverlyingSigners = new address[](initialOverlyingThreshold);
        initialOverlyingSigners[0] = address(policyGuardianSigner);
        for (uint256 i = 0; i < underlyingThreshold; i++) initialOverlyingSigners[i + 1] = underlyingOwners[i];
        
        // Deploy Safe (enabling the module simultaneously)
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

        // Predict WaymontSafeAdvancedSigner address
        bytes32 salt = keccak256(abi.encode(safeInstance, underlyingOwners, underlyingThreshold, deploymentNonce));
        address predictedAdvancedSignerInstanceAddress = Clones.predictDeterministicAddress(waymontSafeFactory.advancedSignerImplementation(), salt, address(waymontSafeFactory));

        // Try and fail to deploy WaymontSafeAdvancedSigner (since it has not yet been added to the Safe)
        vm.expectRevert("The Safe is not owned by this Waymont signer contract.");
        advancedSignerInstance = waymontSafeFactory.createAdvancedSigner(safeInstance, underlyingOwners, underlyingThreshold, deploymentNonce);

        // Add WaymontSafeAdvancedSigner to Safe as signer
        {
            // Set params for execTransaction
            address to = address(safeInstance);
            uint256 value = 0;
            bytes memory data = abi.encodeWithSelector(safeInstance.swapOwner.selector, initialOverlyingSigners[0], initialOverlyingSigners[1], predictedAdvancedSignerInstanceAddress);

            // Get signatures
            (bytes memory userSignature1, bytes memory userSignature2, bytes memory policyGuardianOverlyingSignaturePointer, bytes memory policyGuardianOverlyingSignatureData) = _getUserSignaturesAndOverlyingPolicyGuardianSignature(to, value, data, 2);

            // Order and pack all overlying signatures
            address[] memory signers = new address[](3);
            signers[0] = address(policyGuardianSigner);
            signers[1] = ALICE;
            signers[2] = BOB;
            bytes[] memory signatures = new bytes[](3);
            signatures[0] = policyGuardianOverlyingSignaturePointer;
            signatures[1] = userSignature1;
            signatures[2] = userSignature2;
            bytes memory packedOverlyingSignatures = abi.encodePacked(_packSignaturesOrderedBySigner(signatures, signers), policyGuardianOverlyingSignatureData);

            // Safe.execTransaction
            safeInstance.execTransaction(to, value, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), packedOverlyingSignatures);
        }

        // Assert signers modified correctly
        {
            address[] memory tempOverlyingSigners = new address[](3);
            tempOverlyingSigners[0] = address(policyGuardianSigner);
            tempOverlyingSigners[1] = predictedAdvancedSignerInstanceAddress;
            tempOverlyingSigners[2] = BOB;
            for (uint256 i = 0; i < tempOverlyingSigners.length; i++) assert(safeInstance.isOwner(tempOverlyingSigners[i]));
            assert(safeInstance.getOwners().length == tempOverlyingSigners.length);
            assert(safeInstance.getThreshold() == initialOverlyingThreshold);
        }

        // Deploy WaymontSafeAdvancedSigner (now that it has been added to the Safe)
        advancedSignerInstance = waymontSafeFactory.createAdvancedSigner(safeInstance, underlyingOwners, underlyingThreshold, deploymentNonce);

        // Try and fail to re-initialize the WaymontSafeAdvancedSigner instance
        vm.expectRevert("GS200");
        advancedSignerInstance.initialize(safeInstance, underlyingOwners, underlyingThreshold);

        // Assert deployed correctly
        assert(address(advancedSignerInstance) == predictedAdvancedSignerInstanceAddress);
        for (uint256 i = 0; i < underlyingOwners.length; i++) assert(advancedSignerInstance.isOwner(underlyingOwners[i]));
        assert(address(advancedSignerInstance.safe()) == address(safeInstance));
        assert(advancedSignerInstance.getThreshold() == underlyingThreshold);

        // Set new threshold for after the extra signer will be removed (if there were multiple signers, decrease this by 1 with each removal until it gets down to 2)
        uint256 finalOverlyingThreshold = 2;

        // Remove extra signers from Safe (only 1 in this case)
        {
            // Set params for execTransaction
            address to = address(safeInstance);
            uint256 value = 0;
            bytes memory data = abi.encodeWithSelector(safeInstance.removeOwner.selector, address(advancedSignerInstance), initialOverlyingSigners[2], finalOverlyingThreshold);

            // Get signatures
            (bytes memory userSignature1, bytes memory userSignature2, bytes memory policyGuardianOverlyingSignaturePointer, bytes memory policyGuardianOverlyingSignatureData) = _getUserSignaturesAndOverlyingPolicyGuardianSignature(to, value, data, 2);

            // Pack user signatures
            bytes memory packedUserSignatures = abi.encodePacked(userSignature1, userSignature2);

            // Generate overlying WaymontSafeAdvancedSigner signature
            bytes memory advancedSignerOverlyingSignaturePointer = abi.encodePacked(
                bytes32(uint256(uint160(address(advancedSignerInstance)))),
                uint256((65 * 3) + 32 + 65),
                uint8(0)
            );
            bytes memory advancedSignerOverlyingSignatureData = abi.encodePacked(
                uint256(65 * 2),
                packedUserSignatures
            );

            // Order and pack all overlying signatures
            address[] memory signers = new address[](3);
            signers[0] = address(policyGuardianSigner);
            signers[1] = address(advancedSignerInstance);
            signers[2] = BOB;
            bytes[] memory signatures = new bytes[](3);
            signatures[0] = policyGuardianOverlyingSignaturePointer;
            signatures[1] = advancedSignerOverlyingSignaturePointer;
            signatures[2] = userSignature2;
            bytes memory packedOverlyingSignatures = abi.encodePacked(_packSignaturesOrderedBySigner(signatures, signers), policyGuardianOverlyingSignatureData, advancedSignerOverlyingSignatureData);

            // Safe.execTransaction
            safeInstance.execTransaction(to, value, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), packedOverlyingSignatures);
        }

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
        salt = keccak256(abi.encode(safeInstance, moduleCreationParams.recoverySigners, moduleCreationParams.recoveryThreshold, moduleCreationParams.recoverySigningTimelock, moduleCreationParams.requirePolicyGuardianForRecovery, deploymentNonce));
        address predictedTimelockedRecoveryModuleInstanceAddress = Clones.predictDeterministicAddress(waymontSafeFactory.timelockedRecoveryModuleImplementation(), salt, address(waymontSafeFactory));

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

        // Enable WaymontSafeTimelockedRecoveryModule on the Safe
        {
            // Set params for execTransaction
            address to = address(safeInstance);
            uint256 value = 0;
            bytes memory data = abi.encodeWithSelector(safeInstance.enableModule.selector, predictedTimelockedRecoveryModuleInstanceAddress);

            // Safe.execTransaction
            _execTransaction(to, value, data);
        }

        // Assert signers configured correctly now
        {
            address[] memory finalOverlyingSigners = new address[](2);
            finalOverlyingSigners[0] = address(policyGuardianSigner);
            finalOverlyingSigners[1] = address(advancedSignerInstance);
            for (uint256 i = 0; i < finalOverlyingSigners.length; i++) assert(safeInstance.isOwner(finalOverlyingSigners[i]));
            assert(safeInstance.getOwners().length == finalOverlyingSigners.length);
            assert(safeInstance.getThreshold() == finalOverlyingThreshold);
        }

        // Try and fail to deploy WaymontSafeTimelockedRecoveryModule with a short signing timelock (< 15 minutes)
        vm.expectRevert("The Safe does not have this Waymont module enabled.");
        timelockedRecoveryModuleInstance = waymontSafeFactory.createTimelockedRecoveryModule(
            safeInstance,
            moduleCreationParams.recoverySigners,
            moduleCreationParams.recoveryThreshold,
            14 minutes,
            moduleCreationParams.requirePolicyGuardianForRecovery,
            deploymentNonce
        );

        // Deploy WaymontSafeTimelockedRecoveryModule
        timelockedRecoveryModuleInstance = waymontSafeFactory.createTimelockedRecoveryModule(
            safeInstance,
            moduleCreationParams.recoverySigners,
            moduleCreationParams.recoveryThreshold,
            moduleCreationParams.recoverySigningTimelock,
            moduleCreationParams.requirePolicyGuardianForRecovery,
            deploymentNonce
        );

        // Try and fail to re-initialize the WaymontSafeTimelockedRecoveryModule instance
        vm.expectRevert("GS200");
        timelockedRecoveryModuleInstance.initialize(
            safeInstance,
            moduleCreationParams.recoverySigners,
            moduleCreationParams.recoveryThreshold,
            moduleCreationParams.recoverySigningTimelock,
            policyGuardianSigner
        );

        // Assert deployed correctly
        assert(address(timelockedRecoveryModuleInstance) == predictedTimelockedRecoveryModuleInstanceAddress);
        assert(address(advancedSignerInstance.safe()) == address(safeInstance));
        for (uint256 i = 0; i < moduleCreationParams.recoverySigners.length; i++) assert(timelockedRecoveryModuleInstance.isOwner(moduleCreationParams.recoverySigners[i]));
        assert(advancedSignerInstance.getThreshold() == moduleCreationParams.recoveryThreshold);
        assert(timelockedRecoveryModuleInstance.signingTimelock() == moduleCreationParams.recoverySigningTimelock);
        assert(address(timelockedRecoveryModuleInstance.waymontSafeFactory()) == address(waymontSafeFactory));
        assert(address(timelockedRecoveryModuleInstance.policyGuardianSigner()) == (moduleCreationParams.requirePolicyGuardianForRecovery ? address(policyGuardianSigner) : address(0)));
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
        vm.expectEmit(false, false, false, true, address(policyGuardianSigner));
        emit PolicyGuardianDisabledGlobally(true);
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
        _execTransaction(to, value, data);

        // Assert TX succeeded
        assert(policyGuardianSigner.policyGuardianDisabled(safeInstance));
    }

    function testSetPolicyGuardianTimelock() public {
        // Transaction params
        address to = address(policyGuardianSigner);
        uint256 value = 0;
        bytes memory data = abi.encodeWithSelector(policyGuardianSigner.setPolicyGuardianTimelock.selector, 7 days);

        // Safe.execTransaction
        _execTransaction(to, value, data);

        // Assert TX succeeded
        assert(policyGuardianSigner.getPolicyGuardianTimelock(safeInstance) == 7 days);
        assert(policyGuardianSigner.customPolicyGuardianTimelocks(safeInstance) == 7 days);
    }

    function testCannotSetPolicyGuardianTimelockBelowMin() public {
        // Transaction params
        address to = address(policyGuardianSigner);
        uint256 value = 0;
        bytes memory data = abi.encodeWithSelector(policyGuardianSigner.setPolicyGuardianTimelock.selector, 14 minutes);

        // Safe.execTransaction
        vm.expectRevert("Policy guardian timelock must be at least 15 minutes. Call disablePolicyGuardian to disable it.");
        _execTransaction(to, value, data);
    }

    function testExecTransaction() public {
        // Send ETH to Safe
        vm.deal(address(safeInstance), 1337);

        // Transaction params
        address to = address(this);
        uint256 value = 1337;
        bytes memory data = abi.encodeWithSelector(this.sampleWalletOnlyFunction.selector, 22222222);

        // Safe.execTransaction
        _execTransaction(to, value, data);

        // Assert TX succeeded
        assert(dummy == 22222222);
    }

    function _getUserSignaturesAndOverlyingPolicyGuardianSignature(address to, uint256 value, bytes memory data, uint256 overlyingSignaturesBeforePolicyGuardian) internal view returns (
        bytes memory userSignature1,
        bytes memory userSignature2,
        bytes memory policyGuardianOverlyingSignaturePointer,
        bytes memory policyGuardianOverlyingSignatureData
    ) {
        // Generate data hash for the new transaction
        bytes32 txHash = keccak256(safeInstance.encodeTransactionData(to, value, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), safeInstance.nonce()));

        // Generate user signing device signature #1
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE, txHash);
        userSignature1 = abi.encodePacked(r, s, v);

        // Generate user signing device signature #2
        (v, r, s) = vm.sign(BOB_PRIVATE, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", txHash)));
        userSignature2 = abi.encodePacked(r, s, v + 4);

        // Generate underlying/actual policy guardian signature
        (v, r, s) = vm.sign(POLICY_GUARDIAN_PRIVATE, txHash);
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

    function _execTransaction(address to, uint256 value, bytes memory data) internal {
        // Standard Safe.execTransaction params
        Enum.Operation operation = Enum.Operation.Call;
        uint256 safeTxGas = 0;
        uint256 baseGas = 0;
        uint256 gasPrice = 0;
        address gasToken = address(0);
        address payable refundReceiver = payable(address(0));

        // Get signature data:
        bytes memory packedOverlyingSignatures;
        {
            // Get signatures
            (bytes memory userSignature1, bytes memory userSignature2, bytes memory policyGuardianOverlyingSignaturePointer, bytes memory policyGuardianOverlyingSignatureData) = _getUserSignaturesAndOverlyingPolicyGuardianSignature(to, value, data, 1);

            // Pack user signatures
            bytes memory packedUserSignatures = BOB_PRIVATE > ALICE_PRIVATE ? abi.encodePacked(userSignature1, userSignature2) : abi.encodePacked(userSignature2, userSignature1);

            // Generate overlying WaymontSafeAdvancedSigner signature
            bytes memory advancedSignerOverlyingSignaturePointer = abi.encodePacked(
                bytes32(uint256(uint160(address(advancedSignerInstance)))),
                uint256((65 * 2) + 32 + 65),
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
        safeInstance.execTransaction(to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, packedOverlyingSignatures);
    }

    function testDisablePolicyGuardianWithoutPolicyGuardian() public {
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
        bytes memory packedUserSignatures = BOB_PRIVATE > ALICE_PRIVATE ? abi.encodePacked(userSignature1, userSignature2) : abi.encodePacked(userSignature2, userSignature1);

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
        packedUserSignatures = BOB_PRIVATE > ALICE_PRIVATE ? abi.encodePacked(userSignature1, userSignature2) : abi.encodePacked(userSignature2, userSignature1);

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
        policyGuardianSigner.queueDisablePolicyGuardian(safeInstance, packedOverlyingSignaturesForQueueing);
        assert(policyGuardianSigner.nonces(safeInstance) == ++signerNonce);
        assert(policyGuardianSigner.disablePolicyGuardianQueueTimestamps(safeInstance) == block.timestamp);

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
        packedUserSignatures = BOB_PRIVATE > ALICE_PRIVATE ? abi.encodePacked(userSignature1, userSignature2) : abi.encodePacked(userSignature2, userSignature1);

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

        // Fail to disable the policy guardian
        vm.expectRevert("Timelock not satisfied.");
        policyGuardianSigner.disablePolicyGuardianWithoutPolicyGuardian(safeInstance, packedOverlyingSignatures2);

        // Wait for the timelock to pass in full
        vm.warp(block.timestamp + 1 seconds);

        // Disable the policy guardian
        policyGuardianSigner.disablePolicyGuardianWithoutPolicyGuardian(safeInstance, packedOverlyingSignatures2);
        assert(policyGuardianSigner.nonces(safeInstance) == ++signerNonce);
        assert(policyGuardianSigner.policyGuardianDisabled(safeInstance));
    }

    function testSocialRecovery() public {
        // Underlying transaction params
        address to = address(advancedSignerInstance);
        bytes memory data = abi.encodeWithSelector(advancedSignerInstance.swapOwner.selector, BOB, JOE, JOE_REPLACEMENT);

        // Standard params
        uint256 value = 0;
        Enum.Operation operation = Enum.Operation.Call;
        
        // Generate data hash for underlying transaction
        uint256 moduleNonce = timelockedRecoveryModuleInstance.nonce();
        bytes32 underlyingHash = keccak256(abi.encode(EXEC_TRANSACTION_TYPEHASH, safeInstance, moduleNonce, to, value, keccak256(data), operation));
        bytes32 txHash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), timelockedRecoveryModuleInstance.domainSeparator(), underlyingHash));

        // To queue signaure #1:
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

            // Queue signature #1
            timelockedRecoveryModuleInstance.queueSignature(underlyingHash, friendSignature1, friend1PolicyGuardianSignature);
            assert(timelockedRecoveryModuleInstance.pendingSignatures(keccak256(friendSignature1)) == block.timestamp);
        }

        // To queue signature #2:
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

            // Queue signature #2
            timelockedRecoveryModuleInstance.queueSignature(underlyingHash, friendSignature2, friend2PolicyGuardianSignature);
            assert(timelockedRecoveryModuleInstance.pendingSignatures(keccak256(friendSignature2)) == block.timestamp);
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

        // WaymontSafeTimelockedRecoveryModule.execTransaction
        timelockedRecoveryModuleInstance.execTransaction(to, value, data, operation, packedFriendSignatures, finalPolicyGuardianSignature);

        // Assert TX succeeded
        assert(timelockedRecoveryModuleInstance.nonce() == moduleNonce + 1);
        assert(advancedSignerInstance.isOwner(JOE_REPLACEMENT));
        assert(!advancedSignerInstance.isOwner(JOE));
    }

    function sampleWalletOnlyFunction(uint256 arg) public payable {
        // Example function to be called by the Safe
        assert(msg.sender == address(safeInstance));
        assert(msg.value == 1337);
        dummy = arg;
    }
}
