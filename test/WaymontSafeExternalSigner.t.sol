// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import "lib/openzeppelin-contracts/contracts/proxy/Clones.sol";

import "lib/safe-contracts/contracts/Safe.sol";
import "lib/safe-contracts/contracts/common/Enum.sol";
import "lib/safe-contracts/contracts/handler/CompatibilityFallbackHandler.sol";
import "lib/safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import "lib/safe-contracts/contracts/libraries/MultiSend.sol";
import "lib/safe-contracts/contracts/interfaces/IStandardSignatureValidator.sol";

import "../src/WaymontSafeFactory.sol";
import "../src/WaymontSafePolicyGuardianSigner.sol";
import "../src/WaymontSafeTimelockedRecoveryModule.sol";
import "../src/WaymontSafeExternalSignerFactory.sol";
import "../src/WaymontSafeExternalSigner.sol";

contract WaymontSafeExternalSignerTest is Test {
    // Typehashes copied from contracts
    bytes32 private constant QUEUE_SIGNATURE_TYPEHASH = 0x56f7b592467518044b02545f1b4518cd51c746d04978afb6a3b9d05895cb79cf;
    bytes32 private constant EXEC_TRANSACTION_TYPEHASH = 0x017ac7ed7bb44ab92aef10c445ff46b9a95c18bfa2bf271178886356daa01e9c;
    bytes32 private constant QUEUE_DISABLE_POLICY_GUARDIAN_TYPEHASH = 0xd5fa5ce164fba34243c3b3b9c5346acc2eae6f31655b86516d465566d0ba53f7;
    bytes32 private constant UNQUEUE_DISABLE_POLICY_GUARDIAN_TYPEHASH = 0x16dda714d491dced303c8770c04d1539fd0000764e8745d3fe40945bb0d59dcf;
    bytes32 private constant DISABLE_POLICY_GUARDIAN_TYPEHASH = 0x1fa738809572ae202e6e8b28ae7d08f5972c3ae85e70f8bc386515bb47925975;
    bytes32 private constant EXTERNAL_SIGNER_SAFE_TX_TYPEHASH = 0xf641ab1aa14257ef40a4f6202602bc27847e79f0aa3bac95aa170c03c99d6290;

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
    address constant public SAM_UNDERLYING = 0x1234051c1188414823A78Ddb03cF2D6fe8f9BF27;
    uint256 constant public SAM_UNDERLYING_PRIVATE = 0x14daba645f7e785be462f836a36e5cb1c14ef7570198074443425e527fdd6e8b;
    address constant public SAM_SCW = 0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa;

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
    WaymontSafeTimelockedRecoveryModule public timelockedRecoveryModuleInstance;
    WaymontSafeExternalSignerFactory public waymontSafeExternalSignerFactory;
    WaymontSafeExternalSigner public externalSignerInstance;

    // Safe contracts
    SafeProxyFactory public safeProxyFactory;
    Safe public safeInstance;
    address public safeImplementation;
    CompatibilityFallbackHandler public compatibilityFallbackHandler;
    MultiSend public multiSend;

    // Dummy variable to be manipulated by the example test Safe
    uint256 public dummy;
    uint256 public dummy2;

    // Last unique ID used; used solely for the purpose of these tests as a seed for the next one (should be RANDOM in practice)
    uint256 public lastUniqueId;

    function setUp() public {
        setUpSafeProxyFactory();
        multiSend = new MultiSend();
        setUpWaymontSafeFactory();
        setUpWaymontSafeExternalSignerFactory();
        setUpWaymontSafe(true);
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

    function setUpWaymontSafeExternalSignerFactory() public {
        // Successfully create WaymontSafeExternalSignerFactory
        waymontSafeExternalSignerFactory = new WaymontSafeExternalSignerFactory(policyGuardianSigner);

        // Check WaymontSafePolicyGuardianSigner
        assert(address(waymontSafeExternalSignerFactory.policyGuardianSigner()) == address(policyGuardianSigner));

        // Check deployed contract exists
        assert(waymontSafeExternalSignerFactory.externalSignerImplementation() != address(0));

        // Check implementation singleton threshold
        assert(WaymontSafeExternalSigner(waymontSafeExternalSignerFactory.externalSignerImplementation()).getThreshold() == 1);
    }

    struct CreateTimelockedRecoveryModuleParams {
        address[] recoverySigners;
        uint256 recoveryThreshold;
        uint256 recoverySigningTimelock;
        bool requirePolicyGuardianForRecovery;
        address predictedTimelockedRecoveryModuleInstanceAddress;
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
        address predictedExternalSignerInstanceAddress,
        address predictedTimelockedRecoveryModuleInstanceAddress,
        uint256 deploymentNonce,
        bool expectRevert,
        bool requirePolicyGuardianForReusableCalls
    ) internal {
        // Get Safe.execTransaction params
        address to;
        bytes memory data;
        Enum.Operation operation = Enum.Operation.DelegateCall;
        {
            // Set new threshold for after the WaymontSafeExternalSigner is added
            uint256 finalOverlyingThreshold = 2;

            // Add WaymontSafeExternalSigner to Safe as signer using Safe.addOwnerWithThreshold
            to = address(safeInstance);
            data = abi.encodeWithSelector(safeInstance.addOwnerWithThreshold.selector, predictedExternalSignerInstanceAddress, finalOverlyingThreshold);
            bytes memory multiSendTransactions = abi.encodePacked(uint8(0), to, uint256(0), data.length, data);

            // Enable WaymontSafeTimelockedRecoveryModule on the Safe
            to = address(safeInstance);
            data = abi.encodeWithSelector(safeInstance.enableModule.selector, predictedTimelockedRecoveryModuleInstanceAddress);
            multiSendTransactions = abi.encodePacked(multiSendTransactions, uint8(0), to, uint256(0), data.length, data);

            // Deploy WaymontSafeExternalSigner
            to = address(waymontSafeExternalSignerFactory);
            data = abi.encodeWithSelector(waymontSafeExternalSignerFactory.createExternalSigner.selector, safeInstance, underlyingOwners, underlyingThreshold, requirePolicyGuardianForReusableCalls, deploymentNonce);
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
            // Get signatures
            (, bytes memory policyGuardianOverlyingSignaturePointer, bytes memory policyGuardianOverlyingSignatureData) = _getUserSignaturesAndOverlyingPolicyGuardianSignature(to, 0, data, operation, 0, false);

            // Pack all overlying signatures
            packedOverlyingSignatures = abi.encodePacked(policyGuardianOverlyingSignaturePointer, policyGuardianOverlyingSignatureData);
        }

        // Safe.execTransaction
        if (expectRevert) vm.expectRevert("GS013");
        safeInstance.execTransaction(to, 0, data, operation, 0, 0, 0, address(0), payable(address(0)), packedOverlyingSignatures);
    }

    function setUpWaymontSafe(bool requirePolicyGuardianForReusableCalls) public {
        // WaymontExternalSigner params
        address[] memory underlyingOwners = new address[](4);
        underlyingOwners[0] = ALICE;
        underlyingOwners[1] = BOB;
        underlyingOwners[2] = JOE;
        underlyingOwners[3] = SAM_SCW;
        uint256 underlyingThreshold = 3;
        uint256 deploymentNonce = 4444;

        // Safe params--initiating signers are the signers that will remove themselves in favor of the `ExternalSigner` (but the WaymontSafePolicyGuardianSigner will stay)
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
                uint256 saltNonce = requirePolicyGuardianForReusableCalls ? 0x9999999999999999999999999999999999999999999999999999999999999999 : 0x8888888888888888888888888888888888888888888888888888888888888888;  // Use a different nonce if requirePolicyGuardianForReusableCalls is false so we can deploy multiple Safes (one with requirePolicyGuardianForReusableCalls set to true and one with requirePolicyGuardianForReusableCalls set to false)
                safeInstance = Safe(payable(address(safeProxyFactory.createProxyWithNonce(safeImplementation, initializer, saltNonce))));
            }

            // Assert Safe deployed correctly
            for (uint256 i = 0; i < initialOverlyingSigners.length; i++) assert(safeInstance.isOwner(initialOverlyingSigners[i]));
            assert(safeInstance.getThreshold() == initialOverlyingThreshold);
        }

        // Predict WaymontSafeExternalSigner address
        address predictedExternalSignerInstanceAddress;
        {
            bytes32 salt = keccak256(abi.encode(safeInstance, underlyingOwners, underlyingThreshold, requirePolicyGuardianForReusableCalls, deploymentNonce));
            predictedExternalSignerInstanceAddress = Clones.predictDeterministicAddress(waymontSafeExternalSignerFactory.externalSignerImplementation(), salt, address(waymontSafeExternalSignerFactory));
        }

        // Try and fail to deploy WaymontSafeExternalSigner (since it has not yet been added to the Safe)
        vm.expectRevert("The Safe is not owned by this Waymont signer contract.");
        externalSignerInstance = waymontSafeExternalSignerFactory.createExternalSigner(safeInstance, underlyingOwners, underlyingThreshold, requirePolicyGuardianForReusableCalls, deploymentNonce);

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
                requirePolicyGuardianForRecovery: true,
                predictedTimelockedRecoveryModuleInstanceAddress: address(0)
            });
        }

        // Predict WaymontSafeTimelockedRecoveryModule address
        {
            bytes32 salt = keccak256(abi.encode(safeInstance, moduleCreationParams.recoverySigners, moduleCreationParams.recoveryThreshold, moduleCreationParams.recoverySigningTimelock, moduleCreationParams.requirePolicyGuardianForRecovery, deploymentNonce));
            moduleCreationParams.predictedTimelockedRecoveryModuleInstanceAddress = Clones.predictDeterministicAddress(waymontSafeFactory.timelockedRecoveryModuleImplementation(), salt, address(waymontSafeFactory));
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
            predictedExternalSignerInstanceAddress,
            moduleCreationParams.predictedTimelockedRecoveryModuleInstanceAddress,
            deploymentNonce,
            true,
            requirePolicyGuardianForReusableCalls
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
            predictedExternalSignerInstanceAddress,
            badPredictedTimelockedRecoveryModuleInstanceAddress,
            deploymentNonce,
            true,
            requirePolicyGuardianForReusableCalls
        );
        moduleCreationParams.recoverySigningTimelock = 3 days;

        // Use Safe.execTransaction to call MultiSend.multiSend to add WaymontSafeExternalSigner to the Safe as a signer using Safe.swapOwner, remove the extra signer(s) from the Safe with Safe.removeOwner, enable the WaymontSafeTimelockedRecoveryModule on the Safe, deploy the WaymontSafeExternalSigner, and deploy the WaymontSafeTimelockedRecoveryModule
        _execInitialConfigOnSafe(
            underlyingOwners,
            underlyingThreshold,
            moduleCreationParams,
            predictedExternalSignerInstanceAddress,
            moduleCreationParams.predictedTimelockedRecoveryModuleInstanceAddress,
            deploymentNonce,
            false,
            requirePolicyGuardianForReusableCalls
        );

        // Set WaymontSafeExternalSigner
        externalSignerInstance = WaymontSafeExternalSigner(predictedExternalSignerInstanceAddress);

        // Assert WaymontSafeExternalSigner deployed correctly
        assert(address(externalSignerInstance) == predictedExternalSignerInstanceAddress);
        for (uint256 i = 0; i < underlyingOwners.length; i++) assert(externalSignerInstance.isOwner(underlyingOwners[i]));
        assert(address(externalSignerInstance.safe()) == address(safeInstance));
        assert(externalSignerInstance.getThreshold() == underlyingThreshold);
        assert(address(externalSignerInstance.policyGuardianSigner()) == (requirePolicyGuardianForReusableCalls ? address(policyGuardianSigner) : address(0)));

        // Assert signers configured correctly now
        {
            address[] memory finalOverlyingSigners = new address[](2);
            finalOverlyingSigners[0] = address(policyGuardianSigner);
            finalOverlyingSigners[1] = address(externalSignerInstance);
            for (uint256 i = 0; i < finalOverlyingSigners.length; i++) assert(safeInstance.isOwner(finalOverlyingSigners[i]));
            assert(safeInstance.getOwners().length == finalOverlyingSigners.length);
            assert(safeInstance.getThreshold() == 2);
        }

        // Set WaymontSafeTimelockedRecoveryModule
        timelockedRecoveryModuleInstance = WaymontSafeTimelockedRecoveryModule(moduleCreationParams.predictedTimelockedRecoveryModuleInstanceAddress);

        // Assert deployed correctly
        assert(address(timelockedRecoveryModuleInstance) == moduleCreationParams.predictedTimelockedRecoveryModuleInstanceAddress);
        assert(address(timelockedRecoveryModuleInstance.safe()) == address(safeInstance));
        for (uint256 i = 0; i < moduleCreationParams.recoverySigners.length; i++) assert(timelockedRecoveryModuleInstance.isOwner(moduleCreationParams.recoverySigners[i]));
        assert(timelockedRecoveryModuleInstance.getThreshold() == moduleCreationParams.recoveryThreshold);
        assert(timelockedRecoveryModuleInstance.signingTimelock() == moduleCreationParams.recoverySigningTimelock);
        assert(address(timelockedRecoveryModuleInstance.waymontSafeFactory()) == address(waymontSafeFactory));
        assert(address(timelockedRecoveryModuleInstance.policyGuardianSigner()) == (moduleCreationParams.requirePolicyGuardianForRecovery ? address(policyGuardianSigner) : address(0)));
        assert(safeInstance.isModuleEnabled(address(timelockedRecoveryModuleInstance)));
    }

    function testCannotCreateExternalSignerWithMismatchingDeploymentNonce() public {
        // WaymontSafeExternalSigner params
        address[] memory underlyingOwners = new address[](4);
        underlyingOwners[0] = ALICE;
        underlyingOwners[1] = BOB;
        underlyingOwners[2] = JOE;
        underlyingOwners[3] = SAM_SCW;
        uint256 underlyingThreshold = 3;
        bool requirePolicyGuardianForReusableCalls = true;
        uint256 deploymentNonce = 5555;

        // Failure
        vm.expectRevert("The Safe is not owned by this Waymont signer contract.");
        waymontSafeExternalSignerFactory.createExternalSigner(safeInstance, underlyingOwners, underlyingThreshold, requirePolicyGuardianForReusableCalls, deploymentNonce);
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

    function testCannotCreateExternalSignerWithSameParamsTwice() public {
        // WaymontSafeExternalSigner params
        address[] memory underlyingOwners = new address[](4);
        underlyingOwners[0] = ALICE;
        underlyingOwners[1] = BOB;
        underlyingOwners[2] = JOE;
        underlyingOwners[3] = SAM_SCW;
        uint256 underlyingThreshold = 3;
        bool requirePolicyGuardianForReusableCalls = true;
        uint256 deploymentNonce = 4444;

        // Failure
        vm.expectRevert();
        waymontSafeExternalSignerFactory.createExternalSigner(safeInstance, underlyingOwners, underlyingThreshold, requirePolicyGuardianForReusableCalls, deploymentNonce);
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

    function testCannotReinitializeExternalSigner() public {
        // WaymontSafeExternalSigner params
        address[] memory underlyingOwners = new address[](4);
        underlyingOwners[0] = ALICE;
        underlyingOwners[1] = BOB;
        underlyingOwners[2] = JOE;
        underlyingOwners[3] = SAM_SCW;
        uint256 underlyingThreshold = 3;

        // Try and fail to re-initialize the WaymontSafeExternalSigner instance
        vm.expectRevert("GS200");
        externalSignerInstance.initialize(safeInstance, underlyingOwners, underlyingThreshold, policyGuardianSigner);
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
                requirePolicyGuardianForRecovery: true,
                predictedTimelockedRecoveryModuleInstanceAddress: address(0)
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
    ) internal returns (
        bytes memory externalSignatures,
        bytes memory policyGuardianOverlyingSignaturePointer,
        bytes memory policyGuardianOverlyingSignatureData
    ) {
        // Generate data hash for the new transaction
        bytes32 txHash = keccak256(safeInstance.encodeTransactionData(to, value, data, operation, 0, 0, 0, address(0), payable(address(0)), safeInstance.nonce()));

        // Generate user signing device signature #1
        Signature memory sig;
        (sig.v, sig.r, sig.s) = vm.sign(ALICE_PRIVATE, txHash);
        bytes[] memory topLevelExternalSignatures = new bytes[](3);
        topLevelExternalSignatures[0] = abi.encodePacked(sig.r, sig.s, sig.v);

        // Generate user signing device signature #2
        (sig.v, sig.r, sig.s) = vm.sign(BOB_PRIVATE, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", txHash)));
        topLevelExternalSignatures[1] = abi.encodePacked(sig.r, sig.s, sig.v + 4);

        // Generate user signing device signature #3
        (sig.v, sig.r, sig.s) = vm.sign(SAM_UNDERLYING_PRIVATE, txHash);
        bytes memory samUnderlyingSignature = abi.encodePacked(sig.r, sig.s, sig.v);

        // Wrap user signing device signature #3 with a fake SCW
        topLevelExternalSignatures[2] = abi.encodePacked(
            bytes32(uint256(uint160(SAM_SCW))),
            uint256(3 * 65),
            uint8(0)
        );
        bytes memory samScwOverlyingSignatureData = abi.encodePacked(
            uint256(65),
            samUnderlyingSignature
        );

        // Mock fake SCW
        vm.mockCall(
            address(SAM_SCW),
            abi.encodeWithSelector(IStandardSignatureValidator.isValidSignature.selector, txHash, samUnderlyingSignature),
            abi.encode(bytes4(0x1626ba7e))
        );

        // Generate underlying/actual policy guardian signature
        (sig.v, sig.r, sig.s) = vm.sign(useSecondaryPolicyGuardian ? SECONDARY_POLICY_GUARDIAN_PRIVATE : POLICY_GUARDIAN_PRIVATE, txHash);
        bytes memory policyGuardianUnderlyingSignature = abi.encodePacked(sig.r, sig.s, sig.v);

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

        // Get packed ExternalSigner signatures
        address[] memory externalSigners = new address[](3);
        externalSigners[0] = ALICE;
        externalSigners[1] = BOB;
        externalSigners[2] = SAM_SCW;
        externalSignatures = abi.encodePacked(_packSignaturesOrderedBySigner(topLevelExternalSignatures, externalSigners), samScwOverlyingSignatureData);
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
            (bytes memory externalSignatures, bytes memory policyGuardianOverlyingSignaturePointer, bytes memory policyGuardianOverlyingSignatureData) = _getUserSignaturesAndOverlyingPolicyGuardianSignature(to, value, data, Enum.Operation.Call, 1, options.useSecondaryPolicyGuardian);
            if (options.testInvalidUserSignature) externalSignatures[SAM_SCW > ALICE || SAM_SCW > BOB ? 50 : 100] = externalSignatures[SAM_SCW > ALICE || SAM_SCW > BOB ? 50 : 100] == bytes1(0x55) ? bytes1(0x66) : bytes1(0x55);
            else if (options.testInvalidPolicyGuardianSignature) policyGuardianOverlyingSignatureData[50] = policyGuardianOverlyingSignatureData[50] == bytes1(0x55) ? bytes1(0x66) : bytes1(0x55);
            else if (options.testShortPolicyGuardianSignature) policyGuardianOverlyingSignatureData = abi.encodePacked(uint256(64), hex'12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678');

            // Generate overlying WaymontSafeExternalSigner signature
            bytes memory externalSignerOverlyingSignaturePointer = abi.encodePacked(
                bytes32(uint256(uint160(address(externalSignerInstance)))),
                uint256((65 * 2) + 32 + (options.testShortPolicyGuardianSignature ? 64 : 65)),
                uint8(0)
            );
            bytes memory externalSignerOverlyingSignatureData = abi.encodePacked(
                externalSignatures.length,
                externalSignatures
            );

            // Pack all overlying signatures (in correct order)
            if (address(externalSignerInstance) > address(policyGuardianSigner)) {
                packedOverlyingSignatures = abi.encodePacked(policyGuardianOverlyingSignaturePointer, externalSignerOverlyingSignaturePointer, policyGuardianOverlyingSignatureData, externalSignerOverlyingSignatureData);
            } else {
                packedOverlyingSignatures = abi.encodePacked(externalSignerOverlyingSignaturePointer, policyGuardianOverlyingSignaturePointer, policyGuardianOverlyingSignatureData, externalSignerOverlyingSignatureData);
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

    struct Signature {
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    function _testDisablePolicyGuardianWithoutPolicyGuardian(bool testUnqueueingInstead) internal {
        // Generate underlying hash + overlying signed data (to queue disabling)
        uint256 signerNonce = policyGuardianSigner.nonces(safeInstance);
        bytes32 underlyingHash = keccak256(abi.encode(QUEUE_DISABLE_POLICY_GUARDIAN_TYPEHASH, safeInstance, signerNonce));
        bytes32 txHash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), policyGuardianSigner.domainSeparator(), underlyingHash));

        // Generate user signing device signature #1 (to queue disabling)
        Signature memory sig;
        (sig.v, sig.r, sig.s) = vm.sign(ALICE_PRIVATE, txHash);
        bytes[] memory topLevelExternalSignatures = new bytes[](3);
        topLevelExternalSignatures[0] = abi.encodePacked(sig.r, sig.s, sig.v);

        // Generate user signing device signature #2 (to queue disabling)
        (sig.v, sig.r, sig.s) = vm.sign(BOB_PRIVATE, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", txHash)));
        topLevelExternalSignatures[1] = abi.encodePacked(sig.r, sig.s, sig.v + 4);

        // Generate user signing device signature #3 (to queue disabling)
        (sig.v, sig.r, sig.s) = vm.sign(SAM_UNDERLYING_PRIVATE, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", txHash)));
        bytes memory samUnderlyingSignature = abi.encodePacked(sig.r, sig.s, sig.v);

        // Wrap user signing device signature #3 with a fake SCW (to queue disabling)
        topLevelExternalSignatures[2] = abi.encodePacked(
            bytes32(uint256(uint160(SAM_SCW))),
            uint256(3 * 65),
            uint8(0)
        );
        bytes memory samScwOverlyingSignatureData = abi.encodePacked(
            uint256(65),
            samUnderlyingSignature
        );

        // Mock fake SCW
        vm.mockCall(
            address(SAM_SCW),
            abi.encodeWithSelector(IStandardSignatureValidator.isValidSignature.selector, txHash, samUnderlyingSignature),
            abi.encode(bytes4(0x1626ba7e))
        );

        // Get packed ExternalSigner signatures (to queue disabling)
        address[] memory externalSigners = new address[](3);
        externalSigners[0] = ALICE;
        externalSigners[1] = BOB;
        externalSigners[2] = SAM_SCW;
        bytes memory packedUserSignatures = abi.encodePacked(_packSignaturesOrderedBySigner(topLevelExternalSignatures, externalSigners), samScwOverlyingSignatureData);

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

        // Generate overlying WaymontSafeExternalSigner signature (to queue disabling)
        bytes memory externalSignerOverlyingSignaturePointer = abi.encodePacked(
            bytes32(uint256(uint160(address(externalSignerInstance)))),
            uint256((65 * 2) + 32 + 65),
            uint8(0)
        );
        bytes memory externalSignerOverlyingSignatureData = abi.encodePacked(
            packedUserSignatures.length,
            packedUserSignatures
        );

        // Pack all overlying signatures in correct order (to queue disabling)
        bytes memory packedOverlyingSignaturesForQueueing;

        if (address(externalSignerInstance) > address(policyGuardianSigner)) {
            packedOverlyingSignaturesForQueueing = abi.encodePacked(policyGuardianOverlyingSignaturePointer, externalSignerOverlyingSignaturePointer, policyGuardianOverlyingSignatureData, externalSignerOverlyingSignatureData);
        } else {
            packedOverlyingSignaturesForQueueing = abi.encodePacked(externalSignerOverlyingSignaturePointer, policyGuardianOverlyingSignaturePointer, policyGuardianOverlyingSignatureData, externalSignerOverlyingSignatureData);
        }

        // Generate underlying hash + overlying signed data (to execute disabling)
        underlyingHash = keccak256(abi.encode(DISABLE_POLICY_GUARDIAN_TYPEHASH, safeInstance, signerNonce));
        txHash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), policyGuardianSigner.domainSeparator(), underlyingHash));

        // Generate user signing device signature #1 (to execute disabling)
        (sig.v, sig.r, sig.s) = vm.sign(ALICE_PRIVATE, txHash);
        topLevelExternalSignatures[0] = abi.encodePacked(sig.r, sig.s, sig.v);

        // Generate user signing device signature #2 (to execute disabling)
        (sig.v, sig.r, sig.s) = vm.sign(BOB_PRIVATE, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", txHash)));
        topLevelExternalSignatures[1] = abi.encodePacked(sig.r, sig.s, sig.v + 4);

        // Generate user signing device signature #3 (to execute disabling)
        (sig.v, sig.r, sig.s) = vm.sign(SAM_UNDERLYING_PRIVATE, txHash);
        samUnderlyingSignature = abi.encodePacked(sig.r, sig.s, sig.v);

        // Wrap user signing device signature #3 with a fake SCW (to execute disabling)
        samScwOverlyingSignatureData = abi.encodePacked(
            uint256(65),
            samUnderlyingSignature
        );

        // Mock fake SCW (to execute disabling)
        vm.mockCall(
            address(SAM_SCW),
            abi.encodeWithSelector(IStandardSignatureValidator.isValidSignature.selector, txHash, samUnderlyingSignature),
            abi.encode(bytes4(0x1626ba7e))
        );

        // Get packed ExternalSigner signatures (to execute disabling)
        packedUserSignatures = abi.encodePacked(_packSignaturesOrderedBySigner(topLevelExternalSignatures, externalSigners), samScwOverlyingSignatureData);

        // Generate overlying WaymontSafeExternalSigner signature (to execute disabling)
        externalSignerOverlyingSignaturePointer = abi.encodePacked(
            bytes32(uint256(uint160(address(externalSignerInstance)))),
            uint256((65 * 2) + 32 + 65),
            uint8(0)
        );
        externalSignerOverlyingSignatureData = abi.encodePacked(
            packedUserSignatures.length,
            packedUserSignatures
        );

        {
            // Pack all overlying signatures in correct order (to execute disabling)
            bytes memory packedOverlyingSignatures;

            if (address(externalSignerInstance) > address(policyGuardianSigner)) {
                packedOverlyingSignatures = abi.encodePacked(policyGuardianOverlyingSignaturePointer, externalSignerOverlyingSignaturePointer, policyGuardianOverlyingSignatureData, externalSignerOverlyingSignatureData);
            } else {
                packedOverlyingSignatures = abi.encodePacked(externalSignerOverlyingSignaturePointer, policyGuardianOverlyingSignaturePointer, policyGuardianOverlyingSignatureData, externalSignerOverlyingSignatureData);
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
            (sig.v, sig.r, sig.s) = vm.sign(ALICE_PRIVATE, txHash);
            topLevelExternalSignatures[0] = abi.encodePacked(sig.r, sig.s, sig.v);

            // Generate user signing device signature #2 (to queue disabling)
            (sig.v, sig.r, sig.s) = vm.sign(BOB_PRIVATE, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", txHash)));
            topLevelExternalSignatures[1] = abi.encodePacked(sig.r, sig.s, sig.v + 4);

            // Generate user signing device signature #3
            (sig.v, sig.r, sig.s) = vm.sign(SAM_UNDERLYING_PRIVATE, txHash);
            samUnderlyingSignature = abi.encodePacked(sig.r, sig.s, sig.v);

            // Wrap user signing device signature #3 with a fake SCW
            samScwOverlyingSignatureData = abi.encodePacked(
                uint256(65),
                samUnderlyingSignature
            );

            // Mock fake SCW
            vm.mockCall(
                address(SAM_SCW),
                abi.encodeWithSelector(IStandardSignatureValidator.isValidSignature.selector, txHash, samUnderlyingSignature),
                abi.encode(bytes4(0x1626ba7e))
            );

            // Get packed ExternalSigner signatures
            packedUserSignatures = abi.encodePacked(_packSignaturesOrderedBySigner(topLevelExternalSignatures, externalSigners), samScwOverlyingSignatureData);

            // Generate overlying WaymontSafeExternalSigner signature (to queue disabling)
            externalSignerOverlyingSignatureData = abi.encodePacked(
                packedUserSignatures.length,
                packedUserSignatures
            );

            // Pack all overlying signatures in correct order (to queue disabling)
            bytes memory packedOverlyingSignaturesForUnqueueing;

            if (address(externalSignerInstance) > address(policyGuardianSigner)) {
                packedOverlyingSignaturesForUnqueueing = abi.encodePacked(policyGuardianOverlyingSignaturePointer, externalSignerOverlyingSignaturePointer, policyGuardianOverlyingSignatureData, externalSignerOverlyingSignatureData);
            } else {
                packedOverlyingSignaturesForUnqueueing = abi.encodePacked(externalSignerOverlyingSignaturePointer, policyGuardianOverlyingSignaturePointer, policyGuardianOverlyingSignatureData, externalSignerOverlyingSignatureData);
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
        (sig.v, sig.r, sig.s) = vm.sign(ALICE_PRIVATE, txHash);
        topLevelExternalSignatures[0] = abi.encodePacked(sig.r, sig.s, sig.v);

        // AGAIN WITH NEW NONCE: Generate user signing device signature #2 (to execute disabling)
        (sig.v, sig.r, sig.s) = vm.sign(BOB_PRIVATE, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", txHash)));
        topLevelExternalSignatures[1] = abi.encodePacked(sig.r, sig.s, sig.v + 4);

        // AGAIN WITH NEW NONCE: Generate user signing device signature #3
        (sig.v, sig.r, sig.s) = vm.sign(SAM_UNDERLYING_PRIVATE, txHash);
        samUnderlyingSignature = abi.encodePacked(sig.r, sig.s, sig.v);

        // AGAIN WITH NEW NONCE: Wrap user signing device signature #3 with a fake SCW
        samScwOverlyingSignatureData = abi.encodePacked(
            uint256(65),
            samUnderlyingSignature
        );

        // AGAIN WITH NEW NONCE: Mock fake SCW
        vm.mockCall(
            address(SAM_SCW),
            abi.encodeWithSelector(IStandardSignatureValidator.isValidSignature.selector, txHash, samUnderlyingSignature),
            abi.encode(bytes4(0x1626ba7e))
        );

        // AGAIN WITH NEW NONCE: Get packed ExternalSigner signatures
        packedUserSignatures = abi.encodePacked(_packSignaturesOrderedBySigner(topLevelExternalSignatures, externalSigners), samScwOverlyingSignatureData);

        // AGAIN WITH NEW NONCE: Generate overlying WaymontSafeExternalSigner signature
        externalSignerOverlyingSignatureData = abi.encodePacked(
            packedUserSignatures.length,
            packedUserSignatures
        );

        // AGAIN WITH NEW NONCE: Pack all overlying signatures in correct order (to execute disabling)
        bytes memory packedOverlyingSignatures2;

        if (address(externalSignerInstance) > address(policyGuardianSigner)) {
            packedOverlyingSignatures2 = abi.encodePacked(policyGuardianOverlyingSignaturePointer, externalSignerOverlyingSignaturePointer, policyGuardianOverlyingSignatureData, externalSignerOverlyingSignatureData);
        } else {
            packedOverlyingSignatures2 = abi.encodePacked(externalSignerOverlyingSignaturePointer, policyGuardianOverlyingSignaturePointer, policyGuardianOverlyingSignatureData, externalSignerOverlyingSignatureData);
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
        address to = address(externalSignerInstance);
        bytes memory data = abi.encodeWithSelector(externalSignerInstance.swapOwner.selector, options.testRevertingUnderlyingTransaction ? ALICE : BOB, JOE, JOE_REPLACEMENT);

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
                assert(externalSignerInstance.isOwner(JOE_REPLACEMENT));
                assert(!externalSignerInstance.isOwner(JOE));
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

    function sampleWalletOnlyFunction2(uint256 arg) public payable {
        // Example function to be called by the Safe
        assert(msg.sender == address(safeInstance));
        assert(msg.value == 1338);
        dummy2 = arg;
    }

    struct TestSeparatelyExecNonIncrementalTransactionsSignedTogetherOptions {
        bool testSigningMultipleChainIdsTogether;
        bool testMultiUse;
        bool testMultiUseOfSingleUse;
        bool testExecBlacklisted;
        bool testExpiredTx;
        bool testRevertBecausePolicyGuardianMustBeEnabled;
        bool testGasTank;
        bool testInsufficientGasTank;
    }

    struct TestSeparatelyExecNonIncrementalTransactionsSignedTogetherVariables {
        bytes externalSignatures;
        bytes32[][] merkleProofs;
    }

    function _separatelyExecNonIncrementalTransactionsSignedTogether(
        ExternalSignerSafeTxBasicParams[] memory txs,
        TestExecTransactionOptions memory options,
        TestSeparatelyExecNonIncrementalTransactionsSignedTogetherOptions memory moreOptions
    ) internal {
        // Get external signatures param
        TestSeparatelyExecNonIncrementalTransactionsSignedTogetherVariables memory vars = _getExternalSignaturesForNonIncrementalTxsWithMerkleTree(txs, moreOptions.testSigningMultipleChainIdsTogether, moreOptions.testGasTank);

        // If testing multi-use, loop this code a second time:
        for (uint256 round = 0; round < (moreOptions.testMultiUse || moreOptions.testMultiUseOfSingleUse ? 2 : 1); round++) {
            // For each TX:
            uint256 initialChainId;

            for (uint256 i = 0; i < txs.length; i++) {
                // Change the chain ID if testing multiple chain IDs
                if (moreOptions.testSigningMultipleChainIdsTogether && i == 1) {
                    initialChainId = block.chainid;
                    vm.chainId(1234);
                }

                // If testing gas tanks (for multi-use function calls), set gas refund variables for Safe TXs
                GetExternalSignaturesForNonIncrementalTxsWithMerkleTreeVariables memory vars2;
                if (moreOptions.testGasTank) vars2 = GetExternalSignaturesForNonIncrementalTxsWithMerkleTreeVariables(500000, 2.5e6, type(uint256).max, address(0xC0FFEE)); // 500k + 2.5m gas = 3m = 1/4th of 12m total in the sufficiently-funded gas tank used in these tests

                // Get signature data:
                bytes memory packedOverlyingSignatures;
                {
                    // Get signatures
                    (
                        bytes memory policyGuardianOverlyingSignaturePointer,
                        bytes memory policyGuardianOverlyingSignatureData
                    ) = _getOverlyingPolicyGuardianSignature(txs[i].to, txs[i].value, txs[i].data, txs[i].operation, 1, options.useSecondaryPolicyGuardian, vars2);

                    // Tamper with raw signatures for negative test cases only
                    if (options.testInvalidUserSignature) vars.externalSignatures[SAM_SCW > ALICE || SAM_SCW > BOB ? 50 : 100] = vars.externalSignatures[SAM_SCW > ALICE || SAM_SCW > BOB ? 50 : 100] == bytes1(0x55) ? bytes1(0x66) : bytes1(0x55);
                    else if (options.testInvalidPolicyGuardianSignature) policyGuardianOverlyingSignatureData[50] = policyGuardianOverlyingSignatureData[50] == bytes1(0x55) ? bytes1(0x66) : bytes1(0x55);
                    else if (options.testShortPolicyGuardianSignature) policyGuardianOverlyingSignatureData = abi.encodePacked(uint256(64), hex'12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678');

                    // Generate overlying WaymontSafeExternalSigner signature
                    bytes memory externalSignerOverlyingSignaturePointer = abi.encodePacked(
                        bytes32(uint256(uint160(address(externalSignerInstance)))),
                        uint256(0),
                        uint8(1)
                    );

                    // Pack all overlying signatures (in correct order)
                    if (address(externalSignerInstance) > address(policyGuardianSigner)) {
                        packedOverlyingSignatures = abi.encodePacked(policyGuardianOverlyingSignaturePointer, externalSignerOverlyingSignaturePointer, policyGuardianOverlyingSignatureData);
                    } else {
                        packedOverlyingSignatures = abi.encodePacked(externalSignerOverlyingSignaturePointer, policyGuardianOverlyingSignaturePointer, policyGuardianOverlyingSignatureData);
                    }
                }

                // Expect reverts and/or emits if testing certain things
                if (moreOptions.testRevertBecausePolicyGuardianMustBeEnabled) vm.expectRevert("Policy guardian must be enabled to submit reusable transactions.");
                else if (options.testInvalidUserSignature) vm.expectRevert("GS026");
                else if (options.testInvalidPolicyGuardianSignature) vm.expectRevert("Invalid policy guardian signature.");
                else if (options.testShortPolicyGuardianSignature) vm.expectRevert("Invalid signature length.");
                else if (options.expectRevert) vm.expectRevert("GS013");
                else if (options.expectEmitPolicyGuardianDisabledOnSafe) {
                    vm.expectEmit(true, false, false, true, address(policyGuardianSigner));
                    emit PolicyGuardianDisabledOnSafe(safeInstance, false);
                } else if (options.expectEmitPolicyGuardianTimelockChanged) {
                    vm.expectEmit(true, false, false, true, address(policyGuardianSigner));
                    emit PolicyGuardianTimelockChanged(safeInstance, options.newPolicyGuardianTimelock);
                } else if (moreOptions.testExpiredTx) vm.expectRevert("This TX is expired/past its deadline.");
                else if ((moreOptions.testMultiUseOfSingleUse && round > 0) || (moreOptions.testExecBlacklisted && !moreOptions.testMultiUse && i == 1)) vm.expectRevert("Function call unique ID has already been used or has been blacklisted.");
                else if (moreOptions.testExecBlacklisted && moreOptions.testMultiUse) vm.expectRevert("Function call group unique ID has been blacklisted.");
                else if (moreOptions.testGasTank && moreOptions.testInsufficientGasTank && (round * txs.length) + i >= 3) vm.expectRevert(stdError.arithmeticError);

                // ExternalSigner.execTransaction
                WaymontSafeExternalSigner.AdditionalExecTransactionParams memory additionalParams = WaymontSafeExternalSigner.AdditionalExecTransactionParams(
                    vars.externalSignatures,
                    txs[i].uniqueId,
                    txs[i].groupUniqueId,
                    txs[i].deadline,
                    vars.merkleProofs[i]
                );
                externalSignerInstance.execTransaction(
                    txs[i].to,
                    txs[i].value,
                    txs[i].data,
                    txs[i].operation,
                    vars2.safeTxGas,
                    vars2.baseGas,
                    vars2.gasPrice,
                    address(0),
                    payable(vars2.refundReceiver),
                    packedOverlyingSignatures,
                    additionalParams
                );
            }

            // Revert chain ID if necessary
            if (moreOptions.testSigningMultipleChainIdsTogether && txs.length > 1) vm.chainId(initialChainId);
        }
    }

    struct ExecNonIncrementalTransactionSigningParams {
        uint256 uniqueId;
        uint256 groupUniqueId;
        uint256 deadline;
    }

    function _encodeNonIncrementalTransactionData(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        ExecNonIncrementalTransactionSigningParams memory additionalParams
    ) internal view returns (bytes memory) {
        bytes32 safeTxHash = keccak256(abi.encode(
            EXTERNAL_SIGNER_SAFE_TX_TYPEHASH,
            to,
            value,
            keccak256(data),
            operation,
            safeTxGas,
            baseGas,
            gasPrice,
            gasToken,
            refundReceiver,
            additionalParams.uniqueId,
            additionalParams.groupUniqueId,
            additionalParams.deadline
        ));
        return abi.encodePacked(bytes1(0x19), bytes1(0x01), externalSignerInstance.domainSeparator(), safeTxHash);
    }

    struct ExternalSignerSafeTxBasicParams {
        address to;
        uint256 value;
        bytes data;
        Enum.Operation operation;
        uint256 uniqueId;
        uint256 groupUniqueId;
        uint256 deadline;
    }

    struct GetExternalSignaturesForNonIncrementalTxsWithMerkleTreeVariables {
        uint256 safeTxGas;
        uint256 baseGas;
        uint256 gasPrice;
        address refundReceiver;
    }

    function _getExternalSignaturesForNonIncrementalTxsWithMerkleTree(
        ExternalSignerSafeTxBasicParams[] memory txs,
        bool testSigningMultipleChainIdsTogether,
        bool testGasTank
    ) internal returns (TestSeparatelyExecNonIncrementalTransactionsSignedTogetherVariables memory ret) {
        // Merkle proof code below only supports up to 2 TXs
        assert(txs.length <= 2);
        
        // Generate merkle tree
        // NOTE: Merkle proof code below only supports up to 2 TXs
        bytes32 root;
        GetExternalSignaturesForNonIncrementalTxsWithMerkleTreeVariables memory vars;

        if (txs.length == 2) {
            // Generate data hash for the new transactions--decide common gas refund params based on testGasTank
            if (testGasTank) vars = GetExternalSignaturesForNonIncrementalTxsWithMerkleTreeVariables(500000, 2.5e6, type(uint256).max, address(0xC0FFEE)); // 500k + 2.5m gas = 3m = 1/4th of 12m total in the sufficiently-funded gas tank used in these tests

            // Generate data hash A
            ExecNonIncrementalTransactionSigningParams memory additionalParams = ExecNonIncrementalTransactionSigningParams(txs[0].uniqueId, txs[0].groupUniqueId, txs[0].deadline);
            bytes32 txHashA = keccak256(_encodeNonIncrementalTransactionData(
                txs[0].to,
                txs[0].value,
                txs[0].data,
                txs[0].operation,
                vars.safeTxGas,
                vars.baseGas,
                vars.gasPrice,
                address(0),
                vars.refundReceiver,
                additionalParams
            ));

            // Store current chain ID and switch to other chain ID to generate TX B data hash
            uint256 initialChainId;

            if (testSigningMultipleChainIdsTogether) {
                initialChainId = block.chainid;
                vm.chainId(1234);
            }

            // Generate TX B data hash
            additionalParams = ExecNonIncrementalTransactionSigningParams(txs[1].uniqueId, txs[1].groupUniqueId, txs[1].deadline);
            bytes32 txHashB = keccak256(_encodeNonIncrementalTransactionData(
                txs[1].to,
                txs[1].value,
                txs[1].data,
                txs[1].operation,
                vars.safeTxGas,
                vars.baseGas,
                vars.gasPrice,
                address(0),
                vars.refundReceiver,
                additionalParams
            ));

            // Back to initial chain ID
            if (testSigningMultipleChainIdsTogether) vm.chainId(initialChainId);

            // Get merkle root
            root = keccak256(txHashA < txHashB ? abi.encode(txHashA, txHashB) : abi.encode(txHashB, txHashA));

            // Build merkle proofs
            ret.merkleProofs = new bytes32[][](2);
            ret.merkleProofs[0] = new bytes32[](1);
            ret.merkleProofs[0][0] = txHashB;
            ret.merkleProofs[1] = new bytes32[](1);
            ret.merkleProofs[1][0] = txHashA;
        } else {
            // Only one level in merkle tree
            ExecNonIncrementalTransactionSigningParams memory additionalParams = ExecNonIncrementalTransactionSigningParams(txs[0].uniqueId, txs[0].groupUniqueId, txs[0].deadline);
            root = keccak256(_encodeNonIncrementalTransactionData(
                txs[0].to,
                txs[0].value,
                txs[0].data,
                txs[0].operation,
                vars.safeTxGas,
                vars.baseGas,
                vars.gasPrice,
                address(0),
                vars.refundReceiver,
                additionalParams
            ));
        }

        // Generate user signing device signature #1
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE, root);
        bytes[] memory topLevelExternalSignatures = new bytes[](3);
        topLevelExternalSignatures[0] = abi.encodePacked(r, s, v);

        // Generate user signing device signature #2
        (v, r, s) = vm.sign(BOB_PRIVATE, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", root)));
        topLevelExternalSignatures[1] = abi.encodePacked(r, s, v + 4);

        // Generate user signing device signature #3
        (v, r, s) = vm.sign(SAM_UNDERLYING_PRIVATE, root);
        bytes memory samUnderlyingSignature = abi.encodePacked(r, s, v);

        // Wrap user signing device signature #3 with a fake SCW
        topLevelExternalSignatures[2] = abi.encodePacked(
            bytes32(uint256(uint160(SAM_SCW))),
            uint256(3 * 65),
            uint8(0)
        );
        bytes memory samScwOverlyingSignatureData = abi.encodePacked(
            uint256(65),
            samUnderlyingSignature
        );

        // Mock fake SCW
        vm.mockCall(
            address(SAM_SCW),
            abi.encodeWithSelector(IStandardSignatureValidator.isValidSignature.selector, root, samUnderlyingSignature),
            abi.encode(bytes4(0x1626ba7e))
        );

        // Return packed signatures
        address[] memory externalSigners = new address[](3);
        externalSigners[0] = ALICE;
        externalSigners[1] = BOB;
        externalSigners[2] = SAM_SCW;
        ret.externalSignatures = abi.encodePacked(_packSignaturesOrderedBySigner(topLevelExternalSignatures, externalSigners), samScwOverlyingSignatureData);
    }

    function _getOverlyingPolicyGuardianSignature(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 overlyingSignaturesBeforePolicyGuardian,
        bool useSecondaryPolicyGuardian,
        GetExternalSignaturesForNonIncrementalTxsWithMerkleTreeVariables memory gasVars
    ) internal view returns (
        bytes memory policyGuardianOverlyingSignaturePointer,
        bytes memory policyGuardianOverlyingSignatureData
    ) {
        // Generate data hash for the new transaction
        bytes32 txHash = keccak256(safeInstance.encodeTransactionData(to, value, data, operation, gasVars.safeTxGas, gasVars.baseGas, gasVars.gasPrice, address(0), payable(gasVars.refundReceiver), safeInstance.nonce()));

        // Generate underlying/actual policy guardian signature
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(useSecondaryPolicyGuardian ? SECONDARY_POLICY_GUARDIAN_PRIVATE : POLICY_GUARDIAN_PRIVATE, txHash);
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

    function testSetGasTankValue() public {
        uint256 gasTankValue = 1234;
        _execTransaction(address(externalSignerInstance), 0, abi.encodeWithSelector(externalSignerInstance.setGasTank.selector, gasTankValue));
        assert(externalSignerInstance.reusableFunctionCallGasTank() == gasTankValue);
    }

    function _demoSeparatelyExecNonIncrementalTransactionsSignedTogether(
        TestSeparatelyExecNonIncrementalTransactionsSignedTogetherOptions memory moreOptionsRaw,
        bool skipPolicyGuardianAssertions
    ) internal {
        // Send ETH to Safe
        vm.deal(address(safeInstance), (1337 + 1338) * (moreOptionsRaw.testMultiUse ? 2 : 1));

        // Transaction params
        ExternalSignerSafeTxBasicParams[] memory txs = new ExternalSignerSafeTxBasicParams[](2);
        txs[0] = ExternalSignerSafeTxBasicParams(
            address(this),
            1337,
            abi.encodeWithSelector(this.sampleWalletOnlyFunction.selector, 22222222),
            Enum.Operation.Call,
            0,
            0,
            block.timestamp + 365 days
        );
        txs[1] = ExternalSignerSafeTxBasicParams(
            address(this),
            1338,
            abi.encodeWithSelector(this.sampleWalletOnlyFunction2.selector, 33333333),
            Enum.Operation.Call,
            0,
            0,
            block.timestamp + 365 days
        );

        // Use groupUniqueIds if multiUse or uniqueIds by default
        if (moreOptionsRaw.testMultiUse) {
            // Simulate random ID generation--IN PRACTICE THESE SHOULD ALWAYS BE RANDOM
            lastUniqueId = uint256(keccak256(abi.encode(lastUniqueId)));
            txs[0].groupUniqueId = lastUniqueId;
            txs[1].groupUniqueId = lastUniqueId;
        } else {
            // Simulate random ID generation--IN PRACTICE THESE SHOULD ALWAYS BE RANDOM
            lastUniqueId = uint256(keccak256(abi.encode(lastUniqueId)));
            txs[0].uniqueId = lastUniqueId;
            lastUniqueId = uint256(keccak256(abi.encode(lastUniqueId)));
            txs[1].uniqueId = lastUniqueId;
        }

        // Set gas tank
        uint256 initialVmGasPrice;

        if (moreOptionsRaw.testGasTank) {
            initialVmGasPrice = tx.gasprice;
            vm.txGasPrice(2); // Set tx.gasprice to 2 for example purposes
            uint256 gasTankValue = (moreOptionsRaw.testInsufficientGasTank ? 9e6 : 12e6) * tx.gasprice;
            _execTransaction(address(externalSignerInstance), 0, abi.encodeWithSelector(externalSignerInstance.setGasTank.selector, gasTankValue));
            assert(externalSignerInstance.reusableFunctionCallGasTank() == gasTankValue);
            vm.deal(address(safeInstance), gasTankValue);
        }

        // Safe.execTransaction expecting revert
        TestExecTransactionOptions memory options = TestExecTransactionOptions(false, false, true, false, false, false, false, 0);
        TestSeparatelyExecNonIncrementalTransactionsSignedTogetherOptions memory moreOptions = TestSeparatelyExecNonIncrementalTransactionsSignedTogetherOptions(moreOptionsRaw.testSigningMultipleChainIdsTogether, moreOptionsRaw.testMultiUse, false, false, false, moreOptionsRaw.testRevertBecausePolicyGuardianMustBeEnabled, moreOptionsRaw.testGasTank, false);
        _separatelyExecNonIncrementalTransactionsSignedTogether(txs, options, moreOptions);

        if (!skipPolicyGuardianAssertions) {
            options = TestExecTransactionOptions(false, false, false, true, false, false, false, 0);
            _separatelyExecNonIncrementalTransactionsSignedTogether(txs, options, moreOptions);
            options = TestExecTransactionOptions(false, false, false, false, true, false, false, 0);
            _separatelyExecNonIncrementalTransactionsSignedTogether(txs, options, moreOptions);
        }

        // Expect revert when expired if specified in test options
        if (moreOptionsRaw.testExpiredTx) {
            vm.warp(block.timestamp + 365 days + 1 seconds);
            moreOptions.testExpiredTx = true;
        }

        // If option is set, test blacklisting
        if (moreOptionsRaw.testExecBlacklisted) {
            bytes memory data2 = abi.encodeWithSelector(externalSignerInstance.blacklistFunctionCall.selector, moreOptionsRaw.testMultiUse ? txs[1].groupUniqueId : txs[1].uniqueId);
            _execTransaction(address(externalSignerInstance), 0, data2);
            moreOptions.testExecBlacklisted = true;
        }

        // Safe.execTransaction
        moreOptions.testMultiUseOfSingleUse = moreOptionsRaw.testMultiUseOfSingleUse;
        moreOptions.testInsufficientGasTank = moreOptionsRaw.testInsufficientGasTank;
        _separatelyExecNonIncrementalTransactionsSignedTogether(txs, TestExecTransactionOptions(false, false, false, false, false, false, false, 0), moreOptions);

        // Assert TX succeeded
        if (!moreOptionsRaw.testExpiredTx && !moreOptionsRaw.testExecBlacklisted && !moreOptionsRaw.testRevertBecausePolicyGuardianMustBeEnabled) {
            assert(dummy == 22222222);
            assert(dummy2 == 33333333);
        }

        // Reset tx.gasprice to what it was initially
        if (moreOptionsRaw.testGasTank) vm.txGasPrice(initialVmGasPrice);
    }

    function testSeparatelyExecNonIncrementalTransactionsSignedTogether() public {
        _demoSeparatelyExecNonIncrementalTransactionsSignedTogether(TestSeparatelyExecNonIncrementalTransactionsSignedTogetherOptions(false, false, false, false, false, false, false, false), false);
    }

    function testExecTransactionsWithDifferentChainIdsSignedTogether() public {
        _demoSeparatelyExecNonIncrementalTransactionsSignedTogether(TestSeparatelyExecNonIncrementalTransactionsSignedTogetherOptions(true, false, false, false, false, false, false, false), false);
    }

    function testRepeatedlySeparatelyExecMultiUseTransactionsSignedTogether() public {
        _demoSeparatelyExecNonIncrementalTransactionsSignedTogether(TestSeparatelyExecNonIncrementalTransactionsSignedTogetherOptions(false, true, false, false, false, false, false, false), false);
    }

    function testRepeatedlySeparatelyExecMultiUseTransactionsSignedTogetherUsingGasTank() public {
        _demoSeparatelyExecNonIncrementalTransactionsSignedTogether(TestSeparatelyExecNonIncrementalTransactionsSignedTogetherOptions(false, true, false, false, false, false, true, false), false);
    }

    function testRepeatedlySeparatelyExecMultiUseTransactionsSignedTogetherUsingInsufficientGasTank() public {
        _demoSeparatelyExecNonIncrementalTransactionsSignedTogether(TestSeparatelyExecNonIncrementalTransactionsSignedTogetherOptions(false, true, false, false, false, false, true, true), false);
    }

    function testCannotRepeatedlyExecSingleUseNonIncrementalTransactions() public {
        _demoSeparatelyExecNonIncrementalTransactionsSignedTogether(TestSeparatelyExecNonIncrementalTransactionsSignedTogetherOptions(false, false, true, false, false, false, false, false), false);
    }

    function testCannotExecBlacklistedNonIncrementalTransaction() public {
        _demoSeparatelyExecNonIncrementalTransactionsSignedTogether(TestSeparatelyExecNonIncrementalTransactionsSignedTogetherOptions(false, false, false, true, false, false, false, false), false);
    }

    function testCannotExecBlacklistedMultiUseTransaction() public {
        _demoSeparatelyExecNonIncrementalTransactionsSignedTogether(TestSeparatelyExecNonIncrementalTransactionsSignedTogetherOptions(false, true, false, true, false, false, false, false), false);
    }

    function testCannotExecExpiredNonIncrementalTransactions() public {
        _demoSeparatelyExecNonIncrementalTransactionsSignedTogether(TestSeparatelyExecNonIncrementalTransactionsSignedTogetherOptions(false, false, false, false, true, false, false, false), false);
    }

    function testExecMultiUseTransactionWithoutPolicyGuardianIfNotEnforced() public {
        // Set up Safe with requirePolicyGuardianForReusableCalls off
        setUpWaymontSafe(false);

        // Remove policy guardian from Safe
        _execTransaction(address(safeInstance), 0, abi.encodeWithSelector(safeInstance.removeOwner.selector, address(externalSignerInstance), address(policyGuardianSigner), 1));

        // Make sure it works
        _demoSeparatelyExecNonIncrementalTransactionsSignedTogether(TestSeparatelyExecNonIncrementalTransactionsSignedTogetherOptions(false, true, false, false, false, false, false, false), true);
    }

    function testCannotExecMultiUseTransactionWithoutPolicyGuardianIfEnforced() public {
        // Remove policy guardian from Safe
        _execTransaction(address(safeInstance), 0, abi.encodeWithSelector(safeInstance.removeOwner.selector, address(externalSignerInstance), address(policyGuardianSigner), 1));

        // Make sure it fails
        _demoSeparatelyExecNonIncrementalTransactionsSignedTogether(TestSeparatelyExecNonIncrementalTransactionsSignedTogetherOptions(false, true, false, false, false, true, false, false), true);
    }

    function testExecMultiUseTransactionWithDisabledPolicyGuardianIfNotEnforced() public {
        // Set up Safe with requirePolicyGuardianForReusableCalls off
        setUpWaymontSafe(false);

        // Disable policy guardian on the Safe
        testDisablePolicyGuardian();

        // Make sure it works
        _demoSeparatelyExecNonIncrementalTransactionsSignedTogether(TestSeparatelyExecNonIncrementalTransactionsSignedTogetherOptions(false, true, false, false, false, false, false, false), true);
    }

    function testCannotExecMultiUseTransactionWithDisabledPolicyGuardianIfEnforced() public {
        // Disable policy guardian on the Safe
        testDisablePolicyGuardian();

        // Make sure it fails
        _demoSeparatelyExecNonIncrementalTransactionsSignedTogether(TestSeparatelyExecNonIncrementalTransactionsSignedTogetherOptions(false, true, false, false, false, true, false, false), true);
    }

    function testExecMultiUseTransactionAfterPolicyGuardianDisabledWithoutPolicyGuardianIfPolicyGuardianNotEnforced() public {
        // Set up Safe with requirePolicyGuardianForReusableCalls off
        setUpWaymontSafe(false);

        // Disable policy guardian on the Safe
        testDisablePolicyGuardianWithoutPolicyGuardian();

        // Make sure it works
        _demoSeparatelyExecNonIncrementalTransactionsSignedTogether(TestSeparatelyExecNonIncrementalTransactionsSignedTogetherOptions(false, true, false, false, false, false, false, false), true);
    }

    function testExecMultiUseTransactionAfterPolicyGuardianDisabledWithoutPolicyGuardianIfPolicyGuardianEnforced() public {
        // Disable policy guardian on the Safe
        testDisablePolicyGuardianWithoutPolicyGuardian();

        // Make sure it fails
        _demoSeparatelyExecNonIncrementalTransactionsSignedTogether(TestSeparatelyExecNonIncrementalTransactionsSignedTogetherOptions(false, true, false, false, false, true, false, false), true);
    }

    function testExecMultiUseTransactionWithGloballyDisabledPolicyGuardianIfNotEnforced() public {
        // Set up Safe with requirePolicyGuardianForReusableCalls off
        setUpWaymontSafe(false);

        // Disable the policy guardian globally
        testDisablePolicyGuardianGlobally();

        // Make sure it works
        _demoSeparatelyExecNonIncrementalTransactionsSignedTogether(TestSeparatelyExecNonIncrementalTransactionsSignedTogetherOptions(false, true, false, false, false, false, false, false), true);
    }

    function testCannotExecMultiUseTransactionWithGloballyDisabledPolicyGuardianIfEnforced() public {
        // Disable the policy guardian globally
        testDisablePolicyGuardianGlobally();

        // Make sure it fails
        _demoSeparatelyExecNonIncrementalTransactionsSignedTogether(TestSeparatelyExecNonIncrementalTransactionsSignedTogetherOptions(false, true, false, false, false, true, false, false), true);
    }

    function testExecMultiUseTransactionWithPermanentlyDisabledPolicyGuardianIfNotEnforced() public {
        // Set up Safe with requirePolicyGuardianForReusableCalls off
        setUpWaymontSafe(false);

        // Disable the policy guardian permanently
        testDisablePolicyGuardianPermanently();

        // Make sure it works
        _demoSeparatelyExecNonIncrementalTransactionsSignedTogether(TestSeparatelyExecNonIncrementalTransactionsSignedTogetherOptions(false, true, false, false, false, false, false, false), true);
    }

    function testCannotExecMultiUseTransactionWithPermanentlyDisabledPolicyGuardianIfEnforced() public {
        // Disable the policy guardian permanently
        testDisablePolicyGuardianPermanently();

        // Make sure it fails
        _demoSeparatelyExecNonIncrementalTransactionsSignedTogether(TestSeparatelyExecNonIncrementalTransactionsSignedTogetherOptions(false, true, false, false, false, true, false, false), true);
    }

    function testExecMultiUseTransactionWithLowThresholdIfPolicyGuardianNotEnforced() public {
        // Set up Safe with requirePolicyGuardianForReusableCalls off
        setUpWaymontSafe(false);

        // Decrease Safe threshold by 1
        _execTransaction(address(safeInstance), 0, abi.encodeWithSelector(safeInstance.changeThreshold.selector, safeInstance.getThreshold() - 1));

        // Make sure it works
        _demoSeparatelyExecNonIncrementalTransactionsSignedTogether(TestSeparatelyExecNonIncrementalTransactionsSignedTogetherOptions(false, true, false, false, false, false, false, false), true);
    }

    function testCannotExecMultiUseTransactionWithLowThresholdIfPolicyGuardianEnforced() public {
        // Decrease Safe threshold by 1
        _execTransaction(address(safeInstance), 0, abi.encodeWithSelector(safeInstance.changeThreshold.selector, safeInstance.getThreshold() - 1));

        // Make sure it fails
        _demoSeparatelyExecNonIncrementalTransactionsSignedTogether(TestSeparatelyExecNonIncrementalTransactionsSignedTogetherOptions(false, true, false, false, false, true, false, false), true);
    }
}
