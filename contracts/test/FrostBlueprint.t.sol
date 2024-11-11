// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.9.0;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@src/FrostBlueprint.sol";

contract ERC20Mock is ERC20, Ownable {
    constructor(string memory name, string memory symbol, uint8 decimals, address owner, uint256 initialSupply)
        Ownable(owner)
        ERC20(name, symbol)
    {
        mint(owner, initialSupply * (10 ** uint256(decimals)));
    }

    function mint(address to, uint256 value) public virtual {
        _mint(to, value);
    }

    function burn(address from, uint256 value) public virtual {
        _burn(from, value);
    }
}

contract FrostBlueprintTest is Test {
    // Instance of the FrostBlueprint contract
    FrostBlueprint public frostBlueprint;

    // Mock ERC20 token
    ERC20Mock public mockERC20;

    // Address variables for different roles
    address public owner;
    address public rootChain;
    bytes public operator1PublicKey;
    bytes public operator2PublicKey;
    address public operator1;
    address public operator2;
    address public serviceOwner;
    address public nonAuthorized;

    // Constants
    address constant TNT_ERC20_ADDRESS = address(0x0000000000000000000000000000000000000802);

    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    uint8 constant KEYGEN_JOB_ID = 0;
    uint8 constant SIGN_JOB_ID = 1;

    // Setup function runs before each test
    function setUp() public {
        // Assign test addresses
        owner = address(0x1);
        rootChain = address(0x2);
        operator1PublicKey = hex"14463bfb5433001c187e7a28c480d3945db9279ba4ef96f29c5e0e565f56b254d5";
        operator2PublicKey = hex"7f316ac29a1c2a5e6e5c8cff51b225af088b5066e569c73ba6eba896a07c560f54";
        operator1 = operatorAddress(operator1PublicKey);
        operator2 = operatorAddress(operator2PublicKey);
        serviceOwner = address(0x5);
        nonAuthorized = address(0x6);

        // Deploy mock ERC20 token
        mockERC20 = new ERC20Mock("Tangle", "TNT", 18, owner, 1e24); // 1 million tokens
        bytes memory code = address(mockERC20).code;
        vm.etch(TNT_ERC20_ADDRESS, code);
        mockERC20 = ERC20Mock(TNT_ERC20_ADDRESS);
        mockERC20.mint(owner, 1e24); // Mint 1 million tokens to owner

        // Deploy FrostBlueprint contract with owner as the deployer
        vm.startPrank(owner);
        frostBlueprint = new FrostBlueprint();
        rootChain = frostBlueprint.ROOT_CHAIN();
        assertEq(frostBlueprint.owner(), owner);
        vm.stopPrank();
    }

    // Helper function to convert a public key to an operator address
    function operatorAddress(bytes memory publicKey) internal pure returns (address) {
        return address(uint160(uint256(keccak256(publicKey))));
    }

    // Test deployment and initial configuration
    function testDeployment() public {
        // Check that the owner has DEFAULT_ADMIN_ROLE
        assertTrue(frostBlueprint.hasRole(DEFAULT_ADMIN_ROLE, owner));

        // Check that rootChain has ROOT_CHAIN_ROLE and DEFAULT_ADMIN_ROLE
        assertTrue(frostBlueprint.hasRole(frostBlueprint.ROOT_CHAIN_ROLE(), rootChain));
        assertTrue(frostBlueprint.hasRole(DEFAULT_ADMIN_ROLE, rootChain));

        // Check that TNT_ERC20_ADDRESS is supported by default
        address[] memory supportedTokens = frostBlueprint.supportedTokens();
        bool tokenSupported = false;
        for (uint256 i = 0; i < supportedTokens.length; i++) {
            if (supportedTokens[i] == TNT_ERC20_ADDRESS) {
                tokenSupported = true;
                break;
            }
        }
        assertTrue(tokenSupported, "TNT_ERC20_ADDRESS should be supported by default");

        // Check initial job costs
        // Assuming mockERC20 is deployed at TNT_ERC20_ADDRESS
        // Verify keygen job cost
        uint256 keygenCost = frostBlueprint.jobCost(KEYGEN_JOB_ID, TNT_ERC20_ADDRESS);
        assertEq(keygenCost, 1e15, "Keygen job cost should be 0.001 ether");

        // Verify sign job cost
        uint256 signCost = frostBlueprint.jobCost(SIGN_JOB_ID, TNT_ERC20_ADDRESS);
        assertEq(signCost, 1e13, "Sign job cost should be 0.00001 ether");
    }

    // Test operator registration
    function testOperatorRegistration() public {
        bytes memory operatorPublicKey = abi.encodePacked(operator1);
        // Simulate rootChain calling onRegister
        vm.prank(rootChain);
        frostBlueprint.onRegister(operatorPublicKey, "");

        // Verify that operator1 has OPERATOR_ROLE
        address expectedOperator = frostBlueprint.operatorAddressFromPublicKey(operatorPublicKey);
        assertTrue(
            frostBlueprint.hasRole(frostBlueprint.OPERATOR_ROLE(), expectedOperator),
            "Operator should have OPERATOR_ROLE"
        );

        // Emit and verify OperatorRegistered event
        // Note: Events are not directly captured in Forge tests, but can be verified via other means if necessary
    }

    // Test operator registration by non-rootChain should fail
    function testOperatorRegistrationUnauthorized() public {
        bytes memory operatorPublicKey = abi.encodePacked(operator1);

        // Attempt to register operator1 from non-rootChain address
        vm.prank(nonAuthorized);
        vm.expectRevert("Unauthorized");
        frostBlueprint.onRegister(operatorPublicKey, "");
    }

    // Test adding service operators
    function testAddServiceOperator() public {
        // First, register operator1
        bytes memory operatorPublicKey = abi.encodePacked(operator1);
        vm.prank(rootChain);
        frostBlueprint.onRegister(operatorPublicKey, "");

        uint64 serviceId = 1;

        // Simulate rootChain calling onRequest to add operator1 to serviceId
        bytes[] memory operators = new bytes[](1);
        operators[0] = operatorPublicKey;
        vm.prank(rootChain);
        frostBlueprint.onRequest(serviceId, operators, "");

        // Verify that operator1 is added to the service
        address[] memory serviceOperators = frostBlueprint.serviceOperators(serviceId);
        assertEq(serviceOperators.length, 1, "Service should have 1 operator");

        assertTrue(serviceOperators[0] == operatorAddress(operatorPublicKey), "Operator1 should be added to service");
    }

    // Test adding the same operator twice should revert
    function testAddServiceOperatorTwice() public {
        // Register operator1
        vm.prank(rootChain);
        frostBlueprint.onRegister(operator1PublicKey, "");

        uint64 serviceId = 1;

        bytes[] memory operators = new bytes[](1);
        operators[0] = operator1PublicKey;

        // Add operator1 to serviceId
        vm.prank(rootChain);
        frostBlueprint.onRequest(serviceId, operators, "");

        // Attempt to add operator1 again to the same service
        vm.prank(rootChain);
        vm.expectRevert(abi.encodeWithSelector(FrostBlueprint.OperatorAlreadyAdded.selector, serviceId, operator1));
        frostBlueprint.onRequest(serviceId, operators, "");
    }

    // Test adding unregistered operator should revert
    function testAddUnregisteredServiceOperator() public {
        uint64 serviceId = 1;

        bytes[] memory operators = new bytes[](1);
        bytes memory unregisteredOperatorPK = abi.encodePacked(operator2);
        operators[0] = unregisteredOperatorPK;

        // Attempt to add unregistered operator2 to serviceId
        vm.prank(rootChain);
        vm.expectRevert(abi.encodeWithSelector(FrostBlueprint.OperatorNotRegistered.selector, operator2));
        frostBlueprint.onRequest(serviceId, operators, "");
    }

    // Test handling keygen job result
    function testHandleKeygenJobResult() public {
        // Register operator1
        bytes memory operatorPublicKey = abi.encodePacked(operator1);
        vm.prank(rootChain);
        frostBlueprint.onRegister(operatorPublicKey, "");

        uint64 serviceId = 1;

        // Add operator1 to serviceId
        bytes[] memory operators = new bytes[](1);
        operators[0] = operatorPublicKey;
        vm.prank(rootChain);
        frostBlueprint.onRequest(serviceId, operators, "");

        // Prepare inputs and outputs for keygen job
        bytes memory inputs = ""; // Assuming no inputs needed
        bytes memory validPublicKey = new bytes(33); // Valid ECDSA public key length
        validPublicKey[0] = 0x04; // Uncompressed key prefix
        // Fill the rest with dummy data
        for (uint256 i = 1; i < 33; i++) {
            validPublicKey[i] = bytes1(uint8(i));
        }
        bytes memory outputs = validPublicKey;

        // Mock the supportedTokens to include mockERC20
        // Since the constructor adds TNT_ERC20_ADDRESS, ensure it's the mockERC20 address
        // For simplicity, assume mockERC20 is at TNT_ERC20_ADDRESS

        // Assign mockERC20 balance to FrostBlueprint
        // Transfer tokens from owner to FrostBlueprint
        vm.prank(owner);
        mockERC20.transfer(address(frostBlueprint), 1e18); // 1 token

        // Simulate rootChain calling onJobResult
        vm.prank(rootChain);
        frostBlueprint.onJobResult(serviceId, KEYGEN_JOB_ID, 1, operatorPublicKey, inputs, outputs);

        // Verify that operator1 has been credited
        uint256 expectedAmount = 1e15 * 5 * 1; // tokensPerSec * duration * operatorsCount
        uint256 actualBalance = frostBlueprint.operatorBalanceOf(operator1, TNT_ERC20_ADDRESS);
        assertEq(actualBalance, expectedAmount, "Operator1 should be credited correctly");
    }

    // Test handling sign job result
    function testHandleSignJobResult() public {
        // Register operator1
        bytes memory operatorPublicKey = abi.encodePacked(operator1);
        vm.prank(rootChain);
        frostBlueprint.onRegister(operatorPublicKey, "");

        uint64 serviceId = 1;

        // Add operator1 to serviceId
        bytes[] memory operators = new bytes[](1);
        operators[0] = operatorPublicKey;
        vm.prank(rootChain);
        frostBlueprint.onRequest(serviceId, operators, "");

        // Prepare inputs and outputs for sign job
        bytes memory publicKey = abi.encodePacked(operator1);
        bytes memory message = "Test Message";
        bytes memory inputs = abi.encode(publicKey, message);
        bytes memory signature = new bytes(65); // Valid ECDSA signature length
        // Fill with dummy data
        for (uint256 i = 0; i < 65; i++) {
            signature[i] = bytes1(uint8(i));
        }
        bytes memory outputs = signature;

        // Assign mockERC20 balance to FrostBlueprint
        vm.prank(owner);
        mockERC20.transfer(address(frostBlueprint), 1e18); // 1 token

        // Simulate rootChain calling onJobResult
        vm.prank(rootChain);
        frostBlueprint.onJobResult(serviceId, SIGN_JOB_ID, 1, operatorPublicKey, inputs, outputs);

        // Verify that operator1 has been credited
        uint256 expectedAmount = 1e13 * 3; // tokensPerSec * duration
        uint256 actualBalance = frostBlueprint.operatorBalanceOf(operator1, TNT_ERC20_ADDRESS);
        assertEq(actualBalance, expectedAmount, "Operator1 should be credited correctly for sign job");
    }

    // Test handling unsupported job
    function testHandleUnsupportedJob() public {
        uint64 serviceId = 1;
        uint8 unsupportedJobId = 2;

        bytes memory operatorPublicKey = abi.encodePacked(operator1);

        // Simulate rootChain calling onJobResult with unsupported job
        vm.prank(rootChain);
        vm.expectRevert(abi.encodeWithSelector(FrostBlueprint.UnsupportedJob.selector, unsupportedJobId));
        frostBlueprint.onJobResult(serviceId, unsupportedJobId, 1, operatorPublicKey, "", "");
    }

    // Test handling invalid ECDSA public key
    function testHandleInvalidECDSAPublicKey() public {
        // Register operator1
        bytes memory operatorPublicKey = abi.encodePacked(operator1);
        vm.prank(rootChain);
        frostBlueprint.onRegister(operatorPublicKey, "");

        uint64 serviceId = 1;

        // Add operator1 to serviceId
        bytes[] memory operators = new bytes[](1);
        operators[0] = operatorPublicKey;
        vm.prank(rootChain);
        frostBlueprint.onRequest(serviceId, operators, "");

        // Prepare invalid outputs for keygen job (length != 33)
        bytes memory outputs = new bytes(32); // Invalid length

        // Simulate rootChain calling onJobResult
        vm.prank(rootChain);
        vm.expectRevert(abi.encodeWithSelector(FrostBlueprint.InvalidECDSAPublicKey.selector, outputs));
        frostBlueprint.onJobResult(serviceId, KEYGEN_JOB_ID, 1, operatorPublicKey, "", outputs);
    }

    // Test handling invalid ECDSA signature
    function testHandleInvalidECDSASignature() public {
        // Register operator1
        bytes memory operatorPublicKey = abi.encodePacked(operator1);
        vm.prank(rootChain);
        frostBlueprint.onRegister(operatorPublicKey, "");

        uint64 serviceId = 1;

        // Add operator1 to serviceId
        bytes[] memory operators = new bytes[](1);
        operators[0] = operatorPublicKey;
        vm.prank(rootChain);
        frostBlueprint.onRequest(serviceId, operators, "");

        // Prepare inputs and outputs for sign job with invalid signature length
        bytes memory publicKey = abi.encodePacked(operator1);
        bytes memory message = "Test Message";
        bytes memory inputs = abi.encode(publicKey, message);
        bytes memory invalidSignature = new bytes(64); // Invalid length
        bytes memory outputs = invalidSignature;

        // Simulate rootChain calling onJobResult
        vm.prank(rootChain);
        vm.expectRevert(abi.encodeWithSelector(FrostBlueprint.InvalidECDSASignature.selector, invalidSignature));
        frostBlueprint.onJobResult(serviceId, SIGN_JOB_ID, 1, operatorPublicKey, inputs, outputs);
    }

    // Test calculateServiceCost
    function testCalculateServiceCost() public {
        uint256 serviceDuration = 10; // seconds

        // Calculate expected cost
        uint256 oneKeygenCall = 1e15; // as set in deployment
        uint256 oneSignCall = 1e13;
        uint256 expectedCostPerSec = oneKeygenCall + oneSignCall;
        uint256 expectedTotalCost = expectedCostPerSec * serviceDuration;

        uint256 actualCost = frostBlueprint.calculateServiceCost(serviceDuration, TNT_ERC20_ADDRESS);
        assertEq(actualCost, expectedTotalCost, "Service cost should be calculated correctly");
    }

    // Test updateJobCost
    function testUpdateJobCost() public {
        // New costs
        uint256 newKeygenCost = 2e15; // 0.002 ether
        uint256 newSignCost = 2e13; // 0.00002 ether

        // Update keygen job cost
        vm.prank(owner);
        frostBlueprint.updateJobCost(KEYGEN_JOB_ID, TNT_ERC20_ADDRESS, newKeygenCost);

        // Update sign job cost
        vm.prank(owner);
        frostBlueprint.updateJobCost(SIGN_JOB_ID, TNT_ERC20_ADDRESS, newSignCost);

        // Verify updates
        uint256 updatedKeygenCost = frostBlueprint.jobCost(KEYGEN_JOB_ID, TNT_ERC20_ADDRESS);
        assertEq(updatedKeygenCost, newKeygenCost, "Keygen job cost should be updated");

        uint256 updatedSignCost = frostBlueprint.jobCost(SIGN_JOB_ID, TNT_ERC20_ADDRESS);
        assertEq(updatedSignCost, newSignCost, "Sign job cost should be updated");
    }

    // Test updateJobCost with unsupported job ID
    function testUpdateJobCostUnsupportedJob() public {
        uint8 unsupportedJobId = 2;
        uint256 newCost = 1e12;

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(FrostBlueprint.UnsupportedJob.selector, unsupportedJobId));
        frostBlueprint.updateJobCost(unsupportedJobId, TNT_ERC20_ADDRESS, newCost);
    }

    // Test adding supported tokens
    function testAddSupportedTokens() public {
        // Deploy a new mock token
        ERC20Mock newMockToken = new ERC20Mock("New Mock Token", "NMTKN", 18, owner, 1e24);

        address[] memory tokensToAdd = new address[](1);
        tokensToAdd[0] = address(newMockToken);

        vm.prank(owner);
        frostBlueprint.addSupportedTokens(tokensToAdd);

        // Verify the token is added
        address[] memory supportedTokens = frostBlueprint.supportedTokens();
        bool tokenAdded = false;
        for (uint256 i = 0; i < supportedTokens.length; i++) {
            if (supportedTokens[i] == address(newMockToken)) {
                tokenAdded = true;
                break;
            }
        }
        assertTrue(tokenAdded, "New mock token should be added to supported tokens");
    }

    // Test adding already supported token should revert
    function testAddAlreadySupportedToken() public {
        address[] memory tokensToAdd = new address[](1);
        tokensToAdd[0] = TNT_ERC20_ADDRESS;

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(PaymentManagerBase.TokenAlreadySupported.selector, TNT_ERC20_ADDRESS));
        frostBlueprint.addSupportedTokens(tokensToAdd);
    }

    // Test removing supported tokens
    function testRemoveSupportedTokens() public {
        address[] memory tokensToRemove = new address[](1);
        tokensToRemove[0] = TNT_ERC20_ADDRESS;

        vm.prank(owner);
        frostBlueprint.removeSupportedTokens(tokensToRemove);

        // Verify the token is removed
        address[] memory supportedTokens = frostBlueprint.supportedTokens();
        bool tokenRemoved = true;
        for (uint256 i = 0; i < supportedTokens.length; i++) {
            if (supportedTokens[i] == TNT_ERC20_ADDRESS) {
                tokenRemoved = false;
                break;
            }
        }
        assertTrue(tokenRemoved, "TNT_ERC20_ADDRESS should be removed from supported tokens");
    }

    // Test removing a token that is not supported should revert
    function testRemoveUnsupportedToken() public {
        // Deploy a new mock token
        ERC20Mock newMockToken = new ERC20Mock("New Mock Token", "NMTKN", 18, owner, 1e24);

        address[] memory tokensToRemove = new address[](1);
        tokensToRemove[0] = address(newMockToken);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(PaymentManagerBase.TokenNotSupported.selector, address(newMockToken)));
        frostBlueprint.removeSupportedTokens(tokensToRemove);
    }

    // Test deposit tokens by service owner
    function testDepositTokens() public {
        uint256 depositAmount = 1e18; // 1 token

        // Deploy a new mock token and add to supported tokens
        ERC20Mock newMockToken = new ERC20Mock("New Mock Token", "NMTKN", 18, owner, 1e24);
        address[] memory tokensToAdd = new address[](1);
        tokensToAdd[0] = address(newMockToken);
        vm.prank(owner);
        frostBlueprint.addSupportedTokens(tokensToAdd);

        // Approve FrostBlueprint to spend tokens
        vm.prank(serviceOwner);
        newMockToken.approve(address(frostBlueprint), depositAmount);

        // Simulate serviceOwner depositing tokens
        vm.prank(serviceOwner);
        frostBlueprint.deposit(address(newMockToken), depositAmount);

        // Verify Deposit event (optional)

        // Verify the contract's balance
        uint256 contractBalance = newMockToken.balanceOf(address(frostBlueprint));
        assertEq(contractBalance, depositAmount, "FrostBlueprint should have the deposited tokens");
    }

    // Test deposit ETH by service owner
    function testDepositETH() public {
        uint256 depositAmount = 1 ether;

        // Simulate serviceOwner depositing ETH
        vm.deal(serviceOwner, depositAmount);
        vm.prank(serviceOwner);
        frostBlueprint.deposit{value: depositAmount}(address(0), depositAmount);

        // Verify the contract's ETH balance
        uint256 contractBalance = address(frostBlueprint).balance;
        assertEq(contractBalance, depositAmount, "FrostBlueprint should have the deposited ETH");
    }

    // Test deposit with invalid amount should revert
    function testDepositInvalidAmount() public {
        uint256 depositAmount = 0;

        // Attempt to deposit with amount 0
        vm.prank(serviceOwner);
        vm.expectRevert("InvalidAmount()");
        frostBlueprint.deposit(address(0), depositAmount);
    }

    // Test withdraw tokens by operator
    function testWithdrawTokens() public {
        uint256 depositAmount = 1e18; // 1 token
        uint256 withdrawAmount = 0.0005 ether; // 0.0005 ether (less than keygen job cost)

        // Register operator1 and credit
        vm.prank(rootChain);
        frostBlueprint.onRegister(operator1PublicKey, "");

        uint256 balance = mockERC20.balanceOf(owner);
        // Transfer some tokens from owner to blueprint manager by depositing
        vm.prank(owner);
        // Approve FrostBlueprint to spend tokens
        mockERC20.approve(address(frostBlueprint), balance);
        vm.prank(owner);
        frostBlueprint.deposit(TNT_ERC20_ADDRESS, depositAmount);

        // Credit operator1
        vm.prank(rootChain);
        frostBlueprint.creditOperator(operator1, TNT_ERC20_ADDRESS, withdrawAmount);

        // Record initial balance of operator1
        uint256 initialBalance = mockERC20.balanceOf(operator1);

        // Simulate operator1 withdrawing tokens
        vm.prank(operator1);
        frostBlueprint.withdraw(TNT_ERC20_ADDRESS, withdrawAmount);

        // Verify operator1 received tokens
        uint256 finalBalance = mockERC20.balanceOf(operator1);
        assertEq(finalBalance, initialBalance + withdrawAmount, "Operator1 should receive withdrawn tokens");

        // Verify operator's balance in FrostBlueprint
        uint256 operatorBalance = frostBlueprint.operatorBalanceOf(operator1, TNT_ERC20_ADDRESS);
        assertEq(operatorBalance, 0, "Operator1's balance should be zero after withdrawal");
    }

    // Test withdraw ETH by operator
    function testWithdrawETH() public {
        uint256 depositAmount = 1 ether;
        uint256 withdrawAmount = 5 ether;

        // Credit operator1 with ETH (assuming contract has enough balance)
        // For testing, fund the contract with ETH
        vm.deal(owner, withdrawAmount);
        vm.deal(address(frostBlueprint), withdrawAmount);

        // Add Support for name tokens
        vm.prank(owner);
        address[] memory supportedTokens = new address[](1);
        supportedTokens[0] = address(0);
        frostBlueprint.addSupportedTokens(supportedTokens);

        // Register operator1 and credit
        vm.prank(rootChain);
        frostBlueprint.onRegister(operator1PublicKey, "");

        // Credit operator1
        vm.prank(rootChain);
        frostBlueprint.creditOperator(operator1, address(0), withdrawAmount);

        // Record initial ETH balance of operator1
        uint256 initialBalance = operator1.balance;

        // Simulate operator1 withdrawing ETH
        vm.prank(operator1);
        frostBlueprint.withdraw(address(0), withdrawAmount);

        // Verify operator1 received ETH
        uint256 finalBalance = operator1.balance;
        assertEq(finalBalance, initialBalance + withdrawAmount, "Operator1 should receive withdrawn ETH");

        // Verify operator's ETH balance in FrostBlueprint
        uint256 operatorETHBalance = frostBlueprint.operatorBalanceOf(operator1, address(0));
        assertEq(operatorETHBalance, 0, "Operator1's ETH balance should be zero after withdrawal");
    }

    // Test withdraw with insufficient balance should revert
    function testWithdrawInsufficientBalance() public {
        uint256 withdrawAmount = 1e18; // 1 token

        // Register operator1
        bytes memory operatorPublicKey = abi.encodePacked(operator1);
        vm.prank(rootChain);
        frostBlueprint.onRegister(operatorPublicKey, "");

        // Attempt to withdraw without crediting
        vm.prank(operator1);
        vm.expectRevert(abi.encodeWithSelector(PaymentManagerBase.InsufficientBalance.selector, TNT_ERC20_ADDRESS));
        frostBlueprint.withdraw(TNT_ERC20_ADDRESS, withdrawAmount);
    }

    // Test withdraw to a specific recipient
    function testWithdrawAndTransfer() public {
        uint256 depositAmount = 1e18; // 1 token
        uint256 withdrawAmount = 5e14; // 0.0005 ether

        // Register operator1 and credit
        bytes memory operatorPublicKey = abi.encodePacked(operator1);
        vm.prank(rootChain);
        frostBlueprint.onRegister(operatorPublicKey, "");

        vm.prank(rootChain);
        frostBlueprint.creditOperator(operator1, TNT_ERC20_ADDRESS, withdrawAmount);

        // Record initial balance of nonAuthorized
        uint256 initialBalance = mockERC20.balanceOf(nonAuthorized);

        // Simulate operator1 withdrawing to nonAuthorized
        vm.prank(operator1);
        frostBlueprint.withdrawAndTransfer(TNT_ERC20_ADDRESS, withdrawAmount, nonAuthorized);

        // Verify nonAuthorized received tokens
        uint256 finalBalance = mockERC20.balanceOf(nonAuthorized);
        assertEq(finalBalance, initialBalance + withdrawAmount, "nonAuthorized should receive withdrawn tokens");

        // Verify operator's balance in FrostBlueprint
        uint256 operatorBalance = frostBlueprint.operatorBalanceOf(operator1, TNT_ERC20_ADDRESS);
        assertEq(operatorBalance, 0, "Operator1's balance should be zero after withdrawal");
    }

    // Test withdrawAndTransfer with invalid recipient should revert
    function testWithdrawAndTransferInvalidRecipient() public {
        uint256 withdrawAmount = 1e18; // 1 token

        // Register operator1 and credit
        bytes memory operatorPublicKey = abi.encodePacked(operator1);
        vm.prank(rootChain);
        frostBlueprint.onRegister(operatorPublicKey, "");

        vm.prank(rootChain);
        frostBlueprint.creditOperator(operator1, TNT_ERC20_ADDRESS, withdrawAmount);

        // Attempt to withdraw to address(0)
        vm.prank(operator1);
        vm.expectRevert(abi.encodeWithSelector(PaymentManagerBase.InvalidRecipient.selector, address(0)));
        frostBlueprint.withdrawAndTransfer(TNT_ERC20_ADDRESS, withdrawAmount, address(0));
    }

    // Test deposit ETH with incorrect msg.value should revert
    function testDepositETHIncorrectValue() public {
        uint256 depositAmount = 1 ether;
        uint256 sentValue = 2 ether;

        // Attempt to deposit ETH with incorrect msg.value
        vm.prank(serviceOwner);
        vm.expectRevert(abi.encodeWithSelector(PaymentManagerBase.InvalidETHAmount.selector));
        frostBlueprint.deposit{value: sentValue}(address(0), depositAmount);
    }

    // Test deposit unsupported token should revert
    function testDepositUnsupportedToken() public {
        // Deploy a new mock token but do not add to supported tokens
        ERC20Mock newMockToken = new ERC20Mock("Unsupported Token", "USTKN", 18, owner, 1e24);

        uint256 depositAmount = 1e18; // 1 token

        // Approve FrostBlueprint to spend tokens
        vm.prank(serviceOwner);
        newMockToken.approve(address(frostBlueprint), depositAmount);

        // Attempt to deposit unsupported token
        vm.prank(serviceOwner);
        vm.expectRevert(abi.encodeWithSelector(PaymentManagerBase.TokenNotSupported.selector, address(newMockToken)));
        frostBlueprint.deposit(address(newMockToken), depositAmount);
    }

    // Test withdraw unsupported token should revert
    function testWithdrawUnsupportedToken() public {
        // Deploy a new mock token but do not add to supported tokens
        ERC20Mock newMockToken = new ERC20Mock("Unsupported Token", "USTKN", 18, owner, 1e24);

        uint256 withdrawAmount = 1e18; // 1 token

        // Attempt to withdraw unsupported token
        vm.prank(operator1);
        vm.expectRevert(abi.encodeWithSelector(PaymentManagerBase.TokenNotSupported.selector, address(newMockToken)));
        frostBlueprint.withdraw(address(newMockToken), withdrawAmount);
    }

    // Test unauthorized withdrawal should revert
    function testUnauthorizedWithdrawal() public {
        uint256 withdrawAmount = 1e18; // 1 token

        // Attempt to withdraw as non-operator
        vm.prank(nonAuthorized);
        vm.expectRevert("Unauthorized");
        frostBlueprint.withdraw(TNT_ERC20_ADDRESS, withdrawAmount);
    }
}
