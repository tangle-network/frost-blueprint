// SPDX-License-Identifier: UNLICENSE
pragma solidity >=0.8.13;

import "tnt-core/BlueprintServiceManagerBase.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";

import "@src/payments/IPaymentManager.sol";
import "@src/payments/PaymentManagerBase.sol";

/**
 * @title FrostBlueprint
 * @dev This contract is a blueprint for a FROST service. It extends the
 * `BlueprintServiceManagerBase` contract, which provides the basic functionality
 */
contract FrostBlueprint is BlueprintServiceManagerBase, PaymentManagerBase {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableMap for EnumerableMap.UintToAddressMap;
    using EnumerableMap for EnumerableMap.AddressToUintMap;

    // =============== CONSTANTS ======================

    /// @dev The IERC20 contract's address of TNT.
    ///
    /// TODO: move this into the TNT core contracts.
    address constant TNT_ERC20_ADDRESS = 0x0000000000000000000000000000000000000802;

    /// @dev The Job Id for `keygen` job.
    uint8 constant KEYGEN_JOB_ID = 0;
    /// @dev The Job Id for `sign` job.
    uint8 constant SIGN_JOB_ID = 1;

    /// @dev Keygen Job Avarage duration in seconds.
    uint256 constant KEYGEN_JOB_DURATION_SECS = 5 seconds;
    /// @dev Sign Job Avarage duration in seconds.
    uint256 constant SIGN_JOB_DURATION_SECS = 3 seconds;

    // ================ STORAGE =======================

    /// @dev Mapping of service IDs to service operators addresses
    mapping(uint64 => EnumerableSet.AddressSet) private _serviceOperators;

    /// @dev Mapping from job id to the amount of tokens required for the job.
    /// This is used to determine the amount of tokens to be transferred from the
    /// service owner balance to the operator balance.
    EnumerableMap.AddressToUintMap private _keygenJobCost;
    EnumerableMap.AddressToUintMap private _signJobCost;

    // ================ EVENTS ========================
    event OperatorRegistered(address operator);
    event ServiceOperatorAdded(uint64 indexed serviceId, address indexed operator);

    // ================ ERRORS ========================
    error OperatorNotRegistered(address operator);
    error OperatorAlreadyAdded(uint64 serviceId, address operator);
    error UnsupportedJob(uint8 job);
    error InvalidECDSAPublicKey(bytes publicKey);
    error InvalidECDSASignature(bytes signature);

    /**
     * @dev Constructor for the FrostBlueprint contract
     */
    constructor() PaymentManagerBase(_msgSender()) {
        // Grant Root Chain role to the runtime.
        grantRole(ROOT_CHAIN_ROLE, ROOT_CHAIN);
        // Also Make it an Admin.
        grantRole(DEFAULT_ADMIN_ROLE, ROOT_CHAIN);
        // Add TNT as a supported token for payments by default.
        address[] memory supportedTokens = new address[](1);
        supportedTokens[0] = TNT_ERC20_ADDRESS;
        addSupportedTokens(supportedTokens);

        // Set the cost of the jobs.
        _keygenJobCost.set(TNT_ERC20_ADDRESS, 0.001 ether);
        _signJobCost.set(TNT_ERC20_ADDRESS, 0.00001 ether);
    }

    /**
     * @dev Hook for service operator registration. Called when a service operator
     * attempts to register with the blueprint.
     * @param operator The operator's details.
     * @param _registrationInputs Inputs required for registration.
     */
    function onRegister(bytes calldata operator, bytes calldata _registrationInputs)
        public
        payable
        override
        onlyFromRootChain
    {
        // Grant the operator the OPERATOR_ROLE.
        grantRole(OPERATOR_ROLE, operatorAddressFromPublicKey(operator));
    }

    /**
     * @dev Hook for service instance requests. Called when a user requests a service
     * instance from the blueprint.
     * @param serviceId The ID of the requested service.
     * @param operators The operators involved in the service.
     * @param _requestInputs Inputs required for the service request.
     */
    function onRequest(uint64 serviceId, bytes[] calldata operators, bytes calldata _requestInputs)
        public
        payable
        override
        onlyFromRootChain
    {
        // TODO: once we have access to the service owner, we can use it
        // to verify the service request and payment.
        // See: https://github.com/tangle-network/tangle/issues/817
        uint256 operatorsCount = operators.length;
        for (uint256 i = 0; i < operatorsCount; i++) {
            _addServiceOperator(serviceId, operatorAddressFromPublicKey(operators[i]));
        }
    }

    /**
     * @dev Hook for handling job call results. Called when operators send the result
     * of a job execution.
     * @param serviceId The ID of the service related to the job.
     * @param job The job identifier.
     * @param jobCallId The unique ID for the job call.
     * @param participant The participant (operator) sending the result.
     * @param inputs Inputs used for the job execution.
     * @param outputs Outputs resulting from the job execution.
     */
    function onJobResult(
        uint64 serviceId,
        uint8 job,
        uint64 jobCallId,
        bytes calldata participant,
        bytes calldata inputs,
        bytes calldata outputs
    ) public payable virtual override onlyFromRootChain {
        if (job == KEYGEN_JOB_ID) {
            _handleKeygenJobResult(serviceId, jobCallId, operatorAddressFromPublicKey(participant), inputs, outputs);
        } else if (job == SIGN_JOB_ID) {
            _handleSignJobResult(serviceId, jobCallId, operatorAddressFromPublicKey(participant), inputs, outputs);
        } else {
            revert UnsupportedJob(job);
        }
    }

    /**
     * @dev Implement the calculateServiceCost function.
     */
    function calculateServiceCost(uint256 serviceDuration, address token) external view override returns (uint256) {
        uint256 cost = 0;
        uint256 oneKeygenCall = _jobCost(KEYGEN_JOB_ID, token);
        uint256 oneSignCall = _jobCost(SIGN_JOB_ID, token);
        cost += oneKeygenCall + oneSignCall;
        return cost * serviceDuration;
    }

    /**
     * @dev Get the cost of a job per sec in a given token.
     * @param jobId uint8 The job identifier.
     * @param token address The token address.
     * @return cost uint256 The cost of the job per sec in the given token.
     */
    function jobCost(uint8 jobId, address token) external view returns (uint256) {
        return _jobCost(jobId, token);
    }

    /**
     * @dev Get Service operators for a given service ID.
     * @param serviceId uint64 The service ID.
     * @return operators address[] The operators for the given service ID.
     */
    function serviceOperators(uint64 serviceId) external view returns (address[] memory) {
        return _serviceOperators[serviceId].values();
    }

    /**
     * @dev Update the cost of a job.
     * @param jobId uint8 The job identifier.
     * @param token address The token address.
     * @param cost uint256 The new cost of the job per sec in the given token.
     */
    function updateJobCost(uint8 jobId, address token, uint256 cost) external onlyOwner {
        if (jobId == KEYGEN_JOB_ID) {
            _keygenJobCost.set(token, cost);
        } else if (jobId == SIGN_JOB_ID) {
            _signJobCost.set(token, cost);
        } else {
            revert UnsupportedJob(jobId);
        }
    }

    /**
     * @dev Converts a public key to an operator address.
     * @param publicKey bytes The public key to convert.
     * @return operator address The operator address.
     */
    function operatorAddressFromPublicKey(bytes calldata publicKey) public pure returns (address operator) {
        return address(uint160(uint256(keccak256(publicKey))));
    }

    /**
     * @dev Add a service operator to the service.
     * @param serviceId The ID of the service.
     * @param operator The operator to add.
     */
    function _addServiceOperator(uint64 serviceId, address operator) internal {
        if (!hasRole(OPERATOR_ROLE, operator)) {
            revert OperatorNotRegistered(operator);
        }

        bool added = _serviceOperators[serviceId].add(operator);
        if (!added) {
            revert OperatorAlreadyAdded(serviceId, operator);
        }
    }

    /**
     * @dev Handle the result of a `keygen` job.
     * @param serviceId uint64 The ID of the service.
     * @param _jobCallId uint64 The ID of the job call.
     * @param operator address The operator who executed the job.
     * @param _inputs bytes The inputs used for the job execution.
     * @param outputs bytes The outputs resulting from the job execution.
     */
    function _handleKeygenJobResult(
        uint64 serviceId,
        uint64 _jobCallId,
        address operator,
        bytes calldata _inputs,
        bytes calldata outputs
    ) internal {
        if (outputs.length != 33) {
            revert InvalidECDSAPublicKey(outputs);
        }
        uint256 operatorsCount = _serviceOperators[serviceId].length();
        address[] memory _tokens = supportedTokens();
        for (uint256 i = 0; i < _tokens.length; i++) {
            address token = _tokens[i];
            uint256 tokensPerSec = _jobCost(KEYGEN_JOB_ID, token);
            uint256 amount = tokensPerSec * KEYGEN_JOB_DURATION_SECS * operatorsCount;
            creditOperator(operator, token, amount);
        }
    }

    /**
     * @dev Handle the result of a `sign` job.
     * @param _serviceId uint64 The ID of the service.
     * @param _jobCallId uint64 The ID of the job call.
     * @param operator address The operator who executed the job.
     * @param inputs bytes The inputs used for the job execution.
     * @param outputs bytes The outputs resulting from the job execution.
     */
    function _handleSignJobResult(
        uint64 _serviceId,
        uint64 _jobCallId,
        address operator,
        bytes calldata inputs,
        bytes calldata outputs
    ) internal {
        (bytes memory _publicKey, bytes memory _msg) = abi.decode(inputs, (bytes, bytes));
        bytes memory signature = abi.decode(outputs, (bytes));
        if (signature.length != 65) {
            revert InvalidECDSASignature(signature);
        }
        // TODO: verify the signature
        address[] memory _tokens = supportedTokens();
        for (uint256 i = 0; i < _tokens.length; i++) {
            address token = _tokens[i];
            uint256 tokensPerSec = _jobCost(SIGN_JOB_ID, token);
            uint256 amount = tokensPerSec * SIGN_JOB_DURATION_SECS;
            creditOperator(operator, token, amount);
        }
    }

    /**
     * @dev Get the Job Cost by Job ID and Token Address
     * @param jobId uint8 The ID of the job.
     * @param token address The token address.
     * @return amount uint256 The amount of the token required for the job.
     */
    function _jobCost(uint8 jobId, address token) internal view returns (uint256 amount) {
        if (jobId == KEYGEN_JOB_ID) {
            return _keygenJobCost.get(token);
        } else if (jobId == SIGN_JOB_ID) {
            return _signJobCost.get(token);
        } else {
            revert UnsupportedJob(jobId);
        }
    }
}
