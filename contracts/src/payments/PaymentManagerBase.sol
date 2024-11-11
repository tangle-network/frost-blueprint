// SPDX-License-Identifier: UNLICENSE
pragma solidity >=0.8.13;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import "@src/payments/IPaymentManager.sol";

/**
 * @title PaymentManagerBase
 * @dev Base contract implementing the IPaymentManager interface with additional functionalities.
 */
abstract contract PaymentManagerBase is IPaymentManager, Ownable, AccessControlEnumerable, ReentrancyGuard {
    using SafeERC20 for IERC20;
    using EnumerableSet for EnumerableSet.AddressSet;

    // Roles
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant SERVICE_OWNER_ROLE = keccak256("SERVICE_OWNER_ROLE");
    bytes32 public constant ROOT_CHAIN_ROLE = keccak256("ROOT_CHAIN_ROLE");

    EnumerableSet.AddressSet private supportedTokensSet;

    // Operator balances: operator => token => balance
    mapping(address => mapping(address => uint256)) private operatorBalancesMapping;

    // Service Owners balances: serviceOwner => token => balance
    mapping(address => mapping(address => uint256)) private serviceOwnerBalancesMapping;

    // Events
    event TokensAdded(address[] tokens);
    event TokensRemoved(address[] tokens);
    event Deposited(address indexed user, address indexed token, uint256 amount);
    event Withdrawn(address indexed user, address indexed token, uint256 amount);
    event WithdrawnTo(address indexed user, address indexed token, uint256 amount, address indexed recipient);
    event OperatorCredited(address indexed operator, address indexed token, uint256 amount);

    // Custom Errors
    error TokenAlreadySupported(address token);
    error TokenNotSupported(address token);
    error InvalidAmount();
    error Unauthorized();
    error InsufficientBalance(address token);
    error TransferFailed();
    error InvalidRecipient(address recipient);
    error InvalidETHAmount();

    /**
     * @dev Constructor sets up roles.
     */
    constructor(address initialOwner) Ownable(initialOwner) {
        _grantRole(DEFAULT_ADMIN_ROLE, initialOwner);
    }

    /**
     * @dev Modifier to restrict functions to the root chain.
     */
    modifier onlyRootChain() {
        if (!hasRole(ROOT_CHAIN_ROLE, msg.sender)) {
            revert Unauthorized();
        }
        _;
    }

    /**
     * @dev Modifier to restrict functions to service owners.
     */
    modifier onlyServiceOwner() {
        if (!hasRole(SERVICE_OWNER_ROLE, msg.sender)) {
            revert Unauthorized();
        }
        _;
    }

    /**
     * @dev Modifier to restrict functions to operators.
     */
    modifier onlyOperator() {
        if (!hasRole(OPERATOR_ROLE, msg.sender)) {
            revert Unauthorized();
        }
        _;
    }

    /**
     * @dev Get the list of supported tokens.
     * @return address[] List of supported tokens
     */
    function supportedTokens() public view override returns (address[] memory) {
        return supportedTokensSet.values();
    }

    /**
     * @dev Add new tokens to the list of supported tokens.
     * @param _tokens List of token addresses to add.
     */
    function addSupportedTokens(address[] memory _tokens) public override onlyOwner {
        uint256 length = _tokens.length;
        for (uint256 i = 0; i < length; i++) {
            address token = _tokens[i];
            bool added = supportedTokensSet.add(token);
            if (!added) {
                revert TokenAlreadySupported(token);
            }
        }
        emit TokensAdded(_tokens);
    }

    /**
     * @dev Remove tokens from the list of supported tokens.
     * @param _tokens List of token addresses to remove.
     */
    function removeSupportedTokens(address[] memory _tokens) public override onlyOwner {
        uint256 length = _tokens.length;
        for (uint256 i = 0; i < length; i++) {
            address token = _tokens[i];
            bool removed = supportedTokensSet.remove(token);
            if (!removed) {
                revert TokenNotSupported(token);
            }
        }
        emit TokensRemoved(_tokens);
    }

    /**
     * @dev Get the balance of the PaymentManager contract for a specific token.
     * @param _token Token address.
     * @return Balance of the contract for the token.
     */
    function balanceOf(address _token) public view override returns (uint256) {
        if (_token == address(0)) {
            return address(this).balance;
        } else {
            return IERC20(_token).balanceOf(address(this));
        }
    }

    /**
     * @dev Get the balance of an Operator for a specific token.
     * @param _operator Operator address.
     * @param _token Token address.
     * @return Balance of the operator for the token.
     */
    function operatorBalanceOf(address _operator, address _token) public view override returns (uint256) {
        return operatorBalancesMapping[_operator][_token];
    }

    /**
     * @dev Credit an Operator with tokens for their services.
     * @param _operator Operator address.
     * @param _token Token address.
     * @param _amount Amount of tokens to credit.
     */
    function creditOperator(address _operator, address _token, uint256 _amount)
        public
        override
        onlyRootChain
        nonReentrant
    {
        if (_amount == 0) {
            revert InvalidAmount();
        }

        if (!supportedTokensSet.contains(_token)) {
            revert TokenNotSupported(_token);
        }

        if (_token == address(0)) {
            if (address(this).balance < _amount) {
                revert InsufficientBalance(_token);
            }
            operatorBalancesMapping[_operator][_token] += _amount;
        } else {
            uint256 contractBalance = IERC20(_token).balanceOf(address(this));
            if (contractBalance < _amount + operatorBalancesMapping[_operator][_token]) {
                revert InsufficientBalance(_token);
            }
            operatorBalancesMapping[_operator][_token] += _amount;
        }

        emit OperatorCredited(_operator, _token, _amount);
    }

    /**
     * @dev Deposit tokens or ETH to the PaymentManager contract.
     * @param _token Token address (address(0) for ETH).
     * @param _amount Amount to deposit.
     */
    function deposit(address _token, uint256 _amount) public payable override nonReentrant {
        if (_amount == 0) {
            revert InvalidAmount();
        }

        if (_token == address(0)) {
            if (msg.value != _amount) {
                revert InvalidETHAmount();
            }
            emit Deposited(msg.sender, _token, _amount);
        } else {
            if (!supportedTokensSet.contains(_token)) {
                revert TokenNotSupported(_token);
            }
            // Check if the contract has enough allowance to transfer the tokens.
            IERC20(_token).safeTransferFrom(msg.sender, address(this), _amount);
            emit Deposited(msg.sender, _token, _amount);
        }
    }

    /**
     * @dev Withdraw tokens or ETH to the caller.
     * @param _token Token address (address(0) for ETH).
     * @param _amount Amount to withdraw.
     */
    function withdraw(address _token, uint256 _amount) public override nonReentrant onlyOperator {
        _withdraw(_token, _amount, _msgSender());
    }

    /**
     * @dev Withdraw tokens or ETH to a specific recipient.
     * @param _token Token address (address(0) for ETH).
     * @param _amount Amount to withdraw.
     * @param _recipient Recipient address.
     */
    function withdrawAndTransfer(address _token, uint256 _amount, address _recipient)
        public
        override
        nonReentrant
        onlyOperator
    {
        if (_recipient == address(0)) {
            revert InvalidRecipient(_recipient);
        }
        _withdraw(_token, _amount, _recipient);
    }

    /**
     * @dev Internal withdraw function.
     * @param _token Token address.
     * @param _amount Amount to withdraw.
     * @param _recipient Recipient address.
     */
    function _withdraw(address _token, uint256 _amount, address _recipient) internal {
        if (_amount == 0) {
            revert InvalidAmount();
        }

        if (_token == address(0)) {
            _withdrawNative(_amount, _recipient);
        } else {
            _withdrawERC20(_token, _amount, _recipient);
        }

        emit Withdrawn(_recipient, _token, _amount);
    }

    /**
     * @dev Internal withdraw function for native tokens.
     * @param _amount Amount to withdraw.
     * @param _recipient Recipient address.
     */
    function _withdrawNative(uint256 _amount, address _recipient) internal {
        address _token = address(0);
        if (_amount == 0) {
            revert InvalidAmount();
        }

        // Check if the credit balance is enough to withdraw the requested amount.
        uint256 creditBalance = operatorBalancesMapping[_msgSender()][_token];

        if (creditBalance < _amount) {
            revert InsufficientBalance(_token);
        }

        if (address(this).balance < _amount) {
            revert InsufficientBalance(_token);
        }

        Address.sendValue(payable(_recipient), _amount);

        operatorBalancesMapping[_msgSender()][_token] -= _amount;
    }

    /**
     * @dev Internal withdraw function for non-native tokens.
     * @param _token Token address.
     * @param _amount Amount to withdraw.
     * @param _recipient Recipient address.
     */
    function _withdrawERC20(address _token, uint256 _amount, address _recipient) internal {
        if (_amount == 0) {
            revert InvalidAmount();
        }

        if (!supportedTokensSet.contains(_token)) {
            revert TokenNotSupported(_token);
        }

        // Check if the credit balance is enough to withdraw the requested amount.
        uint256 creditBalance = operatorBalancesMapping[_msgSender()][_token];

        if (creditBalance < _amount) {
            revert InsufficientBalance(_token);
        }

        uint256 contractBalance = IERC20(_token).balanceOf(address(this));
        if (contractBalance < _amount) {
            revert InsufficientBalance(_token);
        }

        IERC20(_token).safeTransfer(_recipient, _amount);
        // Deduct the withdrawn amount from the credit balance.
        operatorBalancesMapping[_msgSender()][_token] -= _amount;
    }

    /**
     * @dev Fallback function to prevent accidental ETH transfers.
     */
    fallback() external payable {
        revert TransferFailed();
    }

    /**
     * @dev Receive function to prevent accidental ETH transfers.
     */
    receive() external payable {
        revert TransferFailed();
    }

    /**
     * @dev Calculate service cost - to be implemented by inheriting contracts.
     * @param _serviceDuration Duration of the service in seconds.
     * @param _token Token address.
     * @return Total cost of the service.
     */
    function calculateServiceCost(uint256 _serviceDuration, address _token)
        external
        view
        virtual
        override
        returns (uint256);
}
