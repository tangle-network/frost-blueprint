// SPDX-License-Identifier: UNLICENSE
pragma solidity >=0.8.13;

/**
 * @title IPaymentManager
 * @dev Interface for the PaymentManager contract
 * @dev This contract is responsible for managing the payments of service
 * that are made by the users of the blueprint.
 * @dev The payments are made in the form of tokens, which are transferred
 * to the Operators whom provide the services.
 */
interface IPaymentManager {
    /**
     * @dev Get the list of supported tokens
     * @return address[] List of supported tokens
     */
    function supportedTokens() external view returns (address[] memory);

    /**
     * @dev Add a new token(s) to the list of supported tokens
     * @param _tokens address[] List of tokens to be added
     */
    function addSupportedTokens(address[] memory _tokens) external;

    /**
     * @dev Remove a token(s) from the list of supported tokens
     * @param _tokens address[] List of tokens to be removed
     */
    function removeSupportedTokens(address[] memory _tokens) external;

    /**
     * @dev Get the balance of the PaymentManager contract for a specific token
     * @param _token address Token address
     * @return uint256 Balance of the PaymentManager contract for the token
     */
    function balanceOf(address _token) external view returns (uint256);

    /**
     * @dev Get the balance of an Operator for a specific token
     * @param _operator address Operator address
     * @param _token address Token address
     * @return uint256 Balance of the Operator for the token
     */
    function operatorBalanceOf(address _operator, address _token) external view returns (uint256);

    /**
     * @dev Credit an Operator with tokens for their services.
     * @param _operator address Operator address
     * @param _token address Token address
     * @param _amount uint256 Amount of tokens to transfer
     */
    function creditOperator(address _operator, address _token, uint256 _amount) external;

    /**
     * @dev Deposit tokens to the PaymentManager contract for a specific token as payment
     * for the services provided by the Operators (upfront payment)
     * @param _token address Token address (must be a supported token)
     * @param _amount uint256 Amount of tokens to pay
     */
    function deposit(address _token, uint256 _amount) external payable;

    /**
     * @dev Withdraw tokens from the PaymentManager contract to the caller
     * @param _token address Token address
     * @param _amount uint256 Amount of tokens to withdraw
     */
    function withdraw(address _token, uint256 _amount) external;

    /**
     * @dev Withdraw tokens from the PaymentManager contract to a specific recipient
     * @param _token address Token address
     * @param _amount uint256 Amount of tokens to withdraw
     * @param _recipient address Recipient address
     */
    function withdrawAndTransfer(address _token, uint256 _amount, address _recipient) external;

    /**
     * @dev Get the total amount of tokens required for the service to be provided by the Operators
     * @param _serviceDuration uint256 Duration of the service in seconds (time)
     * @param _token address Token address for the payment (must be a supported token)
     * @return uint256 Total amount of tokens required for the service
     */
    function calculateServiceCost(uint256 _serviceDuration, address _token) external view returns (uint256);
}
