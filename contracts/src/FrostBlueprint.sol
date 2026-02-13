// SPDX-License-Identifier: UNLICENSE
pragma solidity >=0.8.20;

import "tnt-core/BlueprintServiceManagerBase.sol";

/**
 * @title FrostBlueprint
 * @dev This contract is a blueprint for a FROST service. It extends the
 * `BlueprintServiceManagerBase` contract, which provides the basic functionality
 */
contract FrostBlueprint is BlueprintServiceManagerBase {
    function operatorAddressFromPublicKey(bytes memory operatorPublicKey) public pure returns (address) {
        // First hash with keccak256 and then with ripemd160
        // Convert the ripemd160 hash to address by taking the last 20 bytes
        bytes32 keccakHash = keccak256(operatorPublicKey);
        bytes memory encoded = abi.encodePacked(keccakHash);
        bytes20 ripemdHash = ripemd160(encoded);
        return address(uint160(bytes20(ripemdHash)));
    }
}
