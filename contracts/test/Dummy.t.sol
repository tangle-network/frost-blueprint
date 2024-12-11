// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.9.0;

import {Test} from "forge-std/Test.sol";

contract Dummy {
    uint256 public value;

    function setValue(uint256 _value) public {
        value = _value;
    }
}

contract DummyTest is Test {
    Dummy dummy;

    function beforeEach() public {
        dummy = new Dummy();
    }

    function testSetValue() public {
        dummy.setValue(10);
        assertEq(dummy.value(), 10);
    }
}
