// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SafeGovernanceToken {
    mapping(address => uint256) private bal;
    uint256 private snapId;

    function snapshot() external {
        require(msg.sender == address(this), "restricted");
        snapId += 1;
    }

    function getBalanceAtLastSnapshot(address who) external view returns (uint256) {
        return bal[who];
    }
}

contract SafeSimpleGovernance {
    SafeGovernanceToken token;

    constructor(SafeGovernanceToken _t) {
        token = _t;
    }

    function queueAction(address, uint128, bytes calldata) external {
        token.getBalanceAtLastSnapshot(msg.sender);
    }
}

contract SafeSelfiePool {
    function flashLoan(address, uint256, bytes calldata) external {}
}
