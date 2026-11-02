// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IAccounting {
    function mint(address, uint256) external;
    function snapshot() external returns (uint256);
    function balanceOfAt(address, uint256) external view returns (uint256);
    function totalSupplyAt(uint256) external view returns (uint256);
}

contract SafeRewarderPool {
    IAccounting public accounting;
    uint128 public lastSnapshotIdForRewards;

    constructor(IAccounting _acct) {
        accounting = _acct;
        lastSnapshotIdForRewards = uint128(accounting.snapshot());
    }

    function deposit(uint256 amount) external {
        accounting.mint(msg.sender, amount);
        distributeRewards();
    }

    function distributeRewards() public {
        uint256 id = lastSnapshotIdForRewards;
        accounting.balanceOfAt(msg.sender, id);
        accounting.totalSupplyAt(id);
    }
}
